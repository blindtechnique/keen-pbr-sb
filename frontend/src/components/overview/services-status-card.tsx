import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { RotateCw } from "lucide-react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import type { TransportStatus } from "@/api/generated/model"
import { TransportActionRequestAction } from "@/api/generated/model"
import { useGetHealthService, useGetTransports } from "@/api/generated/keen-api"
import {
  usePostServiceActionMutation,
  usePostTransportActionMutation,
  useRoutingControlPendingState,
} from "@/api/mutations"
import { getDnsmasqBadgeState } from "@/components/overview/dnsmasq-status"
import { Switch } from "@/components/ui/switch"
import { SectionCard } from "@/components/shared/section-card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

/** The dnsmasq status vocabulary is not the badge vocabulary. */
function badgeVariantForTone(
  tone: "healthy" | "warning" | "degraded"
): "success" | "warning" | "destructive" {
  if (tone === "healthy") return "success"
  if (tone === "warning") return "warning"
  return "destructive"
}

type NfqwsStatus = {
  installed: boolean
  running: boolean
}

type ServiceRow = {
  key: string
  label: string
  detail: string
  state: "up" | "down" | "absent"
  onRestart?: () => void
  restarting?: boolean
  // Only the routing service itself can be switched off from here.
  toggle?: {
    checked: boolean
    disabled: boolean
    label: string
    onChange: (checked: boolean) => void
  }
  badges?: { label: string; tone: "success" | "warning" | "destructive" }[]
}

/**
 * Compact health strip for the two companion services users care about at a
 * glance: the sing-box transports keen-pbr routes through and the optional
 * nfqws2 daemon that handles traffic staying on the direct route.
 */
export function ServicesStatusCard() {
  const { t } = useTranslation()

  const transportsQuery = useGetTransports({
    query: { refetchInterval: 5_000 },
  })
  const nfqwsQuery = useQuery<NfqwsStatus>({
    queryKey: ["nfqws"],
    queryFn: async () => {
      const response = await fetch("/api/nfqws")
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json()
    },
    refetchInterval: 10_000,
  })

  const transports: TransportStatus[] =
    transportsQuery.data?.status === 200 ? transportsQuery.data.data : []
  const singboxTransports = transports.filter(
    (transport) => transport.type !== "native"
  )
  const runningSingbox = singboxTransports.filter(
    (transport) => transport.state === "up"
  ).length

  const queryClient = useQueryClient()
  const serviceHealthQuery = useGetHealthService({
    query: { refetchInterval: 10_000 },
  })
  const serviceRestartMutation = usePostServiceActionMutation("restart")
  const serviceStartMutation = usePostServiceActionMutation("start")
  const serviceStopMutation = usePostServiceActionMutation("stop")
  const { anyPending: routingActionPending } = useRoutingControlPendingState()
  const transportActionMutation = usePostTransportActionMutation()
  const nfqwsRestartMutation = useMutation({
    mutationFn: async () => {
      const response = await fetch("/api/nfqws", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "service", command: "restart" }),
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json()
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["nfqws"] })
      toast.success(t("overview.services.restartRequested"))
    },
    onError: () => toast.error(t("overview.services.restartFailed")),
  })

  // Restarting sing-box means restarting every managed transport it runs.
  const restartSingbox = () => {
    for (const transport of singboxTransports) {
      transportActionMutation.mutate({
        data: {
          tag: transport.tag,
          action: TransportActionRequestAction.restart,
        },
      })
    }
    toast.success(t("overview.services.restartRequested"))
  }

  const serviceHealth =
    serviceHealthQuery.data?.status === 200 ? serviceHealthQuery.data.data : undefined
  const serviceRunning = serviceHealth?.status === "running"

  const dnsmasqBadge = getDnsmasqBadgeState(
    serviceHealth?.resolver_live_status,
    serviceHealth?.resolver_config_sync_state
  )

  const nfqws = nfqwsQuery.data
  const rows: ServiceRow[] = [
    {
      key: "keen-pbr",
      label: "keen-pbr-sb",
      detail: serviceHealth
        ? t("overview.services.version", {
            version: serviceHealth.version,
            build: serviceHealth.build,
          })
        : t("overview.services.unknown"),
      state: !serviceHealth ? "absent" : serviceRunning ? "up" : "down",
      onRestart: serviceHealth
        ? () => serviceRestartMutation.mutate()
        : undefined,
      restarting: serviceRestartMutation.isPending,
      toggle: {
        checked: serviceRunning,
        disabled: routingActionPending || !serviceHealth,
        label: serviceRunning
          ? t("overview.runtime.actions.stop")
          : t("overview.runtime.actions.start"),
        onChange: (checked: boolean) =>
          checked
            ? serviceStartMutation.mutate()
            : serviceStopMutation.mutate(),
      },
      badges: serviceHealth
        ? [
            {
              label: t(dnsmasqBadge.labelKey),
              tone: badgeVariantForTone(dnsmasqBadge.tone),
            },
          ]
        : undefined,
    },
    {
      key: "singbox",
      label: t("overview.services.singbox"),
      detail:
        singboxTransports.length === 0
          ? t("overview.services.noTransports")
          : t("overview.services.transportsRunning", {
              running: runningSingbox,
              total: singboxTransports.length,
            }),
      state:
        singboxTransports.length === 0
          ? "absent"
          : runningSingbox > 0
            ? "up"
            : "down",
      onRestart: singboxTransports.length > 0 ? restartSingbox : undefined,
      restarting: transportActionMutation.isPending,
    },
    {
      key: "nfqws",
      label: t("overview.services.nfqws"),
      detail: !nfqws?.installed
        ? t("overview.services.notInstalled")
        : nfqws.running
          ? t("overview.services.running")
          : t("overview.services.stopped"),
      state: !nfqws?.installed ? "absent" : nfqws.running ? "up" : "down",
      onRestart: nfqws?.installed
        ? () => nfqwsRestartMutation.mutate()
        : undefined,
      restarting: nfqwsRestartMutation.isPending,
    },
  ]

  return (
    <SectionCard className="h-full" title={t("overview.services.title")}>
      <div className="space-y-3">
        {rows.map((row) => (
          <div
            className="flex items-center justify-between gap-3"
            key={row.key}
          >
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                <span className="truncate text-sm font-medium">{row.label}</span>
                {row.badges?.map((badge) => (
                  <Badge key={badge.label} size="xs" variant={badge.tone}>
                    {badge.label}
                  </Badge>
                ))}
              </div>
              <div className="truncate text-xs text-muted-foreground">
                {row.detail}
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-1.5">
            {row.toggle ? (
              <Switch
                aria-label={row.toggle.label}
                checked={row.toggle.checked}
                disabled={row.toggle.disabled}
                onCheckedChange={row.toggle.onChange}
                title={row.toggle.label}
              />
            ) : null}
            {row.onRestart ? (
              <Button
                aria-label={t("overview.services.restart")}
                className="size-7"
                disabled={row.restarting}
                onClick={row.onRestart}
                size="icon"
                title={t("overview.services.restart")}
                variant="ghost"
              >
                <RotateCw
                  className={cn("size-3.5", row.restarting && "animate-spin")}
                />
              </Button>
            ) : null}
            <Badge
              size="xs"
              variant={
                row.state === "up"
                  ? "success"
                  : row.state === "down"
                    ? "destructive"
                    : "secondary"
              }
            >
              {row.state === "up"
                ? t("overview.services.badgeUp")
                : row.state === "down"
                  ? t("overview.services.badgeDown")
                  : t("overview.services.badgeAbsent")}
            </Badge>
            </div>
          </div>
        ))}
      </div>
    </SectionCard>
  )
}
