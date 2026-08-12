import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { RotateCw } from "lucide-react"
import { useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import type { TransportStatus } from "@/api/generated/model"
import { TransportActionRequestAction } from "@/api/generated/model"
import {
  getHealthRouting,
  getHealthService,
  getTransports,
  postTransportAction,
  useGetHealthService,
  useGetTransports,
} from "@/api/generated/keen-api"
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { waitForRuntimeReadiness } from "@/lib/runtime-readiness"
import {
  parseServiceCommandResult,
  ServiceRestartFailure,
} from "@/lib/service-restart-result"
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
  // One line on what the service is for. The card has the room, and the
  // names alone mean nothing to someone who did not set this up.
  summary: string
  detail: string
  state: "up" | "down" | "pending" | "absent"
  onRestart?: () => void
  restarting?: boolean
  // Every service on the card can be switched from here.
  toggle?: {
    checked: boolean
    disabled: boolean
    label: string
    onChange: (checked: boolean) => void
  }
  badges?: { label: string; tone: "success" | "warning" | "destructive" }[]
}

const errorMessage = (error: unknown) => {
  if (error instanceof Error) return error.message
  if (
    error &&
    typeof error === "object" &&
    "message" in error &&
    typeof error.message === "string"
  ) {
    return error.message
  }
  return "unknown error"
}

/**
 * Compact health strip for the two companion services users care about at a
 * glance: the sing-box transports keen-pbr routes through and the optional
 * nfqws2 daemon that handles traffic staying on the direct route.
 */
/**
 * The terminal outcome of a restart, kept so it can be shown in full.
 *
 * Only services restarted through an init script have real command output. The
 * routing runtime is restarted in-process and has none, so it keeps its toast
 * rather than being given an empty panel that implies output was captured.
 */
type RestartOutcome = {
  readonly service: string
  readonly ok: boolean
  readonly exitCode: number | undefined
  readonly output: string
}

export function ServicesStatusCard() {
  const { t } = useTranslation()
  const [restartOutcome, setRestartOutcome] = useState<RestartOutcome | null>(
    null
  )

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
  const restartableSingboxTransports = singboxTransports.filter(
    (transport) => transport.desired_up || transport.state === "up"
  )

  const queryClient = useQueryClient()
  const serviceHealthQuery = useGetHealthService()
  const serviceRestartMutation = usePostServiceActionMutation("restart")
  const serviceStartMutation = usePostServiceActionMutation("start")
  const serviceStopMutation = usePostServiceActionMutation("stop")
  const { anyPending: routingActionPending } = useRoutingControlPendingState()
  const transportActionMutation = usePostTransportActionMutation()
  const runtimeReadinessProbe = {
    health: async () => {
      const response = await getHealthService({ cache: "no-store" })
      return response.data
    },
    routing: async () => {
      const response = await getHealthRouting({ cache: "no-store" })
      if (response.status !== 200) {
        throw new Error("routing health endpoint returned an error")
      }
      return response.data
    },
    transports: async () => {
      const response = await getTransports({ cache: "no-store" })
      if (response.status !== 200) {
        throw new Error("transport manager is unavailable")
      }
      return response.data
    },
  }
  const routingRestartMutation = useMutation({
    mutationFn: async () => {
      await serviceRestartMutation.mutateAsync()
      await waitForRuntimeReadiness(runtimeReadinessProbe)
    },
    onSuccess: async () => {
      await Promise.all([
        serviceHealthQuery.refetch(),
        transportsQuery.refetch(),
      ])
      toast.success(t("overview.services.restartComplete"))
    },
    onError: (error) =>
      toast.error(
        t("overview.services.restartFailedDetail", {
          error: errorMessage(error),
        })
      ),
  })
  const nfqwsRestartMutation = useMutation({
    mutationFn: async () => {
      const response = await fetch("/api/nfqws", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "service", command: "restart" }),
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      // The endpoint answers 200 even when the init script failed, so the
      // body is the only report of what actually happened to the service.
      // Trusting the HTTP status alone made every failed restart look
      // successful.
      const result = parseServiceCommandResult(await response.json())
      if (!result.ok) {
        throw new ServiceRestartFailure(result)
      }
      return result
    },
    onSuccess: async (result) => {
      await queryClient.invalidateQueries({ queryKey: ["nfqws"] })
      // Not restartComplete: that string promises "routing and DNS are ready",
      // which this path never checks. It belongs to the keen-pbr and sing-box
      // restarts, which do await waitForRuntimeReadiness.
      toast.success(
        t("overview.services.outcomeSucceeded", { service: "nfqws2" })
      )
      if (result.output.trim().length > 0) {
        setRestartOutcome({ service: "nfqws2", ...result })
      }
    },
    onError: async (error) => {
      // Refresh regardless: a failed restart still moved the service, and a
      // stale "running" badge next to a failure notice is its own lie.
      await queryClient.invalidateQueries({ queryKey: ["nfqws"] })
      toast.error(
        t("overview.services.restartFailedDetail", {
          error: errorMessage(error),
        })
      )
      // A failure is exactly when the full output matters, so open it rather
      // than leaving the user with a single truncated line.
      if (error instanceof ServiceRestartFailure) {
        setRestartOutcome({ service: "nfqws2", ...error.result })
      }
    },
  })

  const nfqwsServiceMutation = useMutation({
    mutationFn: async (command: "start" | "stop") => {
      const response = await fetch("/api/nfqws", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "service", command }),
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json()
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["nfqws"] })
    },
    onError: () => toast.error(t("overview.services.switchFailed")),
  })

  // There is no sing-box service to switch: sing-box exists only as the
  // transports it runs, so the switch raises or drops all of them at once.
  const setSingboxRunning = (running: boolean) => {
    for (const transport of singboxTransports) {
      transportActionMutation.mutate({
        data: {
          tag: transport.tag,
          action: running
            ? TransportActionRequestAction.up
            : TransportActionRequestAction.down,
        },
      })
    }
  }

  // Restart managed tunnels first, then rebuild keen-pbr routes/firewall and
  // dnsmasq against the interfaces that actually came back. The previous
  // fire-and-forget loop could display success while the routes still pointed
  // at a TUN interface that had disappeared during restart.
  const singboxRestartMutation = useMutation({
    mutationFn: async () => {
      // An intentionally stopped transport must stay stopped. Restart only
      // transports whose desired runtime state is up (plus a live legacy
      // status that does not yet expose desired_up correctly).
      const tags = restartableSingboxTransports.map(
        (transport) => transport.tag
      )
      await Promise.all(
        tags.map((tag) =>
          postTransportAction({
            tag,
            action: TransportActionRequestAction.restart,
          })
        )
      )
      await serviceRestartMutation.mutateAsync()
      await waitForRuntimeReadiness(runtimeReadinessProbe, {
        expectedTransportTags: tags,
      })
    },
    onSuccess: async () => {
      await Promise.all([
        serviceHealthQuery.refetch(),
        transportsQuery.refetch(),
      ])
      toast.success(t("overview.services.restartComplete"))
    },
    onError: (error) =>
      toast.error(
        t("overview.services.restartFailedDetail", {
          error: errorMessage(error),
        })
      ),
  })

  const serviceHealth =
    serviceHealthQuery.data?.status === 200 ? serviceHealthQuery.data.data : undefined
  const serviceRunning = serviceHealth?.status === "running"
  const serviceTransitioning =
    serviceHealth?.runtime_state === "starting" ||
    serviceHealth?.runtime_state === "applying" ||
    serviceHealth?.runtime_state === "shutting_down"

  const dnsmasqBadge = getDnsmasqBadgeState(
    serviceHealth?.resolver_live_status,
    serviceHealth?.resolver_config_sync_state
  )

  const nfqws = nfqwsQuery.data
  const rows: ServiceRow[] = [
    {
      key: "keen-pbr",
      label: "keen-pbr-sb",
      summary: t("overview.services.summary.keenPbr"),
      detail: serviceHealth
        ? t("overview.services.version", {
            version: serviceHealth.version,
            build: serviceHealth.build,
          })
        : t("overview.services.unknown"),
      state: !serviceHealth
        ? "absent"
        : serviceTransitioning
          ? "pending"
          : serviceRunning
            ? "up"
            : "down",
      onRestart: serviceHealth
        ? () => routingRestartMutation.mutate()
        : undefined,
      restarting: routingRestartMutation.isPending || serviceTransitioning,
      toggle: {
        checked: serviceRunning,
        disabled: routingActionPending || serviceTransitioning || !serviceHealth,
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
      summary: t("overview.services.summary.singbox"),
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
      onRestart:
        restartableSingboxTransports.length > 0
          ? () => singboxRestartMutation.mutate()
          : undefined,
      restarting:
        singboxRestartMutation.isPending || transportActionMutation.isPending,
      toggle: {
        checked: runningSingbox > 0,
        disabled:
          singboxTransports.length === 0 || transportActionMutation.isPending,
        label:
          runningSingbox > 0
            ? t("overview.runtime.actions.stop")
            : t("overview.runtime.actions.start"),
        onChange: setSingboxRunning,
      },
    },
    {
      key: "nfqws",
      label: t("overview.services.nfqws"),
      summary: t("overview.services.summary.nfqws"),
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
      toggle: {
        checked: Boolean(nfqws?.running),
        disabled: !nfqws?.installed || nfqwsServiceMutation.isPending,
        label: nfqws?.running
          ? t("overview.runtime.actions.stop")
          : t("overview.runtime.actions.start"),
        onChange: (checked: boolean) =>
          nfqwsServiceMutation.mutate(checked ? "start" : "stop"),
      },
    },
  ]

  return (
    <SectionCard className="h-full" title={t("overview.services.title")}>
      <div className="space-y-3">
        {rows.map((row) => (
          <div
            className="flex items-start justify-between gap-3"
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
              <div className="text-xs leading-snug text-muted-foreground">
                {row.summary}
              </div>
              <div className="truncate text-xs text-muted-foreground/80">
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
                  : row.state === "pending"
                    ? "warning"
                  : row.state === "down"
                    ? "destructive"
                    : "secondary"
              }
            >
              {row.state === "up"
                ? t("overview.services.badgeUp")
                : row.state === "pending"
                  ? t("overview.services.badgeTransitioning")
                : row.state === "down"
                  ? t("overview.services.badgeDown")
                  : t("overview.services.badgeAbsent")}
            </Badge>
            </div>
          </div>
        ))}
      </div>
      <ServiceRestartOutcomeDialog
        onClose={() => setRestartOutcome(null)}
        outcome={restartOutcome}
      />
    </SectionCard>
  )
}

/**
 * Shows what the init script actually printed.
 *
 * A toast can carry one line, which is enough to say a restart failed and not
 * nearly enough to say why. The output is the difference between "restart
 * failed" and "address already in use" - the second one a user can act on
 * without opening an SSH session.
 */
function ServiceRestartOutcomeDialog({
  onClose,
  outcome,
}: {
  readonly onClose: () => void
  readonly outcome: RestartOutcome | null
}) {
  const { t } = useTranslation()
  if (!outcome) {
    return null
  }

  return (
    <Dialog
      onOpenChange={(open) => {
        if (!open) onClose()
      }}
      open
    >
      <DialogContent className="overflow-hidden sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>
            {outcome.ok
              ? t("overview.services.outcomeSucceeded", {
                  service: outcome.service,
                })
              : t("overview.services.outcomeFailed", {
                  service: outcome.service,
                })}
          </DialogTitle>
          <DialogDescription>
            {outcome.exitCode === undefined
              ? t("overview.services.outcomeNoExitCode")
              : t("overview.services.outcomeExitCode", {
                  code: outcome.exitCode,
                })}
          </DialogDescription>
        </DialogHeader>
        {outcome.output.trim().length > 0 ? (
          <pre className="max-h-72 overflow-auto rounded-[4px] border bg-muted/40 p-3 text-xs whitespace-pre-wrap">
            {outcome.output}
          </pre>
        ) : (
          <p className="text-sm text-muted-foreground">
            {t("overview.services.outcomeNoOutput")}
          </p>
        )}
        <DialogFooter>
          <Button onClick={onClose} variant="outline">
            {t("common.chrome.close")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
