import {
  PencilIcon,
  PlusIcon,
  RefreshCwIcon,
  RotateCw,
  ShieldCheckIcon,
  TrashIcon,
  WorkflowIcon,
} from "lucide-react"
import { useState } from "react"
import { useMutation, useQuery } from "@tanstack/react-query"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import { useLocation } from "wouter"

import type { ApiError } from "@/api/client"
import {
  TransportActionRequestAction,
  TransportConfigOperationOperation,
  type TransportSpec,
  type TransportStatus,
} from "@/api/generated/model"
import {
  usePostTransportActionMutation,
  usePostTransportConfigMutation,
  usePostConfigMutation,
} from "@/api/mutations"
import {
  useGetConfig,
  useGetRuntimeOutbounds,
  useGetTransportConfig,
  useGetTransports,
} from "@/api/queries"
import { selectConfig } from "@/api/selectors"
import { DeleteImpactDialog } from "@/components/shared/delete-impact-dialog"
import { PageHeader } from "@/components/shared/page-header"
import { TransportConfigDialog } from "@/components/transports/transport-config-dialog"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Switch } from "@/components/ui/switch"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { getApiErrorMessage } from "@/lib/api-errors"
import {
  useServerLocations,
  type ServerLocation,
} from "@/hooks/use-server-locations"
import { cn } from "@/lib/utils"

type ProbeEntry = {
  success: boolean
  latency_ms: number
  age_seconds: number
  error?: string
  interface?: string
}

type ProbesResponse = {
  interval_seconds: number
  probes: Record<string, ProbeEntry>
}

/**
 * Latency with the age of the measurement next to it. A figure that refreshes
 * on screen but was taken minutes ago reads as live and misleads; saying how
 * old it is costs one line and makes the number honest.
 */
function LatencyPill({
  probe,
  fallbackMs,
  onRefresh,
  refreshing,
  t,
}: {
  probe?: ProbeEntry
  fallbackMs?: number
  onRefresh: () => void
  refreshing: boolean
  t: (key: string, options?: Record<string, unknown>) => string
}) {
  const latency = probe?.success ? probe.latency_ms : fallbackMs

  if (latency === undefined) {
    return null
  }

  return (
    <span className="inline-flex items-center gap-1">
      <Badge size="xs" variant="success">
        {t("transports.latencyValue", { value: latency })}
      </Badge>
      {probe ? (
        <span className="text-xs text-muted-foreground tabular-nums">
          {t("transports.latencyAge", { seconds: probe.age_seconds })}
        </span>
      ) : null}
      <Button
        aria-label={t("transports.latencyRefresh")}
        className="size-6"
        disabled={refreshing}
        onClick={onRefresh}
        size="icon"
        title={t("transports.latencyRefresh")}
        variant="ghost"
      >
        <RotateCw className={cn("size-3", refreshing && "animate-spin")} />
      </Button>
    </span>
  )
}

export function TransportsPage() {
  const { t } = useTranslation()
  const [, navigate] = useLocation()
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<TransportSpec | undefined>()
  const [deleting, setDeleting] = useState<TransportSpec | undefined>()
  const query = useGetTransports({
    query: {
      refetchInterval: 3_000,
      refetchIntervalInBackground: false,
    },
  })
  const items: TransportStatus[] =
    query.data?.status === 200 ? query.data.data : []
  const { locationOf } = useServerLocations(
    items.map((item) => item.server ?? "")
  )
  const error = getApiErrorMessage(query.error as ApiError | null)
  const configQuery = useGetTransportConfig()
  const keenConfigQuery = useGetConfig()
  const runtimeOutboundsQuery = useGetRuntimeOutbounds({
    query: {
      // The latency pill doubles as a liveness indicator, so it refreshes
      // noticeably faster than the rest of the runtime data.
      refetchInterval: 3_000,
      refetchIntervalInBackground: false,
    },
  })
  const probesQuery = useQuery<ProbesResponse>({
    queryKey: ["system-probes"],
    queryFn: async () => {
      const response = await fetch("/api/system/probes")
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json()
    },
    refetchInterval: 3_000,
    refetchIntervalInBackground: false,
  })

  const runProbeMutation = useMutation({
    mutationFn: async () => {
      const response = await fetch("/api/system/probes/run", { method: "POST" })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json()
    },
    onSuccess: () => {
      // The probe runs in the background; give it a moment before re-reading.
      setTimeout(() => probesQuery.refetch(), 2_000)
    },
  })

  // Probe results are keyed by outbound tag but shown per interface.
  const probeByInterface = new Map<string, ProbeEntry>()
  for (const entry of Object.values(probesQuery.data?.probes ?? {})) {
    if (entry.interface) {
      probeByInterface.set(entry.interface, entry)
    }
  }

  const transportLatencyByInterface = new Map<string, number>()
  if (runtimeOutboundsQuery.data?.status === 200) {
    for (const outbound of runtimeOutboundsQuery.data.data.outbounds) {
      for (const candidate of outbound.interfaces) {
        if (
          candidate.interface_name &&
          typeof candidate.latency_ms === "number"
        ) {
          const current = transportLatencyByInterface.get(
            candidate.interface_name
          )
          if (current === undefined || candidate.latency_ms < current) {
            transportLatencyByInterface.set(
              candidate.interface_name,
              candidate.latency_ms
            )
          }
        }
      }
    }
  }
  const keenConfig = selectConfig(keenConfigQuery.data)
  // DNS detour is a property of the DNS server, not of the transport, so the
  // card only points at it instead of duplicating the setting.
  const dnsServersByInterface = new Map<string, string[]>()
  const outboundInterfaces = (tag: string, depth = 0): string[] => {
    if (depth > 4) return []
    const outbound = (keenConfig?.outbounds ?? []).find(
      (candidate) => candidate.tag === tag
    )
    if (!outbound) return []
    if (outbound.interface) return [outbound.interface]
    // A detour may point at a failover group, so expand it to its members.
    return (outbound.outbound_groups ?? []).flatMap((group) =>
      (group.outbounds ?? []).flatMap((child) =>
        outboundInterfaces(child, depth + 1)
      )
    )
  }
  for (const server of keenConfig?.dns?.servers ?? []) {
    if (!server.detour || !server.tag) continue
    for (const interfaceName of outboundInterfaces(server.detour)) {
      const current = dnsServersByInterface.get(interfaceName) ?? []
      if (!current.includes(server.tag)) current.push(server.tag)
      dnsServersByInterface.set(interfaceName, current)
    }
  }
  const environmentQuery = useQuery({
    queryKey: ["transport-environment"],
    queryFn: async () => {
      const response = await fetch("/api/transports/environment")
      if (!response.ok) throw new Error("transport environment unavailable")
      return (await response.json()) as {
        sing_box_installed: boolean
        sing_box_binary: string
        tested_version: string
      }
    },
  })
  const configured: TransportSpec[] =
    configQuery.data?.status === 200 ? configQuery.data.data : []
  const actionMutation = usePostTransportActionMutation({
    mutation: {
      onSuccess: (_data, variables) => {
        toast.success(
          variables.data.action === TransportActionRequestAction.up
            ? t("transports.started")
            : variables.data.action === TransportActionRequestAction.restart
              ? t("transports.restarted")
              : t("transports.stopped")
        )
      },
      onError: (mutationError) => {
        toast.error(getApiErrorMessage(mutationError as ApiError), {
          richColors: true,
        })
      },
    },
  })
  const configMutation = usePostTransportConfigMutation({
    mutation: {
      onSuccess: (_data, variables) => {
        setDialogOpen(false)
        setEditing(undefined)
        setDeleting(undefined)
        toast.success(
          t(`transports.configMessages.${variables.data.operation}`)
        )
      },
      onError: (mutationError) => {
        toast.error(getApiErrorMessage(mutationError as ApiError), {
          richColors: true,
        })
      },
    },
  })
  const bypassMutation = usePostConfigMutation({
    mutation: {
      onSuccess: () => toast.success(t("transports.loopProtection.saved")),
      onError: (mutationError) =>
        toast.error(getApiErrorMessage(mutationError as ApiError), {
          richColors: true,
        }),
    },
  })

  const addLoopProtection = (server: string) => {
    if (!keenConfig) return
    const bypassTag = "transport_bypass"
    const listName = "transport_servers"
    const existingBypass = (keenConfig.outbounds ?? []).find(
      (outbound) => outbound.tag === bypassTag
    )
    if (existingBypass && existingBypass.type !== "ignore") {
      toast.error(t("transports.loopProtection.tagConflict", { tag: bypassTag }))
      return
    }
    if (!window.confirm(t("transports.loopProtection.confirm", { server }))) {
      return
    }
    const existingList = keenConfig.lists?.[listName] ?? {}
    const isIp = server.includes(":") || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(server)
    const domains = new Set(existingList.domains ?? [])
    const ipCidrs = new Set(existingList.ip_cidrs ?? [])
    if (isIp) ipCidrs.add(server)
    else domains.add(server)
    const rules = keenConfig.route?.rules ?? []
    const hasRule = rules.some(
      (rule) => rule.outbound === bypassTag && rule.list?.includes(listName)
    )
    bypassMutation.mutate({
      data: {
        ...keenConfig,
        outbounds: existingBypass
          ? keenConfig.outbounds
          : [{ type: "ignore", tag: bypassTag }, ...(keenConfig.outbounds ?? [])],
        lists: {
          ...keenConfig.lists,
          [listName]: {
            ...existingList,
            domains: [...domains],
            ip_cidrs: [...ipCidrs],
          },
        },
        route: {
          ...keenConfig.route,
          rules: hasRule
            ? rules
            : [{ list: [listName], outbound: bypassTag }, ...rules],
        },
      },
    })
  }

  // Creating the matching interface outbound right away is what turns a fresh
  // transport into an actual route; doing it here saves a trip to Outbounds.
  const createInterfaceOutbound = (spec: TransportSpec) => {
    if (!keenConfig) return
    const outbounds = keenConfig.outbounds ?? []
    if (outbounds.some((outbound) => outbound.tag === spec.tag)) {
      toast.error(t("transports.form.outboundExists", { tag: spec.tag }))
      return
    }
    bypassMutation.mutate({
      data: {
        ...keenConfig,
        outbounds: [
          ...outbounds,
          { type: "interface", tag: spec.tag, interface: spec.interface },
        ],
      },
    })
  }

  const saveTransport = (
    spec: TransportSpec,
    options: { createOutbound: boolean }
  ) => {
    configMutation.mutate(
      {
        data: editing
          ? {
              operation: TransportConfigOperationOperation.update,
              tag: editing.tag,
              transport: spec,
            }
          : {
              operation: TransportConfigOperationOperation.create,
              transport: spec,
            },
      },
      {
        onSuccess: () => {
          if (!editing && options.createOutbound) createInterfaceOutbound(spec)
        },
      }
    )
  }

  return (
    <div>
      <PageHeader
        actions={
          <div className="flex gap-2">
            <Button
              onClick={() => {
                setEditing(undefined)
                setDialogOpen(true)
              }}
            >
              <PlusIcon />
              {t("transports.add")}
            </Button>
            <Button
              disabled={query.isFetching}
              onClick={() => {
                void query.refetch()
                void configQuery.refetch()
              }}
              variant="outline"
            >
              <RefreshCwIcon
                className={query.isFetching ? "animate-spin" : ""}
              />
              {t("transports.refresh")}
            </Button>
          </div>
        }
        description={t("transports.description")}
        title={t("transports.title")}
      />

      {error ? (
        <Alert className="mb-6" variant="destructive">
          <AlertTitle>{t("transports.unavailable")}</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      {environmentQuery.data?.sing_box_installed === false ? (
        <Alert className="mb-6" variant="destructive">
          <AlertTitle>{t("transports.singBoxMissing.title")}</AlertTitle>
          <AlertDescription className="space-y-2">
            <p>{t("transports.singBoxMissing.description")}</p>
            <code className="block overflow-x-auto rounded bg-muted p-2 text-xs text-foreground">
              sh -c &quot;$(curl -fsSL
              https://raw.githubusercontent.com/blindtechnique/keen-pbr-sb/main/install.sh)&quot;
            </code>
          </AlertDescription>
        </Alert>
      ) : null}

      {!query.isLoading && !error && items.length === 0 ? (
        <Card>
          <CardContent className="py-8 text-center text-muted-foreground">
            {t("transports.empty")}
          </CardContent>
        </Card>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-2">
        {items.map((item) => (
          <Card className="min-w-0 overflow-hidden" key={item.tag}>
            <CardHeader className="min-w-0 flex-col items-start gap-3 sm:flex-row sm:justify-between">
              <div className="min-w-0">
                <CardTitle className="break-words [overflow-wrap:anywhere]">
                  {item.tag}
                </CardTitle>
                {/* Что за туннель и куда он ведёт — двумя словами. Тип
                    («sing-box») говорит, кто его запускает, а не что внутри,
                    поэтому впереди стоит протокол. */}
                <p className="mt-1 text-sm text-muted-foreground">
                  {describeTransport(item, locationOf(item.server))}
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {item.state === "up" ? (
                  <Badge size="xs" variant="success">
                    <span className="mr-1.5 size-1.5 rounded-full bg-current" />
                    {t("transports.states.connected")}
                  </Badge>
                ) : (
                  <Badge size="xs" variant="secondary">
                    {t(`transports.states.${item.state}`)}
                  </Badge>
                )}
                {item.state === "up" ? (
                  <LatencyPill
                    fallbackMs={transportLatencyByInterface.get(item.interface)}
                    onRefresh={() => runProbeMutation.mutate()}
                    probe={probeByInterface.get(item.interface)}
                    refreshing={runProbeMutation.isPending}
                    t={t}
                  />
                ) : null}
              </div>
            </CardHeader>
            <CardContent className="grid min-w-0 gap-2 text-sm">
              <TransportField
                label={t("transports.interface")}
                value={item.interface}
              />
              {/* Номер процесса убран: на него нельзя ни нажать, ни что-то
                  с ним сделать из интерфейса, а место он занимал наравне с
                  тем, что действительно нужно знать. */}
              <TransportField
                label={t("transports.updatedAt")}
                value={new Date(item.updated_at).toLocaleString()}
              />
              {item.type !== "native" ? (
                <TransportField
                  label={t("transports.autoRecovery")}
                  value={
                    item.desired_up
                      ? t("transports.enabled")
                      : t("transports.paused")
                  }
                />
              ) : null}
              {dnsServersByInterface.has(item.interface) ? (
                <TransportField
                  label={t("transports.dnsDetour")}
                  value={(dnsServersByInterface.get(item.interface) ?? []).join(
                    ", "
                  )}
                />
              ) : null}
              {item.retry_count ? (
                <TransportField
                  label={t("transports.retryCount")}
                  value={String(item.retry_count)}
                />
              ) : null}
              {item.next_retry_at ? (
                <TransportField
                  label={t("transports.nextRetryAt")}
                  value={new Date(item.next_retry_at).toLocaleString()}
                />
              ) : null}
              {item.error ? (
                <p className="mt-2 rounded-md bg-destructive/10 p-3 text-destructive">
                  {item.error}
                </p>
              ) : null}
              {item.server ? (
                <TransportField
                  label={t("transports.server")}
                  value={describeServer(
                    item.server,
                    item.server_port,
                    locationOf(item.server)
                  )}
                />
              ) : null}
              {describeConnection(item) ? (
                <TransportField
                  label={t("transports.connection")}
                  value={describeConnection(item)}
                />
              ) : null}
              {item.type === "native" ? (
                <p className="mt-2 text-muted-foreground">
                  {t("transports.nativeManagedExternally")}
                </p>
              ) : (
                <TransportActions
                  item={item}
                  mutation={actionMutation}
                  restartLabel={t("transports.restart")}
                  startLabel={t("transports.start")}
                  stopLabel={t("transports.stop")}
                />
              )}
              <div className="mt-2 flex min-w-0 flex-wrap items-center justify-start gap-2 border-t pt-4 sm:justify-end">
                {item.server ? (
                  <Button
                    className="h-auto max-w-full whitespace-normal text-left"
                    disabled={bypassMutation.isPending || !keenConfig}
                    onClick={() => addLoopProtection(item.server!)}
                    size="sm"
                    variant="outline"
                  >
                    <ShieldCheckIcon />
                    {t("transports.loopProtection.action")}
                  </Button>
                ) : null}
                <Button
                  className="h-auto max-w-full whitespace-normal text-left"
                  size="sm"
                  variant="outline"
                  onClick={() =>
                    navigate(
                      `/outbounds/create?type=interface&interface=${encodeURIComponent(item.interface)}`
                    )
                  }
                >
                  <WorkflowIcon />
                  {t("transports.routing.bindOutbound")}
                </Button>
                <Button
                  className="h-auto max-w-full whitespace-normal"
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    const spec = configured.find(
                      (entry) => entry.tag === item.tag
                    )
                    if (spec) {
                      setEditing(spec)
                      setDialogOpen(true)
                    }
                  }}
                >
                  <PencilIcon />
                  {t("common.edit")}
                </Button>
                <Button
                  className="h-auto max-w-full whitespace-normal"
                  size="sm"
                  variant="ghost"
                  onClick={() =>
                    setDeleting(
                      configured.find((entry) => entry.tag === item.tag)
                    )
                  }
                >
                  <TrashIcon />
                  {t("common.delete")}
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
      {dialogOpen ? (
        <TransportConfigDialog
          initial={editing}
          isPending={configMutation.isPending}
          onOpenChange={setDialogOpen}
          onSubmit={saveTransport}
          open
          singBoxAvailable={environmentQuery.data?.sing_box_installed !== false}
        />
      ) : null}
      <DeleteImpactDialog
        confirmLabel={t("common.delete")}
        description={t("transports.deleteDescription")}
        impactItems={deleting ? [{ label: deleting.tag }] : []}
        isPending={configMutation.isPending}
        onConfirm={() =>
          deleting &&
          configMutation.mutate({
            data: {
              operation: TransportConfigOperationOperation.delete,
              tag: deleting.tag,
            },
          })
        }
        onOpenChange={(open) => !open && setDeleting(undefined)}
        open={Boolean(deleting)}
        title={t("transports.deleteTitle")}
      />
    </div>
  )
}

function TransportActions({
  item,
  mutation,
  restartLabel,
  startLabel,
  stopLabel,
}: {
  item: TransportStatus
  mutation: ReturnType<typeof usePostTransportActionMutation>
  restartLabel: string
  startLabel: string
  stopLabel: string
}) {
  const isRunning = item.state === "up" || item.state === "starting"
  // Only the card whose action is in flight reacts: a restart briefly takes the
  // transport down, so the pending action decides what stays on screen instead
  // of the live state, and other cards remain operable.
  const isPendingForItem =
    mutation.isPending && mutation.variables?.data.tag === item.tag
  const pendingAction = isPendingForItem
    ? mutation.variables?.data.action
    : undefined
  const isRestarting = pendingAction === TransportActionRequestAction.restart
  // While a restart is in flight the transport dips to "down"; keep the switch
  // reading as on so it does not flicker mid-operation.
  const switchChecked = isRestarting ? true : isRunning

  return (
    <div className="mt-3 flex min-w-0 flex-wrap items-center justify-between gap-3 border-t pt-4">
      <label className="flex min-w-0 cursor-pointer items-center gap-2">
        <Switch
          aria-label={switchChecked ? stopLabel : startLabel}
          checked={switchChecked}
          disabled={isPendingForItem}
          onCheckedChange={(checked) =>
            mutation.mutate({
              data: {
                tag: item.tag,
                action: checked
                  ? TransportActionRequestAction.up
                  : TransportActionRequestAction.down,
              },
            })
          }
        />
        <span className="truncate text-sm text-muted-foreground">
          {isPendingForItem && !isRestarting
            ? "…"
            : switchChecked
              ? stopLabel
              : startLabel}
        </span>
      </label>
      <Button
        className="h-auto max-w-full whitespace-normal"
        disabled={isPendingForItem || !switchChecked}
        onClick={() =>
          mutation.mutate({
            data: {
              tag: item.tag,
              action: TransportActionRequestAction.restart,
            },
          })
        }
        variant="outline"
      >
        <RefreshCwIcon className={isRestarting ? "animate-spin" : undefined} />
        {restartLabel}
      </Button>
    </div>
  )
}

/**
 * «1.2.3.4:443 · 🇳🇱», либо просто адрес, если страну выяснить не удалось.
 * Отсутствие страны — рядовой случай, а не ошибка: интернета может не быть,
 * сервис может не ответить, имя может не разрешиться.
 */
function describeServer(
  server: string,
  port?: number,
  location?: ServerLocation
): string {
  const endpoint = port ? `${server}:${port}` : server
  const flag = countryMark(location)
  return flag ? `${endpoint} · ${flag}` : endpoint
}

/** «VLESS · 🇳🇱» — протокол туннеля и страна сервера. */
function describeTransport(
  item: TransportStatus,
  location?: ServerLocation
): string {
  const parts = [item.protocol ? item.protocol.toUpperCase() : item.type]
  const flag = countryMark(location)
  if (flag) {
    parts.push(flag)
  }
  return parts.join(" · ")
}

/**
 * Флаг страны. Эмодзи короче любого названия и читается мгновенно; там, где
 * шрифт флагов не рисует, остаётся код страны — тоже коротко и понятно.
 */
function countryMark(location?: ServerLocation): string {
  if (!location) {
    return ""
  }
  return location.emoji || location.country_code || ""
}

/**
 * «Reality · ws · SNI example.com» — то, что раньше знала только ссылка.
 * Ничего из этого не секрет, но без этих трёх вещей по карточке нельзя
 * понять, чем именно отличаются два внешне одинаковых транспорта.
 */
function describeConnection(item: TransportStatus): string {
  const parts: string[] = []
  if (item.security) {
    parts.push(item.security === "reality" ? "Reality" : "TLS")
  }
  // tcp — это отсутствие обёртки, показывать его не о чем.
  if (item.network && item.network !== "tcp") {
    parts.push(item.network)
  }
  if (item.sni && item.sni !== item.server) {
    parts.push(`SNI ${item.sni}`)
  }
  return parts.join(" · ")
}

function TransportField({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid min-w-0 grid-cols-[minmax(0,1fr)_minmax(0,1fr)] items-baseline gap-4">
      <span className="min-w-0 text-muted-foreground">{label}</span>
      <span className="min-w-0 break-words text-right font-mono [overflow-wrap:anywhere]">
        {value}
      </span>
    </div>
  )
}
