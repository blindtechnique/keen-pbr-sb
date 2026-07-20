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
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
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
  const queryClient = useQueryClient()
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

  // libcronet.so — сетевой стек Chromium, без которого sing-box не умеет
  // naive. Он весит десятки мегабайт, поэтому не ставится вместе с пакетом:
  // спрашиваем только когда naive-транспорт действительно появился.
  const naiveComponentQuery = useQuery<{ installed: boolean }>({
    queryKey: ["naive-component"],
    queryFn: async () => {
      const response = await fetch("/api/system/naive-component")
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json()
    },
    staleTime: 60_000,
    retry: false,
  })
  const naiveInstallMutation = useMutation({
    mutationFn: async () => {
      const response = await fetch("/api/system/naive-component", {
        method: "POST",
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return (await response.json()) as { installed: boolean; log?: string }
    },
    onSuccess: async (body) => {
      await queryClient.invalidateQueries({ queryKey: ["naive-component"] })
      if (body.installed) {
        toast.success(t("transports.naiveComponent.installed"))
      } else {
        toast.error(body.log || t("transports.naiveComponent.failed"), {
          richColors: true,
        })
      }
    },
    onError: () => toast.error(t("transports.naiveComponent.failed")),
  })
  const needsNaiveComponent =
    items.some((item) => item.protocol === "naive") &&
    naiveComponentQuery.data?.installed === false
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

      {needsNaiveComponent ? (
        <Alert className="mb-6" variant="warning">
          <AlertTitle>{t("transports.naiveComponent.title")}</AlertTitle>
          <AlertDescription className="space-y-2">
            <p>{t("transports.naiveComponent.description")}</p>
            <Button
              disabled={naiveInstallMutation.isPending}
              onClick={() => naiveInstallMutation.mutate()}
              size="sm"
              variant="outline"
            >
              {naiveInstallMutation.isPending
                ? t("transports.naiveComponent.installing")
                : t("transports.naiveComponent.install")}
            </Button>
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
          <Card className="flex h-full min-w-0 flex-col overflow-hidden" key={item.tag}>
            <CardHeader className="min-w-0 flex-row items-start justify-between gap-3">
              <div className="min-w-0">
                <CardTitle className="truncate">{item.tag}</CardTitle>
                {/* Что за туннель и куда он ведёт — двумя словами. Тип
                    («sing-box») говорит, кто его запускает, а не что внутри,
                    поэтому впереди стоит протокол. */}
                <p className="mt-1 truncate text-sm text-muted-foreground">
                  {describeTransport(item, locationOf(item.server))}
                </p>
              </div>
              {/* Выключатель — в правом верхнем углу: это единственное
                  действие, которое меняет состояние туннеля, и искать его
                  среди кнопок внизу незачем. */}
              <div className="flex shrink-0 items-center gap-2">
                {item.state === "up" ? (
                  <LatencyPill
                    fallbackMs={transportLatencyByInterface.get(item.interface)}
                    onRefresh={() => runProbeMutation.mutate()}
                    probe={probeByInterface.get(item.interface)}
                    refreshing={runProbeMutation.isPending}
                    t={t}
                  />
                ) : (
                  <Badge size="xs" variant="secondary">
                    {t(`transports.states.${item.state}`)}
                  </Badge>
                )}
                {item.type !== "native" ? (
                  <Button
                    aria-label={t("transports.restart")}
                    className="size-7"
                    disabled={actionMutation.isPending}
                    onClick={() =>
                      actionMutation.mutate({
                        data: {
                          tag: item.tag,
                          action: TransportActionRequestAction.restart,
                        },
                      })
                    }
                    size="icon"
                    title={t("transports.restart")}
                    variant="ghost"
                  >
                    <RefreshCwIcon className="size-4" />
                  </Button>
                ) : null}
                {item.type !== "native" ? (
                  <Switch
                    aria-label={
                      item.desired_up
                        ? t("transports.stop")
                        : t("transports.start")
                    }
                    checked={item.desired_up}
                    disabled={actionMutation.isPending}
                    onCheckedChange={(checked) =>
                      actionMutation.mutate({
                        data: {
                          tag: item.tag,
                          action: checked
                            ? TransportActionRequestAction.up
                            : TransportActionRequestAction.down,
                        },
                      })
                    }
                  />
                ) : null}
              </div>
            </CardHeader>
            <CardContent className="flex min-w-0 flex-1 flex-col gap-1.5 text-sm">
              {/* Три строки, всегда одни и те же и в одном порядке: только так
                  соседние карточки стоят вровень. Всё необязательное ушло
                  ниже, в строку значков, где отсутствие ничего не двигает. */}
              <TransportField
                label={t("transports.interface")}
                value={item.interface}
              />
              <TransportField
                label={t("transports.server")}
                value={
                  item.server
                    ? item.server_port
                      ? `${item.server}:${item.server_port}`
                      : item.server
                    : "—"
                }
              />
              <TransportField
                label={t("transports.connection")}
                value={describeConnection(item) || "—"}
              />

              <div className="mt-1 flex min-w-0 flex-wrap items-center gap-1.5">
                {/* Вид транспорта уехал из подзаголовка, когда его место занял
                    протокол. Знать, кто держит туннель, всё же полезно —
                    поэтому он здесь, рядом с остальными необязательными
                    подробностями. */}
                <Badge size="xs" variant="outline">
                  {item.type}
                </Badge>
                {dnsServersByInterface.has(item.interface) ? (
                  <Badge size="xs" variant="outline">
                    {t("transports.dnsDetour")}:{" "}
                    {(dnsServersByInterface.get(item.interface) ?? []).join(", ")}
                  </Badge>
                ) : null}
                {item.type !== "native" && !item.desired_up ? (
                  <Badge size="xs" variant="secondary">
                    {t("transports.paused")}
                  </Badge>
                ) : null}
                {item.retry_count ? (
                  <Badge size="xs" variant="warning">
                    {t("transports.retryCount")}: {item.retry_count}
                  </Badge>
                ) : null}
              </div>

              {item.error ? (
                <p className="mt-1 rounded-md bg-destructive/10 p-2 text-xs text-destructive">
                  {item.error}
                </p>
              ) : null}

              {item.type === "native" ? (
                <p className="mt-1 text-xs text-muted-foreground">
                  {t("transports.nativeManagedExternally")}
                </p>
              ) : null}
              {/* Действия иконками и по углам: подписи к карандашу и
                  корзине ничего не добавляли, а забирали две строки высоты
                  на каждой карточке. */}
              {/* Подвал прижат к низу: карточки в ряду тянутся до одной
                  высоты, и без этого кнопки вставали на разных уровнях у
                  соседей просто потому, что у одного транспорта строкой
                  значков больше. */}
              <div className="mt-auto flex min-w-0 flex-wrap items-center gap-2 border-t pt-3">
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
                  onClick={() =>
                    navigate(
                      `/outbounds/create?type=interface&interface=${encodeURIComponent(item.interface)}`
                    )
                  }
                  size="sm"
                  variant="outline"
                >
                  <WorkflowIcon />
                  {t("transports.routing.bindOutbound")}
                </Button>
                <span className="ml-auto flex shrink-0 items-center gap-1">
                  <Button
                    aria-label={t("common.edit")}
                    className="size-8"
                    onClick={() => {
                      const spec = configured.find(
                        (entry) => entry.tag === item.tag
                      )
                      if (spec) {
                        setEditing(spec)
                        setDialogOpen(true)
                      }
                    }}
                    size="icon"
                    title={t("common.edit")}
                    variant="ghost"
                  >
                    <PencilIcon className="size-4" />
                  </Button>
                  <Button
                    aria-label={t("common.delete")}
                    className="size-8 text-destructive hover:text-destructive"
                    onClick={() =>
                      setDeleting(
                        configured.find((entry) => entry.tag === item.tag)
                      )
                    }
                    size="icon"
                    title={t("common.delete")}
                    variant="ghost"
                  >
                    <TrashIcon className="size-4" />
                  </Button>
                </span>
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
 * Флаг страны.
 *
 * Собирается из двухбуквенного кода прямо здесь, а не берётся у сервиса:
 * флаговые эмодзи — это ровно две «региональные» буквы, сдвинутые в другой
 * диапазон, так что «DE» превращается в 🇩🇪 четырьмя строками и без единого
 * байта данных. Заодно это не зависит от того, доехало ли поле с эмодзи
 * через все слои, — код страны короче и надёжнее.
 */
function countryMark(location?: ServerLocation): string {
  const code = location?.country_code?.trim().toUpperCase()
  if (!code || !/^[A-Z]{2}$/.test(code)) {
    return location?.emoji ?? ""
  }
  const base = 0x1f1e6 // 🇦
  return String.fromCodePoint(
    base + (code.charCodeAt(0) - 65),
    base + (code.charCodeAt(1) - 65)
  )
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
    // Подпись занимает столько, сколько ей нужно, значение — весь остаток.
    // При равных долях длинное значение переносилось на вторую строку, хотя
    // место рядом пустовало, и соседние карточки переставали совпадать
    // строками. Однострочная высота задана здесь же, чтобы ряды двух карточек
    // стояли вровень независимо от длины значения.
    <div className="grid min-w-0 grid-cols-[auto_minmax(0,1fr)] items-baseline gap-4">
      <span className="min-w-0 whitespace-nowrap text-muted-foreground">
        {label}
      </span>
      <span
        className="min-w-0 truncate text-right font-mono"
        title={value}
      >
        {value}
      </span>
    </div>
  )
}
