import {
  PencilIcon,
  PlayIcon,
  PlusIcon,
  RefreshCwIcon,
  ShieldCheckIcon,
  SquareIcon,
  TrashIcon,
  WorkflowIcon,
} from "lucide-react"
import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
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
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { getApiErrorMessage } from "@/lib/api-errors"

export function TransportsPage() {
  const { t } = useTranslation()
  const [, navigate] = useLocation()
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<TransportSpec | undefined>()
  const [deleting, setDeleting] = useState<TransportSpec | undefined>()
  const query = useGetTransports({
    query: {
      refetchInterval: 10_000,
      refetchIntervalInBackground: false,
    },
  })
  const items: TransportStatus[] =
    query.data?.status === 200 ? query.data.data : []
  const error = getApiErrorMessage(query.error as ApiError | null)
  const configQuery = useGetTransportConfig()
  const keenConfigQuery = useGetConfig()
  const runtimeOutboundsQuery = useGetRuntimeOutbounds({
    query: {
      refetchInterval: 10_000,
      refetchIntervalInBackground: false,
    },
  })
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

  const saveTransport = (spec: TransportSpec) => {
    configMutation.mutate({
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
    })
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

      <Alert className="mb-6">
        <WorkflowIcon />
        <AlertTitle>{t("transports.routing.title")}</AlertTitle>
        <AlertDescription className="space-y-3">
          <p>{t("transports.routing.description")}</p>
          <div className="flex flex-wrap gap-2">
            <Button
              onClick={() => navigate("/outbounds/create")}
              size="sm"
              variant="outline"
            >
              {t("transports.routing.createOutbound")}
            </Button>
            <Button
              onClick={() => navigate("/outbounds/create?type=urltest")}
              size="sm"
              variant="outline"
            >
              {t("transports.routing.createFailover")}
            </Button>
          </div>
        </AlertDescription>
      </Alert>

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
                <p className="mt-1 text-sm text-muted-foreground">
                  {item.type}
                </p>
              </div>
              <Badge variant={item.state === "up" ? "default" : "secondary"}>
                {t(`transports.states.${item.state}`)}
              </Badge>
            </CardHeader>
            <CardContent className="grid min-w-0 gap-2 text-sm">
              <TransportField
                label={t("transports.interface")}
                value={item.interface}
              />
              <TransportField
                label={t("transports.pid")}
                value={item.pid ? String(item.pid) : "—"}
              />
              <TransportField
                label={t("transports.updatedAt")}
                value={new Date(item.updated_at).toLocaleString()}
              />
              <TransportField
                label={t("transports.latency")}
                value={
                  transportLatencyByInterface.has(item.interface)
                    ? `${transportLatencyByInterface.get(item.interface)} ms`
                    : t("transports.latencyUnavailable")
                }
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
                  value={item.server}
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
  const action = isRunning
    ? TransportActionRequestAction.down
    : TransportActionRequestAction.up
  // Only the card whose action is in flight reacts: a restart briefly takes the
  // transport down, so the pending action decides what stays on screen instead
  // of the live state, and other cards remain operable.
  const isPendingForItem =
    mutation.isPending && mutation.variables?.data.tag === item.tag
  const pendingAction = isPendingForItem
    ? mutation.variables?.data.action
    : undefined
  const isRestarting =
    pendingAction === TransportActionRequestAction.restart
  const showRestart = isRunning || isRestarting

  return (
    <div className="mt-3 flex min-w-0 flex-wrap justify-start border-t pt-4 sm:justify-end">
      <Button
        className="h-auto max-w-full whitespace-normal"
        disabled={isPendingForItem}
        onClick={() => mutation.mutate({ data: { tag: item.tag, action } })}
        variant={isRunning ? "outline" : "default"}
      >
        {isRunning ? <SquareIcon /> : <PlayIcon />}
        {isPendingForItem && !isRestarting
          ? "…"
          : isRunning
            ? stopLabel
            : startLabel}
      </Button>
      {showRestart ? (
        <Button
          className="ml-2 h-auto max-w-full whitespace-normal"
          disabled={isPendingForItem}
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
          <RefreshCwIcon
            className={isRestarting ? "animate-spin" : undefined}
          />
          {restartLabel}
        </Button>
      ) : null}
    </div>
  )
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
