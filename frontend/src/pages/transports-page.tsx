import {
  PencilIcon,
  PlayIcon,
  PlusIcon,
  RefreshCwIcon,
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
} from "@/api/mutations"
import { useGetTransportConfig, useGetTransports } from "@/api/queries"
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
          <Card key={item.tag}>
            <CardHeader className="flex-row items-start justify-between gap-3">
              <div>
                <CardTitle>{item.tag}</CardTitle>
                <p className="mt-1 text-sm text-muted-foreground">
                  {item.type}
                </p>
              </div>
              <Badge variant={item.state === "up" ? "default" : "secondary"}>
                {t(`transports.states.${item.state}`)}
              </Badge>
            </CardHeader>
            <CardContent className="grid gap-2 text-sm">
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
              {item.type === "native" ? (
                <p className="mt-2 text-muted-foreground">
                  {t("transports.nativeManagedExternally")}
                </p>
              ) : (
                <TransportActions
                  item={item}
                  mutation={actionMutation}
                  startLabel={t("transports.start")}
                  stopLabel={t("transports.stop")}
                />
              )}
              <div className="mt-2 flex justify-end gap-2">
                <Button
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
  startLabel,
  stopLabel,
}: {
  item: TransportStatus
  mutation: ReturnType<typeof usePostTransportActionMutation>
  startLabel: string
  stopLabel: string
}) {
  const isRunning = item.state === "up" || item.state === "starting"
  const action = isRunning
    ? TransportActionRequestAction.down
    : TransportActionRequestAction.up
  const isPendingForItem =
    mutation.isPending && mutation.variables?.data.tag === item.tag

  return (
    <div className="mt-3 flex justify-end border-t pt-4">
      <Button
        disabled={mutation.isPending}
        onClick={() => mutation.mutate({ data: { tag: item.tag, action } })}
        variant={isRunning ? "outline" : "default"}
      >
        {isRunning ? <SquareIcon /> : <PlayIcon />}
        {isPendingForItem ? "…" : isRunning ? stopLabel : startLabel}
      </Button>
    </div>
  )
}

function TransportField({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-4">
      <span className="text-muted-foreground">{label}</span>
      <span className="min-w-0 truncate font-mono">{value}</span>
    </div>
  )
}
