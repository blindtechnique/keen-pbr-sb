import { useMutation, useQueryClient } from "@tanstack/react-query"
import { Plus, RefreshCw } from "lucide-react"
import { useEffect, useMemo, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import {
  getGetSubscriptionsQueryKey,
  postSubscriptionRefresh,
  postSubscriptionRename,
  postSubscriptionRemove,
  postSubscriptionSettings,
  useGetSubscriptions,
} from "@/api/generated/keen-api"
import type { SavedSubscription, TransportStatus } from "@/api/generated/model"
import { EditDeleteActions } from "@/components/shared/edit-delete-actions"
import { DeleteImpactDialog } from "@/components/shared/delete-impact-dialog"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { subscriptionBytes, subscriptionUsage } from "./subscription-usage"
import { SubscriptionImportDialog } from "./subscription-import-dialog"
import { useCatalogNavigation } from "@/hooks/use-catalog-navigation"
import { queryKeys } from "@/api/query-keys"
import { OperationErrorMessage } from "@/components/shared/operation-error-message"
import { cn } from "@/lib/utils"
import { SubscriptionRefreshFields } from "./subscription-refresh-fields"
import {
  DEFAULT_SUBSCRIPTION_REFRESH_SECONDS,
  subscriptionCardId,
  subscriptionRefreshDraft,
  subscriptionRefreshSeconds,
} from "./subscription-settings-model"

type Action =
  | {
      kind: "edit"
      record: SavedSubscription
      name: string
      refreshIntervalSeconds: number
    }
  | { kind: "refresh" | "remove"; id: string }

export function SubscriptionsPanel({
  transports,
  selectedSubscriptionId,
}: {
  transports: TransportStatus[]
  selectedSubscriptionId?: string
}) {
  const { t, i18n } = useTranslation()
  const catalogNavigation = useCatalogNavigation()
  const client = useQueryClient()
  const query = useGetSubscriptions({ query: { retry: false } })
  const [editing, setEditing] = useState<SavedSubscription | null>(null)
  const [importing, setImporting] = useState<"new" | SavedSubscription | null>(
    null
  )
  const [removing, setRemoving] = useState<SavedSubscription | null>(null)
  const [name, setName] = useState("")
  const [refreshDraft, setRefreshDraft] = useState(() =>
    subscriptionRefreshDraft()
  )
  const refreshIntervalSeconds = subscriptionRefreshSeconds(refreshDraft)
  const lastFocusedSubscription = useRef<string | null>(null)
  const importSeed = useMemo(
    () =>
      importing && importing !== "new"
        ? { subscription_id: importing.id, pending_only: true as const }
        : undefined,
    [importing]
  )
  const names = new Map(
    transports.map((item) => [item.tag, item.display_name || item.tag])
  )
  const mutation = useMutation({
    mutationFn: async (action: Action) => {
      switch (action.kind) {
        case "edit": {
          if (action.name !== action.record.name) {
            await postSubscriptionRename({
              id: action.record.id,
              name: action.name,
            })
          }
          if (
            action.refreshIntervalSeconds !==
            (action.record.refresh_interval_seconds ??
              DEFAULT_SUBSCRIPTION_REFRESH_SECONDS)
          ) {
            return postSubscriptionSettings({
              id: action.record.id,
              refresh_interval_seconds: action.refreshIntervalSeconds,
            })
          }
          return undefined
        }
        case "refresh":
          return postSubscriptionRefresh({ id: action.id })
        case "remove":
          return postSubscriptionRemove({ id: action.id })
      }
    },
    onSuccess: async (response, action) => {
      await client.invalidateQueries({
        queryKey: getGetSubscriptionsQueryKey(),
      })
      if (action.kind === "edit") {
        setEditing(null)
      }
      if (action.kind === "remove") setRemoving(null)
      if (action.kind === "refresh") {
        await Promise.all(
          [
            queryKeys.transportConfig(),
            queryKeys.transports(),
            queryKeys.runtimeInterfaces(),
            queryKeys.runtimeOutbounds(),
            queryKeys.config(),
          ].map((queryKey) => client.invalidateQueries({ queryKey }))
        )
      }
      if (
        action.kind === "refresh" &&
        response &&
        (("error" in response.data && response.data.error) ||
          ("last_sync_error" in response.data && response.data.last_sync_error))
      )
        toast.error(t("subscriptions.refreshFailed"))
      else
        toast.success(
          action.kind === "refresh"
            ? t("subscriptions.refreshed")
            : t("subscriptions.saved")
        )
    },
  })
  const records = useMemo(
    () => (query.data?.status === 200 ? query.data.data : []),
    [query.data]
  )
  useEffect(() => {
    if (!selectedSubscriptionId) {
      lastFocusedSubscription.current = null
      return
    }
    if (
      lastFocusedSubscription.current === selectedSubscriptionId ||
      !records.some((record) => record.id === selectedSubscriptionId)
    )
      return
    const card = document.getElementById(
      subscriptionCardId(selectedSubscriptionId)
    )
    if (!card) return
    lastFocusedSubscription.current = selectedSubscriptionId
    card.focus({ preventScroll: true })
    card.scrollIntoView({
      block: "center",
      behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches
        ? "auto"
        : "smooth",
    })
  }, [records, selectedSubscriptionId])
  const edit = (record: SavedSubscription) => {
    mutation.reset()
    setName(record.name)
    setRefreshDraft(subscriptionRefreshDraft(record.refresh_interval_seconds))
    setEditing(record)
  }
  const close = () => {
    if (!mutation.isPending) {
      setEditing(null)
      mutation.reset()
    }
  }
  const date = (seconds: number) =>
    new Intl.DateTimeFormat(i18n.language, {
      dateStyle: "medium",
      timeStyle: "short",
    }).format(seconds * 1000)
  const bytes = (value: number) => subscriptionBytes(value, i18n.language)
  return (
    <section className="space-y-4" aria-label={t("subscriptions.title")}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <p className="max-w-3xl text-sm text-muted-foreground">
          {t("subscriptions.description")}
        </p>
        <Button
          onClick={() => setImporting("new")}
          variant="outline"
          disabled={importing !== null || mutation.isPending}
        >
          <Plus />
          {t("subscriptions.add")}
        </Button>
      </div>
      {query.isLoading ? (
        <p role="status">{t("subscriptions.loading")}</p>
      ) : null}
      {query.isError ? (
        <Alert variant="destructive">
          <AlertDescription>
            {t("subscriptions.loadFailed")}{" "}
            <Button
              size="sm"
              variant="outline"
              onClick={() => void query.refetch()}
            >
              {t("subscriptions.retry")}
            </Button>
          </AlertDescription>
        </Alert>
      ) : null}
      {!query.isLoading && !query.isError && records.length === 0 ? (
        <div className="rounded-lg border p-5 text-sm text-muted-foreground">
          {t("subscriptions.empty")}
        </div>
      ) : null}
      {selectedSubscriptionId &&
      !query.isLoading &&
      !query.isError &&
      !records.some((record) => record.id === selectedSubscriptionId) ? (
        <p className="text-sm text-muted-foreground" role="status">
          {t("subscriptions.targetMissing")}
        </p>
      ) : null}
      {mutation.isError && !editing && !removing ? (
        <Alert variant="destructive">
          <AlertDescription>
            <OperationErrorMessage
              error={mutation.error}
              fallbackSummary={t("subscriptions.actionFailed")}
            />
          </AlertDescription>
        </Alert>
      ) : null}
      {records.map((record) => {
        const usage = subscriptionUsage(record)
        const linked = record.transport_tags.filter((tag) => names.has(tag))
        const refreshing =
          mutation.isPending &&
          mutation.variables.kind === "refresh" &&
          mutation.variables.id === record.id
        return (
          <article
            data-row-actions
            className={cn(
              "scroll-mt-24 space-y-4 rounded-lg border p-4 outline-none sm:p-5",
              selectedSubscriptionId === record.id &&
                "border-primary ring-2 ring-primary/25"
            )}
            key={record.id}
            id={subscriptionCardId(record.id)}
            tabIndex={-1}
            aria-label={record.name}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <h3 className="truncate font-medium">{record.name}</h3>
                <p className="truncate text-sm text-muted-foreground">
                  {record.source_host}
                </p>
              </div>
              <div className="flex shrink-0 gap-1">
                <Button
                  size="icon"
                  variant="outline"
                  className="keen-row-action size-8 rounded-[4px]"
                  disabled={mutation.isPending}
                  aria-label={t("subscriptions.refresh")}
                  title={t("subscriptions.refresh")}
                  onClick={() =>
                    mutation.mutate({ kind: "refresh", id: record.id })
                  }
                >
                  <RefreshCw
                    className={refreshing ? "size-4 animate-spin" : "size-4"}
                  />
                </Button>
                <EditDeleteActions
                  editDisabled={mutation.isPending}
                  deleteDisabled={mutation.isPending}
                  editTitle={t("subscriptions.edit")}
                  deleteTitle={t("subscriptions.remove")}
                  onEdit={() => edit(record)}
                  onDelete={() => {
                    mutation.reset()
                    setRemoving(record)
                  }}
                />
              </div>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1">
                <p className="text-sm font-medium">
                  {t("subscriptions.traffic")}
                </p>
                <p className="text-sm">
                  {usage.remaining !== undefined &&
                  record.total_bytes !== undefined
                    ? t("subscriptions.remaining", {
                        remaining: bytes(usage.remaining),
                        total: bytes(record.total_bytes),
                      })
                    : record.total_bytes !== undefined
                      ? t("subscriptions.limit", {
                          total: bytes(record.total_bytes),
                        })
                      : t("subscriptions.unknownTraffic")}
                </p>
                {usage.used !== undefined ? (
                  <p className="text-xs text-muted-foreground">
                    {t("subscriptions.used", { used: bytes(usage.used) })}
                  </p>
                ) : null}
                {usage.percent !== undefined ? (
                  <div
                    role="progressbar"
                    aria-label={t("subscriptions.traffic")}
                    aria-valuemin={0}
                    aria-valuemax={100}
                    aria-valuenow={Math.round(usage.percent)}
                    className="h-1.5 overflow-hidden rounded bg-muted"
                  >
                    <div
                      className="h-full bg-primary"
                      style={{ width: `${usage.percent}%` }}
                    />
                  </div>
                ) : null}
              </div>
              <div className="space-y-1">
                <p className="text-sm font-medium">
                  {t("subscriptions.expiry")}
                </p>
                <p className="text-sm">
                  {record.expires_at
                    ? date(record.expires_at)
                    : t("subscriptions.unknownExpiry")}
                </p>
                {usage.days !== undefined ? (
                  <Badge variant={usage.expired ? "secondary" : "success"}>
                    {usage.expired
                      ? t("subscriptions.expired")
                      : t("subscriptions.days", { count: usage.days })}
                  </Badge>
                ) : null}
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
              {record.node_count !== undefined ? (
                <span>
                  {t("subscriptions.nodes", { count: record.node_count })}
                </span>
              ) : null}
              <span>{t("subscriptions.linked", { count: linked.length })}</span>
              {linked.map((tag) => (
                <Badge variant="outline" key={tag}>
                  {names.get(tag)}
                </Badge>
              ))}
            </div>
            <p className="text-xs text-muted-foreground">
              {record.updated_at
                ? t("subscriptions.updated", { date: date(record.updated_at) })
                : t("subscriptions.neverUpdated")}
            </p>
            <div className="space-y-1 text-xs text-muted-foreground">
              <p>
                {t("subscriptions.autoRefresh")}:{" "}
                {(record.refresh_interval_seconds ??
                  DEFAULT_SUBSCRIPTION_REFRESH_SECONDS) === 0
                  ? t("subscriptions.autoRefreshOff")
                  : t("subscriptions.autoRefreshHours", {
                      hours:
                        (record.refresh_interval_seconds ??
                          DEFAULT_SUBSCRIPTION_REFRESH_SECONDS) / 3_600,
                    })}
              </p>
              {record.next_check_at ? (
                <p>
                  {t("subscriptions.nextRefresh", {
                    date: date(record.next_check_at),
                  })}
                </p>
              ) : null}
            </div>
            {(record.pending_new_servers_count ?? 0) > 0 ? (
              <div className="space-y-2 rounded-[4px] border border-primary/30 bg-primary/5 p-3">
                <p className="text-sm font-medium">
                  {t("subscriptions.newServers", {
                    count: record.pending_new_servers_count,
                  })}
                </p>
                <p className="text-xs text-muted-foreground">
                  {t("subscriptions.newServersHint")}
                </p>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={mutation.isPending || importing !== null}
                  onClick={() => setImporting(record)}
                >
                  {t("subscriptions.previewNewServers")}
                </Button>
              </div>
            ) : null}
            {record.last_sync_error ? (
              <OperationErrorMessage
                error={record.last_sync_error}
                fallbackSummary={t("subscriptions.syncFailed")}
              />
            ) : null}
            {record.error ? (
              <p role="status" className="text-sm text-destructive">
                {t("subscriptions.refreshFailed")}
              </p>
            ) : null}
          </article>
        )
      })}
      {importing ? (
        <SubscriptionImportDialog
          open
          seed={importSeed}
          onOpenChange={(open) => {
            if (!open) setImporting(null)
          }}
          onComplete={(results) => {
            setImporting(null)
            toast.success(
              t("transports.subscriptionImport.completed", {
                count: results.results.length,
              }),
              {
                action: catalogNavigation.successAction(),
              }
            )
          }}
          onResultsDismiss={() => setImporting(null)}
        />
      ) : null}
      <Dialog
        open={editing !== null}
        onOpenChange={(open) => {
          if (!open) close()
        }}
      >
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{t("subscriptions.edit")}</DialogTitle>
          </DialogHeader>
          <form
            className="space-y-4"
            onSubmit={(event) => {
              event.preventDefault()
              if (
                !editing ||
                mutation.isPending ||
                refreshIntervalSeconds === undefined
              )
                return
              mutation.mutate({
                kind: "edit",
                record: editing,
                name: name.trim(),
                refreshIntervalSeconds,
              })
            }}
          >
            <label className="block space-y-1 text-sm">
              <span>{t("subscriptions.name")}</span>
              <Input
                autoFocus
                required
                maxLength={80}
                value={name}
                onChange={(event) => setName(event.target.value)}
                disabled={mutation.isPending}
              />
            </label>
            <SubscriptionRefreshFields
              draft={refreshDraft}
              onChange={setRefreshDraft}
              originalSeconds={
                editing?.refresh_interval_seconds ??
                DEFAULT_SUBSCRIPTION_REFRESH_SECONDS
              }
              disabled={mutation.isPending}
            />
            {mutation.isError ? (
              <div role="alert" className="text-sm text-destructive">
                <OperationErrorMessage
                  error={mutation.error}
                  fallbackSummary={t("subscriptions.saveFailed")}
                />
              </div>
            ) : null}
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                disabled={mutation.isPending}
                onClick={close}
              >
                {t("subscriptions.cancel")}
              </Button>
              <Button
                type="submit"
                disabled={
                  mutation.isPending ||
                  !name.trim() ||
                  refreshIntervalSeconds === undefined
                }
              >
                {mutation.isPending
                  ? t("subscriptions.saving")
                  : t("subscriptions.save")}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
      <DeleteImpactDialog
        open={removing !== null}
        title={t("subscriptions.remove")}
        description={t("subscriptions.removeHint", { name: removing?.name })}
        confirmLabel={t("subscriptions.remove")}
        impactItems={[]}
        isPending={mutation.isPending}
        onConfirm={() => {
          if (removing) mutation.mutate({ kind: "remove", id: removing.id })
        }}
        onOpenChange={(open) => {
          if (!open && !mutation.isPending) {
            setRemoving(null)
            mutation.reset()
          }
        }}
      >
        {mutation.isError ? (
          <p role="alert" className="text-sm text-destructive">
            {t("subscriptions.actionFailed")}
          </p>
        ) : null}
      </DeleteImpactDialog>
    </section>
  )
}
