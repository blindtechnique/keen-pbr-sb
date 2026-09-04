import { useMutation, useQueryClient } from "@tanstack/react-query"
import { Plus, RefreshCw } from "lucide-react"
import { useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import {
  getGetSubscriptionsQueryKey,
  postSubscriptionRefresh,
  postSubscriptionRename,
  postSubscriptionRemove,
  useGetSubscriptions,
} from "@/api/generated/keen-api"
import type { SavedSubscription, TransportStatus } from "@/api/generated/model"
import { KeenPencilIcon, KeenTrashIcon } from "@/components/shared/keen-icons"
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

type Action =
  | { kind: "rename"; id: string; name: string }
  | { kind: "refresh" | "remove"; id: string }

export function SubscriptionsPanel({
  transports,
}: {
  transports: TransportStatus[]
}) {
  const { t, i18n } = useTranslation()
  const client = useQueryClient()
  const query = useGetSubscriptions({ query: { retry: false } })
  const [editing, setEditing] = useState<SavedSubscription | null>(null)
  const [importing, setImporting] = useState(false)
  const [removing, setRemoving] = useState<SavedSubscription | null>(null)
  const [name, setName] = useState("")
  const names = new Map(
    transports.map((item) => [item.tag, item.display_name || item.tag])
  )
  const mutation = useMutation({
    mutationFn: async (action: Action) => {
      switch (action.kind) {
        case "rename":
          return postSubscriptionRename({ id: action.id, name: action.name })
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
      if (action.kind === "rename") {
        setEditing(null)
      }
      if (action.kind === "remove") setRemoving(null)
      if ("error" in response.data && response.data.error)
        toast.error(t("subscriptions.refreshFailed"))
      else
        toast.success(
          action.kind === "refresh"
            ? t("subscriptions.refreshed")
            : t("subscriptions.saved")
        )
    },
  })
  const records = query.data?.status === 200 ? query.data.data : []
  const edit = (record: SavedSubscription) => {
    mutation.reset()
    setName(record.name)
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
          onClick={() => setImporting(true)}
          variant="outline"
          disabled={importing || mutation.isPending}
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
      {mutation.isError && !editing && !removing ? (
        <Alert variant="destructive">
          <AlertDescription>{t("subscriptions.actionFailed")}</AlertDescription>
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
            className="space-y-4 rounded-lg border p-4 sm:p-5"
            key={record.id}
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
                <Button
                  size="icon"
                  variant="outline"
                  className="keen-row-action size-8 rounded-[4px]"
                  disabled={mutation.isPending}
                  aria-label={t("subscriptions.rename")}
                  title={t("subscriptions.rename")}
                  onClick={() => edit(record)}
                >
                  <KeenPencilIcon className="size-4" />
                </Button>
                <Button
                  size="icon"
                  variant="outline"
                  className="keen-row-action keen-row-action--danger size-8 rounded-[4px]"
                  disabled={mutation.isPending}
                  aria-label={t("subscriptions.remove")}
                  title={t("subscriptions.remove")}
                  onClick={() => {
                    mutation.reset()
                    setRemoving(record)
                  }}
                >
                  <KeenTrashIcon className="size-4" />
                </Button>
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
          onOpenChange={setImporting}
          onComplete={() => setImporting(false)}
          onResultsDismiss={() => setImporting(false)}
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
            <DialogTitle>{t("subscriptions.rename")}</DialogTitle>
          </DialogHeader>
          <form
            className="space-y-4"
            onSubmit={(event) => {
              event.preventDefault()
              if (!editing || mutation.isPending) return
              mutation.mutate({
                kind: "rename",
                id: editing.id,
                name: name.trim(),
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
            {mutation.isError ? (
              <p role="alert" className="text-sm text-destructive">
                {t("subscriptions.saveFailed")}
              </p>
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
              <Button type="submit" disabled={mutation.isPending}>
                {mutation.isPending
                  ? t("subscriptions.saving")
                  : t("subscriptions.save")}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
      <Dialog
        open={removing !== null}
        onOpenChange={(open) => {
          if (!open && !mutation.isPending) {
            setRemoving(null)
            mutation.reset()
          }
        }}
      >
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{t("subscriptions.remove")}</DialogTitle>
          </DialogHeader>
          <p className="text-sm">
            {t("subscriptions.removeHint", { name: removing?.name })}
          </p>
          {mutation.isError ? (
            <p role="alert" className="text-sm text-destructive">
              {t("subscriptions.actionFailed")}
            </p>
          ) : null}
          <DialogFooter>
            <Button
              variant="outline"
              disabled={mutation.isPending}
              onClick={() => setRemoving(null)}
            >
              {t("subscriptions.cancel")}
            </Button>
            <Button
              disabled={mutation.isPending}
              onClick={() => {
                if (removing)
                  mutation.mutate({ kind: "remove", id: removing.id })
              }}
            >
              {t("subscriptions.remove")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </section>
  )
}
