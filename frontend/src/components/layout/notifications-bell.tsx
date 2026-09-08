import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useState, useMemo } from "react"
import { BellIcon, CheckCheckIcon } from "lucide-react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import { Link } from "wouter"

import {
  dismissNotifications,
  getNotifications,
} from "@/api/generated/keen-api"
import type { NotificationDismissalState } from "@/api/generated/model"
import {
  applyNotificationState,
  NOTIFICATION_STATE_QUERY_KEY,
} from "@/api/notification-events"

import { nfqwsUpdateQueryOptions } from "@/api/nfqws"
import { useGetConfig, useGetHealthService } from "@/api/queries"
import { selectListRefreshState } from "@/api/selectors"
import { Button } from "@/components/ui/button"
import { TOP_BAR_CONTROL_CLASS } from "@/components/layout/top-bar-control-styles"
import {
  collectNotices,
  type SoftwareUpdateResponse,
} from "@/components/layout/notifications"
import { notificationUpdateIds } from "@/components/layout/subscription-notices"
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover"
import { cn } from "@/lib/utils"

/**
 * The feed combines the log with current subscription and update notices.
 * Only bounded dismissal identities
 * live on the router, shared across browsers without touching routing state.
 */
export function NotificationsBell() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const stateQuery = useQuery<NotificationDismissalState | null>({
    queryKey: NOTIFICATION_STATE_QUERY_KEY,
    queryFn: () => null,
    initialData: null,
    enabled: false,
  })
  const logsQuery = useQuery({
    queryKey: ["logs", "notifications"],
    queryFn: async () => {
      const response = await getNotifications()
      if (response.status !== 200) throw new Error(`HTTP ${response.status}`)
      applyNotificationState(queryClient, response.data.state)
      return response.data
    },
    refetchInterval: 60_000,
    refetchIntervalInBackground: false,
  })

  const updateQuery = useQuery<SoftwareUpdateResponse>({
    queryKey: ["system-update", "notifications"],
    queryFn: async () => {
      const response = await fetch("/api/system/update")
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json()
    },
    // The router's link to GitHub is unreliable; failing here must stay quiet.
    retry: false,
    refetchInterval: 6 * 60 * 60 * 1000,
    refetchIntervalInBackground: false,
  })

  const nfqwsUpdateQuery = useQuery(nfqwsUpdateQueryOptions())
  const serviceHealthQuery = useGetHealthService()
  // Тот же источник, что у страницы списков. Она молчала про списки, которые
  // давно обновились, а колокольчик про них кричал — потому что читал журнал,
  // а не состояние.
  const configQuery = useGetConfig()
  const listRefreshState = selectListRefreshState(configQuery.data)
  const dismissedIds = useMemo(
    () =>
      new Set([
        ...(stateQuery.data?.log_ids ?? []),
        ...(stateQuery.data?.update_ids ?? []),
      ]),
    [stateQuery.data]
  )

  // Колокольчик смонтирован дважды всегда: десктопная и мобильная шапки
  // скрыты через CSS, а не размонтированы. Разбор двухсот строк лога
  // регулярками в теле рендера умножался на два и повторялся на каждый
  // рендер оболочки.
  const notices = useMemo(
    () =>
      collectNotices(
        logsQuery.data?.lines ?? [],
        updateQuery.data,
        nfqwsUpdateQuery.data,
        listRefreshState,
        logsQuery.data?.line_ids ?? [],
        dismissedIds,
        t,
        {
          service:
            serviceHealthQuery.data?.status === 200
              ? serviceHealthQuery.data.data
              : undefined,
        },
        logsQuery.data?.subscription_notices
      ),
    [
      logsQuery.data,
      updateQuery.data,
      nfqwsUpdateQuery.data,
      listRefreshState,
      dismissedIds,
      serviceHealthQuery.data,
      t,
    ]
  )

  const clearMutation = useMutation({
    mutationFn: async () => {
      // Include the whole loaded warning/error window, not just the visible
      // twenty. New entries arriving during this request are not dismissed.
      const logIds = (logsQuery.data?.line_ids ?? []).filter((_, index) =>
        /^\S+ \S+\s+\[[EW]\]\s+/.test(logsQuery.data?.lines[index] ?? "")
      )
      const updateIds = notificationUpdateIds(
        notices,
        logsQuery.data?.subscription_notices ?? []
      )
      const response = await dismissNotifications({
        log_ids: logIds,
        update_ids: updateIds,
      })
      if (response.status !== 200) throw new Error(`HTTP ${response.status}`)
      applyNotificationState(queryClient, response.data)
    },
    onSuccess: () => setOpen(false),
    onError: () => toast.error(t("notifications.clearFailed")),
  })

  return (
    <Popover onOpenChange={setOpen} open={open}>
      <PopoverTrigger
        render={
          <Button
            aria-label={t("notifications.title")}
            className={TOP_BAR_CONTROL_CLASS}
            size="icon"
            title={t("notifications.title")}
            variant="ghost"
          />
        }
      >
        <BellIcon />
        {notices.length > 0 ? (
          <span
            className={cn(
              "absolute top-1.5 right-1.5 size-2 rounded-full",
              notices.some((notice) => notice.level === "error")
                ? "bg-destructive"
                : "bg-warning"
            )}
          />
        ) : null}
      </PopoverTrigger>
      <PopoverContent align="end" className="w-80 p-0">
        <div className="flex items-center justify-between gap-2 border-b py-1.5 pr-1.5 pl-3">
          <span className="text-sm font-medium">
            {t("notifications.title")}
          </span>
          {notices.length > 0 ? (
            <Button
              className="h-7 gap-1.5 px-2 text-xs text-muted-foreground"
              disabled={
                clearMutation.isPending || !stateQuery.data || !logsQuery.data
              }
              onClick={() => clearMutation.mutate()}
              size="sm"
              variant="ghost"
            >
              <CheckCheckIcon className="size-3.5" />
              {t("notifications.clear")}
            </Button>
          ) : null}
        </div>

        {logsQuery.data?.subscription_notices_error ? (
          <p
            className="border-b px-3 py-2 text-sm text-muted-foreground"
            role="status"
          >
            {t("notifications.subscriptions.loadFailed")}
          </p>
        ) : null}

        {logsQuery.isPending || logsQuery.isError ? (
          <p
            className="px-3 py-6 text-center text-sm text-muted-foreground"
            role="status"
          >
            {t(
              logsQuery.isError
                ? "notifications.loadFailed"
                : "notifications.loading"
            )}
          </p>
        ) : notices.length === 0 &&
          !logsQuery.data?.subscription_notices_error ? (
          <p className="px-3 py-6 text-center text-sm text-muted-foreground">
            {t("notifications.empty")}
          </p>
        ) : (
          <ul className="max-h-80 divide-y overflow-y-auto">
            {notices.map((notice) => (
              <li className="px-3 py-2" key={notice.id}>
                <div className="flex items-start gap-2">
                  <span
                    className={cn(
                      "mt-1.5 size-1.5 shrink-0 rounded-full",
                      notice.level === "error"
                        ? "bg-destructive"
                        : notice.level === "warning"
                          ? "bg-warning"
                          : "bg-primary"
                    )}
                  />
                  <div className="min-w-0">
                    <p className="text-sm break-words">{notice.text}</p>
                    {notice.href && notice.actionLabel ? (
                      <Link
                        className="mt-1 inline-block text-sm text-primary underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-offset-2"
                        href={notice.href}
                        onClick={() => setOpen(false)}
                      >
                        {notice.actionLabel}
                      </Link>
                    ) : null}
                    {notice.details ? (
                      <details className="mt-1 text-xs text-muted-foreground">
                        <summary className="cursor-pointer">
                          {t("notifications.details")}
                        </summary>
                        <p className="mt-1 break-words whitespace-pre-wrap">
                          {notice.details}
                        </p>
                      </details>
                    ) : null}
                    {notice.timestamp ? (
                      <p className="text-xs text-muted-foreground">
                        {notice.timestamp}
                      </p>
                    ) : null}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </PopoverContent>
    </Popover>
  )
}
