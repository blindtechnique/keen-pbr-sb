import { useQuery } from "@tanstack/react-query"
import { useState, type MouseEvent, useMemo } from "react"
import { BellIcon, CheckCheckIcon } from "lucide-react"
import { useTranslation } from "react-i18next"

import { nfqwsUpdateQueryOptions } from "@/api/nfqws"
import { useGetConfig, useGetHealthService } from "@/api/queries"
import { selectListRefreshState } from "@/api/selectors"
import { Button } from "@/components/ui/button"
import { TOP_BAR_CONTROL_CLASS } from "@/components/layout/top-bar-control-styles"
import {
  collectNotices,
  type SoftwareUpdateResponse,
} from "@/components/layout/notifications"
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover"
import { cn } from "@/lib/utils"

type LogsResponse = {
  lines: string[]
}

/**
 * Notifications are derived rather than stored: the log already records
 * everything the service considers worth saying, so a separate feed would only
 * be a second place for the same facts to drift out of sync.
 */
const DISMISSED_KEY = "keen-pbr-notifications-dismissed-until"
const DISMISSED_IDS_KEY = "keen-pbr-notifications-dismissed-ids"

export function NotificationsBell() {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [dismissedUntil, setDismissedUntil] = useState(() => {
    const stored = window.localStorage.getItem(DISMISSED_KEY)
    return stored ? Number(stored) : 0
  })
  const [dismissedIds, setDismissedIds] = useState<ReadonlySet<string>>(() => {
    const stored = window.localStorage.getItem(DISMISSED_IDS_KEY)
    if (!stored) return new Set()
    try {
      const parsed: unknown = JSON.parse(stored)
      return new Set(
        Array.isArray(parsed)
          ? parsed.filter((value): value is string => typeof value === "string")
          : []
      )
    } catch {
      return new Set()
    }
  })

  const logsQuery = useQuery<LogsResponse>({
    queryKey: ["logs", "notifications"],
    queryFn: async () => {
      const response = await fetch("/api/logs?lines=200")
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json()
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
        dismissedUntil,
        dismissedIds,
        t,
        {
          service:
            serviceHealthQuery.data?.status === 200
              ? serviceHealthQuery.data.data
              : undefined,
        }
      ),
    [
      logsQuery.data,
      updateQuery.data,
      nfqwsUpdateQuery.data,
      listRefreshState,
      dismissedUntil,
      dismissedIds,
      serviceHealthQuery.data,
      t,
    ]
  )

  const dismissAll = (event: MouseEvent<HTMLButtonElement>) => {
    const now =
      event.timeStamp > 1_000_000_000_000
        ? event.timeStamp
        : performance.timeOrigin + event.timeStamp
    const syntheticIds = notices
      .filter((notice) => notice.timestamp === undefined)
      .map((notice) => notice.id)
    const nextDismissedIds = new Set([...dismissedIds, ...syntheticIds])
    window.localStorage.setItem(DISMISSED_KEY, String(now))
    window.localStorage.setItem(
      DISMISSED_IDS_KEY,
      JSON.stringify([...nextDismissedIds])
    )
    setDismissedUntil(now)
    setDismissedIds(nextDismissedIds)
    setOpen(false)
  }

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
              onClick={dismissAll}
              size="sm"
              variant="ghost"
            >
              <CheckCheckIcon className="size-3.5" />
              {t("notifications.clear")}
            </Button>
          ) : null}
        </div>

        {notices.length === 0 ? (
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
