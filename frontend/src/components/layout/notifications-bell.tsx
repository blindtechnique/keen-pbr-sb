import { useQuery } from "@tanstack/react-query"
import { useState } from "react"
import { BellIcon } from "lucide-react"
import { useTranslation } from "react-i18next"

import { Button } from "@/components/ui/button"
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover"
import { cn } from "@/lib/utils"

type LogsResponse = {
  lines: string[]
}

type UpdateResponse = {
  available?: boolean
  latest?: string
}

type Notice = {
  id: string
  level: "error" | "warning" | "info"
  text: string
  timestamp?: string
}

/**
 * Notifications are derived rather than stored: the log already records
 * everything the service considers worth saying, so a separate feed would only
 * be a second place for the same facts to drift out of sync.
 */
export function NotificationsBell() {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)

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

  const updateQuery = useQuery<UpdateResponse>({
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

  const notices = collectNotices(logsQuery.data?.lines ?? [], updateQuery.data, t)

  return (
    <Popover onOpenChange={setOpen} open={open}>
      <PopoverTrigger
        render={
          <Button
            aria-label={t("notifications.title")}
            className="relative size-9 text-muted-foreground hover:text-foreground"
            size="icon"
            title={t("notifications.title")}
            variant="ghost"
          />
        }
      >
        <BellIcon className="size-4" />
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
        <div className="border-b px-3 py-2 text-sm font-medium">
          {t("notifications.title")}
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

const MAX_NOTICES = 20

/**
 * Log lines look like "2026-07-19 23:13:43.549 [W] message". The level marker
 * is absent on ordinary info lines, which is exactly what we want to skip.
 */
function collectNotices(
  lines: string[],
  update: UpdateResponse | undefined,
  t: (key: string, options?: Record<string, unknown>) => string
): Notice[] {
  const notices: Notice[] = []

  if (update?.available && update.latest) {
    notices.push({
      id: `update-${update.latest}`,
      level: "info",
      text: t("notifications.updateAvailable", { version: update.latest }),
    })
  }

  // Newest first: the tail of the file is the most recent.
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    if (notices.length >= MAX_NOTICES) {
      break
    }
    const line = lines[index]
    const match = line.match(/^(\S+ \S+)\s+\[([EW])\]\s+(.*)$/)
    if (!match) {
      continue
    }
    const [, timestamp, marker, text] = match
    notices.push({
      id: `${timestamp}-${index}`,
      level: marker === "E" ? "error" : "warning",
      text,
      timestamp,
    })
  }

  return notices
}
