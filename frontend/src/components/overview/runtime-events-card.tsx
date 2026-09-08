import { CheckCircle2, CircleAlert, History, Info, Loader2 } from "lucide-react"
import { useId, useState } from "react"
import { useTranslation } from "react-i18next"
import { Link } from "wouter"

import { SectionCard } from "@/components/shared/section-card"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

export type RuntimeEventView = Readonly<{
  id: string
  timestamp: string
  text: string
  tone: "info" | "warning" | "success"
  href: string
}>

export function RuntimeEventsCard({
  events,
  state,
}: {
  events: readonly RuntimeEventView[]
  state: "loading" | "ready" | "error"
}) {
  const { t } = useTranslation()
  const [expanded, setExpanded] = useState(false)
  const listId = useId()
  const visibleEvents = events.slice(0, expanded ? 20 : 5)

  return (
    <SectionCard
      title={t("overview.runtimeEvents.title")}
      description={t("overview.runtimeEvents.description")}
      action={
        <Button render={<Link href="/general#logging" />} variant="outline">
          <History aria-hidden="true" />
          {t("overview.runtimeEvents.openJournal")}
        </Button>
      }
    >
      {state === "loading" ? (
        <p
          className="flex items-center gap-2 text-sm text-muted-foreground"
          role="status"
        >
          <Loader2
            className="size-4 shrink-0 animate-spin"
            aria-hidden="true"
          />
          {t("overview.runtimeEvents.loading")}
        </p>
      ) : state === "error" ? (
        <p
          className="flex items-start gap-2 text-sm text-muted-foreground"
          role="status"
        >
          <CircleAlert
            className="mt-0.5 size-4 shrink-0 text-warning"
            aria-hidden="true"
          />
          {events.length > 0
            ? t("overview.runtimeEvents.stale")
            : t("overview.runtimeEvents.loadFailed")}
        </p>
      ) : events.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          {t("overview.runtimeEvents.empty")}
        </p>
      ) : null}
      {visibleEvents.length > 0 ? (
        <ol
          id={listId}
          className="divide-y"
          aria-label={t("overview.runtimeEvents.title")}
        >
          {visibleEvents.map((event) => {
            const EventIcon =
              event.tone === "warning"
                ? CircleAlert
                : event.tone === "success"
                  ? CheckCircle2
                  : Info
            return (
              <li
                key={event.id}
                className="flex min-w-0 items-start gap-3 py-3 first:pt-0 last:pb-0"
              >
                <EventIcon
                  aria-hidden="true"
                  className={cn(
                    "mt-0.5 size-4 shrink-0",
                    event.tone === "warning"
                      ? "text-warning"
                      : event.tone === "success"
                        ? "text-success"
                        : "text-muted-foreground"
                  )}
                />
                <div className="min-w-0 flex-1 space-y-1">
                  <p className="text-sm [overflow-wrap:anywhere]">
                    {event.text}
                  </p>
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                    <span
                      className="text-xs [overflow-wrap:anywhere] text-muted-foreground"
                      title={t("overview.runtimeEvents.observedTime")}
                    >
                      {event.timestamp}
                    </span>
                    <Link
                      className="text-sm text-primary underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-offset-2"
                      href={event.href}
                    >
                      {t("overview.runtimeEvents.openDetails")}
                    </Link>
                  </div>
                </div>
              </li>
            )
          })}
        </ol>
      ) : null}
      {events.length > 5 ? (
        <Button
          aria-controls={listId}
          aria-expanded={expanded}
          onClick={() => setExpanded((value) => !value)}
          variant="outline"
        >
          {expanded
            ? t("overview.runtimeEvents.showLess")
            : t("overview.runtimeEvents.showMore")}
        </Button>
      ) : null}
    </SectionCard>
  )
}
