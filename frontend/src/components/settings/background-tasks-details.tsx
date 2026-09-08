import { useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"

import type { PeriodicTaskMetricsResponse } from "@/api/generated/model"
import { Button } from "@/components/ui/button"
import {
  backgroundTaskNextRun,
  backgroundTaskNumber,
  backgroundTaskOutcome,
  backgroundTaskTitle,
  createBackgroundTaskRequest,
  loadBackgroundTasks,
  type BackgroundTaskRequest,
  type BackgroundTaskState,
} from "@/components/settings/background-tasks-model"

export function BackgroundTasksDetails({
  request = loadBackgroundTasks,
}: {
  request?: BackgroundTaskRequest
}) {
  const { t } = useTranslation()
  const [state, setState] = useState<BackgroundTaskState>({ status: "idle" })
  const session = useRef<ReturnType<typeof createBackgroundTaskRequest> | null>(
    null
  )
  useEffect(() => {
    const current = createBackgroundTaskRequest(request, setState)
    session.current = current
    return () => {
      current.dispose()
      if (session.current === current) session.current = null
    }
  }, [request])

  return (
    <details
      className="mt-4 min-w-0 border-t pt-3 text-sm"
      onToggle={(event) => {
        if (event.target !== event.currentTarget) return
        if (event.currentTarget.open) {
          void session.current?.load()
        } else {
          session.current?.cancel()
          setState({ status: "idle" })
        }
      }}
    >
      <summary className="cursor-pointer font-medium">
        {t("backgroundTasks.title")}
      </summary>
      <div className="mt-3 space-y-3">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="max-w-prose space-y-1 text-xs text-muted-foreground">
            <p>{t("backgroundTasks.description")}</p>
            <p>{t("backgroundTasks.scheduleHint")}</p>
          </div>
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={state.status === "loading"}
            onClick={() => void session.current?.load()}
          >
            {t("backgroundTasks.refresh")}
          </Button>
        </div>
        {state.status === "loading" ? (
          <p role="status">{t("backgroundTasks.loading")}</p>
        ) : null}
        {state.status === "failed" ? (
          <p className="text-destructive" role="alert">
            {t("backgroundTasks.failed")}
          </p>
        ) : null}
        {state.status === "ready" ? (
          <BackgroundTasksResult result={state.result} />
        ) : null}
      </div>
    </details>
  )
}

export function BackgroundTasksResult({
  result,
}: {
  result: PeriodicTaskMetricsResponse
}) {
  const { t, i18n } = useTranslation()
  const language = i18n.resolvedLanguage ?? i18n.language ?? "ru"
  const number = (value: number | undefined) =>
    backgroundTaskNumber(value, language) ?? t("backgroundTasks.unknown")
  if (result.tasks.length === 0) {
    return <p className="text-muted-foreground">{t("backgroundTasks.empty")}</p>
  }
  return (
    <ul className="divide-y" aria-label={t("backgroundTasks.title")}>
      {result.tasks.map((task) => (
        <li className="space-y-2 py-3 first:pt-0 last:pb-0" key={task.label}>
          <div>
            <p className="font-medium">{backgroundTaskTitle(task.label, t)}</p>
            <p className="font-mono text-xs break-all text-muted-foreground">
              {task.label}
            </p>
          </div>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs sm:grid-cols-3">
            <div>
              <dt className="text-muted-foreground">
                {t("backgroundTasks.outcome")}
              </dt>
              <dd>{backgroundTaskOutcome(task.last_outcome, t)}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">
                {t("backgroundTasks.duration")}
              </dt>
              <dd>
                {backgroundTaskNumber(task.last_duration_ms, language) === null
                  ? t("backgroundTasks.unknown")
                  : t("backgroundTasks.milliseconds", {
                      value: number(task.last_duration_ms),
                    })}
              </dd>
            </div>
            <div>
              <dt className="text-muted-foreground">
                {t("backgroundTasks.failures")}
              </dt>
              <dd>{number(task.consecutive_failures)}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">
                {t("backgroundTasks.inFlight")}
              </dt>
              <dd>{number(task.in_flight)}</dd>
            </div>
            <div className="col-span-2">
              <dt className="text-muted-foreground">
                {t("backgroundTasks.nextRun")}
              </dt>
              <dd>{backgroundTaskNextRun(task, t, language)}</dd>
            </div>
          </dl>
          {task.last_error ? (
            <details className="text-xs">
              <summary className="cursor-pointer text-muted-foreground">
                {t("backgroundTasks.technicalDetails")}
              </summary>
              <p className="mt-1 font-mono break-words whitespace-pre-wrap">
                {task.last_error}
              </p>
            </details>
          ) : null}
        </li>
      ))}
    </ul>
  )
}
