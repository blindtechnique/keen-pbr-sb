import type { TFunction } from "i18next"

import { getDiagnosticTasks } from "@/api/generated/keen-api"
import type {
  PeriodicTaskMetricsEntry,
  PeriodicTaskMetricsResponse,
} from "@/api/generated/model"

export type BackgroundTaskRequest = (
  signal: AbortSignal
) => Promise<PeriodicTaskMetricsResponse>

export type BackgroundTaskState =
  | { status: "idle" | "loading" | "failed" }
  | { status: "ready"; result: PeriodicTaskMetricsResponse }

export const loadBackgroundTasks: BackgroundTaskRequest = async (signal) => {
  const response = await getDiagnosticTasks({ signal, cache: "no-store" })
  if (response.status !== 200 || !Array.isArray(response.data?.tasks)) {
    throw new Error("Invalid background task diagnostics response")
  }
  return response.data
}

// This request session has no timer, query observer, retry or stream listener.
// Closing the details invalidates late results even if fetch ignores abort.
export function createBackgroundTaskRequest(
  request: BackgroundTaskRequest,
  publish: (state: BackgroundTaskState) => void
) {
  let active: AbortController | null = null
  let disposed = false
  const cancel = () => {
    active?.abort()
    active = null
  }
  return {
    async load() {
      if (disposed || active) return
      const controller = new AbortController()
      active = controller
      publish({ status: "loading" })
      try {
        const result = await request(controller.signal)
        if (active === controller && !disposed) {
          publish({ status: "ready", result })
        }
      } catch {
        if (active === controller && !disposed) publish({ status: "failed" })
      } finally {
        if (active === controller) active = null
      }
    },
    cancel,
    dispose() {
      disposed = true
      cancel()
    },
  }
}

export function backgroundTaskTitle(label: string, t: TFunction): string {
  switch (label) {
    case "resolver-hash-refresh":
      return t("backgroundTasks.names.resolver")
    case "keenetic-dns-refresh":
      return t("backgroundTasks.names.keeneticDns")
    case "owned-snat-health":
      return t("backgroundTasks.names.snat")
    case "interface-probe":
      return t("backgroundTasks.names.interfaces")
    case "interface-traffic-sample":
      return t("backgroundTasks.names.traffic")
    default:
      return t("backgroundTasks.names.other")
  }
}

export function backgroundTaskOutcome(
  outcome: string | undefined,
  t: TFunction
): string {
  switch (outcome) {
    case "success":
      return t("backgroundTasks.outcomes.success")
    case "noop":
      return t("backgroundTasks.outcomes.noop")
    case "failure":
      return t("backgroundTasks.outcomes.failure")
    case "skipped":
      return t("backgroundTasks.outcomes.skipped")
    case "abandoned":
      return t("backgroundTasks.outcomes.abandoned")
    default:
      return t("backgroundTasks.unknown")
  }
}

export function backgroundTaskNumber(
  value: number | undefined,
  language: string
): string | null {
  return typeof value === "number" && Number.isInteger(value) && value >= 0
    ? new Intl.NumberFormat(language).format(value)
    : null
}

export function backgroundTaskNextRun(
  task: Pick<
    PeriodicTaskMetricsEntry,
    "scheduling_state" | "next_run_at_unix_ms"
  >,
  t: TFunction,
  language: string,
  timeZone?: string
): string {
  if (task.scheduling_state === "not_scheduled") {
    return t("backgroundTasks.notScheduled")
  }
  const timestamp = task.next_run_at_unix_ms
  if (
    task.scheduling_state !== "scheduled" ||
    typeof timestamp !== "number" ||
    !Number.isSafeInteger(timestamp) ||
    Number.isNaN(new Date(timestamp).getTime())
  ) {
    return t("backgroundTasks.unknown")
  }
  return new Intl.DateTimeFormat(language, {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
    ...(timeZone ? { timeZone } : {}),
  }).format(timestamp)
}
