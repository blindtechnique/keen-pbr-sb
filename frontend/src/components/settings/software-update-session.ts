export type UpdateProgress = {
  running: boolean
  log: string
  phase?: string
  percent?: number
  message?: string
  success?: boolean | null
  updated_at?: number
  package_rescue_ready?: boolean
  package_rollback_available?: boolean
  package_rollback_state?: string
}

export type UpdateAttempt = {
  id: string
  kind: "update" | "rollback"
  target: string
  startedAt: number
  pollUntil: number
  baselineUpdatedAt: number | null
  lastUpdatedAt: number | null
  accepted: boolean
  observedRunning: boolean
  phase: string
  percent: number
}

export const UPDATE_SESSION_KEY = "keen-pbr-software-update-v1"
export const UPDATE_POLL_WINDOW_MS = 15 * 60_000
type SessionStorage = Pick<Storage, "getItem" | "setItem" | "removeItem">

export function newUpdateAttempt(
  kind: UpdateAttempt["kind"],
  target: string,
  baselineUpdatedAt: number | undefined,
  now = Date.now()
): UpdateAttempt {
  return {
    id: `${now}-${Math.random().toString(36).slice(2)}`,
    kind,
    target: target.slice(0, 100),
    startedAt: now,
    pollUntil: now + UPDATE_POLL_WINDOW_MS,
    baselineUpdatedAt: baselineUpdatedAt ?? null,
    lastUpdatedAt: null,
    accepted: false,
    observedRunning: false,
    phase: kind === "rollback" ? "rollback" : "preparing",
    percent: 0,
  }
}

// Only an explicit allowlist of non-secret metadata survives an auth remount
// or reload. Never persist the response, log, backup, config or credentials.
export function saveUpdateAttempt(
  storage: SessionStorage | null,
  attempt: UpdateAttempt | null
) {
  try {
    if (!attempt) {
      storage?.removeItem(UPDATE_SESSION_KEY)
      return
    }
    const {
      id,
      kind,
      target,
      startedAt,
      pollUntil,
      baselineUpdatedAt,
      lastUpdatedAt,
      accepted,
      observedRunning,
      phase,
      percent,
    } = attempt
    storage?.setItem(
      UPDATE_SESSION_KEY,
      JSON.stringify({
        id,
        kind,
        target,
        startedAt,
        pollUntil,
        baselineUpdatedAt,
        lastUpdatedAt,
        accepted,
        observedRunning,
        phase,
        percent,
      })
    )
  } catch {
    // Private browsing/storage policy must not prevent a router operation.
  }
}

export function loadUpdateAttempt(
  storage: SessionStorage | null
): UpdateAttempt | null {
  try {
    const value: unknown = JSON.parse(
      storage?.getItem(UPDATE_SESSION_KEY) ?? "null"
    )
    if (!value || typeof value !== "object") return null
    const item = value as Record<string, unknown>
    if (
      typeof item.id !== "string" ||
      item.id.length > 100 ||
      (item.kind !== "update" && item.kind !== "rollback") ||
      typeof item.target !== "string" ||
      item.target.length > 100 ||
      typeof item.phase !== "string" ||
      item.phase.length > 80 ||
      typeof item.accepted !== "boolean" ||
      typeof item.observedRunning !== "boolean" ||
      ![item.startedAt, item.pollUntil, item.percent].every(
        (v) => typeof v === "number" && Number.isFinite(v)
      ) ||
      ![item.baselineUpdatedAt, item.lastUpdatedAt].every(
        (v) => v === null || (typeof v === "number" && Number.isFinite(v))
      )
    )
      return null
    // Rebuild, rather than spreading untrusted storage with extra fields.
    return {
      id: item.id,
      kind: item.kind,
      target: item.target,
      startedAt: item.startedAt as number,
      pollUntil: item.pollUntil as number,
      baselineUpdatedAt: item.baselineUpdatedAt as number | null,
      lastUpdatedAt: item.lastUpdatedAt as number | null,
      accepted: item.accepted,
      observedRunning: item.observedRunning,
      phase: item.phase,
      percent: Math.min(100, Math.max(0, item.percent as number)),
    }
  } catch {
    return null
  }
}

export function browserUpdateStorage(): SessionStorage | null {
  try {
    return typeof window === "undefined" ? null : window.sessionStorage
  } catch {
    return null
  }
}

export function parseUpdateProgress(value: unknown): UpdateProgress | null {
  if (!value || typeof value !== "object") return null
  const item = value as Record<string, unknown>
  if (typeof item.running !== "boolean" || typeof item.log !== "string")
    return null
  if (
    item.success !== undefined &&
    item.success !== null &&
    typeof item.success !== "boolean"
  )
    return null
  return {
    running: item.running,
    log: item.log,
    ...(typeof item.package_rescue_ready === "boolean"
      ? { package_rescue_ready: item.package_rescue_ready }
      : {}),
    ...(typeof item.package_rollback_available === "boolean"
      ? { package_rollback_available: item.package_rollback_available }
      : {}),
    ...(typeof item.package_rollback_state === "string"
      ? { package_rollback_state: item.package_rollback_state }
      : {}),
    ...(typeof item.phase === "string" ? { phase: item.phase } : {}),
    ...(typeof item.message === "string" ? { message: item.message } : {}),
    ...(typeof item.percent === "number" && Number.isFinite(item.percent)
      ? { percent: Math.min(100, Math.max(0, item.percent)) }
      : {}),
    ...(typeof item.updated_at === "number" && Number.isFinite(item.updated_at)
      ? { updated_at: item.updated_at }
      : {}),
    ...(item.success !== undefined
      ? { success: item.success as boolean | null }
      : {}),
  }
}

export function observeUpdateProgress(
  attempt: UpdateAttempt,
  progress: UpdateProgress
): {
  attempt: UpdateAttempt
  apply: boolean
  terminal: boolean
} {
  const stamp = progress.updated_at
  // `running` comes from a lock independently of the helper's state file.
  // A new lock can still accompany the previous operation's terminal file.
  if (
    progress.running &&
    (progress.phase === "completed" ||
      progress.phase === "failed" ||
      typeof progress.success === "boolean")
  ) {
    return { attempt, apply: false, terminal: false }
  }
  const newerThanBaseline =
    stamp !== undefined &&
    attempt.baselineUpdatedAt !== null &&
    stamp > attempt.baselineUpdatedAt
  const stale =
    stamp !== undefined &&
    ((attempt.lastUpdatedAt !== null && stamp < attempt.lastUpdatedAt) ||
      (attempt.baselineUpdatedAt !== null &&
        stamp <= attempt.baselineUpdatedAt))
  if (stale) return { attempt, apply: false, terminal: false }
  const terminal =
    !progress.running &&
    (progress.success === false ||
      progress.phase === "failed" ||
      (progress.phase === "completed" && progress.success === true))
  // No comparison of browser time with router time. A previous completed file
  // cannot acknowledge a new POST, even when its HTTP response was accepted.
  if (
    !progress.running &&
    (!terminal || (!newerThanBaseline && !attempt.observedRunning))
  ) {
    return { attempt, apply: false, terminal: false }
  }
  return {
    attempt: {
      ...attempt,
      accepted: true,
      observedRunning: attempt.observedRunning || progress.running,
      lastUpdatedAt: stamp ?? attempt.lastUpdatedAt,
      phase: (progress.phase ?? attempt.phase).slice(0, 80),
      percent: progress.percent ?? attempt.percent,
    },
    apply: true,
    terminal,
  }
}

export function updateAttemptNotice(attempt: UpdateAttempt, now = Date.now()) {
  if (now >= attempt.pollUntil) return "resultUnknown" as const
  return attempt.accepted
    ? ("reconnecting" as const)
    : ("admissionUnknown" as const)
}

export function updateHttpStatus(error: unknown): number | null {
  return typeof error === "object" &&
    error !== null &&
    "status" in error &&
    typeof error.status === "number"
    ? error.status
    : null
}
