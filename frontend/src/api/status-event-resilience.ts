import type { StatusEventConnectionState } from "@/api/status-event-connection"

export const STATUS_EVENT_FALLBACK_INTERVAL_MS = 15_000

type IntervalHandle = ReturnType<typeof setInterval>

type StatusQueryResilienceOptions = Readonly<{
  refresh: () => void | Promise<void>
  schedule?: (callback: () => void, delayMs: number) => IntervalHandle
  cancel?: (handle: IntervalHandle) => void
}>

/**
 * SSE is the normal steady-state transport. During its bounded reconnect
 * window, periodically refresh the three runtime snapshots so a baseline that
 * happened to land before the first probe cannot remain UNKNOWN forever.
 */
export function createStatusQueryResilience({
  refresh,
  schedule = (callback, delayMs) => setInterval(callback, delayMs),
  cancel = (handle) => clearInterval(handle),
}: StatusQueryResilienceOptions) {
  let fallback: IntervalHandle | undefined
  let refreshInFlight = false
  let refreshSerial = 0
  let currentState: StatusEventConnectionState | undefined
  let disposed = false

  const stopFallback = () => {
    if (fallback === undefined) return
    cancel(fallback)
    fallback = undefined
  }

  const refreshOnce = (force = false) => {
    if (disposed || (refreshInFlight && !force)) return
    const serial = ++refreshSerial
    refreshInFlight = true
    try {
      const result = refresh()
      if (result && typeof result.then === "function") {
        void result
          .catch(() => undefined)
          .finally(() => {
            if (refreshSerial === serial) refreshInFlight = false
          })
      } else {
        if (refreshSerial === serial) refreshInFlight = false
      }
    } catch {
      if (refreshSerial === serial) refreshInFlight = false
    }
  }

  const transition = (state: StatusEventConnectionState) => {
    if (disposed) return
    const changed = state !== currentState
    currentState = state

    if (state === "paused") {
      stopFallback()
      return
    }

    if (state === "connected") {
      stopFallback()
      // A reconnect carries a fresh SSE snapshot, but also refresh the REST
      // baselines immediately. This closes the race where an older HTTP reply
      // lands after the snapshot and overwrites the cache.
      if (changed) refreshOnce(/*force=*/ true)
      return
    }

    if (fallback === undefined) {
      fallback = schedule(refreshOnce, STATUS_EVENT_FALLBACK_INTERVAL_MS)
    }
    if (state === "disconnected" && changed) {
      refreshOnce()
    }
  }

  return {
    transition,
    dispose() {
      disposed = true
      stopFallback()
    },
  }
}
