import type { QueryClient } from "@tanstack/react-query"

// The existing metadata query uses this raw key; local metrics have a separate
// key and keep their independent 15-second schedule.
export const ROUTER_INFO_QUERY_KEY = ["system-router"] as const
export const ROUTER_INFO_EVENT_WINDOW_MS = 5_000

type TimerHandle = ReturnType<typeof setTimeout>
type Scheduling = {
  schedule?: (callback: () => void, delayMs: number) => TimerHandle
  cancel?: (handle: TimerHandle) => void
}

/** Coalesce bursts without postponing the first event's fixed refresh window. */
export function createRouterInfoEventRefresh(
  client: QueryClient,
  {
    schedule = (callback, delayMs) => setTimeout(callback, delayMs),
    cancel = (handle) => clearTimeout(handle),
  }: Scheduling = {}
) {
  let timer: TimerHandle | null = null
  let due = false
  let waitingForFetch = false
  let refreshing = false
  let disposed = false
  const query = { queryKey: ROUTER_INFO_QUERY_KEY, exact: true }

  const waitForFetch = () => {
    waitingForFetch = true
    if (timer !== null) cancel(timer)
    timer = null
    due = false
  }

  const startWindow = () => {
    if (disposed || timer !== null || due || waitingForFetch) return
    timer = schedule(() => {
      timer = null
      due = true
      refreshIfReady()
    }, ROUTER_INFO_EVENT_WINDOW_MS)
  }

  const refreshIfReady = () => {
    if (disposed || !due || refreshing) return
    if (
      client.getQueryState(ROUTER_INFO_QUERY_KEY)?.fetchStatus === "fetching"
    ) {
      waitForFetch()
      return
    }
    due = false
    refreshing = true
    void client
      .invalidateQueries(
        { ...query, refetchType: "active" },
        { cancelRefetch: false }
      )
      .catch(() => undefined)
      .finally(() => {
        refreshing = false
        refreshIfReady()
      })
  }

  const unsubscribe = client.getQueryCache().subscribe((event) => {
    const key = event.query.queryKey
    if (key.length !== 1 || key[0] !== ROUTER_INFO_QUERY_KEY[0]) return
    if (event.query.state.fetchStatus === "fetching") {
      // A regular poll can start while the event window is still pending.
      if (timer !== null || due) waitForFetch()
    } else if (event.query.state.fetchStatus === "idle" && waitingForFetch) {
      // The server's event cooldown starts when its fetch completes. Reusing
      // the old promise or immediately following it would retain stale data.
      // Arm one fixed successor window here; more events do not postpone it.
      waitingForFetch = false
      startWindow()
    } else if (event.query.state.fetchStatus === "idle") {
      refreshIfReady()
    }
  })

  const cancelPending = () => {
    if (timer !== null) cancel(timer)
    timer = null
    due = false
    waitingForFetch = false
  }

  return {
    scheduleRefresh() {
      if (disposed) return
      // Never cancel a slow GET. Events during it share one post-completion
      // window, rather than continually restarting either the GET or a timer.
      if (
        client.getQueryState(ROUTER_INFO_QUERY_KEY)?.fetchStatus === "fetching"
      ) {
        waitForFetch()
      } else {
        startWindow()
      }
    },
    cancelPending,
    dispose() {
      disposed = true
      cancelPending()
      unsubscribe()
    },
  }
}

export function applyRouterInfoStatusEvent(
  serialized: string,
  scheduleRefresh: () => void
): boolean {
  try {
    if (JSON.parse(serialized)?.type !== "router_info") return false
  } catch {
    return false
  }
  scheduleRefresh()
  return true
}
