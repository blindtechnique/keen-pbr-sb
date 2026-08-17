import { useEffect, useState } from "react"

/**
 * Re-renders on an interval, but only while the tab is actually visible.
 *
 * Anything that ages against the wall clock - "measured N ago", "up for N" -
 * needs a reason to re-render even when no new data arrives, or a stalled
 * value simply freezes on screen looking healthy. A plain setInterval would
 * pay that cost in a background tab forever, which is the opposite of what
 * adaptive cadence is for, so the timer is torn down while hidden and one
 * catch-up render is forced on return.
 *
 * Returns an opaque counter. Read the clock yourself during render; the value
 * exists only to schedule that render.
 */
export function useVisibleTick(intervalMs: number): number {
  const [tick, setTick] = useState(0)

  useEffect(() => {
    if (typeof document === "undefined") {
      return
    }

    let timer: ReturnType<typeof setInterval> | undefined

    const stop = () => {
      if (timer === undefined) {
        return
      }
      clearInterval(timer)
      timer = undefined
    }

    const sync = () => {
      if (document.visibilityState === "hidden") {
        stop()
        return
      }
      // The age grew while the tab was hidden, so render once immediately
      // rather than showing a stale value until the next interval elapses.
      setTick((current) => current + 1)
      if (timer === undefined) {
        timer = setInterval(
          () => setTick((current) => current + 1),
          intervalMs
        )
      }
    }

    sync()
    document.addEventListener("visibilitychange", sync)
    return () => {
      document.removeEventListener("visibilitychange", sync)
      stop()
    }
  }, [intervalMs])

  return tick
}
