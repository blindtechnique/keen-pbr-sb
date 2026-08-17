/**
 * Tracks how far the router's clock sits from this browser's.
 *
 * Every timestamp the daemon publishes is on the ROUTER's wall clock, and the
 * browser has its own. Comparing them directly - which is what a plain
 * `Date.now() - sampled_at` does - measures the disagreement between two
 * machines rather than the age of anything. On a Keenetic that disagreement
 * can be large and one-sided: the router has no battery-backed RTC, so before
 * NTP settles its clock can be years behind, and a naive comparison then
 * declares every healthy interface stale for as long as it takes to sync.
 *
 * The correction is deliberately derived from data we already receive: each
 * traffic batch carries the router's own idea of "now", so the difference
 * between that and the browser's clock at the moment of receipt is the offset.
 * It self-corrects on every batch and needs no extra request.
 */

let offsetMs = 0
let haveSample = false

/**
 * Records the router's clock as observed in a message that just arrived.
 *
 * `routerUnixMs` must be a timestamp the daemon generated at send time, not one
 * it is reporting about the past - otherwise the age of that past event would
 * be folded into the offset.
 */
export function noteRouterClock(
  routerUnixMs: number,
  clientNowMs: number = Date.now()
): void {
  if (!Number.isFinite(routerUnixMs) || routerUnixMs <= 0) {
    return
  }
  offsetMs = clientNowMs - routerUnixMs
  haveSample = true
}

/**
 * The router's current time, expressed from this browser's clock.
 *
 * Before any batch has been seen there is nothing to correct by, so this is
 * just the local clock: with no evidence of disagreement, assuming none is the
 * only honest option.
 */
export function routerNowMs(clientNowMs: number = Date.now()): number {
  return clientNowMs - offsetMs
}

/** Whether an offset has actually been measured, rather than assumed zero. */
export function hasRouterClockSample(): boolean {
  return haveSample
}

/** Test seam. Resets the measured offset. */
export function resetRouterClock(): void {
  offsetMs = 0
  haveSample = false
}
