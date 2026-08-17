import { describe, expect, test } from "bun:test"

import {
  isTrafficReadingStale,
  TRAFFIC_STALE_AFTER_MS,
} from "../src/components/transports/interface-traffic-model"

const now = 1_754_812_800_000

describe("traffic reading staleness", () => {
  test("a reading from the last sampling round is current", () => {
    expect(isTrafficReadingStale(now - 2_000, now)).toBe(false)
  })

  test("a reading at the daemon's slowest cadence is still current", () => {
    // The daemon backs an idle interface off to five ticks of a two-second
    // timer. Marking that healthy quiet link stale would punish the backoff
    // for working.
    expect(isTrafficReadingStale(now - 10_000, now)).toBe(false)
  })

  test("a reading older than the event-stream fallback poll is still current", () => {
    // The client falls back to a 15s poll while the stream reconnects.
    expect(isTrafficReadingStale(now - 15_000, now)).toBe(false)
  })

  test("a reading that stopped arriving is reported as stale", () => {
    expect(isTrafficReadingStale(now - TRAFFIC_STALE_AFTER_MS - 1, now)).toBe(
      true
    )
    expect(isTrafficReadingStale(now - 120_000, now)).toBe(true)
  })

  test("the boundary itself is not stale", () => {
    expect(isTrafficReadingStale(now - TRAFFIC_STALE_AFTER_MS, now)).toBe(false)
  })

  test("a missing timestamp is not an accusation of staleness", () => {
    // An older daemon simply does not report the per-interface instant, and
    // calling that stale would be a claim we cannot support.
    expect(isTrafficReadingStale(undefined, now)).toBe(false)
  })

  test("the threshold clears the slowest cadence by a wide margin", () => {
    // Guards the coupling itself: raising the daemon's backoff ceiling without
    // revisiting this constant would start marking healthy links stale.
    expect(TRAFFIC_STALE_AFTER_MS).toBeGreaterThan(10_000)
    expect(TRAFFIC_STALE_AFTER_MS).toBeGreaterThan(15_000)
  })
})
