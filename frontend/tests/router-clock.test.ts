import { beforeEach, describe, expect, test } from "bun:test"

import {
  hasRouterClockSample,
  noteRouterClock,
  resetRouterClock,
  routerNowMs,
} from "../src/api/router-clock"
import { isTrafficReadingStale } from "../src/components/transports/interface-traffic-model"

describe("router clock offset", () => {
  beforeEach(() => {
    resetRouterClock()
  })

  test("with no sample yet, the local clock is used unchanged", () => {
    // No evidence of disagreement means assuming none, which is the only
    // honest option before the first batch arrives.
    expect(hasRouterClockSample()).toBe(false)
    expect(routerNowMs(1_000)).toBe(1_000)
  })

  test("a router running behind is corrected for", () => {
    // Browser is at t=1_000_000; the router says it is t=400_000.
    noteRouterClock(400_000, 1_000_000)

    expect(hasRouterClockSample()).toBe(true)
    expect(routerNowMs(1_000_000)).toBe(400_000)
    // Time passes on the browser; the router's clock advances with it.
    expect(routerNowMs(1_005_000)).toBe(405_000)
  })

  test("a router running ahead is corrected for too", () => {
    noteRouterClock(9_000_000, 1_000_000)
    expect(routerNowMs(1_000_000)).toBe(9_000_000)
  })

  test("a nonsensical router timestamp is ignored", () => {
    noteRouterClock(0, 1_000_000)
    noteRouterClock(Number.NaN, 1_000_000)
    noteRouterClock(-5, 1_000_000)

    expect(hasRouterClockSample()).toBe(false)
    expect(routerNowMs(1_000)).toBe(1_000)
  })

  test("the newest sample wins", () => {
    noteRouterClock(400_000, 1_000_000)
    noteRouterClock(2_000_000, 1_010_000)
    expect(routerNowMs(1_010_000)).toBe(2_000_000)
  })
})

describe("staleness across disagreeing clocks", () => {
  beforeEach(() => {
    resetRouterClock()
  })

  test("a huge router/browser clock gap does not brand a live link stale", () => {
    // The Keenetic has no battery-backed RTC. Before NTP settles, its clock can
    // be years behind the browser's; comparing the two directly would report
    // every interface as stale for as long as that lasts.
    const browserNow = 1_754_812_800_000
    const routerNow = 1_600_000_000_000
    noteRouterClock(routerNow, browserNow)

    // A reading the router took two seconds ago, on the router's clock.
    expect(isTrafficReadingStale(routerNow - 2_000, routerNowMs(browserNow))).toBe(
      false
    )
  })

  test("a genuinely old reading is still stale despite the gap", () => {
    // The correction must not become a blanket excuse: a dead link has to stay
    // detectable whatever the clocks are doing.
    const browserNow = 1_754_812_800_000
    const routerNow = 1_600_000_000_000
    noteRouterClock(routerNow, browserNow)

    expect(
      isTrafficReadingStale(routerNow - 120_000, routerNowMs(browserNow))
    ).toBe(true)
  })
})
