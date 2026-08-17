import { describe, expect, test } from "bun:test"

import {
  formatUptimeSeconds,
  formatUptimeSince,
} from "../src/lib/uptime-format"

// Renders the key and its interpolated values so a test asserts which branch
// was taken, not how a particular locale happens to word it.
const t = (key: string, options?: Record<string, unknown>): string =>
  options ? `${key}(${JSON.stringify(options)})` : key

describe("uptime formatting", () => {
  test("renders KeeneticOS's HH:MM:SS below a day", () => {
    // The format the firmware itself uses, so the two can sit side by side
    // without a reader wondering whether they mean the same thing.
    expect(formatUptimeSeconds(15 * 3_600 + 7 * 60 + 55, t)).toBe("15:07:55")
  })

  test("pads every component to two digits", () => {
    expect(formatUptimeSeconds(1 * 3_600 + 2 * 60 + 3, t)).toBe("01:02:03")
    expect(formatUptimeSeconds(0, t)).toBe("00:00:00")
    expect(formatUptimeSeconds(9, t)).toBe("00:00:09")
  })

  test("adds a day count past twenty-four hours", () => {
    const seconds = 3 * 86_400 + 4 * 3_600 + 5 * 60 + 6
    expect(formatUptimeSeconds(seconds, t)).toBe(
      'common.uptime.withDays({"days":3,"clock":"04:05:06"})'
    )
  })

  test("the clock restarts at each day boundary", () => {
    expect(formatUptimeSeconds(86_399, t)).toBe("23:59:59")
    expect(formatUptimeSeconds(86_400, t)).toBe(
      'common.uptime.withDays({"days":1,"clock":"00:00:00"})'
    )
  })

  test("an absent anchor is unknown, never another uptime", () => {
    // The backend omits the field when it has no confirmed transition. This is
    // the case roadmap item 2 is explicitly about: anything other than
    // "unknown" here would be some other clock wearing an interface label.
    expect(formatUptimeSince(undefined, t, 0)).toBe("common.uptime.unknown")
    expect(formatUptimeSince(null, t, 0)).toBe("common.uptime.unknown")
  })

  test("a non-finite anchor is unknown rather than NaN", () => {
    expect(formatUptimeSince(Number.NaN, t, 0)).toBe("common.uptime.unknown")
  })

  test("derives elapsed time from the absolute anchor", () => {
    const now = 1_754_812_800_000
    const upSince = now - (2 * 86_400 + 3 * 3_600 + 4 * 60 + 5) * 1_000
    expect(formatUptimeSince(upSince, t, now)).toBe(
      'common.uptime.withDays({"days":2,"clock":"03:04:05"})'
    )
  })

  test("the same anchor grows as time passes rather than resetting", () => {
    const upSince = 1_754_812_800_000
    // A UI refresh does not change the anchor, only "now" - which is the whole
    // reason the backend publishes an instant instead of a duration.
    expect(formatUptimeSince(upSince, t, upSince + 600_000)).toBe("00:10:00")
    expect(formatUptimeSince(upSince, t, upSince + 4_200_000)).toBe("01:10:00")
  })

  test("an anchor in the future clamps to zero, never counts down", () => {
    const now = 1_754_812_800_000
    // The clocks can still disagree right after an NTP step, even with the
    // router-offset correction applied.
    expect(formatUptimeSince(now + 30_000, t, now)).toBe("00:00:00")
  })
})
