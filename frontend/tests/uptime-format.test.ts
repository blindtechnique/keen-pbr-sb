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
  test("renders days, hours and minutes", () => {
    const seconds = 3 * 86_400 + 4 * 3_600 + 5 * 60 + 30
    expect(formatUptimeSeconds(seconds, t)).toBe(
      'common.uptime.days({"days":3,"hours":4,"minutes":5})'
    )
  })

  test("drops the day component below a day", () => {
    expect(formatUptimeSeconds(4 * 3_600 + 5 * 60, t)).toBe(
      'common.uptime.hours({"hours":4,"minutes":5})'
    )
  })

  test("drops the hour component below an hour", () => {
    expect(formatUptimeSeconds(7 * 60, t)).toBe(
      'common.uptime.minutes({"minutes":7})'
    )
  })

  test("collapses sub-minute durations", () => {
    expect(formatUptimeSeconds(59, t)).toBe("common.uptime.lessThanMinute")
    expect(formatUptimeSeconds(0, t)).toBe("common.uptime.lessThanMinute")
  })

  test("an absent anchor is unknown, never another uptime", () => {
    // The backend omits the field when it has no confirmed transition. This is
    // the case roadmap item 2 is explicitly about: anything other than
    // "unknown" here would be some other clock wearing an interface label.
    expect(formatUptimeSince(undefined, t)).toBe("common.uptime.unknown")
    expect(formatUptimeSince(null, t)).toBe("common.uptime.unknown")
  })

  test("a non-finite anchor is unknown rather than NaN", () => {
    expect(formatUptimeSince(Number.NaN, t)).toBe("common.uptime.unknown")
  })

  test("derives elapsed time from the absolute anchor", () => {
    const now = 1_754_812_800_000
    const upSince = now - (2 * 86_400 + 3 * 3_600 + 4 * 60) * 1_000
    expect(formatUptimeSince(upSince, t, now)).toBe(
      'common.uptime.days({"days":2,"hours":3,"minutes":4})'
    )
  })

  test("the same anchor grows as time passes rather than resetting", () => {
    const upSince = 1_754_812_800_000
    const after10m = formatUptimeSince(upSince, t, upSince + 600_000)
    const after70m = formatUptimeSince(upSince, t, upSince + 4_200_000)

    // A UI refresh does not change the anchor, only "now" - which is the whole
    // reason the backend publishes an instant instead of a duration.
    expect(after10m).toBe('common.uptime.minutes({"minutes":10})')
    expect(after70m).toBe('common.uptime.hours({"hours":1,"minutes":10})')
  })

  test("an anchor in the future reads as just now, not as negative", () => {
    const now = 1_754_812_800_000
    // The daemon's wall clock and the browser's can disagree after an NTP step.
    expect(formatUptimeSince(now + 30_000, t, now)).toBe(
      "common.uptime.lessThanMinute"
    )
  })
})
