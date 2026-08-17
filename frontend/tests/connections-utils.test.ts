import { describe, expect, it } from "bun:test"

import { formatLastSeen } from "../src/pages/connections-utils"

const t = (key: string, options?: Record<string, unknown>) =>
  options?.count === undefined ? key : `${key}:${String(options.count)}`

describe("formatLastSeen", () => {
  it("uses the backend snapshot rather than the browser clock", () => {
    expect(formatLastSeen(990, 1_000, t)).toBe("connections.age.seconds:10")
    expect(formatLastSeen(940, 1_000, t)).toBe("connections.age.minutes:1")
    expect(formatLastSeen(1_000, 4_600, t)).toBe("connections.age.hours:1")
  })

  it("handles clock skew and incomplete timestamps without negative ages", () => {
    expect(formatLastSeen(1_010, 1_000, t)).toBe("connections.age.now")
    expect(formatLastSeen(0, 1_000, t)).toBe("")
    expect(formatLastSeen(1_000, 0, t)).toBe("")
  })
})
