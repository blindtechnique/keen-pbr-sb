import { describe, expect, test } from "bun:test"

import {
  countUnicodeCodePoints,
  validateDisplayName,
} from "../src/lib/display-name-validation"

describe("display name validation", () => {
  test("counts Unicode code points rather than UTF-16 units", () => {
    expect(countUnicodeCodePoints("🚀".repeat(80))).toBe(80)
    expect(validateDisplayName("🚀".repeat(80))).toBeUndefined()
    expect(validateDisplayName("🚀".repeat(81))).toBe("too-long")
  })

  test("accepts emoji joiners but rejects controls and bidi overrides", () => {
    expect(validateDisplayName("Семья 👨‍👩‍👦")).toBeUndefined()
    expect(validateDisplayName("safe\u202etxt.exe")).toBe("control")
    expect(validateDisplayName("VPN\u0085")).toBe("control")
  })

  test("rejects blank and malformed Unicode values", () => {
    expect(validateDisplayName("\u00a0\u3000")).toBe("whitespace-only")
    expect(validateDisplayName("\ud800")).toBe("invalid-unicode")
  })
})
