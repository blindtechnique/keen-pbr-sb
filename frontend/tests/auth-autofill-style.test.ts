import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"

const stylesheet = readFileSync(
  new URL("../src/index.css", import.meta.url),
  "utf8"
)

describe("login autofill surface", () => {
  test("overrides Chromium autofill in every interactive state", () => {
    for (const selector of [
      ".keen-auth-input:-webkit-autofill",
      ".keen-auth-input:-webkit-autofill:hover",
      ".keen-auth-input:-webkit-autofill:focus",
      ".keen-auth-input:-webkit-autofill:active",
    ]) {
      expect(stylesheet).toContain(selector)
    }
    expect(stylesheet).toContain(
      "-webkit-box-shadow: 0 0 0 1000px var(--card) inset !important"
    )
    expect(stylesheet).toContain(
      "box-shadow: 0 0 0 1000px var(--card) inset !important"
    )
    expect(stylesheet).toContain(
      "-webkit-text-fill-color: var(--foreground) !important"
    )
  })
})
