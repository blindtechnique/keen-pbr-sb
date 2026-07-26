import { describe, expect, test } from "bun:test"

import { parseAuthStatus } from "../src/lib/auth-status"

describe("authentication status contract", () => {
  test("accepts only the explicit boolean contract", () => {
    expect(
      parseAuthStatus({ enabled: true, authenticated: false })
    ).toEqual({ enabled: true, authenticated: false })
    expect(
      parseAuthStatus({ enabled: false, authenticated: true })
    ).toEqual({ enabled: false, authenticated: true })
  })

  test("rejects malformed and truthy lookalike responses", () => {
    expect(parseAuthStatus(null)).toBeNull()
    expect(parseAuthStatus({})).toBeNull()
    expect(
      parseAuthStatus({ enabled: "false", authenticated: 1 })
    ).toBeNull()
  })
})
