import { describe, expect, spyOn, test } from "bun:test"

import { nfqwsAction } from "../src/api/nfqws"

function jsonResponse(value: unknown, status: number): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  })
}

describe("nfqws API errors", () => {
  test("shows bounded validator details instead of only the generic error", async () => {
    const validationErrors = Array.from({ length: 7 }, (_, index) => ({
      path: `NFQWS_BASE_ARGS/--lua-init-${index}`,
      message:
        index === 0
          ? "referenced file does not exist: /opt/etc/nfqws2/lua/zapret-lib.lua"
          : `${index}-${"x".repeat(600)}`,
    }))
    const fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse(
        {
          error: "The nfqws2 strategy candidate is invalid",
          validation_errors: validationErrors,
          saved: false,
          applied: false,
        },
        400
      )
    )

    try {
      const error = await nfqwsAction({ action: "apply_strategy" }).catch(
        (reason: unknown) => reason
      )
      expect(error).toBeInstanceOf(Error)
      const message = (error as Error).message
      expect(message).toContain(
        "NFQWS_BASE_ARGS/--lua-init-0: referenced file does not exist: /opt/etc/nfqws2/lua/zapret-lib.lua"
      )
      expect(message.split("\n")).toHaveLength(6)
      expect(message).not.toContain("--lua-init-5")
      expect(message).not.toContain("--lua-init-6")
      expect(message.length).toBeLessThan(3_000)
    } finally {
      fetchSpy.mockRestore()
    }
  })

  test("keeps the existing generic fallback without valid details", async () => {
    const fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse(
        {
          error: "The nfqws2 strategy candidate is invalid",
          validation_errors: [{ path: 1, message: null }],
        },
        400
      )
    )

    try {
      await expect(nfqwsAction({ action: "apply_strategy" })).rejects.toThrow(
        "The nfqws2 strategy candidate is invalid"
      )
    } finally {
      fetchSpy.mockRestore()
    }
  })
})
