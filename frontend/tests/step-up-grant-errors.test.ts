import { afterEach, describe, expect, test } from "bun:test"

import {
  fetchWithStepUp,
  resetStepUpState,
  setStepUpPrompt,
} from "../src/lib/step-up"

afterEach(resetStepUpState)

const required = () =>
  new Response(JSON.stringify({ error: "step_up_required" }), { status: 403 })

describe("step-up grant refusals preserve the real HTTP cause", () => {
  test.each([
    [401, "invalid_credentials"],
    [403, "protected_secret_transport_unavailable"],
    [503, "provider_unavailable"],
  ] as const)(
    "returns grant HTTP %s without repeating the operation",
    async (status, error) => {
      setStepUpPrompt(async () => ({ username: "admin", password: "fixture" }))
      const calls: string[] = []
      const fetchImpl = (async (input) => {
        const url = String(input)
        calls.push(url)
        return url === "/api/auth/step-up"
          ? new Response(JSON.stringify({ error, detail: "original reason" }), {
              status,
              headers: {
                "Cache-Control": "no-store",
                "X-Grant-Result": "refused",
              },
            })
          : required()
      }) as typeof fetch
      const response = await fetchWithStepUp(
        "/api/backup",
        { method: "POST" },
        fetchImpl
      )
      expect(response.status).toBe(status)
      expect(response.headers.get("Cache-Control")).toBe("no-store")
      expect(response.headers.get("X-Grant-Result")).toBe("refused")
      expect(await response.json()).toEqual({
        error,
        detail: "original reason",
      })
      expect(calls).toEqual(["/api/backup", "/api/auth/step-up"])
    }
  )

  test("concurrent callers receive independently readable copies of one grant refusal", async () => {
    let prompts = 0
    let grants = 0
    setStepUpPrompt(async () => {
      prompts++
      return { username: "admin", password: "fixture" }
    })
    const fetchImpl = (async (input) => {
      if (input !== "/api/auth/step-up") return required()
      grants++
      return new Response(JSON.stringify({ error: "invalid_credentials" }), {
        status: 401,
      })
    }) as typeof fetch
    const responses = await Promise.all([
      fetchWithStepUp("/api/backup", { method: "POST" }, fetchImpl),
      fetchWithStepUp("/api/backup/rollback", { method: "POST" }, fetchImpl),
    ])
    expect(prompts).toBe(1)
    expect(grants).toBe(1)
    expect(responses[0]).not.toBe(responses[1])
    for (const response of responses) {
      expect(response.status).toBe(401)
      expect(await response.json()).toEqual({ error: "invalid_credentials" })
    }
  })
})
