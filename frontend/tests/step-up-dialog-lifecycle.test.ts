import { afterEach, describe, expect, mock, test } from "bun:test"
import type { AuthStatus } from "../src/lib/auth-status"
import {
  fetchWithStepUp,
  resetStepUpState,
  setStepUpPrompt,
  stepUpAuthorityKey,
  StepUpNotAdmittedError,
} from "../src/lib/step-up"

afterEach(resetStepUpState)
const status: AuthStatus = {
  enabled: true,
  authenticated: true,
  provider: "keenetic",
  trustedLocalConnection: true,
  trustedLocalConnectionGeneration: "7",
  trustedLocalConnectionValidUntilMs: 10_000,
  noAuthScope: null,
  networkApiBlocked: false,
}
const refusal = () =>
  new Response(JSON.stringify({ error: "step_up_required" }), { status: 403 })

describe("step-up prompt authority and operation admission", () => {
  test("equivalent auth refresh/renewed TTL keeps the prompt registration identity", () => {
    expect(stepUpAuthorityKey(status, 1_000, false)).toBe(
      stepUpAuthorityKey(
        {
          ...status,
          trustedLocalConnectionValidUntilMs: 20_000,
        },
        2_000,
        false
      )
    )
    expect(
      stepUpAuthorityKey(
        { ...status, trustedLocalConnectionGeneration: "8" },
        1_000,
        false
      )
    ).not.toBe(stepUpAuthorityKey(status, 1_000, false))
  })
  test("session, transport and provider revocation invalidates step-up without weakening login collection", () => {
    for (const changed of [
      { ...status, authenticated: false },
      { ...status, enabled: false },
      { ...status, trustedLocalConnection: false },
      { ...status, error: "unavailable" },
      { ...status, provider: null },
    ])
      expect(stepUpAuthorityKey(changed, 1_000, false)).toBeNull()
    expect(stepUpAuthorityKey(status, 10_000, false)).toBeNull()
    expect(
      stepUpAuthorityKey(
        { ...status, provider: "local", authenticated: false },
        1_000,
        false
      )
    ).toBeNull()
  })
  test("normal signed update makes one request and never opens a password prompt", async () => {
    const prompt = mock(async () => ({ username: "admin", password: "secret" }))
    setStepUpPrompt(prompt)
    const request = mock(
      async () => new Response(JSON.stringify({ ok: true, started: true }))
    )
    const response = await fetchWithStepUp(
      "/api/system/update",
      { method: "POST" },
      request as unknown as typeof fetch
    )
    expect(response.ok).toBe(true)
    expect(request).toHaveBeenCalledTimes(1)
    expect(prompt).not.toHaveBeenCalled()
  })
  test("old backend/rollback step-up runs only one replay after a successful grant", async () => {
    const urls: string[] = []
    setStepUpPrompt(async () => ({ username: "admin", password: "secret" }))
    const request = (async (url: string) => {
      urls.push(url)
      return urls.length === 1 ? refusal() : new Response("{}")
    }) as typeof fetch
    await fetchWithStepUp(
      "/api/system/update/rollback",
      { method: "POST" },
      request
    )
    expect(urls).toEqual([
      "/api/system/update/rollback",
      "/api/auth/step-up",
      "/api/system/update/rollback",
    ])
  })
  test("cancelling the prompt never sends the operation again", async () => {
    setStepUpPrompt(async () => null)
    const request = mock(async () => refusal())
    expect(
      (
        await fetchWithStepUp(
          "/api/system/update/rollback",
          { method: "POST" },
          request as unknown as typeof fetch
        )
      ).status
    ).toBe(403)
    expect(request).toHaveBeenCalledTimes(1)
  })
  test("a failed grant is definitely not an admitted update, while a lost operation response is ambiguous", async () => {
    setStepUpPrompt(async () => ({ username: "admin", password: "secret" }))
    let calls = 0
    const request = (async () => {
      calls += 1
      if (calls === 1) return refusal()
      throw new TypeError("Failed to fetch")
    }) as typeof fetch
    const result = await fetchWithStepUp(
      "/api/system/update/rollback",
      { method: "POST" },
      request
    ).catch((error) => error)
    expect(result).toBeInstanceOf(StepUpNotAdmittedError)
    expect(result.requestNotAdmitted).toBe(true)
    expect(calls).toBe(2)
    const ambiguous = await fetchWithStepUp(
      "/api/system/update",
      { method: "POST" },
      (async () => {
        throw new TypeError("Failed to fetch")
      }) as typeof fetch
    ).catch((error) => error)
    expect(ambiguous).not.toBeInstanceOf(StepUpNotAdmittedError)
  })
  test("unrelated 401/403 are not intercepted or retried", async () => {
    const prompt = mock(async () => ({ username: "admin", password: "secret" }))
    setStepUpPrompt(prompt)
    for (const status of [401, 403]) {
      const request = mock(
        async () =>
          new Response(JSON.stringify({ error: "forbidden" }), { status })
      )
      expect(
        (
          await fetchWithStepUp(
            "/api/config",
            {},
            request as unknown as typeof fetch
          )
        ).status
      ).toBe(status)
      expect(request).toHaveBeenCalledTimes(1)
    }
    expect(prompt).not.toHaveBeenCalled()
  })
})
