import { afterEach, describe, expect, mock, test } from "bun:test"

import {
  isReplayable,
  isStepUpRequired,
  requestStepUpGrant,
  resetStepUpState,
  setStepUpPrompt,
} from "./step-up"

afterEach(() => {
  resetStepUpState()
})

const okResponse = () => ({ ok: true }) as Response
const failedResponse = () => ({ ok: false }) as Response
const credentials = () => ({ username: "admin", password: "secret" })

describe("isStepUpRequired", () => {
  test("recognises the machine-readable code the server sends", () => {
    expect(isStepUpRequired(403, { error: "step_up_required" })).toBe(true)
  })

  test("ignores a forbidden response that means something else", () => {
    // Opening a password prompt for an unrelated refusal teaches the user to
    // type the password without reading the prompt.
    expect(isStepUpRequired(403, { error: "forbidden" })).toBe(false)
    expect(isStepUpRequired(403, {})).toBe(false)
    expect(isStepUpRequired(403, null)).toBe(false)
    expect(isStepUpRequired(403, "step_up_required")).toBe(false)
  })

  test("ignores the code on any other status", () => {
    expect(isStepUpRequired(401, { error: "step_up_required" })).toBe(false)
    expect(isStepUpRequired(200, { error: "step_up_required" })).toBe(false)
  })
})

describe("isReplayable", () => {
  test("accepts bodies that can be sent twice", () => {
    expect(isReplayable(null)).toBe(true)
    expect(isReplayable(undefined)).toBe(true)
    expect(isReplayable(JSON.stringify({ enabled: true }))).toBe(true)
  })

  test("refuses a body the first attempt already consumed", () => {
    // Replaying a stream sends an empty body, and the server answers with a
    // confusing 400 instead of the real problem.
    const stream = new Blob([new Uint8Array([1])]).stream()
    expect(isReplayable(stream as unknown as BodyInit)).toBe(false)
    expect(isReplayable(new FormData())).toBe(false)
  })
})

describe("requestStepUpGrant", () => {
  test("returns false when no dialog is mounted", async () => {
    const fetchImpl = mock(() => Promise.resolve(okResponse()))

    // Before React mounts, and under test, there is no prompt. The request
    // must fail with the server's own error rather than wait on a dialog
    // nobody can see.
    expect(await requestStepUpGrant(fetchImpl)).toBe(false)
    expect(fetchImpl).toHaveBeenCalledTimes(0)
  })

  test("returns false and asks nothing when the user dismisses", async () => {
    const fetchImpl = mock(() => Promise.resolve(okResponse()))
    setStepUpPrompt(() => Promise.resolve(null))

    expect(await requestStepUpGrant(fetchImpl)).toBe(false)
    expect(fetchImpl).toHaveBeenCalledTimes(0)
  })

  test("posts the credentials and reports the verdict", async () => {
    const fetchImpl = mock(() => Promise.resolve(okResponse()))
    setStepUpPrompt(() => Promise.resolve(credentials()))

    expect(await requestStepUpGrant(fetchImpl)).toBe(true)
    expect(fetchImpl).toHaveBeenCalledTimes(1)

    const [url, init] = fetchImpl.mock.calls[0] as [string, RequestInit]
    expect(url).toBe("/api/auth/step-up")
    expect(init.method).toBe("POST")
    expect(JSON.parse(init.body as string)).toEqual(credentials())
  })

  test("reports a refused grant as false", async () => {
    const fetchImpl = mock(() => Promise.resolve(failedResponse()))
    setStepUpPrompt(() => Promise.resolve(credentials()))

    expect(await requestStepUpGrant(fetchImpl)).toBe(false)
  })

  test("prompts once when several requests need a grant together", async () => {
    const fetchImpl = mock(() => Promise.resolve(okResponse()))
    const prompt = mock(() => Promise.resolve(credentials()))
    setStepUpPrompt(prompt)

    const results = await Promise.all([
      requestStepUpGrant(fetchImpl),
      requestStepUpGrant(fetchImpl),
      requestStepUpGrant(fetchImpl),
    ])

    expect(results).toEqual([true, true, true])
    // Otherwise a page firing three privileged requests stacks three identical
    // dialogs, and answering the first leaves the user staring at the rest.
    expect(prompt).toHaveBeenCalledTimes(1)
    expect(fetchImpl).toHaveBeenCalledTimes(1)
  })

  test("asks again for a later request rather than reusing the verdict", async () => {
    const fetchImpl = mock(() => Promise.resolve(okResponse()))
    const prompt = mock(() => Promise.resolve(credentials()))
    setStepUpPrompt(prompt)

    await requestStepUpGrant(fetchImpl)
    await requestStepUpGrant(fetchImpl)

    // The single-flight collapses concurrent callers only. A stale verdict
    // answering a request made minutes later would outlive the grant it
    // reported on.
    expect(prompt).toHaveBeenCalledTimes(2)
  })

  test("clears its state when the grant request fails", async () => {
    const failing = mock(() => Promise.reject(new Error()))
    setStepUpPrompt(() => Promise.resolve(credentials()))

    expect(requestStepUpGrant(failing)).rejects.toThrow()
    await requestStepUpGrant(failing).catch(() => undefined)

    // A rejected promise left in the single-flight slot would answer every
    // later request with the same failure forever.
    const recovering = mock(() => Promise.resolve(okResponse()))
    expect(await requestStepUpGrant(recovering)).toBe(true)
  })
})
