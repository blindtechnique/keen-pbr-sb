import { describe, expect, test } from "bun:test"

import {
  firstMeaningfulLine,
  parseServiceCommandResult,
  ServiceRestartFailure,
} from "../src/lib/service-restart-result"

describe("service restart result", () => {
  test("a successful command is reported as successful", () => {
    const result = parseServiceCommandResult({
      ok: true,
      output: "Starting nfqws2... done\n",
      status: 0,
    })

    expect(result.ok).toBe(true)
    expect(result.exitCode).toBe(0)
    expect(result.output).toContain("done")
  })

  test("a failed init script is a failure even though HTTP was 200", () => {
    // This is the whole point: the endpoint answers 200 either way, so a
    // client that only checks the HTTP status congratulates the user on a
    // restart that never happened.
    const result = parseServiceCommandResult({
      ok: false,
      output: "nfqws2: config error on line 3\n",
      status: 1,
    })

    expect(result.ok).toBe(false)
    expect(result.exitCode).toBe(1)
  })

  test("anything other than a literal true is treated as failure", () => {
    // Fail closed. A truthy string or a missing field means we do not know
    // that the service came back, and that is not the same as knowing it did.
    expect(parseServiceCommandResult({ ok: "true" }).ok).toBe(false)
    expect(parseServiceCommandResult({ ok: 1 }).ok).toBe(false)
    expect(parseServiceCommandResult({ output: "done" }).ok).toBe(false)
    expect(parseServiceCommandResult({}).ok).toBe(false)
  })

  test("a body that is not an object at all is a failure, not a crash", () => {
    expect(parseServiceCommandResult(null).ok).toBe(false)
    expect(parseServiceCommandResult(undefined).ok).toBe(false)
    expect(parseServiceCommandResult("ok").ok).toBe(false)
    expect(parseServiceCommandResult([1, 2]).ok).toBe(false)
  })

  test("a non-numeric status is dropped rather than coerced", () => {
    expect(parseServiceCommandResult({ ok: true, status: "0" }).exitCode).toBe(
      undefined
    )
    expect(
      parseServiceCommandResult({ ok: true, status: Number.NaN }).exitCode
    ).toBe(undefined)
  })

  test("a missing output becomes an empty string, never undefined", () => {
    expect(parseServiceCommandResult({ ok: true }).output).toBe("")
    expect(parseServiceCommandResult({ ok: true, output: 42 }).output).toBe("")
  })

  test("the failure carries the output for the notice", () => {
    const failure = new ServiceRestartFailure({
      ok: false,
      output: "\n\n  nfqws2: address already in use\nmore detail\n",
      exitCode: 1,
    })

    expect(failure.message).toBe("nfqws2: address already in use")
    expect(failure.result.exitCode).toBe(1)
  })

  test("a failure with no output still produces a usable message", () => {
    const failure = new ServiceRestartFailure({
      ok: false,
      output: "   \n\n",
      exitCode: undefined,
    })

    expect(failure.message).toBe("service restart failed")
  })

  test("blank and padded lines are skipped when picking a notice line", () => {
    expect(firstMeaningfulLine("\n \n\treal line\nsecond")).toBe("real line")
    expect(firstMeaningfulLine("")).toBe("")
  })
})
