import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"

import { createDnsCheckStreamObservation } from "../src/hooks/use-dns-check"

describe("DNS check shared-stream observation", () => {
  test("does not begin the probe before the shared stream connects", () => {
    const observation = createDnsCheckStreamObservation()
    expect(observation.observe("connecting")).toBe(false)
    expect(observation.observe("disconnected")).toBe(false)
    expect(observation.observe("paused")).toBe(false)
    expect(observation.interrupted).toBe(false)
    expect(observation.timeout(true)).toEqual({
      status: "sse-fail",
      showWarning: false,
    })
    expect(observation.timeout(false)).toEqual({
      status: "sse-fail",
      showWarning: false,
    })
  })

  test("starts once and allows an unobserved-browser outcome only with coverage", () => {
    const observation = createDnsCheckStreamObservation()
    expect(observation.observe("connecting")).toBe(false)
    expect(observation.observe("connected")).toBe(true)
    expect(observation.interrupted).toBe(false)
    expect(observation.observe("connected")).toBe(false)
    expect(observation.timeout(true)).toEqual({
      status: "browser-fail",
      showWarning: false,
    })
  })

  for (const interruptedState of [
    "disconnected",
    "connecting",
    "paused",
  ] as const) {
    test(`does not mistake ${interruptedState} for an absent DNS request`, () => {
      const observation = createDnsCheckStreamObservation()
      expect(observation.observe("connected")).toBe(true)
      expect(observation.observe(interruptedState)).toBe(false)
      expect(observation.interrupted).toBe(true)
      expect(observation.timeout(true)).toEqual({
        status: "sse-fail",
        showWarning: false,
      })
      // Reconnects do not replay missed events and must not launch a new fetch.
      expect(observation.observe("connected")).toBe(false)
      expect(observation.interrupted).toBe(true)
      expect(observation.timeout(true)).toEqual({
        status: "sse-fail",
        showWarning: false,
      })
      expect(observation.timeout(false)).toEqual({
        status: "sse-fail",
        showWarning: false,
      })
    })
  }

  test("finishes a manual timeout instead of leaving the check running", () => {
    const observation = createDnsCheckStreamObservation()
    observation.observe("connected")
    expect(observation.timeout(false)).toEqual({
      status: "idle",
      showWarning: true,
    })
  })

  test("keeps separate user-requested checks independent", () => {
    const previous = createDnsCheckStreamObservation()
    previous.observe("connected")
    previous.observe("disconnected")
    const next = createDnsCheckStreamObservation()
    expect(next.observe("connected")).toBe(true)
    expect(next.timeout(true).status).toBe("browser-fail")
    expect(previous.timeout(true).status).toBe("sse-fail")
  })
})

describe("DNS check hook lifecycle wiring", () => {
  const source = readFileSync(
    new URL("../src/hooks/use-dns-check.ts", import.meta.url),
    "utf8"
  )

  test("keeps connection observation until cleanup and clears waiting on timeout", () => {
    const begin = source.slice(
      source.indexOf("const beginCheckWhenConnected"),
      source.indexOf("subscribeStatusEventConnectionState(beginCheckWhenConnected)")
    )
    expect(begin).not.toContain("connectionSubscriptionRef.current?.()")
    expect(begin).toContain("streamObservation.observe(")
    expect(begin).toContain("getStatusEventConnectionState()")
    expect(begin).toContain("if (streamObservation.interrupted)")
    expect(begin).toContain("finishWithoutProbe()")
    expect(begin.indexOf("finishWithoutProbe()")).toBeLessThan(
      begin.indexOf("if (!shouldBegin)")
    )
    const timeout = source.slice(
      source.indexOf("const finishWithoutProbe"),
      source.indexOf("dnsSubscriptionRef.current = subscribeDnsProbeEvents")
    )
    expect(timeout).toContain("cleanup()")
    expect(timeout).toContain("setStatus(outcome.status)")
    expect(timeout).toContain("waiting: false")
    expect(timeout).toContain("showWarning: outcome.showWarning")
    const cleanup = source.slice(
      source.indexOf("const cleanup = useCallback"),
      source.indexOf("useEffect(() => cleanup")
    )
    expect(cleanup).toContain("connectionSubscriptionRef.current?.()")
    expect(cleanup).toContain("dnsSubscriptionRef.current?.()")
    expect(cleanup).toContain("keepAliveLeaseRef.current?.()")
    expect(cleanup).toContain("fetchControllerRef.current.abort()")
    expect(cleanup).toContain("window.clearTimeout(checkTimeoutRef.current)")
    expect(cleanup).toContain("window.clearTimeout(warningTimeoutRef.current)")
  })

  test("retains the existing probe, timing, and positive nonce evidence", () => {
    expect(source.match(/fetch\(`/g)).toHaveLength(1)
    expect(source).toContain("const browserCheckTimeoutMs = 5_000")
    expect(source).toContain("const sseConnectionTimeoutMs = 12_000")
    expect(source).toContain("const pcCheckTimeoutMs = 300_000")
    expect(source).toContain("const pcWarningTimeoutMs = 30_000")
    expect(source).toContain("if (payload.domain !== domain) return")
    expect(source).toContain(
      'setStatus(performBrowserRequest ? "success" : "pc-success")'
    )
    expect(source).not.toContain("new EventSource")
    expect(source).not.toContain("setInterval")
  })
})
