import { describe, expect, test } from "bun:test"

import {
  ManualProbeError,
  mergeManualProbeObservation,
  runManualInterfaceProbe,
  type InterfaceProbesResponse,
} from "@/lib/manual-interface-probe"

const probe = (id: string, latency = 31, success = true) => ({
  observation_id: id,
  interface: "nwg0",
  success,
  attributed: true,
  latency_ms: latency,
  age_seconds: 0,
})
const snapshot = (
  observations: InterfaceProbesResponse["probes"]
): InterfaceProbesResponse => ({ interval_seconds: 20, probes: observations })

function sequence(responses: unknown[]) {
  const requests: Array<{ url: string; init?: RequestInit }> = []
  const fetchImpl: typeof fetch = async (url, init) => {
    requests.push({ url: String(url), init })
    if (responses.length === 0) throw new Error("Unexpected extra request")
    return Response.json(responses.shift())
  }
  return { fetchImpl, requests }
}

describe("manual interface measurement", () => {
  test("late completion of one row preserves another row's newer result", () => {
    const lateA = snapshot({ a: probe("a2"), b: probe("b1") })
    const current = snapshot({ a: probe("a1"), b: probe("b2") })
    const merged = mergeManualProbeObservation(current, lateA, "a")
    expect(merged.probes.a.observation_id).toBe("a2")
    expect(merged.probes.b.observation_id).toBe("b2")
    expect(current.probes.a.observation_id).toBe("a1")
  })

  test("reads a fresh baseline before starting only the requested tag", async () => {
    const { fetchImpl, requests } = sequence([
      snapshot({ vpn: probe("90071992547409930") }),
      { ok: true, scheduled: true, tag: "vpn" },
      // Another interface changing, or this one's age changing, is not done.
      snapshot({ vpn: probe("90071992547409930"), other: probe("new") }),
      snapshot({ vpn: probe("90071992547409931") }),
    ])
    let sleeps = 0
    const result = await runManualInterfaceProbe("vpn", {
      signal: new AbortController().signal,
      fetch: fetchImpl,
      sleep: async () => {
        sleeps++
      },
    })
    expect(requests.map((request) => request.url)).toEqual([
      "/api/system/probes",
      "/api/system/probes/run",
      "/api/system/probes",
      "/api/system/probes",
    ])
    expect(requests[0].init?.cache).toBe("no-store")
    expect(JSON.parse(String(requests[1].init?.body))).toEqual({ tag: "vpn" })
    expect(sleeps).toBe(1)
    // Equal latency and age still complete: identity is opaque, not a Number.
    expect(result.probes.vpn).toEqual(probe("90071992547409931"))
  })

  test("a declined start stops without any completion poll or false success", async () => {
    const { fetchImpl, requests } = sequence([
      snapshot({ vpn: probe("1") }),
      { ok: true, scheduled: false, tag: "vpn" },
    ])
    await expect(
      runManualInterfaceProbe("vpn", {
        signal: new AbortController().signal,
        fetch: fetchImpl,
      })
    ).rejects.toMatchObject({ reason: "not_scheduled" })
    expect(requests).toHaveLength(2)
  })

  test("a new failed observation completes as failure instead of old latency", async () => {
    const { fetchImpl } = sequence([
      snapshot({ vpn: probe("1") }),
      { ok: true, scheduled: true, tag: "vpn" },
      snapshot({ vpn: probe("2", 0, false) }),
    ])
    const result = await runManualInterfaceProbe("vpn", {
      signal: new AbortController().signal,
      fetch: fetchImpl,
    })
    expect(result.probes.vpn.success).toBe(false)
    expect(result.probes.vpn.latency_ms).toBe(0)
  })

  test("a first observation works without a previously measured row", async () => {
    const { fetchImpl } = sequence([
      snapshot({}),
      { ok: true, scheduled: true, tag: "vpn" },
      snapshot({ vpn: probe("1") }),
    ])
    const result = await runManualInterfaceProbe("vpn", {
      signal: new AbortController().signal,
      fetch: fetchImpl,
    })
    expect(result.probes.vpn.observation_id).toBe("1")
  })

  test("unchanged or legacy observations time out without an unbounded poll", async () => {
    const old = { ...probe("1"), observation_id: undefined }
    const { fetchImpl, requests } = sequence([
      snapshot({ vpn: old }),
      { ok: true, scheduled: true, tag: "vpn" },
      snapshot({ vpn: old }),
      snapshot({ vpn: old }),
    ])
    let now = 0
    await expect(
      runManualInterfaceProbe("vpn", {
        signal: new AbortController().signal,
        fetch: fetchImpl,
        now: () => now,
        timeoutMs: 400,
        sleep: async (milliseconds) => {
          now += milliseconds
        },
      })
    ).rejects.toBeInstanceOf(ManualProbeError)
    expect(requests).toHaveLength(4)
  })

  test("unmount cancellation aborts an in-flight read and does not POST", async () => {
    const controller = new AbortController()
    let requests = 0
    const fetchImpl: typeof fetch = async (_url, options) => {
      requests++
      controller.abort()
      options?.signal?.throwIfAborted()
      return Response.json(snapshot({}))
    }
    await expect(
      runManualInterfaceProbe("vpn", {
        signal: controller.signal,
        fetch: fetchImpl,
      })
    ).rejects.toMatchObject({ name: "AbortError" })
    expect(requests).toBe(1)
  })

  test("a read error stops immediately rather than retrying indefinitely", async () => {
    let requests = 0
    const fetchImpl: typeof fetch = async () => {
      requests++
      return new Response("", { status: 503 })
    }
    await expect(
      runManualInterfaceProbe("vpn", {
        signal: new AbortController().signal,
        fetch: fetchImpl,
      })
    ).rejects.toThrow("HTTP 503")
    expect(requests).toBe(1)
  })
})
