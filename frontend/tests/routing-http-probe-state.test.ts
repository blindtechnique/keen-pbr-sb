import { describe, expect, spyOn, test } from "bun:test"
import { MutationObserver, QueryClient } from "@tanstack/react-query"

import { getPostRoutingTestMutationOptions } from "../src/api/generated/keen-api"
import type {
  RoutingTestHttpProbe,
  RoutingTestResponse,
} from "../src/api/generated/model"
import {
  routingHttpProbeMutationOptions,
  routingHttpProbeState,
} from "../src/components/overview/routing-http-probe-state"

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((accept, refuse) => {
    resolve = accept
    reject = refuse
  })
  return { promise, resolve, reject }
}

function base(): RoutingTestResponse {
  return {
    target: "example.com",
    is_domain: true,
    config_scope: "active",
    unapplied_draft: false,
    resolved_ips: ["192.0.2.1"],
    warnings: [],
    no_matching_rule: false,
    rule_diagnostics: [],
    results: [
      {
        ip: "192.0.2.1",
        expected_outbound: "vpn",
        actual_outbound: "vpn",
        ok: true,
        evaluation: "matched",
        unknown_conditions: [],
        kernel_route: {
          route_status: "resolved",
          interface: "old-iface",
          detail: "",
          fwmark: 0x40000,
          table: 152,
        },
      },
    ],
  }
}

function probe(ip = "192.0.2.1"): RoutingTestHttpProbe {
  return {
    status: "answered",
    reason: "http_response",
    ip,
    url: "https://example.com/",
    interface: "fresh-iface",
    method: "HEAD",
    scope: "router",
    attempted_at: 1700000004,
    http_status: 403,
    fwmark: 0x50000,
    table: 153,
  }
}

function observerFixture() {
  const client = new QueryClient({
    defaultOptions: { mutations: { retry: 5, gcTime: Infinity } },
  })
  const observer = new MutationObserver(
    client,
    getPostRoutingTestMutationOptions(routingHttpProbeMutationOptions)
  )
  const unsubscribe = observer.subscribe(() => undefined)
  return {
    observer,
    dispose() {
      unsubscribe()
      client.clear()
    },
  }
}

describe("manual routing HTTP probe state", () => {
  test("sends exactly one explicit IP probe and retains the base snapshot while pending and after a fresh response", async () => {
    const state = observerFixture()
    const pending = deferred<Response>()
    const started = deferred<void>()
    const calls: unknown[] = []
    const fetch = spyOn(globalThis, "fetch").mockImplementation(
      async (_url, options) => {
        calls.push(JSON.parse(String(options?.body)))
        started.resolve()
        return pending.promise
      }
    )
    const current = base()
    const original = JSON.stringify(current)
    try {
      expect(
        routingHttpProbeState(current, null, state.observer.getCurrentResult())
      ).toEqual({})
      expect(calls).toEqual([])
      const request = state.observer.mutate({
        data: { target: current.target, http_probe_ip: current.results[0].ip },
      })
      await started.promise
      expect(
        routingHttpProbeState(
          current,
          current,
          state.observer.getCurrentResult()
        )
      ).toEqual({ httpPendingIp: "192.0.2.1" })
      pending.resolve(Response.json({ ...current, http_probe: probe() }))
      await request
      expect(
        routingHttpProbeState(
          current,
          current,
          state.observer.getCurrentResult()
        )
      ).toEqual({ httpProbe: probe() })
      expect(calls).toEqual([
        { target: "example.com", http_probe_ip: "192.0.2.1" },
      ])
      expect(JSON.stringify(current)).toBe(original)
    } finally {
      fetch.mockRestore()
      state.dispose()
    }
  })

  test("a changed base hides pending and completed evidence even for the identical domain", async () => {
    const state = observerFixture()
    const pending = deferred<Response>()
    const started = deferred<void>()
    const fetch = spyOn(globalThis, "fetch").mockImplementation(async () => {
      started.resolve()
      return pending.promise
    })
    const oldBase = base()
    const newBase = base()
    try {
      const request = state.observer.mutate({
        data: { target: oldBase.target, http_probe_ip: "192.0.2.1" },
      })
      await started.promise
      expect(
        routingHttpProbeState(
          newBase,
          oldBase,
          state.observer.getCurrentResult()
        )
      ).toEqual({})
      pending.resolve(Response.json({ ...oldBase, http_probe: probe() }))
      await request
      expect(
        routingHttpProbeState(
          newBase,
          oldBase,
          state.observer.getCurrentResult()
        )
      ).toEqual({})
      expect(
        routingHttpProbeState(
          undefined,
          oldBase,
          state.observer.getCurrentResult()
        )
      ).toEqual({})
    } finally {
      fetch.mockRestore()
      state.dispose()
    }
  })

  for (const oldResult of ["success", "error"] as const) {
    test(`reset detaches an old ${oldResult} after the next manual probe completes`, async () => {
      const state = observerFixture()
      const old = deferred<Response>()
      const started = deferred<void>()
      let calls = 0
      const nextBase = base()
      const fetch = spyOn(globalThis, "fetch").mockImplementation(async () => {
        calls += 1
        if (calls === 1) {
          started.resolve()
          return old.promise
        }
        return Response.json({
          ...nextBase,
          http_probe: { ...probe(), http_status: 405 },
        })
      })
      try {
        const oldRequest = state.observer
          .mutate({
            data: { target: "example.com", http_probe_ip: "192.0.2.1" },
          })
          .catch((error: unknown) => error)
        await started.promise
        state.observer.reset()
        expect(
          routingHttpProbeState(
            nextBase,
            null,
            state.observer.getCurrentResult()
          )
        ).toEqual({})
        await state.observer.mutate({
          data: { target: nextBase.target, http_probe_ip: "192.0.2.1" },
        })
        if (oldResult === "success")
          old.resolve(Response.json({ ...base(), http_probe: probe() }))
        else old.reject(new Error("old transfer failed"))
        await oldRequest
        await Promise.resolve()
        expect(
          routingHttpProbeState(
            nextBase,
            nextBase,
            state.observer.getCurrentResult()
          )
        ).toEqual({ httpProbe: { ...probe(), http_status: 405 } })
        expect(calls).toBe(2)
      } finally {
        fetch.mockRestore()
        state.dispose()
      }
    })
  }

  test("request failures are local to the selected IP and do not inherit automatic retries", async () => {
    const state = observerFixture()
    const current = base()
    const fetch = spyOn(globalThis, "fetch").mockRejectedValue(
      new Error("network failed")
    )
    try {
      await state.observer
        .mutate({
          data: { target: current.target, http_probe_ip: "192.0.2.1" },
        })
        .catch(() => undefined)
      expect(fetch).toHaveBeenCalledTimes(1)
      expect(
        routingHttpProbeState(
          current,
          current,
          state.observer.getCurrentResult()
        )
      ).toEqual({ httpError: { ip: "192.0.2.1" } })
      expect(current.results).toHaveLength(1)
    } finally {
      fetch.mockRestore()
      state.dispose()
    }
  })

  test("accepts equivalent IPv6 literals but still rejects a different canonical destination", () => {
    const current = base()
    current.target = "2001:DB8:0:0::8"
    current.is_domain = false
    current.results[0].ip = current.target
    for (const [ip, accepted] of [
      ["2001:db8::8", true],
      ["2001:db8::9", false],
    ] as const) {
      const result = probe(ip)
      expect(
        routingHttpProbeState(current, current, {
          status: "success",
          variables: {
            data: { target: current.target, http_probe_ip: current.target },
          },
          data: {
            data: { ...current, http_probe: result },
            status: 200,
            headers: new Headers(),
          },
        })
      ).toEqual(
        accepted ? { httpProbe: result } : { httpError: { ip: current.target } }
      )
    }
  })

  test("a legacy response or mismatched result cannot be presented as the requested route probe", async () => {
    const current = base()
    for (const response of [
      current,
      { ...current, http_probe: probe("192.0.2.2") },
      { ...current, target: "other.example", http_probe: probe() },
    ]) {
      expect(
        routingHttpProbeState(current, current, {
          status: "success",
          variables: {
            data: { target: current.target, http_probe_ip: "192.0.2.1" },
          },
          data: { data: response, status: 200, headers: new Headers() },
        })
      ).toEqual({ httpError: { ip: "192.0.2.1" } })
    }
  })
})
