import { describe, expect, test } from "bun:test"

import type { HealthResponse } from "../src/api/generated/model/healthResponse"
import type { RuntimeOutboundState } from "../src/api/generated/model/runtimeOutboundState"
import type { TransportStatus } from "../src/api/generated/model/transportStatus"
import { createRuntimeEventHistory } from "../src/components/overview/runtime-events-model"

const HASH_A = "a".repeat(32)
const HASH_B = "b".repeat(32)
function service(overrides: Partial<HealthResponse> = {}): HealthResponse {
  return {
    daemon_pid: 11,
    version: "3.3.0",
    build: "test",
    status: "running",
    runtime_state: "running",
    runtime_state_reason: "test",
    os_type: "keenetic",
    os_version: "5",
    build_variant: "keenetic",
    config_is_draft: false,
    resolver_live_status: "healthy",
    resolver_config_probe_status: "success",
    resolver_config_sync_state: "converged",
    resolver_config_hash: HASH_A,
    resolver_config_hash_actual: HASH_A,
    resolver_config_hash_actual_ts: 100,
    ...overrides,
  }
}
function route(
  overrides: Partial<RuntimeOutboundState> = {}
): RuntimeOutboundState {
  return {
    tag: "route",
    type: "interface",
    status: "healthy",
    interfaces: [{ outbound_tag: "route", status: "active" }],
    ...overrides,
  }
}
function group(
  active: string,
  status: RuntimeOutboundState["status"] = "healthy"
) {
  return route({
    tag: "group",
    type: "urltest",
    status,
    interfaces: [
      { outbound_tag: "one", status: active === "one" ? "active" : "backup" },
      { outbound_tag: "two", status: active === "two" ? "active" : "backup" },
    ],
  })
}
function transport(overrides: Partial<TransportStatus> = {}): TransportStatus {
  return {
    tag: "proxy",
    type: "sing-box",
    interface: "sb0",
    desired_up: true,
    state: "up",
    pid: 10,
    updated_at: "2026-09-06T10:00:00Z",
    ...overrides,
  }
}
const kinds = (history: ReturnType<typeof createRuntimeEventHistory>) =>
  history.getEvents().map((event) => event.kind)

describe("observed runtime event history", () => {
  test("initial healthy or failed snapshots are baselines, not events", () => {
    const history = createRuntimeEventHistory()
    history.observeService(service({ runtime_state: "broken" }), 1)
    history.observeOutbounds([route({ status: "unavailable" })], 1)
    history.observeTransports([transport({ state: "down" })], 1)
    expect(history.getEvents()).toEqual([])
  })

  test("ignores measurements, diagnostics, aliases and scheduling counters", () => {
    const history = createRuntimeEventHistory()
    history.observeService(service(), 1)
    history.observeOutbounds([group("one")], 1)
    history.observeTransports([transport()], 1)
    const first = history.getEvents()
    history.observeService(
      service({ resolver_last_probe_ts: 200, runtime_state_reason: "changed" }),
      2
    )
    const measured = group("one")
    measured.detail = "new detail"
    measured.interfaces[0].latency_ms = 42
    history.observeOutbounds([measured], 2)
    history.observeTransports(
      [
        transport({
          display_name: "new",
          retry_count: 349,
          updated_at: "2026-09-06T11:00:00Z",
        }),
      ],
      2
    )
    expect(history.getEvents()).toBe(first)
  })

  test("records only a confirmed active group member change", () => {
    const history = createRuntimeEventHistory()
    history.observeOutbounds([group("one")], 1)
    history.observeOutbounds([group("two")], 2)
    expect(history.getEvents()).toEqual([
      {
        id: "runtime:1",
        observedAt: 2,
        kind: "groupSwitched",
        tag: "group",
        from: "one",
        to: "two",
      },
    ])
    history.observeOutbounds([group("two")], 3)
    expect(history.getEvents()).toHaveLength(1)
  })

  test("keeps the last confirmed selection across observed route failure", () => {
    const history = createRuntimeEventHistory()
    history.observeOutbounds([group("one")], 1)
    history.observeOutbounds([group("", "degraded")], 2)
    history.observeOutbounds([group("two")], 3)
    expect(kinds(history)).toEqual([
      "routeRecovered",
      "groupSwitched",
      "routeDegraded",
    ])
  })

  test("unknown or multiple active members cannot fabricate a switch", () => {
    const history = createRuntimeEventHistory()
    history.observeOutbounds([group("one")], 1)
    history.observeOutbounds([group("two", "unknown")], 2)
    history.observeOutbounds([group("two")], 3)
    expect(history.getEvents()).toEqual([])
    const ambiguous = group("one")
    ambiguous.interfaces[1].status = "active"
    history.observeOutbounds([ambiguous], 4)
    history.observeOutbounds([group("one")], 5)
    expect(history.getEvents()).toEqual([])
  })

  test("group member order alone does not create a selection event", () => {
    const history = createRuntimeEventHistory()
    history.observeOutbounds([group("one")], 1)
    const reordered = group("one")
    reordered.interfaces.reverse()
    history.observeOutbounds([reordered], 2)
    expect(history.getEvents()).toEqual([])
  })

  test("distinguishes degraded path, total unavailability and recovery", () => {
    const history = createRuntimeEventHistory()
    history.observeOutbounds([route()], 1)
    history.observeOutbounds([route({ status: "degraded" })], 2)
    history.observeOutbounds([route({ status: "unavailable" })], 3)
    history.observeOutbounds([route()], 4)
    expect(kinds(history)).toEqual([
      "routeRecovered",
      "routeUnavailable",
      "routeDegraded",
    ])
  })

  test("ignores table, blackhole and ignore status changes", () => {
    const history = createRuntimeEventHistory()
    const types = ["table", "blackhole", "ignore"] as const
    history.observeOutbounds(
      types.map((type) => route({ type, tag: type })),
      1
    )
    history.observeOutbounds(
      types.map((type) => route({ type, tag: type, status: "unavailable" })),
      2
    )
    expect(history.getEvents()).toEqual([])
  })

  test("removed, readded or retyped routes establish fresh baselines", () => {
    const history = createRuntimeEventHistory()
    history.observeOutbounds([route()], 1)
    history.observeOutbounds([], 2)
    history.observeOutbounds([route({ status: "unavailable" })], 3)
    history.observeOutbounds([route({ type: "urltest" })], 4)
    expect(history.getEvents()).toEqual([])
  })

  test("tracks actual running to broken and applying to recovered transitions", () => {
    const history = createRuntimeEventHistory()
    history.observeService(service(), 1)
    history.observeService(service({ runtime_state: "broken" }), 2)
    history.observeService(service({ runtime_state: "applying" }), 3)
    history.observeService(service(), 4)
    expect(kinds(history)).toEqual(["runtimeRecovered", "runtimeFailed"])
  })

  test("routine apply and an explicit stop/start are not failure recovery", () => {
    const history = createRuntimeEventHistory()
    history.observeService(service(), 1)
    history.observeService(service({ runtime_state: "applying" }), 2)
    history.observeService(service(), 3)
    history.observeService(service({ runtime_state: "stopped" }), 4)
    history.observeService(service({ runtime_state: "starting" }), 5)
    history.observeService(service(), 6)
    expect(history.getEvents()).toEqual([])
  })

  test("a known daemon PID replacement is one service event, not DNS recovery", () => {
    const history = createRuntimeEventHistory()
    history.observeService(service({ runtime_state: "broken" }), 1)
    history.observeService(
      service({ daemon_pid: 12, resolver_config_hash_actual: HASH_B }),
      2
    )
    expect(kinds(history)).toEqual(["serviceRestarted"])
  })

  test("missing daemon PID is not a restart", () => {
    const history = createRuntimeEventHistory()
    history.observeService(service(), 1)
    history.observeService(service({ daemon_pid: undefined }), 2)
    history.observeService(service({ daemon_pid: 12 }), 3)
    expect(history.getEvents()).toEqual([])
  })

  test("expected DNS hash alone is not a DNS change; converged live hash is", () => {
    const history = createRuntimeEventHistory()
    history.observeService(service(), 1)
    history.observeService(
      service({
        resolver_config_hash: HASH_B,
        resolver_config_sync_state: "converging",
      }),
      2
    )
    expect(history.getEvents()).toEqual([])
    history.observeService(
      service({
        resolver_config_hash: HASH_B,
        resolver_config_hash_actual: HASH_B,
        resolver_config_hash_actual_ts: 101,
      }),
      3
    )
    expect(kinds(history)).toEqual(["dnsChanged"])
    expect(JSON.stringify(history.getEvents())).not.toContain(HASH_B)
  })

  test("invalid, unconfirmed and older live DNS hashes cannot create changes", () => {
    const history = createRuntimeEventHistory()
    history.observeService(service(), 1)
    history.observeService(
      service({ resolver_config_hash_actual: "not-a-hash" }),
      2
    )
    history.observeService(
      service({
        resolver_config_hash_actual: HASH_B,
        resolver_config_hash_actual_ts: 99,
      }),
      3
    )
    history.observeService(
      service({
        resolver_config_hash_actual: HASH_B,
        resolver_config_hash_actual_ts: undefined,
      }),
      4
    )
    history.observeService(
      service({
        resolver_config_hash_actual: HASH_B,
        resolver_config_sync_state: "converging",
      }),
      5
    )
    expect(history.getEvents()).toEqual([])
  })

  test.each(["missing_txt", "invalid_txt", "query_failed"] as const)(
    "records explicit DNS failure and recovery for %s",
    (probe) => {
      const history = createRuntimeEventHistory()
      history.observeService(service(), 1)
      history.observeService(
        service({
          resolver_config_probe_status: probe,
          resolver_live_status:
            probe === "query_failed" ? "unavailable" : "degraded",
          resolver_config_sync_state: undefined,
        }),
        2
      )
      history.observeService(service(), 3)
      expect(kinds(history)).toEqual(["dnsRecovered", "dnsProblem"])
    }
  )

  test("successful but stale DNS TXT is a synchronization problem", () => {
    const history = createRuntimeEventHistory()
    history.observeService(service(), 1)
    history.observeService(service({ resolver_config_sync_state: "stale" }), 2)
    expect(kinds(history)).toEqual(["dnsProblem"])
  })

  test("DNS not configured/unknown interrupts the baseline without recovery", () => {
    const history = createRuntimeEventHistory()
    history.observeService(service(), 1)
    history.observeService(
      service({
        resolver_config_probe_status: "not_configured",
        resolver_live_status: "unknown",
        resolver_config_sync_state: undefined,
      }),
      2
    )
    history.observeService(service({ resolver_config_hash_actual: HASH_B }), 3)
    expect(history.getEvents()).toEqual([])
  })

  test("transport running PID changes record a restart, including starting bridge", () => {
    const history = createRuntimeEventHistory()
    history.observeTransports([transport()], 1)
    history.observeTransports([transport({ pid: 20 })], 2)
    history.observeTransports(
      [transport({ state: "starting", pid: undefined })],
      3
    )
    history.observeTransports([transport({ pid: 30 })], 4)
    expect(kinds(history)).toEqual(["transportRestarted", "transportRestarted"])
  })

  test("transport starting alone and unknown PID are not restart evidence", () => {
    const history = createRuntimeEventHistory()
    history.observeTransports([transport()], 1)
    history.observeTransports([transport({ state: "starting" })], 2)
    history.observeTransports([transport()], 3)
    history.observeTransports([transport({ pid: undefined })], 4)
    history.observeTransports([transport({ pid: 30 })], 5)
    expect(history.getEvents()).toEqual([])
  })

  test("failed transport followed by starting/up reports recovery, not duplicate restart", () => {
    const history = createRuntimeEventHistory()
    history.observeTransports([transport()], 1)
    history.observeTransports(
      [transport({ state: "degraded", error: "private-body" })],
      2
    )
    history.observeTransports([transport({ state: "down" })], 3)
    history.observeTransports([transport({ state: "starting" })], 4)
    history.observeTransports([transport({ pid: 20 })], 5)
    expect(kinds(history)).toEqual([
      "transportRecovered",
      "transportUnavailable",
    ])
    expect(JSON.stringify(history.getEvents())).not.toContain("private-body")
  })

  test("disabled, missing and native transports do not fabricate process events", () => {
    const history = createRuntimeEventHistory()
    history.observeTransports([transport()], 1)
    history.observeTransports(
      [transport({ desired_up: false, state: "down" })],
      2
    )
    history.observeTransports([transport({ pid: 20 })], 3)
    history.observeTransports([], 4)
    history.observeTransports([transport({ pid: 30 })], 5)
    history.observeTransports([transport({ type: "native", state: "down" })], 6)
    history.observeTransports([transport({ type: "native", pid: 40 })], 7)
    expect(history.getEvents()).toEqual([])
  })

  test("source-specific reset preserves history and unrelated baselines", () => {
    const history = createRuntimeEventHistory()
    history.observeService(service(), 1)
    history.observeOutbounds([route()], 1)
    history.observeTransports([transport()], 1)
    history.observeOutbounds([route({ status: "unavailable" })], 2)
    const original = history.getEvents()
    history.resetBaseline("outbounds")
    history.observeOutbounds([route()], 3)
    expect(history.getEvents()).toBe(original)
    history.observeTransports([transport({ pid: 20 })], 4)
    expect(kinds(history)).toEqual(["transportRestarted", "routeUnavailable"])
    history.resetBaseline("all")
    history.observeService(service({ daemon_pid: 99 }), 5)
    history.observeOutbounds([route({ status: "unavailable" })], 5)
    history.observeTransports([transport({ pid: 99 })], 5)
    expect(history.getEvents()).toHaveLength(2)
  })

  test("keeps exactly 20 immutable newest-first events with unique sequence IDs", () => {
    const history = createRuntimeEventHistory()
    history.observeTransports([transport()], 0)
    for (let n = 1; n <= 25; n++)
      history.observeTransports([transport({ pid: 10 + n })], n)
    const events = history.getEvents()
    expect(events).toHaveLength(20)
    expect(events[0]).toMatchObject({ id: "runtime:25", observedAt: 25 })
    expect(events[19]).toMatchObject({ id: "runtime:6", observedAt: 6 })
    expect(new Set(events.map((event) => event.id)).size).toBe(20)
    expect(Object.isFrozen(events)).toBe(true)
    expect(Object.isFrozen(events[0])).toBe(true)
    history.resetBaseline("all")
    history.observeTransports([transport()], 26)
    history.observeTransports([transport({ pid: 40 })], 27)
    expect(history.getEvents()[0].id).toBe("runtime:26")
  })

  test("invalid observation time does not modify observations or history", () => {
    const history = createRuntimeEventHistory()
    history.observeTransports([transport()], 1)
    history.observeTransports([transport({ pid: 20 })], Number.NaN)
    history.observeTransports([transport()], 2)
    expect(history.getEvents()).toEqual([])
  })
})
