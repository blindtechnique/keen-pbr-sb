import { describe, expect, test } from "bun:test"

import { semanticJsonEqual } from "../src/lib/semantic-json"
import {
  mapOutboundToDraft,
  normalizeOutboundDraftForPersistence,
  type OutboundDraft,
} from "../src/pages/outbound-upsert-utils"
import type { Outbound } from "../src/api/generated/model/outbound"

const baselineDraft = {
  displayName: "Основной VPN",
  tag: "vpn",
  type: "interface",
  interfaceName: "nwg1",
  gateway: "",
  gateway6: "",
  table: "",
  outboundGroups: [{ outbounds: [], weight: "" }],
  probeUrl: "https://www.gstatic.com/generate_204",
  interval: "180000",
  probeTimeout: "5000",
  tolerance: "100",
  selectionMode: "latency",
  conntrackOnSwitch: "preserve",
  retryAttempts: "3",
  retryInterval: "1000",
  circuitBreakerFailures: "5",
  circuitBreakerSuccesses: "2",
  circuitBreakerTimeout: "30000",
  circuitBreakerHalfOpen: "1",
  strictEnforcement: "default",
} satisfies OutboundDraft

describe("outbound editor persisted normalization", () => {
  test("round-trips a trimmed Unicode alias without changing the technical tag", () => {
    const outbound = {
      tag: "primary_vpn",
      display_name: "Основной VPN 🌐",
      type: "interface",
      interface: "nwg1",
    } satisfies Outbound

    const draft = mapOutboundToDraft(outbound)
    const persisted = normalizeOutboundDraftForPersistence({
      ...draft,
      displayName: "  Основной VPN 🌐  ",
    })

    expect(draft.displayName).toBe("Основной VPN 🌐")
    expect(persisted.tag).toBe("primary_vpn")
    expect(persisted.display_name).toBe("Основной VPN 🌐")
  })

  test("ignores whitespace and fields inactive for the selected type", () => {
    const baseline = normalizeOutboundDraftForPersistence(baselineDraft)
    const restored = normalizeOutboundDraftForPersistence({
      ...baselineDraft,
      tag: " vpn ",
      interfaceName: " nwg1 ",
      probeUrl: "https://example.invalid",
      interval: "1",
      outboundGroups: [{ outbounds: ["unused"], weight: "99" }],
    })

    expect(semanticJsonEqual(restored, baseline)).toBe(true)
  })

  test("normalizes equivalent table numbers", () => {
    const baseline = normalizeOutboundDraftForPersistence({
      ...baselineDraft,
      type: "table",
      table: "153",
    })
    const restored = normalizeOutboundDraftForPersistence({
      ...baselineDraft,
      type: "table",
      table: "0153",
    })

    expect(semanticJsonEqual(restored, baseline)).toBe(true)
  })

  test("keeps persisted changes and failover order significant", () => {
    const baseline = normalizeOutboundDraftForPersistence({
      ...baselineDraft,
      type: "urltest",
      outboundGroups: [
        { outbounds: ["primary"], weight: "1" },
        { outbounds: ["backup"], weight: "2" },
      ],
    })
    const reordered = normalizeOutboundDraftForPersistence({
      ...baselineDraft,
      type: "urltest",
      outboundGroups: [
        { outbounds: ["backup"], weight: "2" },
        { outbounds: ["primary"], weight: "1" },
      ],
    })

    expect(semanticJsonEqual(reordered, baseline)).toBe(false)
  })

  test("keeps latency as the compatible default and persists priority mode", () => {
    const latency = normalizeOutboundDraftForPersistence({
      ...baselineDraft,
      type: "urltest",
      outboundGroups: [
        { outbounds: ["primary"], weight: "" },
        { outbounds: ["backup"], weight: "" },
      ],
      selectionMode: "latency",
    })
    const priority = normalizeOutboundDraftForPersistence({
      ...baselineDraft,
      type: "urltest",
      outboundGroups: [
        { outbounds: ["primary"], weight: "" },
        { outbounds: ["backup"], weight: "" },
      ],
      selectionMode: "priority",
    })

    expect(latency.selection_mode).toBeUndefined()
    expect(priority.selection_mode).toBe("priority")
    expect(semanticJsonEqual(priority, latency)).toBe(false)
  })

  test("keeps established flows by default and persists targeted reconnect mode", () => {
    const preserve = normalizeOutboundDraftForPersistence({
      ...baselineDraft,
      type: "urltest",
      outboundGroups: [{ outbounds: ["primary"], weight: "" }],
      conntrackOnSwitch: "preserve",
    })
    const reconnect = normalizeOutboundDraftForPersistence({
      ...baselineDraft,
      type: "urltest",
      outboundGroups: [{ outbounds: ["primary"], weight: "" }],
      conntrackOnSwitch: "delete",
    })
    const reconnectOnlyOnFailure = normalizeOutboundDraftForPersistence({
      ...baselineDraft,
      type: "urltest",
      outboundGroups: [{ outbounds: ["primary"], weight: "" }],
      selectionMode: "priority",
      conntrackOnSwitch: "delete_on_failure",
    })

    expect(preserve.conntrack_on_switch).toBeUndefined()
    expect(reconnect.conntrack_on_switch).toBe("delete")
    expect(reconnectOnlyOnFailure.conntrack_on_switch).toBe(
      "delete_on_failure"
    )
    expect(semanticJsonEqual(reconnect, preserve)).toBe(false)
  })

  test("round-trips non-default group weights and probe timeout", () => {
    const outbound = {
      tag: "failover",
      type: "urltest",
      url: "https://connectivity-check.example/generate_204",
      interval_ms: 45000,
      probe_timeout_ms: 7250,
      tolerance_ms: 250,
      selection_mode: "priority",
      outbound_groups: [
        { outbounds: ["primary", "secondary"], weight: 5 },
        { outbounds: ["emergency"], weight: 20 },
      ],
      retry: {
        attempts: 4,
        interval_ms: 1500,
      },
      circuit_breaker: {
        failure_threshold: 6,
        success_threshold: 3,
        timeout_ms: 45000,
        half_open_max_requests: 2,
      },
    } satisfies Outbound

    const draft = mapOutboundToDraft(outbound)
    const persisted = normalizeOutboundDraftForPersistence(draft)

    expect(draft.probeTimeout).toBe("7250")
    expect(draft.outboundGroups).toEqual([
      { outbounds: ["primary", "secondary"], weight: "5" },
      { outbounds: ["emergency"], weight: "20" },
    ])
    expect(persisted).toEqual(outbound)
  })

  test("restoring timeout and group weights clears semantic dirty state", () => {
    const outbound = {
      tag: "failover",
      type: "urltest",
      probe_timeout_ms: 6000,
      outbound_groups: [
        { outbounds: ["primary"], weight: 10 },
        { outbounds: ["backup"], weight: 30 },
      ],
    } satisfies Outbound
    const originalDraft = mapOutboundToDraft(outbound)
    const baseline = normalizeOutboundDraftForPersistence(originalDraft)
    const changed = normalizeOutboundDraftForPersistence({
      ...originalDraft,
      probeTimeout: "9000",
      outboundGroups: originalDraft.outboundGroups.map((group, index) =>
        index === 0 ? { ...group, weight: "25" } : group
      ),
    })
    const restored = normalizeOutboundDraftForPersistence({
      ...originalDraft,
      probeTimeout: "6000",
      outboundGroups: originalDraft.outboundGroups.map((group) => ({
        ...group,
      })),
    })

    expect(semanticJsonEqual(changed, baseline)).toBe(false)
    expect(semanticJsonEqual(restored, baseline)).toBe(true)
  })

  test("keeps omitted group weights optional and uses the probe default", () => {
    const draft = mapOutboundToDraft({
      tag: "failover",
      type: "urltest",
      outbound_groups: [{ outbounds: ["primary"] }],
    })
    const persisted = normalizeOutboundDraftForPersistence(draft)

    expect(draft.probeTimeout).toBe("5000")
    expect(draft.outboundGroups[0].weight).toBe("")
    expect(persisted.probe_timeout_ms).toBe(5000)
    expect(persisted.outbound_groups).toEqual([
      { outbounds: ["primary"], weight: undefined },
    ])
  })

  test("keeps each weight attached to its group when groups are reordered", () => {
    const original = mapOutboundToDraft({
      tag: "failover",
      type: "urltest",
      outbound_groups: [
        { outbounds: ["primary"], weight: 5 },
        { outbounds: ["backup"], weight: 50 },
      ],
    })
    const reordered = normalizeOutboundDraftForPersistence({
      ...original,
      outboundGroups: [original.outboundGroups[1], original.outboundGroups[0]],
    })

    expect(reordered.outbound_groups).toEqual([
      { outbounds: ["backup"], weight: 50 },
      { outbounds: ["primary"], weight: 5 },
    ])
  })
})
