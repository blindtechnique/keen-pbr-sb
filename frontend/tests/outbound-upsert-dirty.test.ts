import { describe, expect, test } from "bun:test"

import { semanticJsonEqual } from "../src/lib/semantic-json"
import {
  normalizeOutboundDraftForPersistence,
  type OutboundDraft,
} from "../src/pages/outbound-upsert-utils"

const baselineDraft = {
  tag: "vpn",
  type: "interface",
  interfaceName: "nwg1",
  gateway: "",
  gateway6: "",
  table: "",
  outbounds: [[]],
  probeUrl: "https://www.gstatic.com/generate_204",
  interval: "180000",
  tolerance: "100",
  retryAttempts: "3",
  retryInterval: "1000",
  circuitBreakerFailures: "5",
  circuitBreakerSuccesses: "2",
  circuitBreakerTimeout: "30000",
  circuitBreakerHalfOpen: "1",
  strictEnforcement: "default",
} satisfies OutboundDraft

describe("outbound editor persisted normalization", () => {
  test("ignores whitespace and fields inactive for the selected type", () => {
    const baseline = normalizeOutboundDraftForPersistence(baselineDraft)
    const restored = normalizeOutboundDraftForPersistence({
      ...baselineDraft,
      tag: " vpn ",
      interfaceName: " nwg1 ",
      probeUrl: "https://example.invalid",
      interval: "1",
      outbounds: [["unused"]],
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
      outbounds: [["primary"], ["backup"]],
    })
    const reordered = normalizeOutboundDraftForPersistence({
      ...baselineDraft,
      type: "urltest",
      outbounds: [["backup"], ["primary"]],
    })

    expect(semanticJsonEqual(reordered, baseline)).toBe(false)
  })
})
