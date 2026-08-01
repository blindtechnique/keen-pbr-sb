import { describe, expect, test } from "bun:test"

import {
  applyDnsProbeStatusEvent,
  subscribeDnsProbeEvents,
  type DnsProbeEvent,
} from "../src/api/dns-probe-events"

describe("DNS probes over the shared status stream", () => {
  test("delivers a valid named probe event to active checks", () => {
    const received: DnsProbeEvent[] = []
    const unsubscribe = subscribeDnsProbeEvents((event) => {
      received.push(event)
    })

    expect(
      applyDnsProbeStatusEvent(
        JSON.stringify({
          type: "dns_probe",
          data: {
            type: "DNS",
            domain: "token.check.keen.pbr",
            source_ip: "192.0.2.10",
            ecs: null,
          },
        })
      )
    ).toBe(true)
    expect(received).toEqual([
      {
        type: "DNS",
        domain: "token.check.keen.pbr",
        source_ip: "192.0.2.10",
        ecs: null,
      },
    ])

    unsubscribe()
  })

  test("ignores malformed, unrelated, and unsubscribed events", () => {
    const received: DnsProbeEvent[] = []
    const unsubscribe = subscribeDnsProbeEvents((event) => {
      received.push(event)
    })
    unsubscribe()

    expect(applyDnsProbeStatusEvent("not json")).toBe(false)
    expect(
      applyDnsProbeStatusEvent(
        JSON.stringify({ type: "service", data: { type: "DNS" } })
      )
    ).toBe(false)
    expect(
      applyDnsProbeStatusEvent(
        JSON.stringify({ type: "dns_probe", data: { type: "OTHER" } })
      )
    ).toBe(false)
    expect(
      applyDnsProbeStatusEvent(
        JSON.stringify({
          type: "dns_probe",
          data: { type: "DNS", domain: "ignored.check.keen.pbr" },
        })
      )
    ).toBe(true)
    expect(received).toEqual([])
  })
})
