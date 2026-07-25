import { describe, expect, test } from "bun:test"

import { DnsServerType } from "../src/api/generated/model/dnsServerType"
import {
  buildUpdatedConfigForDnsServerUpsert,
  getDnsServerDraft,
  normalizeDnsAddress,
} from "../src/pages/dns-server-upsert-utils"

describe("DNS server upsert helpers", () => {
  test("normalizes valid IPv4 and IPv6 addresses", () => {
    expect(normalizeDnsAddress(" 1.1.1.1:53 ")).toBe("1.1.1.1:53")
    expect(normalizeDnsAddress("2606:4700:4700::1111")).toBe(
      "2606:4700:4700::1111"
    )
    expect(normalizeDnsAddress("[2606:4700:4700::1111]:5353")).toBe(
      "[2606:4700:4700::1111]:5353"
    )
  })

  test("rejects malformed addresses and ports", () => {
    expect(normalizeDnsAddress("1.1.1.999")).toBeNull()
    expect(normalizeDnsAddress(":::")).toBeNull()
    expect(normalizeDnsAddress("[2606:4700::1111]:0")).toBeNull()
    expect(normalizeDnsAddress("[2606:4700::1111]:65536")).toBeNull()
  })

  test("simple edits preserve an existing detour", () => {
    const config = {
      dns: {
        servers: [
          {
            tag: "cloudflare",
            type: DnsServerType.static,
            address: "1.1.1.1",
            detour: "vpn",
          },
        ],
      },
    }
    const draft = getDnsServerDraft(config.dns.servers[0])
    const updated = buildUpdatedConfigForDnsServerUpsert(
      config,
      "edit",
      { ...draft, address: "1.0.0.1" },
      "cloudflare"
    )

    expect(updated?.dns?.servers?.[0]).toEqual({
      tag: "cloudflare",
      type: DnsServerType.static,
      address: "1.0.0.1",
      detour: "vpn",
    })
  })

  test("Keenetic DNS drops fields that do not apply to it", () => {
    const updated = buildUpdatedConfigForDnsServerUpsert(
      { dns: { servers: [] } },
      "create",
      {
        tag: "router",
        type: DnsServerType.keenetic,
        address: "1.1.1.1",
        detour: "vpn",
      }
    )

    expect(updated?.dns?.servers?.[0]).toEqual({
      tag: "router",
      type: DnsServerType.keenetic,
    })
  })
})
