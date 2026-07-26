import { describe, expect, test } from "bun:test"

import { DnsServerType } from "../src/api/generated/model/dnsServerType"
import {
  buildUpdatedConfigForDnsServerUpsert,
  getDnsServerDraft,
  MAX_PLAIN_DNS_TEMPLATES,
  normalizeDnsAddress,
  normalizePlainDnsTemplateAddress,
  withSavedPlainDnsTemplate,
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

  test("plain DNS template addresses accept IPv4 without a port only", () => {
    expect(normalizePlainDnsTemplateAddress(" 9.9.9.9 ")).toBe("9.9.9.9")
    expect(normalizePlainDnsTemplateAddress("9.9.9.9:53")).toBeNull()
    expect(normalizePlainDnsTemplateAddress("2620:fe::fe")).toBeNull()
  })

  test("simple edits preserve an existing detour", () => {
    const config = {
      dns: {
        servers: [
          {
            tag: "cloudflare",
            display_name: "Cloudflare",
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
      display_name: "Cloudflare",
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
        displayName: "Keenetic DNS",
        tag: "router",
        type: DnsServerType.keenetic,
        address: "1.1.1.1",
        detour: "vpn",
      }
    )

    expect(updated?.dns?.servers?.[0]).toEqual({
      tag: "router",
      display_name: "Keenetic DNS",
      type: DnsServerType.keenetic,
    })
  })

  test("adds a preset primary and backup atomically", () => {
    const updated = buildUpdatedConfigForDnsServerUpsert(
      { dns: { servers: [] } },
      "create",
      {
        displayName: "Cloudflare",
        tag: "cloudflare",
        type: DnsServerType.static,
        address: "1.1.1.1",
        detour: "vpn",
      },
      undefined,
      {
        displayName: "Cloudflare - backup",
        tag: "cloudflare_backup",
        address: "1.0.0.1",
      }
    )

    expect(updated?.dns?.servers).toEqual([
      {
        tag: "cloudflare",
        display_name: "Cloudflare",
        type: DnsServerType.static,
        address: "1.1.1.1",
        detour: "vpn",
      },
      {
        tag: "cloudflare_backup",
        display_name: "Cloudflare - backup",
        type: DnsServerType.static,
        address: "1.0.0.1",
        detour: "vpn",
      },
    ])
  })

  test("does not duplicate an existing preset backup definition", () => {
    const updated = buildUpdatedConfigForDnsServerUpsert(
      {
        dns: {
          servers: [
            {
              tag: "existing_backup",
              type: DnsServerType.static,
              address: "1.0.0.1",
            },
          ],
        },
      },
      "create",
      {
        displayName: "Cloudflare",
        tag: "cloudflare",
        type: DnsServerType.static,
        address: "1.1.1.1",
        detour: "",
      },
      undefined,
      {
        displayName: "Cloudflare - backup",
        tag: "cloudflare_backup",
        address: "1.0.0.1",
      }
    )

    expect(updated?.dns?.servers).toHaveLength(2)
  })

  test("rejects an invalid backup without partially changing config", () => {
    const config = { dns: { servers: [] } }
    const updated = buildUpdatedConfigForDnsServerUpsert(
      config,
      "create",
      {
        displayName: "Cloudflare",
        tag: "cloudflare",
        type: DnsServerType.static,
        address: "1.1.1.1",
        detour: "",
      },
      undefined,
      {
        displayName: "Cloudflare - backup",
        tag: "cloudflare_backup",
        address: "invalid",
      }
    )

    expect(updated).toBeNull()
    expect(config.dns.servers).toEqual([])
  })

  test("rejects a backup that duplicates the primary resolver", () => {
    expect(
      buildUpdatedConfigForDnsServerUpsert(
        { dns: { servers: [] } },
        "create",
        {
          displayName: "Office DNS",
          tag: "office_dns",
          type: DnsServerType.static,
          address: "192.0.2.53",
          detour: "",
        },
        undefined,
        {
          displayName: "Office DNS - backup",
          tag: "office_dns_backup",
          address: "192.0.2.53",
        }
      )
    ).toBeNull()
  })

  test("stores custom templates in config without losing other UI preferences", () => {
    const updated = withSavedPlainDnsTemplate(
      {
        ui_preferences: {
          hidden_native_interface_ids: ["Wireguard0"],
          plain_dns_templates: [],
        },
      },
      {
        name: "Office DNS",
        primary_ipv4: "192.0.2.53",
        secondary_ipv4: "192.0.2.54",
      }
    )

    expect(updated?.ui_preferences).toEqual({
      hidden_native_interface_ids: ["Wireguard0"],
      plain_dns_templates: [
        {
          name: "Office DNS",
          primary_ipv4: "192.0.2.53",
          secondary_ipv4: "192.0.2.54",
        },
      ],
    })
  })

  test("explicitly saving a same-name template replaces only that template", () => {
    const updated = withSavedPlainDnsTemplate(
      {
        ui_preferences: {
          plain_dns_templates: [
            { name: "Office DNS", primary_ipv4: "192.0.2.1" },
            { name: "Lab DNS", primary_ipv4: "198.51.100.53" },
          ],
        },
      },
      {
        name: " office dns ",
        primary_ipv4: "192.0.2.53",
      }
    )

    expect(updated?.ui_preferences?.plain_dns_templates).toEqual([
      { name: "office dns", primary_ipv4: "192.0.2.53" },
      { name: "Lab DNS", primary_ipv4: "198.51.100.53" },
    ])
  })

  test("rejects invalid custom template definitions without mutating config", () => {
    const config = {
      ui_preferences: {
        plain_dns_templates: [
          { name: "Office DNS", primary_ipv4: "192.0.2.53" },
        ],
      },
    }
    expect(
      withSavedPlainDnsTemplate(config, {
        name: "Broken",
        primary_ipv4: "192.0.2.53:53",
      })
    ).toBeNull()
    expect(config.ui_preferences.plain_dns_templates).toHaveLength(1)
  })

  test("accepts the 32nd custom template and rejects the 33rd without mutation", () => {
    const existing = Array.from(
      { length: MAX_PLAIN_DNS_TEMPLATES - 1 },
      (_, index) => ({
        name: `DNS ${index + 1}`,
        primary_ipv4: `192.0.2.${index + 1}`,
      })
    )
    const atLimit = withSavedPlainDnsTemplate(
      { ui_preferences: { plain_dns_templates: existing } },
      {
        name: "DNS 32",
        primary_ipv4: "198.51.100.32",
      }
    )
    expect(atLimit).not.toBeNull()
    const frozenAtLimit = structuredClone(
      atLimit!.ui_preferences!.plain_dns_templates!
    )

    const overLimit = withSavedPlainDnsTemplate(atLimit!, {
      name: "DNS 33",
      primary_ipv4: "198.51.100.33",
    })

    expect(overLimit).toBeNull()
    expect(atLimit?.ui_preferences?.plain_dns_templates).toEqual(frozenAtLimit)
  })
})
