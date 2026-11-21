import { expect, test } from "bun:test"
import {
  buildUpdatedConfigForDnsServerUpsert,
  getDnsServerDraft,
  normalizeDohUrl,
  normalizeDohIps,
  normalizeDnsServerDraftForComparison,
} from "../src/pages/dns-server-upsert-utils"
import {
  buildUpdatedConfigForDnsServersDelete,
  getDnsServerDeleteImpact,
} from "../src/pages/dns-servers-utils"
import type { ConfigObject } from "../src/api/generated/model/configObject"

const config: ConfigObject = {
  dns: {
    passive_learning: true,
    bootstrap: ["plain"],
    servers: [
      { tag: "plain", address: "9.9.9.9" },
      {
        tag: "secure",
        type: "doh",
        address: "https://dns.example/dns-query",
        display_name: "Private DNS",
        detour: "vpn",
        ips: ["1.1.1.1"],
      },
    ],
  },
}

test("DoH draft preserves pins, detour and shared bootstrap on save", () => {
  const draft = getDnsServerDraft(
    config.dns!.servers![1],
    config.dns!.bootstrap
  )
  expect(
    buildUpdatedConfigForDnsServerUpsert(config, "edit", draft, "secure")
  ).toEqual(config)
  expect(
    normalizeDnsServerDraftForComparison({ ...draft, ips: " 1.1.1.1\n" })
  ).toEqual(normalizeDnsServerDraftForComparison(draft))
  const next = buildUpdatedConfigForDnsServerUpsert(
    config,
    "edit",
    { ...draft, type: "static", address: "8.8.8.8" },
    "secure"
  )
  expect(next?.dns?.servers?.[1].ips).toBeUndefined()
  expect(next?.dns?.bootstrap).toEqual(["plain"])
})

test("DoH URL and fixed address validation rejects unsafe or incorrect forms", () => {
  for (const url of [
    "http://dns.example/",
    "https://u:p@dns.example/",
    "https://dns.example/#x",
    "https://dns.example:0/",
    "https://dns.example:65536/",
  ])
    expect(normalizeDohUrl(url)).toBeNull()
  expect(normalizeDohUrl("https://dns.example/dns-query")).toBe(
    "https://dns.example/dns-query"
  )
  expect(normalizeDohIps("1.1.1.1,2001:db8::1")).toEqual([
    "1.1.1.1",
    "2001:db8::1",
  ])
  expect(normalizeDohIps("1.1.1.1:53")).toBeNull()
})

test("Deleting a bootstrap DNS reports and clears its reference only when requested", () => {
  expect(getDnsServerDeleteImpact(config, ["plain"]).usesBootstrap).toBe(true)
  expect(
    buildUpdatedConfigForDnsServersDelete(config, ["plain"], true).dns
      ?.bootstrap
  ).toEqual([])
  expect(
    buildUpdatedConfigForDnsServersDelete(config, ["plain"], false).dns
      ?.bootstrap
  ).toEqual(["plain"])
})
