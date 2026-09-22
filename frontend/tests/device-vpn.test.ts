import { describe, expect, test } from "bun:test"
import type { Outbound, RouteRule } from "../src/api/generated/model"
import {
  deviceIpv4,
  deviceRuleAddress,
  deviceVpnOutbounds,
  emptyDeviceVpnDraft,
  normalizeDeviceVpnDraft,
  removeDeviceVpnRule,
  saveDeviceVpnRule,
  toDeviceVpnDraft,
} from "../src/lib/device-vpn"

const outbounds: Outbound[] = [
  { tag: "vpn", type: "interface", interface: "nwg0", display_name: "My VPN" },
  { tag: "group", type: "urltest", outbound_groups: [{ outbounds: ["vpn"] }] },
  { tag: "main", type: "table", table: 254 },
  { tag: "block", type: "blackhole" },
]
const draft = {
  ...emptyDeviceVpnDraft,
  name: "Laptop",
  address: "192.168.7.19",
  outbound: "vpn",
}
const device: RouteRule = {
  id: "laptop",
  display_name: "Laptop",
  src_addr: "192.168.7.19/32",
  outbound: "vpn",
}
const website: RouteRule = { id: "sites", list: ["video"], outbound: "group" }

describe("exact IPv4 device assignment", () => {
  for (const address of [
    "192.168.7.19",
    "10.0.0.12",
    "172.19.0.1",
    " 192.168.7.19 ",
  ]) {
    test("accepts an exact host: " + address, () =>
      expect(deviceIpv4(address)).toBe(address.trim())
    )
  }
  for (const address of [
    "",
    "0.0.0.0",
    "0.1.2.3",
    "127.0.0.1",
    "224.0.0.1",
    "255.255.255.255",
    "192.168.1.256",
    "192.168.1.01",
    "192.168.1",
    "192.168.1.1/24",
    "192.168.1.1/32",
    "!192.168.1.1",
    "192.168.1.1,10.0.0.1",
    "::1",
    "::ffff:192.168.1.1",
    "192.168.1.1;reboot",
    "0xc0.168.1.1",
  ]) {
    test("rejects broad or ambiguous source: " + address, () =>
      expect(deviceIpv4(address)).toBeUndefined()
    )
  }
  test("recognizes only an unqualified single-host rule", () => {
    expect(deviceRuleAddress(device)).toBe(draft.address)
    expect(deviceRuleAddress({ ...device, src_addr: draft.address })).toBe(
      draft.address
    )
    expect(
      deviceRuleAddress({ ...device, src_addr: "192.168.7.0/24" })
    ).toBeUndefined()
    for (const condition of [
      { list: ["video"] },
      { proto: "tcp" },
      { dscp: 2 },
      { src_port: "443" },
      { dest_port: "443" },
      { dest_addr: "1.1.1.1" },
      { future_selector: true },
    ])
      expect(deviceRuleAddress({ ...device, ...condition })).toBeUndefined()
  })
  test("does not mistake system destinations for VPN choices", () => {
    expect(
      deviceVpnOutbounds(outbounds).map((outbound) => outbound.tag)
    ).toEqual(["vpn", "group"])
  })
  test("puts the exact source rule first and preserves other rules by reference", () => {
    const disabled = {
      ...website,
      id: "disabled",
      enabled: false,
      unknown_field: "preserve",
    }
    const rules = [website, disabled]
    const result = saveDeviceVpnRule(rules, outbounds, draft)
    expect(result.error).toBeUndefined()
    expect(result.rules?.[0]).toMatchObject({
      src_addr: "192.168.7.19/32",
      outbound: "vpn",
      display_name: "Laptop",
    })
    expect(result.rules?.[0]?.list).toBeUndefined()
    expect(result.rules?.[0]?.dest_addr).toBeUndefined()
    expect(result.rules?.[1]).toBe(website)
    expect(result.rules?.[2]).toBe(disabled)
    expect(rules).toEqual([website, disabled])
  })
  test("supports groups without choosing or altering their members", () => {
    const result = saveDeviceVpnRule([website], outbounds, {
      ...draft,
      outbound: "group",
    })
    expect(result.rules?.[0]?.outbound).toBe("group")
    expect(outbounds[1]?.outbound_groups?.[0]?.outbounds).toEqual(["vpn"])
  })
  test("does not inherit unrelated conditions or silently change the global failure policy", () => {
    const result = saveDeviceVpnRule([website], outbounds, draft)
    expect(result.rules?.[0]?.failure_policy).toBeUndefined()
    expect(result.rules?.[0]?.fallback_outbound).toBeUndefined()
  })
  test("rejects duplicate host rules, including disabled, /32 and direct rules", () => {
    for (const other of [
      device,
      { ...device, src_addr: draft.address, enabled: false },
      { ...device, outbound: "main" },
    ]) {
      expect(saveDeviceVpnRule([other], outbounds, draft).error).toBe(
        "duplicate"
      )
    }
  })
  test("allows a device rule to outrank an existing site or subnet rule without changing it", () => {
    const specific = { ...website, src_addr: draft.address }
    const subnet = { ...device, src_addr: "192.168.7.0/24" }
    const result = saveDeviceVpnRule([specific, subnet], outbounds, draft)
    expect(result.rules?.slice(1)).toEqual([specific, subnet])
  })
  test("follows stable identity after reordering, preserving unrelated new rules", () => {
    const other = { ...website, id: "new" }
    const result = saveDeviceVpnRule(
      [other, website, device],
      outbounds,
      { ...draft, outbound: "group" },
      device
    )
    expect(result.rules?.map((rule) => rule.id)).toEqual([
      "laptop",
      "new",
      "sites",
    ])
    expect(result.rules?.[0]?.outbound).toBe("group")
  })
  test("rejects removed or concurrently changed records without overwriting", () => {
    expect(saveDeviceVpnRule([website], outbounds, draft, device).error).toBe(
      "changed"
    )
    expect(
      saveDeviceVpnRule(
        [{ ...device, outbound: "group" }],
        outbounds,
        draft,
        device
      ).error
    ).toBe("changed")
    expect(
      removeDeviceVpnRule([{ ...device, enabled: false }], device)
    ).toBeUndefined()
    expect(removeDeviceVpnRule([website], device)).toBeUndefined()
  })
  test("does not replace a legacy numeric index that now belongs to another rule", () => {
    const legacy = { src_addr: draft.address, outbound: "vpn" }
    const result = saveDeviceVpnRule(
      [website, { ...legacy }],
      outbounds,
      draft,
      legacy
    )
    expect(result.rules?.[0]?.src_addr).toBe(draft.address + "/32")
    expect(result.rules?.[1]).toBe(website)
    expect(
      saveDeviceVpnRule(
        [{ ...legacy }, { ...legacy }],
        outbounds,
        draft,
        legacy
      ).error
    ).toBe("changed")
  })
  test("removes only the captured assignment and restores the remaining order", () => {
    expect(removeDeviceVpnRule([website, device], device)).toEqual([website])
  })
  test("requires a current routable destination and a valid fallback", () => {
    for (const outbound of ["", "missing", "main", "block"]) {
      expect(
        saveDeviceVpnRule([], outbounds, { ...draft, outbound }).error
      ).toBe("outbound")
    }
    expect(
      saveDeviceVpnRule([], outbounds, { ...draft, failurePolicy: "fallback" })
        .error
    ).toBe("fallback")
    expect(
      saveDeviceVpnRule([], outbounds, {
        ...draft,
        failurePolicy: "fallback",
        fallbackOutbound: "vpn",
      }).error
    ).toBe("fallback")
    expect(
      saveDeviceVpnRule([], outbounds, {
        ...draft,
        failurePolicy: "fallback",
        fallbackOutbound: "group",
      }).rules?.[0]
    ).toMatchObject({
      failure_policy: "fallback",
      fallback_outbound: "group",
    })
  })
  test("round trips name, disabled state and explicit failure policy", () => {
    const original: RouteRule = {
      ...device,
      enabled: false,
      failure_policy: "block",
    }
    const value = toDeviceVpnDraft(original)
    expect(value.enabled).toBe(false)
    expect(
      saveDeviceVpnRule([original], outbounds, value, original).rules?.[0]
    ).toMatchObject(original)
  })
  test("generates collision-safe IDs and persists aliases only on explicit save", () => {
    const result = saveDeviceVpnRule(
      [{ ...website, id: "device_192_168_7_19" }],
      outbounds,
      { ...draft, name: "" }
    )
    expect(result.rules?.[0]?.id).toBe("device_192_168_7_19_2")
    expect(result.rules?.[0]?.display_name).toBeUndefined()
    expect(
      saveDeviceVpnRule([], outbounds, { ...draft, name: "x".repeat(81) }).error
    ).toBe("name")
  })
  test("restoring semantic values clears dirty state, including irrelevant fallback", () => {
    expect(
      normalizeDeviceVpnDraft({
        ...draft,
        name: " Laptop ",
        address: " 192.168.7.19 ",
        fallbackOutbound: "group",
      })
    ).toEqual(normalizeDeviceVpnDraft(draft))
  })
})
