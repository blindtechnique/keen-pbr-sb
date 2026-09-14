import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"

import type { Outbound, TransportSpec } from "../src/api/generated/model"
import { selectTransportOrphanOutbounds } from "../src/lib/transport-orphan-outbounds"

const native: TransportSpec = {
  tag: "native_tracker",
  type: "native",
  interface: "nwg4",
}
const nativeOutbound: Outbound = {
  tag: "native_route",
  type: "interface",
  interface: "nwg4",
}
const proxy: TransportSpec = {
  tag: "proxy",
  type: "sing-box",
  interface: "sb0",
}
const proxyOutbound: Outbound = {
  tag: "proxy_route",
  type: "interface",
  interface: "sb0",
}
const group: Outbound = {
  tag: "group",
  type: "urltest",
  outbound_groups: [{ outbounds: [nativeOutbound.tag, proxyOutbound.tag] }],
}
const input = {
  outbounds: [nativeOutbound, proxyOutbound, group],
  managedTransports: [proxy],
  configuredTransports: [native, proxy],
  nativeInterfaces: [],
  inventoryAuthoritative: true,
}

describe("routes retained after native interface deletion", () => {
  test("keeps a stale native group member manageable despite its saved tracker", () => {
    const before = structuredClone(input)
    const selected = selectTransportOrphanOutbounds(input)
    expect(selected.outbounds).toEqual([nativeOutbound])
    expect([...selected.unrepresentedNativeInterfaces]).toEqual(["nwg4"])
    expect(input).toEqual(before)
  })

  test("also exposes a standalone stale native route", () => {
    expect(
      selectTransportOrphanOutbounds({
        ...input,
        outbounds: [nativeOutbound, proxyOutbound],
      }).outbounds
    ).toEqual([nativeOutbound])
  })

  test("does not mistake a stopped interface in the typed inventory for a deletion", () => {
    // No live kernel interface is required: stopped VPNs remain in NDMS.
    const selected = selectTransportOrphanOutbounds({
      ...input,
      nativeInterfaces: [{ kernelName: "nwg4" }],
    })
    expect(selected.outbounds).toEqual([])
    expect([...selected.unrepresentedNativeInterfaces]).toEqual([])
  })

  test("does not infer deletion while NDMS inventory is unavailable", () => {
    const selected = selectTransportOrphanOutbounds({
      ...input,
      inventoryAuthoritative: false,
    })
    expect(selected.outbounds).toEqual([])
    expect([...selected.unrepresentedNativeInterfaces]).toEqual([])
  })

  test("keeps an unresolved native binding editable without claiming the VPN was deleted", () => {
    const selected = selectTransportOrphanOutbounds({
      ...input,
      nativeInterfaces: [{ kernelName: undefined }],
    })
    expect(selected.outbounds).toEqual([nativeOutbound])
  })

  test("does not resurrect a route removed by backend reconciliation", () => {
    expect(
      selectTransportOrphanOutbounds({
        ...input,
        outbounds: [proxyOutbound],
        configuredTransports: [proxy],
      }).outbounds
    ).toEqual([])
  })

  test("preserves management of unrelated interface routes", () => {
    const external: Outbound = {
      tag: "external",
      type: "interface",
      interface: "tun0",
    }
    expect(
      selectTransportOrphanOutbounds({
        ...input,
        outbounds: [nativeOutbound, proxyOutbound, group, external],
        nativeInterfaces: [{ kernelName: "nwg4" }],
      }).outbounds
    ).toEqual([external])
  })

  test("wires retained routes to the existing editor and dependency-aware deletion", () => {
    const page = readFileSync(
      new URL("../src/pages/transports-page.tsx", import.meta.url),
      "utf8"
    )
    expect(page).toMatch(/=\s+selectTransportOrphanOutbounds\(\{/)
    const rows = page.slice(
      page.indexOf("const orphanRows ="),
      page.indexOf("const transportRows =")
    )
    expect(rows).toContain('t("transports.groups.nativeInterfaceNotFound")')
    expect(rows).toContain("encodeURIComponent(outbound.tag)")
    expect(rows).toContain("navigate(editHref)")
    const editor = readFileSync(
      new URL("../src/pages/outbound-upsert-page.tsx", import.meta.url),
      "utf8"
    )
    expect(editor).toContain("<UpsertDeleteAction")
    expect(editor).toContain(
      "buildUpdatedConfigForOutboundsDelete(loadedConfig, [outboundId])"
    )
  })
})
