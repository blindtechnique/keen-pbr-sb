import { describe, expect, test } from "bun:test"
import type { NdmsTunnelInterface } from "../src/api/generated/model"
import {
  nativeInventoryPresentation,
  nativeInventoryRetryInterval,
} from "../src/lib/native-inventory-presentation"
import { dedupeLegacyNativeTransports } from "../src/lib/native-interfaces"
import { selectTransportOrphanOutbounds } from "../src/lib/transport-orphan-outbounds"

const tunnel = {
  id: "Wireguard5",
  firmware_interface_name: "Wireguard5",
  kernel_name: "nwg5",
  label: "Office",
  kind: "amnezia_wireguard",
  owner: "keenetic",
  role: "client",
  connected: false,
  link: false,
} as NdmsTunnelInterface
const runtime = [{ name: "nwg5", status: "up" as const }]

describe("native catalog refresh presentation", () => {
  test("stale metadata retains AWG identity without stale health or authority", () => {
    const fresh = nativeInventoryPresentation(
      { available: true, interfaces: [tunnel] },
      runtime
    )
    const stale = nativeInventoryPresentation(
      { available: false, interfaces: [tunnel] },
      runtime
    )
    expect(fresh.authoritative).toBe(true)
    expect(stale.authoritative).toBe(false)
    expect(stale.interfaces[0].id).toBe("Wireguard5")
    expect(stale.interfaces[0].label).toBe("Office")
    expect(stale.interfaces[0].protocol).toEqual(fresh.interfaces[0].protocol)
    expect(stale.interfaces[0].runtime).toEqual(runtime[0])
    expect(stale.interfaces[0].connected).toBeUndefined()
    expect(stale.interfaces[0].link).toBeUndefined()
    expect(fresh.interfaces[0].connected).toBe(false)
  })

  test("a refreshing native row does not turn into a stopped legacy row or orphan route", () => {
    const view = nativeInventoryPresentation(
      { available: false, interfaces: [tunnel] },
      runtime
    )
    const managed = dedupeLegacyNativeTransports(
      [
        {
          tag: "old",
          type: "native",
          interface: "nwg5",
          state: "down",
          desired_up: false,
          updated_at: "",
        },
      ],
      view.interfaces,
      view.authoritative
    )
    expect(managed).toEqual([])
    expect(
      selectTransportOrphanOutbounds({
        outbounds: [{ tag: "office", type: "interface", interface: "nwg5" }],
        managedTransports: managed,
        configuredTransports: [],
        nativeInterfaces: view.interfaces,
        inventoryAuthoritative: view.authoritative,
      }).outbounds
    ).toEqual([])
  })

  test("a fresh empty inventory removes old rows instead of resurrecting them", () => {
    const view = nativeInventoryPresentation(
      { available: true, interfaces: [] },
      runtime
    )
    expect(view.authoritative).toBe(true)
    expect(view.interfaces).toEqual([])
    expect(nativeInventoryPresentation(undefined, runtime).interfaces).toEqual(
      []
    )
  })

  test("only a temporary unavailable catalog is retried", () => {
    expect(nativeInventoryRetryInterval({ available: false })).toBe(5_000)
    expect(nativeInventoryRetryInterval({ available: true })).toBe(false)
    expect(nativeInventoryRetryInterval(undefined)).toBe(false)
  })
})
