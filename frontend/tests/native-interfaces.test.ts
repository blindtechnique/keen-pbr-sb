import { describe, expect, test } from "bun:test"

import type {
  RuntimeInterfaceInventoryEntry,
  TransportStatus,
} from "../src/api/generated/model"
import {
  dedupeLegacyNativeTransports,
  getNativeRouteActionability,
  mapNativeInterfaces,
  nativeTunnelKindLabel,
  type KeeneticNativeInterface,
} from "../src/lib/native-interfaces"

describe("native Keenetic interfaces", () => {
  test("maps API fields to a read-only card model with centralized kind labels", () => {
    const [mapped] = mapNativeInterfaces(
      [
        nativeInterface({
          label: "Office VPN",
          firmware_interface_name: "Wireguard0",
          kernel_name: "  nwg0  ",
          kind: "amnezia_wireguard",
        }),
      ],
      []
    )

    expect(nativeTunnelKindLabel("amnezia_wireguard")).toBe("AmneziaWG")
    expect(mapped).toMatchObject({
      id: "native-1",
      label: "Office VPN",
      logicalName: "Wireguard0",
      kernelName: "nwg0",
      protocol: {
        kind: "amneziawg",
        label: "AWG",
        evidence: "ndms-kind",
        exact: true,
      },
      live: false,
      connected: true,
      link: true,
    })
  })

  test("keeps the generic NDMS WireGuard family explicitly ambiguous", () => {
    const [mapped] = mapNativeInterfaces(
      [
        nativeInterface({
          firmware_interface_name: "Wireguard2",
          kernel_name: "nwg2",
          kind: "wireguard",
        }),
      ],
      []
    )
    expect(mapped.protocol).toEqual({
      kind: "wireguard_ambiguous",
      label: "AWG/WG",
      evidence: "ndms-kind",
      exact: false,
    })
  })

  test("joins live state only by the resolved kernel name", () => {
    const runtime: RuntimeInterfaceInventoryEntry[] = [
      { name: "nwg0", status: "up", oper_state: "unknown" },
      { name: "Wireguard1", status: "up", oper_state: "up" },
    ]
    const [resolved, unresolved] = mapNativeInterfaces(
      [
        nativeInterface({
          firmware_interface_name: "Wireguard0",
          kernel_name: "nwg0",
        }),
        nativeInterface({
          id: "native-2",
          firmware_interface_name: "Wireguard1",
          kernel_name: undefined,
        }),
      ],
      runtime
    )

    expect(resolved.runtime).toBe(runtime[0])
    expect(resolved.live).toBe(true)
    expect(unresolved.runtime).toBeUndefined()
    expect(unresolved.live).toBe(false)
  })

  test("dedupes legacy native rows by interface deterministically", () => {
    const mapped = mapNativeInterfaces(
      [
        nativeInterface({
          firmware_interface_name: "Wireguard0",
          kernel_name: "nwg0",
        }),
      ],
      [{ name: "nwg0", status: "up" }]
    )
    const transports = [
      transport({
        tag: "represented_legacy",
        interface: "nwg0",
        type: "native",
      }),
      transport({
        tag: "older_fallback",
        interface: "tun9",
        type: "native",
        updated_at: "2026-07-24T12:00:00Z",
      }),
      transport({
        tag: "newer_fallback",
        interface: "tun9",
        type: "native",
        updated_at: "2026-07-25T12:00:00Z",
      }),
      transport({
        tag: "managed_proxy",
        interface: "nwg0",
        type: "sing-box",
      }),
    ]

    expect(
      dedupeLegacyNativeTransports(transports, mapped).map(({ tag }) => tag)
    ).toEqual(["newer_fallback", "managed_proxy"])
    expect(
      dedupeLegacyNativeTransports([...transports].reverse(), mapped)
        .map(({ tag }) => tag)
        .sort()
    ).toEqual(["managed_proxy", "newer_fallback"])
  })

  test("never makes an unresolved interface actionable", () => {
    const [unresolved] = mapNativeInterfaces(
      [
        nativeInterface({
          firmware_interface_name: "Wireguard0",
          kernel_name: undefined,
        }),
      ],
      [{ name: "Wireguard0", status: "up" }]
    )

    expect(
      getNativeRouteActionability(unresolved, {
        hasConfig: true,
      })
    ).toEqual({ enabled: false, reason: "unresolved" })
  })

  test("never attaches server or unclassified interfaces to routes", () => {
    for (const role of ["server", "unknown"] as const) {
      const [native] = mapNativeInterfaces(
        [nativeInterface({ kernel_name: "nwg0", role })],
        [{ name: "nwg0", status: "up" }]
      )

      expect(
        getNativeRouteActionability(native, {
          hasConfig: true,
        })
      ).toEqual({ enabled: false, reason: "not-client" })
    }
  })

  test("requires a live unbound interface and loaded config for route creation", () => {
    const [live] = mapNativeInterfaces(
      [nativeInterface({ kernel_name: "nwg0" })],
      [{ name: "nwg0", status: "up" }]
    )

    expect(
      getNativeRouteActionability(live, {
        hasConfig: false,
      })
    ).toEqual({ enabled: false, reason: "no-config" })
    expect(
      getNativeRouteActionability(live, {
        hasConfig: true,
        boundOutboundTag: "office",
      })
    ).toEqual({ enabled: false, reason: "already-bound" })
    expect(
      getNativeRouteActionability(live, {
        hasConfig: true,
      })
    ).toEqual({ enabled: true, interfaceName: "nwg0" })
  })
})

function nativeInterface(
  overrides: Partial<KeeneticNativeInterface> = {}
): KeeneticNativeInterface {
  return {
    id: "native-1",
    firmware_interface_name: "Wireguard0",
    kernel_name: "nwg0",
    label: "Office VPN",
    firmware_type: "Wireguard",
    kind: "wireguard",
    role: "client",
    owner: "keenetic",
    connected: true,
    link: true,
    capabilities: {
      can_edit: false,
      can_delete: false,
      can_hide: false,
      backup_required: true,
    },
    management_readiness: {
      candidate: true,
      identity_stable: true,
      observed_revision: "ndms-v1-test",
      configuration_snapshot_available: false,
      blockers: [
        "typed_rci_unavailable",
        "automatic_backup_unavailable",
        "ownership_unknown",
        "optimistic_revision_unavailable",
      ],
    },
    ...overrides,
  }
}

function transport(overrides: Partial<TransportStatus>): TransportStatus {
  return {
    tag: "legacy",
    type: "native",
    interface: "nwg0",
    state: "up",
    updated_at: "2026-07-25T00:00:00Z",
    desired_up: true,
    ...overrides,
  }
}
