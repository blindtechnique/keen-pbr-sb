import { describe, expect, test } from "bun:test"

import type {
  NdmsTunnelInterface,
  TransportStatus,
} from "../src/api/generated/model"
import {
  buildInterfaceProtocolIndex,
  protocolForFirmwareType,
  protocolForKernelName,
  protocolForManagedTransport,
  protocolForNdmsKind,
} from "../src/lib/interface-protocol"

describe("interface protocol display", () => {
  test("does not overclaim a generic NDMS WireGuard family", () => {
    expect(protocolForNdmsKind("wireguard")).toMatchObject({
      kind: "wireguard_ambiguous",
      label: "AWG/WG",
      exact: false,
    })
    expect(protocolForNdmsKind("amnezia_wireguard")).toMatchObject({
      kind: "amneziawg",
      label: "AWG",
      exact: true,
    })
  })

  test("typed NDMS evidence overrides an ambiguous legacy native status", () => {
    const protocols = buildInterfaceProtocolIndex(
      [
        transport({
          interface: "nwg2",
          protocol: "WG/AWG",
        }),
      ],
      [
        nativeInterface({
          kernel_name: "nwg2",
          kind: "amnezia_wireguard",
        }),
      ]
    )

    expect(protocols.get("nwg2")).toMatchObject({
      kind: "amneziawg",
      label: "AWG",
      evidence: "ndms-kind",
      exact: true,
    })
  })

  test("keeps legacy firmware and kernel evidence explicitly ambiguous", () => {
    expect(protocolForFirmwareType("Wireguard")).toMatchObject({
      label: "AWG/WG",
      exact: false,
    })
    expect(protocolForKernelName("nwg7")).toMatchObject({
      label: "AWG/WG",
      exact: false,
    })
  })

  test("keeps an explicitly configured managed WireGuard transport exact", () => {
    expect(protocolForManagedTransport("wireguard")).toMatchObject({
      kind: "wireguard",
      label: "WG",
      exact: true,
    })
  })
})

function nativeInterface(
  overrides: Partial<NdmsTunnelInterface> = {}
): NdmsTunnelInterface {
  return {
    id: "Wireguard2",
    firmware_interface_name: "Wireguard2",
    kernel_name: "nwg2",
    label: "Office VPN",
    firmware_type: "Wireguard",
    kind: "wireguard",
    role: "client",
    owner: "keenetic",
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
      blockers: [],
    },
    ...overrides,
  }
}

function transport(overrides: Partial<TransportStatus> = {}): TransportStatus {
  return {
    tag: "legacy-native",
    type: "native",
    interface: "nwg2",
    state: "up",
    updated_at: "2026-07-26T00:00:00Z",
    desired_up: true,
    ...overrides,
  }
}
