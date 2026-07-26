import { describe, expect, test } from "bun:test"

import {
  buildNativeTransportCandidates,
  formatNativeTransportCandidate,
  getHiddenNativeInterfaceIds,
  normalizeHiddenNativeInterfaceIds,
  updateHiddenNativeInterfacePreference,
} from "../src/lib/hidden-native-interfaces"
import type { NativeInterfaceModel } from "../src/lib/native-interfaces"

describe("server-persisted hidden native interface preference", () => {
  test("normalizes invalid, duplicate and blank ids", () => {
    expect(
      normalizeHiddenNativeInterfaceIds([
        "Wireguard0",
        "",
        42,
        " Wireguard0 ",
        "OpenVPN0",
      ])
    ).toEqual(["OpenVPN0", "Wireguard0"])
  })

  test("legacy config without preferences yields an empty set", () => {
    expect(getHiddenNativeInterfaceIds({})).toEqual(new Set())
  })

  test("hiding preserves other UI preferences and sorts ids", () => {
    const updated = updateHiddenNativeInterfacePreference(
      {
        ui_preferences: {
          hidden_native_interface_ids: ["Wireguard1"],
          plain_dns_templates: [
            {
              name: "Office DNS",
              primary_ipv4: "192.0.2.53",
            },
          ],
        },
      },
      "Wireguard0",
      true
    )

    expect(updated.ui_preferences).toEqual({
      hidden_native_interface_ids: ["Wireguard0", "Wireguard1"],
      plain_dns_templates: [
        {
          name: "Office DNS",
          primary_ipv4: "192.0.2.53",
        },
      ],
    })
  })

  test("showing removes only the selected id", () => {
    const updated = updateHiddenNativeInterfacePreference(
      {
        ui_preferences: {
          hidden_native_interface_ids: ["OpenVPN0", "Wireguard0"],
        },
      },
      "Wireguard0",
      false
    )

    expect(
      updated.ui_preferences?.hidden_native_interface_ids
    ).toEqual(["OpenVPN0"])
  })

  test("keeps hidden interfaces in creation candidates with an explicit flag", () => {
    const nativeInterfaces: NativeInterfaceModel[] = [
      {
        id: "Wireguard0",
        label: "Main WG",
        logicalName: "Wireguard0",
        kernelName: "nwg0",
        protocol: {
          kind: "wireguard",
          label: "WG",
          evidence: "ndms-kind",
          exact: true,
        },
        live: true,
        source: {
          id: "Wireguard0",
          firmware_interface_name: "Wireguard0",
          kernel_name: "nwg0",
          label: "Main WG",
          firmware_type: "Wireguard",
          kind: "wireguard",
          role: "client",
          owner: "keenetic",
          capabilities: {
            can_edit: false,
            can_delete: false,
            can_hide: true,
            backup_required: true,
          },
          management_readiness: {
            candidate: false,
            identity_stable: true,
            observed_revision: "revision-wg",
            configuration_snapshot_available: false,
            blockers: ["typed_rci_unavailable"],
          },
        },
      },
      {
        id: "OpenVPN0",
        label: "Server",
        logicalName: "OpenVPN0",
        protocol: {
          kind: "openvpn",
          label: "OPENVPN",
          evidence: "ndms-kind",
          exact: true,
        },
        live: false,
        source: {
          id: "OpenVPN0",
          firmware_interface_name: "OpenVPN0",
          label: "Server",
          firmware_type: "OpenVPN",
          kind: "openvpn",
          role: "server",
          owner: "keenetic",
          capabilities: {
            can_edit: false,
            can_delete: false,
            can_hide: true,
            backup_required: true,
          },
          management_readiness: {
            candidate: false,
            identity_stable: false,
            observed_revision: "revision-openvpn",
            configuration_snapshot_available: false,
            blockers: ["unsupported_role"],
          },
        },
      },
    ]

    const candidates = buildNativeTransportCandidates(nativeInterfaces, {
      ui_preferences: {
        hidden_native_interface_ids: ["Wireguard0"],
      },
    })

    expect(candidates).toEqual([
      {
        id: "Wireguard0",
        interfaceName: "nwg0",
        label: "Main WG",
        protocol: "WG",
        hidden: true,
        selectable: true,
      },
      {
        id: "OpenVPN0",
        interfaceName: undefined,
        label: "Server",
        protocol: "OPENVPN",
        hidden: false,
        selectable: false,
      },
    ])

    expect(
      formatNativeTransportCandidate(candidates[0]!, {
        hidden: "скрытое",
        unavailable: "недоступно",
      })
    ).toBe("Main WG · WG · скрытое")
    expect(
      formatNativeTransportCandidate(candidates[1]!, {
        hidden: "скрытое",
        unavailable: "недоступно",
      })
    ).toBe("Server · OPENVPN · недоступно")
  })
})
