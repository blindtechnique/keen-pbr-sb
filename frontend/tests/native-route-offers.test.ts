import { describe, expect, test } from "bun:test"

import type { NativeInterfaceModel } from "../src/lib/native-interfaces"
import { pickNativeRouteOfferCandidates } from "../src/lib/native-route-offers"

/**
 * Вопрос «использовать новый туннель как VPN?» появляется ровно для тех
 * туннелей, к которым маршрут реально можно привязать прямо сейчас и
 * которых человек не отклонял.
 */
describe("native route offer candidates", () => {
  test("offers only unbound, visible, undismissed client tunnels", () => {
    const candidates = pickNativeRouteOfferCandidates({
      nativeInterfaces: [
        native({ id: "Wireguard0", label: "Old AWG", kernelName: "nwg0" }),
        native({ id: "Wireguard1", label: "New AWG", kernelName: "nwg1" }),
        // Роль не сообщена — всё равно предлагается: прошивка часто не
        // называет роль клиентских туннелей.
        native({
          id: "Wireguard2",
          label: "Role unknown AWG",
          kernelName: "nwg2",
          role: "unknown",
        }),
        native({
          id: "Wireguard3",
          label: "Hidden AWG",
          kernelName: "nwg3",
        }),
        native({
          id: "Wireguard4",
          label: "Dismissed AWG",
          kernelName: "nwg4",
        }),
        // Выключенный в KeeneticOS: без системного имени предлагать нечего.
        native({
          id: "Wireguard5",
          label: "Disabled AWG",
          kernelName: undefined,
        }),
        // Серверная форма — не предлагается никогда.
        native({
          id: "Wireguard6",
          label: "Server-shaped AWG",
          kernelName: "nwg6",
          role: "unknown",
          internalVpnServerCandidate: true,
        }),
        // Импорт панели завершается собственным atomic apply и не должен на
        // мгновение выглядеть как внешний туннель KeeneticOS.
        native({
          id: "Wireguard7",
          label: "Panel import",
          kernelName: "nwg7",
          ownershipState: "panel_owned_active",
        }),
        native({
          id: "Openvpn0",
          kind: "openvpn",
          label: "External OpenVPN",
          kernelName: "ovpn0",
        }),
      ],
      boundInterfaceNames: new Set(["nwg0"]),
      hiddenIds: new Set(["Wireguard3"]),
      dismissedIds: new Set(["Wireguard4"]),
    })

    expect(candidates).toEqual([
      { id: "Wireguard1", label: "New AWG", interfaceName: "nwg1" },
      {
        id: "Wireguard2",
        label: "Role unknown AWG",
        interfaceName: "nwg2",
      },
    ])
  })
})

function native({
  id,
  label,
  kernelName,
  role = "client",
  internalVpnServerCandidate = false,
  kind = "amnezia_wireguard",
  ownershipState = "foreign",
}: {
  id: string
  label: string
  kernelName: string | undefined
  role?: "client" | "server" | "unknown"
  internalVpnServerCandidate?: boolean
  kind?: "amnezia_wireguard" | "openvpn"
  ownershipState?: "foreign" | "panel_owned_active"
}): NativeInterfaceModel {
  return {
    id,
    label,
    logicalName: id,
    kernelName,
    protocol: {
      kind: "amneziawg",
      label: "AWG",
      evidence: "ndms-kind",
      exact: true,
    },
    live: Boolean(kernelName),
    source: {
      id,
      firmware_interface_name: id,
      ...(kernelName ? { kernel_name: kernelName } : {}),
      label,
      firmware_type: "Wireguard",
      kind,
      role,
      internal_vpn_server_candidate: internalVpnServerCandidate,
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
        observed_revision: `revision-${id}`,
        configuration_snapshot_available: false,
        blockers: [],
      },
      native_mutation: {
        ownership_state: ownershipState,
      },
    },
  }
}
