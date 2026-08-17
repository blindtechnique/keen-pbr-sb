import { describe, expect, test } from "bun:test"

import type { NativeInterfaceModel } from "../src/lib/native-interfaces"
import {
  buildInternalVpnServerOptions,
  getInternalVpnServerProcessClients,
  getInternalVpnServerStatus,
  normalizeInternalVpnServerInterfaceNames,
  normalizeInternalVpnServerOverrides,
  reconcileInternalVpnServerOverrides,
  removeInternalVpnServerOverride,
  updateInternalVpnServerOverride,
} from "../src/lib/internal-vpn-server-policy"

describe("internal VPN server policy", () => {
  test("uses only NDMS servers with a resolved kernel interface", () => {
    const options = buildInternalVpnServerOptions({
      nativeInterfaces: [
        nativeInterface({ id: "server", role: "server" }),
        nativeInterface({ id: "client", role: "client" }),
        nativeInterface({ id: "unknown", role: "unknown" }),
        nativeInterface({
          id: "unresolved-server",
          role: "server",
          kernelName: "",
        }),
      ],
    })

    expect(options.map(({ key }) => key)).toEqual(["server"])
  })

  test("offers all supported native VPN servers and excludes proxy records", () => {
    const options = buildInternalVpnServerOptions({
      nativeInterfaces: [
        nativeInterface({ id: "wg", kind: "wireguard" }),
        nativeInterface({
          id: "awg",
          kind: "amnezia_wireguard",
          kernelName: "nwg1",
        }),
        nativeInterface({
          id: "openvpn",
          kind: "openvpn",
          kernelName: "tun0",
        }),
        nativeInterface({ id: "ike", kind: "ike", kernelName: "ipsec0" }),
        nativeInterface({ id: "l2tp", kind: "l2tp", kernelName: "l2tp0" }),
        nativeInterface({ id: "sstp", kind: "sstp", kernelName: "sstp0" }),
        nativeInterface({
          id: "openconnect",
          kind: "openconnect",
          kernelName: "vpn0",
        }),
        nativeInterface({
          id: "http-proxy",
          kind: "http_proxy",
          kernelName: "proxy0",
        }),
      ],
    })

    expect(options.map(({ key }) => key)).toEqual([
      "wg",
      "awg",
      "openvpn",
      "ike",
      "l2tp",
      "sstp",
      "openconnect",
    ])
  })

  test("fresh pooled service inventory hides its duplicate legacy toggle", () => {
    const l2tp = nativeInterface({
      id: "L2TP0",
      kind: "l2tp",
      kernelName: "L2tp0",
    })
    const wireguard = nativeInterface({
      id: "Wireguard0",
      kind: "wireguard",
      kernelName: "nwg0",
    })
    const authoritativeServices = [
      {
        id: "ndms-crypto-map:l2tp:server",
        kind: "l2tp" as const,
        label: "L2TP server",
        enabled: true,
        bound_interface_id: "L2tp0",
        source_cidrs: ["172.16.0.0/24"],
        inventory_revision: "a".repeat(64),
      },
    ]

    expect(
      buildInternalVpnServerOptions({
        nativeInterfaces: [l2tp, wireguard],
        overrides: [
          {
            interface: "L2tp0",
            ndms_id: "L2TP0",
            process_clients: false,
          },
        ],
        authoritativeServices,
      }).map(({ key }) => key)
    ).toEqual(["Wireguard0"])

    expect(
      buildInternalVpnServerOptions({
        nativeInterfaces: [l2tp, wireguard],
        overrides: [
          {
            interface: "L2tp0",
            ndms_id: "L2TP0",
            process_clients: false,
          },
        ],
      }).map(({ key }) => key)
    ).toEqual(["L2TP0", "Wireguard0"])
  })

  test("keeps a saved proxy policy synthetic and removable", () => {
    const [option] = buildInternalVpnServerOptions({
      nativeInterfaces: [
        nativeInterface({
          id: "Proxy0",
          kind: "http_proxy",
          kernelName: "proxy0",
        }),
      ],
      overrides: [
        {
          interface: "proxy0",
          ndms_id: "Proxy0",
          process_clients: false,
        },
      ],
    })

    expect(option).toEqual({
      key: "missing:ndms:Proxy0",
      ndmsId: "Proxy0",
      interfaceName: "proxy0",
      label: "proxy0",
      requiresRoleConfirmation: false,
      missing: true,
    })
  })

  test("does not require native-interface mutation readiness", () => {
    const [option] = buildInternalVpnServerOptions({
      nativeInterfaces: [
        nativeInterface({
          id: "read-only-server",
          identityStable: false,
        }),
      ],
    })

    expect(option).toMatchObject({
      key: "read-only-server",
      interfaceName: "nwg0",
      missing: false,
    })
  })

  test("deduplicates duplicate NDMS rows by the kernel policy key", () => {
    const options = buildInternalVpnServerOptions({
      nativeInterfaces: [
        nativeInterface({ id: "first", kernelName: "nwg0" }),
        nativeInterface({ id: "duplicate", kernelName: "nwg0" }),
      ],
    })

    expect(options.map(({ key }) => key)).toEqual(["first"])
  })

  test("adds a synthetic row for a persisted missing interface", () => {
    const options = buildInternalVpnServerOptions({
      nativeInterfaces: [nativeInterface({ id: "visible" })],
      overrides: [
        { interface: "nwg0", process_clients: true },
        { interface: "nwg9", process_clients: false },
      ],
    })

    expect(options).toHaveLength(2)
    expect(options[1]).toEqual({
      key: "missing:nwg9",
      interfaceName: "nwg9",
      label: "nwg9",
      requiresRoleConfirmation: false,
      missing: true,
    })
  })

  test("offers a structural WireGuard candidate but requires explicit role confirmation", () => {
    const [option] = buildInternalVpnServerOptions({
      nativeInterfaces: [
        nativeInterface({
          id: "roleless-server",
          role: "unknown",
          candidate: true,
          requiresRoleConfirmation: true,
        }),
      ],
    })

    expect(option).toMatchObject({
      key: "roleless-server",
      requiresRoleConfirmation: true,
      missing: false,
    })
  })

  test("inherits all-ingress legacy behavior without materializing overrides", () => {
    expect(
      getInternalVpnServerProcessClients({
        interfaceName: "nwg0",
        overrides: undefined,
        legacyInboundInterfaces: [],
      })
    ).toBe(true)
  })

  test("inherits a non-empty legacy allowlist by exact kernel name", () => {
    expect(
      getInternalVpnServerProcessClients({
        interfaceName: "nwg0",
        legacyInboundInterfaces: ["nwg0"],
      })
    ).toBe(true)
    expect(
      getInternalVpnServerProcessClients({
        interfaceName: "nwg1",
        legacyInboundInterfaces: ["Wireguard1"],
      })
    ).toBe(false)
  })

  test("explicit true and false overrides win over legacy derivation", () => {
    expect(
      getInternalVpnServerProcessClients({
        interfaceName: "nwg0",
        overrides: [{ interface: "nwg0", process_clients: false }],
        legacyInboundInterfaces: [],
      })
    ).toBe(false)
    expect(
      getInternalVpnServerProcessClients({
        interfaceName: "nwg1",
        overrides: [{ interface: "nwg1", process_clients: true }],
        legacyInboundInterfaces: ["br0"],
      })
    ).toBe(true)
  })

  test("stable NDMS identity wins when the kernel interface name changes", () => {
    const [server] = buildInternalVpnServerOptions({
      nativeInterfaces: [
        nativeInterface({ id: "Wireguard0", kernelName: "nwg1" }),
      ],
      overrides: [
        {
          interface: "nwg0",
          ndms_id: "Wireguard0",
          process_clients: false,
        },
      ],
    })

    expect(server).toMatchObject({
      key: "Wireguard0",
      ndmsId: "Wireguard0",
      interfaceName: "nwg1",
      missing: false,
    })
    expect(
      getInternalVpnServerProcessClients({
        ndmsId: server.ndmsId,
        interfaceName: server.interfaceName,
        overrides: [
          {
            interface: "nwg0",
            ndms_id: "Wireguard0",
            process_clients: false,
          },
        ],
        legacyInboundInterfaces: [],
      })
    ).toBe(false)
  })

  test("first explicit toggle stores only the changed interface", () => {
    const next = updateInternalVpnServerOverride({
      interfaceName: "nwg0",
      processClients: false,
      overrides: undefined,
      baselineOverrides: undefined,
      legacyInboundInterfaces: [],
    })

    expect(next).toEqual([{ interface: "nwg0", process_clients: false }])
  })

  test("a native server toggle stores its stable NDMS identity and interface fallback", () => {
    const next = updateInternalVpnServerOverride({
      ndmsId: "Wireguard0",
      interfaceName: "nwg0",
      processClients: false,
      overrides: undefined,
      baselineOverrides: undefined,
      legacyInboundInterfaces: [],
    })

    expect(next).toEqual([
      {
        interface: "nwg0",
        ndms_id: "Wireguard0",
        process_clients: false,
      },
    ])
  })

  test("explicit role confirmation persists even when it equals inherited behavior", () => {
    const confirmed = updateInternalVpnServerOverride({
      ndmsId: "Wireguard0",
      interfaceName: "nwg0",
      processClients: true,
      forceExplicit: true,
      overrides: undefined,
      baselineOverrides: undefined,
      legacyInboundInterfaces: [],
    })

    expect(confirmed).toEqual([
      {
        interface: "nwg0",
        ndms_id: "Wireguard0",
        process_clients: true,
      },
    ])
    expect(
      reconcileInternalVpnServerOverrides({
        overrides: confirmed,
        baselineOverrides: undefined,
        legacyInboundInterfaces: [],
        baselineLegacyInboundInterfaces: [],
        rolelessConfirmationNdmsIds: ["Wireguard0"],
      })
    ).toEqual(confirmed)
  })

  test("role confirmation preserves inherited exclusion instead of enabling clients", () => {
    const inherited = getInternalVpnServerProcessClients({
      ndmsId: "Wireguard0",
      interfaceName: "nwg0",
      overrides: undefined,
      legacyInboundInterfaces: ["br0"],
    })
    expect(inherited).toBe(false)

    expect(
      updateInternalVpnServerOverride({
        ndmsId: "Wireguard0",
        interfaceName: "nwg0",
        processClients: inherited,
        forceExplicit: true,
        overrides: undefined,
        baselineOverrides: undefined,
        legacyInboundInterfaces: ["br0"],
      })
    ).toEqual([
      {
        interface: "nwg0",
        ndms_id: "Wireguard0",
        process_clients: false,
      },
    ])
  })

  test("editing and restoring a legacy row does not force an identity migration", () => {
    const baseline = [{ interface: "nwg0", process_clients: true }] as const
    const changed = updateInternalVpnServerOverride({
      ndmsId: "Wireguard0",
      interfaceName: "nwg0",
      processClients: false,
      overrides: baseline,
      baselineOverrides: baseline,
      legacyInboundInterfaces: [],
    })
    const restored = updateInternalVpnServerOverride({
      ndmsId: "Wireguard0",
      interfaceName: "nwg0",
      processClients: true,
      overrides: changed,
      baselineOverrides: baseline,
      legacyInboundInterfaces: [],
    })

    expect(changed).toEqual([
      {
        interface: "nwg0",
        ndms_id: "Wireguard0",
        process_clients: false,
      },
    ])
    expect(restored).toEqual(baseline)
  })

  test("policy toggle preserves a renamed server fallback without colliding with another server", () => {
    const baseline = [
      {
        interface: "nwg0",
        ndms_id: "Wireguard0",
        process_clients: true,
      },
      {
        interface: "nwg1",
        ndms_id: "Wireguard1",
        process_clients: true,
      },
    ] as const

    const changed = updateInternalVpnServerOverride({
      ndmsId: "Wireguard0",
      // NDMS now reports Wireguard0 as nwg1, which is already the persisted
      // fallback of Wireguard1. A policy toggle is not an interface migration.
      interfaceName: "nwg1",
      processClients: false,
      overrides: baseline,
      baselineOverrides: baseline,
      legacyInboundInterfaces: [],
    })

    expect(changed).toEqual([
      {
        interface: "nwg0",
        ndms_id: "Wireguard0",
        process_clients: false,
      },
      {
        interface: "nwg1",
        ndms_id: "Wireguard1",
        process_clients: true,
      },
    ])
  })

  test("returning to an absent baseline removes the derived override", () => {
    const changed = updateInternalVpnServerOverride({
      interfaceName: "nwg0",
      processClients: false,
      overrides: undefined,
      baselineOverrides: undefined,
      legacyInboundInterfaces: [],
    })
    const restored = updateInternalVpnServerOverride({
      interfaceName: "nwg0",
      processClients: true,
      overrides: changed,
      baselineOverrides: undefined,
      legacyInboundInterfaces: [],
    })

    expect(restored).toBeUndefined()
  })

  test("returning to an explicit baseline restores its exact array", () => {
    const baseline = [
      { interface: "nwg9", process_clients: false },
      { interface: "nwg0", process_clients: true },
    ] as const
    const changed = updateInternalVpnServerOverride({
      interfaceName: "nwg0",
      processClients: false,
      overrides: baseline,
      baselineOverrides: baseline,
      legacyInboundInterfaces: [],
    })
    const restored = updateInternalVpnServerOverride({
      interfaceName: "nwg0",
      processClients: true,
      overrides: changed,
      baselineOverrides: baseline,
      legacyInboundInterfaces: [],
    })

    expect(restored).toEqual(baseline)
  })

  test("inherit removes an explicit override instead of storing a derived value", () => {
    expect(
      removeInternalVpnServerOverride({
        interfaceName: "nwg0",
        overrides: [{ interface: "nwg0", process_clients: false }],
        baselineOverrides: [{ interface: "nwg0", process_clients: false }],
      })
    ).toBeUndefined()
  })

  test("inherit removes only the matching stable identity when interfaces collide", () => {
    const remaining = removeInternalVpnServerOverride({
      ndmsId: "Wireguard0",
      interfaceName: "nwg0",
      overrides: [
        {
          interface: "nwg0",
          ndms_id: "Wireguard0",
          process_clients: false,
        },
        {
          interface: "nwg0",
          ndms_id: "Wireguard1",
          process_clients: true,
        },
      ],
    })

    expect(remaining).toEqual([
      {
        interface: "nwg0",
        ndms_id: "Wireguard1",
        process_clients: true,
      },
    ])
  })

  test("inherit preserves an explicit empty baseline representation", () => {
    expect(
      removeInternalVpnServerOverride({
        interfaceName: "nwg0",
        overrides: [{ interface: "nwg0", process_clients: false }],
        baselineOverrides: [],
      })
    ).toEqual([])
  })

  test("restoring the baseline ingress set also restores a semantically equal override baseline", () => {
    const restored = reconcileInternalVpnServerOverrides({
      overrides: [{ interface: "nwg0", process_clients: true }],
      baselineOverrides: undefined,
      legacyInboundInterfaces: [],
      baselineLegacyInboundInterfaces: [],
    })

    expect(restored).toBeUndefined()
  })

  test("ordinary stable row returns to a pristine absent baseline", () => {
    const restored = reconcileInternalVpnServerOverrides({
      overrides: [
        {
          interface: "nwg0",
          ndms_id: "Wireguard0",
          process_clients: false,
        },
      ],
      baselineOverrides: undefined,
      legacyInboundInterfaces: ["br0"],
      baselineLegacyInboundInterfaces: ["br0"],
      rolelessConfirmationNdmsIds: [],
    })

    expect(restored).toBeUndefined()
  })

  test("session confirmation survives stale inventory while ingress edits round-trip", () => {
    const confirmed = [
      {
        interface: "nwg0",
        ndms_id: "Wireguard0",
        process_clients: false,
      },
    ] as const

    // The live stale inventory masks confirmation_required=false. The page
    // still supplies its session-local confirmed ID until Inherit/Cancel.
    const whileEdited = reconcileInternalVpnServerOverrides({
      overrides: confirmed,
      baselineOverrides: undefined,
      legacyInboundInterfaces: ["br0", "guest"],
      baselineLegacyInboundInterfaces: ["br0"],
      rolelessConfirmationNdmsIds: ["Wireguard0"],
    })
    const restored = reconcileInternalVpnServerOverrides({
      overrides: whileEdited,
      baselineOverrides: undefined,
      legacyInboundInterfaces: ["br0"],
      baselineLegacyInboundInterfaces: ["br0"],
      rolelessConfirmationNdmsIds: ["Wireguard0"],
    })

    expect(restored).toEqual(confirmed)
  })

  test("reconcile compares stable identities across a kernel interface rename", () => {
    const baseline = [
      {
        interface: "nwg0",
        ndms_id: "Wireguard0",
        process_clients: false,
      },
    ] as const
    const restored = reconcileInternalVpnServerOverrides({
      overrides: [
        {
          interface: "nwg1",
          ndms_id: "Wireguard0",
          process_clients: false,
        },
      ],
      baselineOverrides: baseline,
      legacyInboundInterfaces: [],
      baselineLegacyInboundInterfaces: [],
    })

    expect(restored).toEqual(baseline)
  })

  test("reconcile does not conflate different stable identities sharing a fallback", () => {
    const current = [
      {
        interface: "nwg0",
        ndms_id: "Wireguard1",
        process_clients: false,
      },
    ] as const
    const reconciled = reconcileInternalVpnServerOverrides({
      overrides: current,
      baselineOverrides: [
        {
          interface: "nwg0",
          ndms_id: "Wireguard0",
          process_clients: false,
        },
      ],
      legacyInboundInterfaces: [],
      baselineLegacyInboundInterfaces: [],
    })

    expect(reconciled).toEqual(current)
  })

  test("does not erase an explicit choice while the ingress policy is still different", () => {
    const current = [{ interface: "nwg0", process_clients: true }] as const
    const reconciled = reconcileInternalVpnServerOverrides({
      overrides: current,
      baselineOverrides: undefined,
      legacyInboundInterfaces: ["br0"],
      baselineLegacyInboundInterfaces: [],
    })

    expect(reconciled).toEqual(current)
  })

  test("does not restore the baseline when the effective server policy differs", () => {
    const reconciled = reconcileInternalVpnServerOverrides({
      overrides: [{ interface: "nwg0", process_clients: false }],
      baselineOverrides: undefined,
      legacyInboundInterfaces: [],
      baselineLegacyInboundInterfaces: [],
    })

    expect(reconciled).toEqual([{ interface: "nwg0", process_clients: false }])
  })

  test("retains missing-interface overrides while editing another server", () => {
    const next = updateInternalVpnServerOverride({
      interfaceName: "nwg0",
      processClients: false,
      overrides: [{ interface: "nwg9", process_clients: false }],
      baselineOverrides: [{ interface: "nwg9", process_clients: false }],
      legacyInboundInterfaces: [],
    })

    expect(next).toEqual([
      { interface: "nwg0", process_clients: false },
      { interface: "nwg9", process_clients: false },
    ])
  })

  test("normalizes interface keys without losing explicit false values", () => {
    expect(
      normalizeInternalVpnServerOverrides([
        { interface: " nwg1 ", process_clients: true },
        { interface: "nwg1", process_clients: false },
        { interface: " ", process_clients: true },
      ])
    ).toEqual([{ interface: "nwg1", process_clients: false }])
  })

  test("normalizes and deduplicates stable identities without losing ndms_id", () => {
    expect(
      normalizeInternalVpnServerOverrides([
        {
          interface: "nwg0",
          ndms_id: " Wireguard0 ",
          process_clients: true,
        },
        {
          interface: "nwg1",
          ndms_id: "Wireguard0",
          process_clients: false,
        },
      ])
    ).toEqual([
      {
        interface: "nwg1",
        ndms_id: "Wireguard0",
        process_clients: false,
      },
    ])
  })

  test("normalizes the legacy ingress allowlist as an unordered set", () => {
    expect(
      normalizeInternalVpnServerInterfaceNames([" nwg1 ", "br0", "nwg1", ""])
    ).toEqual(["br0", "nwg1"])
  })

  test("does not report a server down before both inventories are ready", () => {
    const [server] = buildInternalVpnServerOptions({
      nativeInterfaces: [nativeInterface({ id: "server" })],
    })

    expect(
      getInternalVpnServerStatus({
        server,
        inventoryReady: false,
        runtimeState: "loading",
      })
    ).toBe("unknown")
    expect(
      getInternalVpnServerStatus({
        server,
        inventoryReady: true,
        runtimeState: "error",
      })
    ).toBe("unknown")
    expect(
      getInternalVpnServerStatus({
        server,
        inventoryReady: true,
        runtimeState: "ready",
      })
    ).toBe("up")
  })

  test("marks a persisted missing policy only after inventory is ready", () => {
    const [server] = buildInternalVpnServerOptions({
      nativeInterfaces: [],
      overrides: [{ interface: "nwg9", process_clients: false }],
    })

    expect(
      getInternalVpnServerStatus({
        server,
        inventoryReady: false,
        runtimeState: "ready",
      })
    ).toBe("unknown")
    expect(
      getInternalVpnServerStatus({
        server,
        inventoryReady: true,
        runtimeState: "ready",
      })
    ).toBe("missing")
  })
})

function nativeInterface({
  id,
  role = "server",
  kind = "wireguard",
  logicalName = "Wireguard0",
  kernelName = "nwg0",
  identityStable = true,
  candidate = role === "server",
  requiresRoleConfirmation = false,
}: {
  id: string
  role?: "client" | "server" | "unknown"
  kind?: NativeInterfaceModel["source"]["kind"]
  logicalName?: string
  kernelName?: string
  identityStable?: boolean
  candidate?: boolean
  requiresRoleConfirmation?: boolean
}): NativeInterfaceModel {
  return {
    id,
    label: id,
    logicalName,
    kernelName,
    protocol: {
      kind: "wireguard_ambiguous",
      label: "AWG/WG",
      evidence: "ndms-kind",
      exact: false,
    },
    live: true,
    runtime: kernelName ? { name: kernelName, status: "up" } : undefined,
    source: {
      id,
      firmware_interface_name: logicalName,
      kernel_name: kernelName,
      label: id,
      firmware_type: "Wireguard",
      kind,
      role,
      internal_vpn_server_candidate: candidate,
      internal_vpn_server_role_confirmation_required:
        requiresRoleConfirmation,
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
        candidate: false,
        identity_stable: identityStable,
        observed_revision: "test-revision",
        configuration_snapshot_available: false,
        blockers: [],
      },
    },
  }
}
