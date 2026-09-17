import { describe, expect, test } from "bun:test"

import {
  buildStagedNativeWireGuardTransport,
  cancelActiveNativeWireGuardImportCompletion,
  clearStagedNativeWireGuardImportCompletion,
  findStagedNativeWireGuardImportIdentity,
  offerNativeWireGuardImportCompletion,
  readStagedNativeWireGuardImportCompletion,
  readBackgroundNativeWireGuardImportCompletionTag,
  rememberNativeWireGuardImportedIdentity,
  stagedNativeWireGuardLinkState,
  subscribeNativeWireGuardImportCompletion,
  registerActiveNativeWireGuardImportCompletion,
  stageNativeWireGuardImportCompletion,
} from "@/lib/native-wireguard-import-completion"

const identity = {
  firmwareInterface: "Wireguard6",
  kernelInterface: "nwg6",
  kind: "amnezia_wireguard" as const,
}

describe("active native import completion hand-off", () => {
  test("gives a recovered identity to the open import form", () => {
    let received: typeof identity | undefined
    const unsubscribe = registerActiveNativeWireGuardImportCompletion(
      (next) => {
        received = next
        return true
      }
    )
    try {
      expect(offerNativeWireGuardImportCompletion(identity)).toBe(true)
      expect(received).toEqual(identity)
    } finally {
      unsubscribe()
    }
    expect(offerNativeWireGuardImportCompletion(identity)).toBe(false)
  })

  test("an old StrictMode cleanup cannot unregister the current form", () => {
    const first = registerActiveNativeWireGuardImportCompletion(() => false)
    const second = registerActiveNativeWireGuardImportCompletion(() => true)
    first()
    expect(offerNativeWireGuardImportCompletion(identity)).toBe(true)
    second()
  })

  test("cancels a waiting form after authoritative no-work absence", () => {
    let cancelled = false
    const unsubscribe = registerActiveNativeWireGuardImportCompletion(
      (next) => {
        cancelled = next === null
        return true
      }
    )
    try {
      cancelActiveNativeWireGuardImportCompletion()
      expect(cancelled).toBe(true)
    } finally {
      unsubscribe()
    }
  })

  test("keeps the non-secret operator plan after the import form closes", () => {
    stageNativeWireGuardImportCompletion({
      tag: "vpn_sdd45",
      displayName: "  vpn-sdd45  ",
      createOutbound: true,
      strictEnforcement: false,
      autoStart: false,
      geoMode: "auto",
      endpointHost: " 95.85.242.33 ",
    })

    const plan = readStagedNativeWireGuardImportCompletion()
    expect(plan).toEqual({
      tag: "vpn_sdd45",
      displayName: "vpn-sdd45",
      createOutbound: true,
      strictEnforcement: false,
      autoStart: false,
      geoMode: "auto",
      endpointHost: "95.85.242.33",
    })
    expect(buildStagedNativeWireGuardTransport(plan!, identity)).toEqual({
      tag: "vpn_sdd45",
      display_name: "vpn-sdd45",
      type: "native",
      interface: "nwg6",
      auto_start: false,
      geo_mode: "auto",
      country_code: undefined,
      country: undefined,
    })

    clearStagedNativeWireGuardImportCompletion()
    expect(readStagedNativeWireGuardImportCompletion()).toBeUndefined()
  })

  test("recovers newly allowed slots only with exact panel ownership", () => {
    const plan = {
      tag: "imported_awg",
      displayName: "Imported AWG",
      createOutbound: true,
      autoStart: true,
    }
    for (const slot of [0, 4, 99, 126]) {
      const row = {
        firmware_interface_name: `Wireguard${slot}`,
        kernel_name: `nwg${slot}`,
        label: plan.displayName,
        kind: "amnezia_wireguard",
        native_mutation: { ownership_state: "panel_owned_active" },
      }
      expect(
        findStagedNativeWireGuardImportIdentity(plan, [row as never], [])
      ).toEqual({
        firmwareInterface: row.firmware_interface_name,
        kernelInterface: row.kernel_name,
        kind: row.kind,
      })
      for (const ownership of ["foreign", "unknown", "panel_owned_deleted"]) {
        expect(
          findStagedNativeWireGuardImportIdentity(
            plan,
            [
              {
                ...row,
                native_mutation: { ownership_state: ownership },
              } as never,
            ],
            []
          )
        ).toBeUndefined()
      }
      expect(
        findStagedNativeWireGuardImportIdentity(
          plan,
          [row as never],
          [row.kernel_name]
        )
      ).toBeUndefined()
      expect(
        findStagedNativeWireGuardImportIdentity(
          plan,
          [{ ...row, label: "Existing VPN" } as never],
          []
        )
      ).toBeUndefined()
    }
  })

  test("recovers one exact untracked panel-owned interface after no-work", () => {
    const plan = {
      tag: "fraystor_awg",
      displayName: "fraystor AWG",
      createOutbound: true,
      autoStart: false,
    }
    const row = {
      firmware_interface_name: "Wireguard5",
      kernel_name: "nwg5",
      label: "fraystor AWG",
      kind: "amnezia_wireguard",
      native_mutation: { ownership_state: "panel_owned_active" },
    }

    expect(
      findStagedNativeWireGuardImportIdentity(plan, [row as never], [])
    ).toEqual({
      firmwareInterface: "Wireguard5",
      kernelInterface: "nwg5",
      kind: "amnezia_wireguard",
    })
    expect(
      findStagedNativeWireGuardImportIdentity(plan, [row as never], ["nwg5"])
    ).toBeUndefined()
    expect(
      findStagedNativeWireGuardImportIdentity(
        plan,
        [
          row as never,
          { ...row, firmware_interface_name: "Wireguard6" } as never,
        ],
        []
      )
    ).toBeUndefined()
  })
})

describe("panel completion after the native journal is gone", () => {
  const plan = {
    tag: "imported_awg",
    displayName: "Imported AWG",
    createOutbound: true,
    autoStart: false,
  }
  const transport = buildStagedNativeWireGuardTransport(plan, identity)
  const outbound = {
    type: "interface" as const,
    tag: plan.tag,
    interface: identity.kernelInterface,
  }

  test("a saved tab plan wakes recovery after reload but not while its form owns completion", () => {
    let changes = 0
    const stop = subscribeNativeWireGuardImportCompletion(() => {
      changes++
    })
    try {
      stageNativeWireGuardImportCompletion(plan)
      expect(readBackgroundNativeWireGuardImportCompletionTag()).toBe(plan.tag)
      const closeForm = registerActiveNativeWireGuardImportCompletion(
        () => true
      )
      expect(readBackgroundNativeWireGuardImportCompletionTag()).toBeUndefined()
      closeForm()
      expect(readBackgroundNativeWireGuardImportCompletionTag()).toBe(plan.tag)
      clearStagedNativeWireGuardImportCompletion(plan.tag)
      expect(readBackgroundNativeWireGuardImportCompletionTag()).toBeUndefined()
      expect(changes).toBe(4)
    } finally {
      stop()
      clearStagedNativeWireGuardImportCompletion()
    }
  })

  test("remembers the confirmed interface without depending on its later alias", () => {
    stageNativeWireGuardImportCompletion(plan)
    rememberNativeWireGuardImportedIdentity(identity)
    const stored = readStagedNativeWireGuardImportCompletion()!
    expect(stored.identity).toEqual(identity)
    const row = {
      firmware_interface_name: identity.firmwareInterface,
      kernel_name: identity.kernelInterface,
      label: "Renamed VPN",
      kind: identity.kind,
      native_mutation: { ownership_state: "panel_owned_active" },
    }
    expect(
      findStagedNativeWireGuardImportIdentity(stored, [row as never], [])
    ).toEqual(identity)
    expect(
      findStagedNativeWireGuardImportIdentity(
        stored,
        [{ ...row, kernel_name: "foreign0" } as never],
        []
      )
    ).toBeUndefined()
    clearStagedNativeWireGuardImportCompletion()
  })

  test("does not create a duplicate after an apply succeeded but its response was lost", () => {
    expect(stagedNativeWireGuardLinkState(plan, identity, [], [])).toBe(
      "create"
    )
    expect(
      stagedNativeWireGuardLinkState(plan, identity, [transport], [outbound])
    ).toBe("complete")
  })

  test("does not mistake a visible tracker or a foreign route for completed linking", () => {
    expect(
      stagedNativeWireGuardLinkState(plan, identity, [transport], [])
    ).toBe("conflict")
    expect(stagedNativeWireGuardLinkState(plan, identity, [], [outbound])).toBe(
      "conflict"
    )
    expect(
      stagedNativeWireGuardLinkState(
        plan,
        identity,
        [{ ...transport, interface: "foreign0" }],
        [outbound]
      )
    ).toBe("conflict")
    expect(
      stagedNativeWireGuardLinkState(
        plan,
        identity,
        [transport],
        [{ ...outbound, interface: "foreign0" }]
      )
    ).toBe("conflict")
    expect(
      stagedNativeWireGuardLinkState(
        plan,
        identity,
        [{ ...transport, tag: "existing_vpn" }],
        []
      )
    ).toBe("conflict")
  })

  test("honors the explicit choice not to create a route", () => {
    const trackerOnly = { ...plan, createOutbound: false }
    expect(stagedNativeWireGuardLinkState(trackerOnly, identity, [], [])).toBe(
      "create"
    )
    expect(
      stagedNativeWireGuardLinkState(trackerOnly, identity, [transport], [])
    ).toBe("complete")
  })
})
