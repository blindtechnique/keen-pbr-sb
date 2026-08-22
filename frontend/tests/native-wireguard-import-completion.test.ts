import { describe, expect, test } from "bun:test"

import {
  buildStagedNativeWireGuardTransport,
  cancelActiveNativeWireGuardImportCompletion,
  clearStagedNativeWireGuardImportCompletion,
  findStagedNativeWireGuardImportIdentity,
  offerNativeWireGuardImportCompletion,
  readStagedNativeWireGuardImportCompletion,
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
