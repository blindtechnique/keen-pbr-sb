import { describe, expect, test } from "bun:test"

import {
  buildStagedNativeWireGuardTransport,
  clearStagedNativeWireGuardImportCompletion,
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
})
