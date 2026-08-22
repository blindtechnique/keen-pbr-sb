import { describe, expect, test } from "bun:test"

import {
  offerNativeWireGuardImportCompletion,
  registerActiveNativeWireGuardImportCompletion,
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
})
