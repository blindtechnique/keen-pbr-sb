import { describe, expect, test } from "bun:test"

import {
  NATIVE_WIREGUARD_CONF_MAX_BYTES,
  NATIVE_WIREGUARD_URI_MAX_BYTES,
  classifyNativeWireGuardSensitiveInput,
  createNativeWireGuardFileReadGate,
  normalizeNativeWireGuardSensitiveInput,
  validateNativeWireGuardImportFile,
  validateNativeWireGuardImportText,
} from "@/lib/native-wireguard-import-file"

describe("native WireGuard .conf intake", () => {
  test("accepts a bounded .conf without trusting browser MIME detection", () => {
    expect(
      validateNativeWireGuardImportFile({
        name: "home-WG.CONF",
        size: 512,
        type: "",
      })
    ).toBeUndefined()
    expect(
      validateNativeWireGuardImportFile({
        name: "provider.vpn",
        size: 2048,
        type: "",
      })
    ).toBeUndefined()
  })

  test("rejects the wrong extension, empty files and oversized input", () => {
    expect(
      validateNativeWireGuardImportFile({
        name: "profile.txt",
        size: 64,
        type: "text/plain",
      })
    ).toBe("supported-extension-required")
    expect(
      validateNativeWireGuardImportFile({
        name: "profile.conf",
        size: 0,
        type: "text/plain",
      })
    ).toBe("empty-file")
    expect(
      validateNativeWireGuardImportFile({
        name: "profile.conf",
        size: NATIVE_WIREGUARD_CONF_MAX_BYTES + 1,
        type: "text/plain",
      })
    ).toBe("file-too-large")
    expect(
      validateNativeWireGuardImportFile({
        name: "profile.vpn",
        size: NATIVE_WIREGUARD_URI_MAX_BYTES + 1,
        type: "text/plain",
      })
    ).toBe("file-too-large")
  })

  test("rejects empty, binary and invalidly decoded content", () => {
    expect(validateNativeWireGuardImportText(" \n\t ")).toBe("empty-file")
    expect(validateNativeWireGuardImportText("[Interface]\0PrivateKey=x")).toBe(
      "not-text"
    )
    expect(validateNativeWireGuardImportText("[Interface]\uFFFD")).toBe(
      "not-text"
    )
    expect(
      validateNativeWireGuardImportText("[Interface]\nAddress=10.0.0.2/32")
    ).toBeUndefined()
  })

  test("intercepts native URIs case-insensitively before normal link state", () => {
    for (const value of ["vpn://payload", "VPN://payload", "  VpN://payload"]) {
      expect(classifyNativeWireGuardSensitiveInput(value)).toBe("vpn-uri")
      expect(normalizeNativeWireGuardSensitiveInput(value, "vpn-uri")).toBe(
        "vpn://payload"
      )
    }
    for (const value of [
      "# exported profile\nVPN://payload",
      "Amnezia: vpn://payload",
      "https://provider.example/help\nvpn://payload",
    ]) {
      expect(classifyNativeWireGuardSensitiveInput(value)).toBe("vpn-uri")
      expect(normalizeNativeWireGuardSensitiveInput(value, "vpn-uri")).toBe(
        "vpn://payload"
      )
    }
    expect(
      validateNativeWireGuardImportText(
        `VPN://${"a".repeat(NATIVE_WIREGUARD_CONF_MAX_BYTES)}`
      )
    ).toBeUndefined()
    expect(classifyNativeWireGuardSensitiveInput("vless://example.net")).toBe(
      undefined
    )
  })

  test("intercepts raw or malformed key-bearing configs before Save state", () => {
    for (const value of [
      "[Interface]\nPrivateKey = secret",
      "[peer]\nPublicKey = public",
      "PrivateKey = secret-without-section",
      "PrivateKey: secret-without-equals",
      "preshared_key=secret",
    ]) {
      expect(classifyNativeWireGuardSensitiveInput(value)).toBe("config")
      expect(normalizeNativeWireGuardSensitiveInput(value, "config")).toBe(
        value
      )
    }
  })

  test("invalidates stale asynchronous reads after a newer choice or clear", () => {
    const gate = createNativeWireGuardFileReadGate()
    const first = gate.begin()
    const second = gate.begin()
    expect(gate.isCurrent(first)).toBe(false)
    expect(gate.isCurrent(second)).toBe(true)

    gate.invalidate()
    expect(gate.isCurrent(second)).toBe(false)
  })
})
