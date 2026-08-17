import { describe, expect, test } from "bun:test"

import { nativeWireGuardImportTransportIsProtected } from "@/lib/native-wireguard-import-transport"

describe("native WireGuard import transport boundary", () => {
  test("allows authenticated HTTPS secure contexts", () => {
    expect(
      nativeWireGuardImportTransportIsProtected({
        protocol: "https:",
        secureContext: true,
        authEnabled: true,
        authenticated: true,
        trustedLocalConnection: false,
      })
    ).toBe(true)
  })

  test("rejects plaintext HTTP even when the browser calls it a secure context", () => {
    expect(
      nativeWireGuardImportTransportIsProtected({
        protocol: "http:",
        secureContext: true,
        authEnabled: true,
        authenticated: true,
        trustedLocalConnection: false,
      })
    ).toBe(false)
  })

  test("allows only a server-proven local HTTP connection as the fallback", () => {
    expect(
      nativeWireGuardImportTransportIsProtected({
        protocol: "http:",
        secureContext: false,
        authEnabled: true,
        authenticated: true,
        trustedLocalConnection: true,
      })
    ).toBe(true)
    expect(
      nativeWireGuardImportTransportIsProtected({
        protocol: "http:",
        secureContext: false,
        authEnabled: true,
        authenticated: true,
        trustedLocalConnection: false,
      })
    ).toBe(false)
  })

  test("rejects unauthenticated, auth-disabled and untrusted states", () => {
    for (const state of [
      {
        secureContext: false,
        authEnabled: true,
        authenticated: true,
        trustedLocalConnection: false,
      },
      {
        secureContext: true,
        authEnabled: false,
        authenticated: true,
        trustedLocalConnection: true,
      },
      {
        secureContext: true,
        authEnabled: true,
        authenticated: false,
        trustedLocalConnection: true,
      },
    ]) {
      expect(
        nativeWireGuardImportTransportIsProtected({
          protocol: "https:",
          ...state,
        })
      ).toBe(false)
    }
  })
})
