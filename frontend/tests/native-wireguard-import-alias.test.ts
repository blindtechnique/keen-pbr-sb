import { describe, expect, test } from "bun:test"

import {
  findNativeWireGuardAliasConflict,
  suggestNativeWireGuardImportAlias,
} from "@/lib/native-wireguard-import-alias"

const interfaces = [
  {
    id: "Wireguard0",
    firmware_interface_name: "Wireguard0",
    label: "Домашний VPN",
  },
]

describe("native WireGuard import alias suggestion", () => {
  test("prefers the file stem and never mutates a draft", () => {
    expect(
      suggestNativeWireGuardImportAlias({
        fileName: " Home WG.CONF ",
        endpointHost: "vpn.example",
      })
    ).toBe("Home WG")
  })

  test("uses the endpoint only as a URI suggestion", () => {
    expect(
      suggestNativeWireGuardImportAlias({ endpointHost: "vpn.example" })
    ).toBe("vpn.example")
  })

  test("detects label and technical-name conflicts case-insensitively", () => {
    expect(
      findNativeWireGuardAliasConflict("домашний vpn", interfaces)?.id
    ).toBe("Wireguard0")
    expect(findNativeWireGuardAliasConflict("WIREGUARD0", interfaces)?.id).toBe(
      "Wireguard0"
    )
    expect(
      findNativeWireGuardAliasConflict("Новый VPN", interfaces)
    ).toBeUndefined()
  })
})
