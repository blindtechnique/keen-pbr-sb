import { afterEach, describe, expect, test } from "bun:test"

import type { TransportSpec } from "../src/api/generated/model"
import { persistNativeWireGuardImportCountry } from "../src/lib/native-wireguard-import-country"

const originalFetch = globalThis.fetch
afterEach(() => {
  globalThis.fetch = originalFetch
})
const original: TransportSpec = {
  tag: "vpn",
  type: "native",
  interface: "nwg1",
  geo_mode: "auto",
  display_name: "Original alias",
  auto_start: true,
}

describe("native automatic country completion", () => {
  test("delayed lookup sends only country and exact identity, never a stale spec", async () => {
    let finishLookup!: (value: Response) => void
    const requests: { url: string; body: unknown }[] = []
    globalThis.fetch = (async (url, init) => {
      requests.push({ url: String(url), body: JSON.parse(String(init?.body)) })
      if (String(url) === "/api/system/geo") {
        return new Promise<Response>((resolve) => {
          finishLookup = resolve
        })
      }
      return Response.json({ updated: true, config_revision: "new" })
    }) as typeof fetch
    const completion = persistNativeWireGuardImportCountry(
      original,
      "vpn.example"
    )
    finishLookup(
      Response.json({
        locations: {
          "vpn.example": { country: "Germany", country_code: "DE" },
        },
      })
    )
    expect(await completion).toBe(true)
    expect(requests[1]).toEqual({
      url: "/api/transports/geo",
      body: {
        tag: "vpn",
        expected_interface: "nwg1",
        country_code: "DE",
        country: "Germany",
      },
    })
    expect(requests).toHaveLength(2)
  })

  test("manual-mode or replaced-interface server no-op is a normal completion", async () => {
    globalThis.fetch = (async (url) =>
      String(url) === "/api/system/geo"
        ? Response.json({
            locations: {
              "vpn.example": { country: "Germany", country_code: "DE" },
            },
          })
        : Response.json({
            updated: false,
            config_revision: "manual-edit",
          })) as typeof fetch
    expect(
      await persistNativeWireGuardImportCountry(original, "vpn.example")
    ).toBe(false)
  })

  test("does not resolve or write a manual or non-native transport", async () => {
    globalThis.fetch = (async () => {
      throw new Error("unexpected request")
    }) as typeof fetch
    expect(
      await persistNativeWireGuardImportCountry(
        { ...original, geo_mode: "manual" },
        "vpn.example"
      )
    ).toBe(false)
    expect(
      await persistNativeWireGuardImportCountry(
        { ...original, type: "sing-box" },
        "vpn.example"
      )
    ).toBe(false)
  })

  test("both normal and recovered native import use the narrow helper", async () => {
    for (const file of ["transport-upsert-page.tsx", "transports-page.tsx"]) {
      const source = await Bun.file(
        new URL(`../src/pages/${file}`, import.meta.url)
      ).text()
      expect(source).toContain("persistNativeWireGuardImportCountry(transport,")
      expect(source).not.toContain("resolveNativeWireGuardImportLocation(")
    }
  })
})
