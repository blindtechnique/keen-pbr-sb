import { describe, expect, test } from "bun:test"

import {
  resolveNativeWireGuardImportLocation,
  resolveNativeWireGuardInterfaceLocation,
} from "@/lib/native-wireguard-import-geo"

describe("native WireGuard import auto country", () => {
  test("polls a pending lookup and returns a normalized country snapshot", async () => {
    let calls = 0
    const sleeps: number[] = []
    const location = await resolveNativeWireGuardImportLocation(
      " 95.85.242.33 ",
      {
        fetchImpl: async (_input, init) => {
          calls += 1
          expect(JSON.parse(String(init?.body))).toEqual({
            hosts: ["95.85.242.33"],
            allow_external_lookup: true,
          })
          return new Response(
            JSON.stringify(
              calls === 1
                ? { locations: {}, pending: true }
                : {
                    locations: {
                      "95.85.242.33": {
                        country: " Netherlands ",
                        country_code: "nl",
                      },
                    },
                    pending: false,
                  }
            ),
            { status: 200 }
          )
        },
        sleep: async (milliseconds) => {
          sleeps.push(milliseconds)
        },
      }
    )

    expect(location).toEqual({
      country: "Netherlands",
      country_code: "NL",
    })
    expect(calls).toBe(2)
    expect(sleeps).toEqual([1_000])
  })

  test("does not invent a flag when lookup is unavailable", async () => {
    const location = await resolveNativeWireGuardImportLocation("vpn.test", {
      fetchImpl: async () =>
        new Response(JSON.stringify({ locations: {}, pending: false }), {
          status: 200,
        }),
      sleep: async () => undefined,
    })
    expect(location).toBeUndefined()
  })

  test("resolves an existing native tunnel from its attributed exit address", async () => {
    const requests: Array<{ url: string; body: unknown }> = []
    const location = await resolveNativeWireGuardInterfaceLocation(" nwg5 ", {
      fetchImpl: async (input, init) => {
        const url = String(input)
        requests.push({ url, body: JSON.parse(String(init?.body)) })
        return url.endsWith("exit-check")
          ? new Response(
              JSON.stringify({
                verdict: "working",
                through: {
                  ok: true,
                  attributed: true,
                  address: "203.0.113.7",
                },
              }),
              { status: 200 }
            )
          : new Response(
              JSON.stringify({
                locations: {
                  "203.0.113.7": {
                    country: "Estonia",
                    country_code: "EE",
                  },
                },
                pending: false,
              }),
              { status: 200 }
            )
      },
    })

    expect(location).toEqual({ country: "Estonia", country_code: "EE" })
    expect(requests).toEqual([
      {
        url: "/api/transports/exit-check",
        body: { interface: "nwg5" },
      },
      {
        url: "/api/system/geo",
        body: {
          hosts: ["203.0.113.7"],
          allow_external_lookup: true,
        },
      },
    ])
  })
})
