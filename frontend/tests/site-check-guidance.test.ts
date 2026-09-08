import { describe, expect, test } from "bun:test"

import { siteCheckPresentation } from "../src/components/overview/site-check-guidance"
import type { SiteProbeState } from "../src/components/overview/site-probe-model"

const complete = {
  inputTarget: "example.com",
  activeTarget: "example.com",
  routingStatus: "success" as const,
  browserProbe: { status: "responded" } as SiteProbeState,
  routerProbe: { status: "responded" } as SiteProbeState,
}

describe("completed site check actions", () => {
  test("both responses need no next-step message", () => {
    expect(siteCheckPresentation(complete)).toEqual({
      retry: true,
      guidance: null,
    })
  })

  test("a changed or invalid input is not a repeat of the previous target", () => {
    for (const inputTarget of ["different.example", null]) {
      expect(siteCheckPresentation({ ...complete, inputTarget }).retry).toBe(
        false
      )
    }
  })

  test("no active target has no result actions", () => {
    expect(siteCheckPresentation({ ...complete, activeTarget: null })).toEqual({
      retry: false,
      guidance: null,
    })
  })

  test("idle or pending routing waits for a complete check", () => {
    for (const routingStatus of ["idle", "pending"] as const) {
      expect(siteCheckPresentation({ ...complete, routingStatus })).toEqual({
        retry: false,
        guidance: null,
      })
    }
  })

  test("each unfinished probe suppresses retry and guidance", () => {
    for (const status of ["idle", "checking"] as const) {
      for (const field of ["browserProbe", "routerProbe"] as const) {
        expect(
          siteCheckPresentation({
            ...complete,
            routingStatus: "error",
            [field]: { status },
          })
        ).toEqual({ retry: false, guidance: null })
      }
    }
  })

  test("an inconclusive browser result contrasts only confirmed router response", () => {
    for (const reason of ["browser", "timeout"] as const) {
      expect(
        siteCheckPresentation({
          ...complete,
          browserProbe: { status: "unconfirmed", reason },
        })
      ).toEqual({ retry: true, guidance: "deviceOnly" })
    }
  })

  test("a router DNS failure offers DNS diagnosis", () => {
    expect(
      siteCheckPresentation({
        ...complete,
        routerProbe: { status: "unconfirmed", reason: "dns" },
      }).guidance
    ).toBe("dns")
  })

  test("inconclusive site failures do not guess DNS or client problems", () => {
    for (const reason of [
      "timeout",
      "tls",
      "connection",
      "sizeLimit",
      "unknown",
    ] as const) {
      expect(
        siteCheckPresentation({
          ...complete,
          browserProbe: { status: "unconfirmed", reason: "browser" },
          routerProbe: { status: "unconfirmed", reason },
        }).guidance
      ).toBeNull()
    }
  })

  test("failed routing API request points to service, even with other DNS evidence", () => {
    expect(
      siteCheckPresentation({
        ...complete,
        routingStatus: "error",
        routerProbe: { status: "unconfirmed", reason: "dns" },
      })
    ).toEqual({ retry: true, guidance: "service" })
  })

  test("failed or malformed router API response points to service", () => {
    for (const reason of ["request", "invalidResponse"] as const) {
      expect(
        siteCheckPresentation({
          ...complete,
          routerProbe: { status: "unconfirmed", reason },
        }).guidance
      ).toBe("service")
    }
  })

  test("an HTTP error response is still a response, not a failed site", () => {
    expect(
      siteCheckPresentation({
        ...complete,
        browserProbe: { status: "responded", httpStatus: 403 },
        routerProbe: { status: "responded", httpStatus: 500 },
      }).guidance
    ).toBeNull()
  })
})
