import { describe, expect, test } from "bun:test"

import {
  buildNativeTransportCreateHref,
  buildTransportEditHref,
  readNativeTransportCreateInterface,
  transportCreateHref,
} from "../src/lib/transport-upsert-route"
import { buildAdvancedEditorHref } from "../src/lib/upsert-presentation"

describe("transport upsert routes", () => {
  test("opens create in the shared dialog presentation by default", () => {
    expect(transportCreateHref).toBe("/transports/create")
  })

  test("encodes a transport tag in the edit deep link", () => {
    expect(buildTransportEditHref("vless/main route")).toBe(
      "/transports/vless%2Fmain%20route/edit"
    )
  })

  test("opens an untracked native interface in the shared transport form", () => {
    const href = buildNativeTransportCreateHref("nwg5/owner")

    expect(href).toBe("/transports/create?nativeInterface=nwg5%2Fowner")
    expect(readNativeTransportCreateInterface(href.split("?", 2)[1])).toBe(
      "nwg5/owner"
    )
  })

  test("ignores an empty native interface seed", () => {
    expect(readNativeTransportCreateInterface("?nativeInterface=%20")).toBe(
      undefined
    )
  })

  test("opens the same transport in the full-page advanced editor", () => {
    expect(
      buildAdvancedEditorHref(buildTransportEditHref("vless1"), "tab=sing-box")
    ).toBe("/transports/vless1/edit?tab=sing-box&view=page")
  })
})
