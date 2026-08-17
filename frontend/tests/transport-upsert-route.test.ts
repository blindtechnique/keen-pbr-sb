import { describe, expect, test } from "bun:test"

import {
  buildTransportEditHref,
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

  test("opens the same transport in the full-page advanced editor", () => {
    expect(
      buildAdvancedEditorHref(buildTransportEditHref("vless1"), "tab=sing-box")
    ).toBe("/transports/vless1/edit?tab=sing-box&view=page")
  })
})
