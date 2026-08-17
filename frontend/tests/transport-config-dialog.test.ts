import { describe, expect, test } from "bun:test"

import {
  TransportSpecType,
  type TransportSpec,
} from "../src/api/generated/model"
import {
  TRANSPORT_SOURCE_MODE_ORDER,
  createTransportFormValue,
  inferTransportAliasSuggestion,
  isNativeImportPreviewOnlyMode,
  isTransportGeoSelectionInvalid,
  nativeImportFieldsStateBoundaryKey,
  normalizeTransportFormComparable,
  normalizeTransportFormValue,
} from "../src/components/transports/transport-config-dialog"
import { isSemanticallyDirty } from "../src/lib/semantic-dirty"
import { semanticJsonEqual } from "../src/lib/semantic-json"

const singBoxTransport: TransportSpec = {
  tag: "primary_vless",
  type: TransportSpecType["sing-box"],
  interface: "vless0",
  auto_start: true,
  outbound_json: '{ "type": "vless" }',
  bootstrap_dns: [" 1.1.1.1 ", ""],
  geo_mode: "manual",
  country_code: "nl",
  country: " Netherlands ",
}

describe("transport form semantics", () => {
  test("offers link, file import, and JSON in the requested order", () => {
    expect(TRANSPORT_SOURCE_MODE_ORDER).toEqual(["link", "file", "json"])
  })

  test("native file and vpn URI previews do not expose a Save action", () => {
    expect(isNativeImportPreviewOnlyMode("file", false)).toBe(true)
    expect(isNativeImportPreviewOnlyMode("link", true)).toBe(true)
    expect(isNativeImportPreviewOnlyMode("link", false)).toBe(false)
    expect(isNativeImportPreviewOnlyMode("json", false)).toBe(false)
  })

  test("remounts native preview state when switching file and link sources", () => {
    const fileKey = nativeImportFieldsStateBoundaryKey("file")
    const linkKey = nativeImportFieldsStateBoundaryKey("link")

    expect(fileKey).not.toBe(linkKey)
    expect(nativeImportFieldsStateBoundaryKey("file")).toBe(fileKey)
    expect(nativeImportFieldsStateBoundaryKey("link")).toBe(linkKey)
  })

  test("uses the preallocated technical identity for a new transport", () => {
    const value = createTransportFormValue(undefined, {
      interfaceName: "kpbrabcd1234",
      tag: "tr_abcd1234",
    })

    expect(value.spec.tag).toBe("tr_abcd1234")
    expect(value.spec.interface).toBe("kpbrabcd1234")
  })

  test("suggests an endpoint alias without mutating the transport", () => {
    const value = createTransportFormValue(undefined, {
      interfaceName: "kpbrabcd1234",
      tag: "tr_abcd1234",
    })
    value.spec.link =
      "vless://00000000-0000-0000-0000-000000000000@nl.example.net:443"

    expect(inferTransportAliasSuggestion("link", value.spec)).toBe(
      "nl.example.net"
    )
    expect(value.spec.display_name).toBeUndefined()
  })

  test("does not silently save or truncate an alias suggestion", () => {
    const value = createTransportFormValue(undefined, {
      interfaceName: "kpbrabcd1234",
      tag: "tr_abcd1234",
    })
    value.spec.outbound_json = JSON.stringify({
      server: `${"🚀".repeat(80)}.example`,
    })

    expect(inferTransportAliasSuggestion("json", value.spec)).toBeUndefined()
    expect(value.spec.display_name).toBeUndefined()
  })

  test("suggests the server from outbound JSON", () => {
    expect(
      inferTransportAliasSuggestion("json", {
        outbound_json: JSON.stringify({
          type: "hysteria2",
          server: "203.0.113.20",
          server_port: 443,
        }),
      })
    ).toBe("203.0.113.20")
  })

  test("does not derive an alias from stale fields in file import mode", () => {
    expect(
      inferTransportAliasSuggestion("file", {
        link: "vless://example.net",
        outbound_json: JSON.stringify({ server: "json.example.net" }),
      })
    ).toBeUndefined()
  })

  test("opens an existing JSON transport in JSON mode", () => {
    const value = createTransportFormValue(singBoxTransport)

    expect(value.sourceMode).toBe("json")
    expect(value.createOutbound).toBe(false)
    expect(value.spec).not.toBe(singBoxTransport)
  })

  test("normalizes the dirty baseline exactly like submission", () => {
    const baseline = createTransportFormValue(singBoxTransport)
    const representationOnlyEdit = {
      ...baseline,
      spec: {
        ...baseline.spec,
        bootstrap_dns: ["1.1.1.1"],
        country_code: "NL",
        country: "Netherlands",
      },
    }

    expect(
      isSemanticallyDirty(representationOnlyEdit, baseline, {
        equals: semanticJsonEqual,
        normalize: (value) =>
          normalizeTransportFormComparable(value, baseline, true),
      })
    ).toBe(false)
  })

  test("treats visible defaults and an empty preserved secret as unchanged", () => {
    const baseline = createTransportFormValue({
      ...singBoxTransport,
      auto_start: undefined,
      mtu: undefined,
    })
    const restored = {
      ...baseline,
      sourceMode: "link" as const,
      spec: {
        ...baseline.spec,
        auto_start: false,
        link: "",
        mtu: 1420,
      },
    }

    expect(
      isSemanticallyDirty(restored, baseline, {
        equals: semanticJsonEqual,
        normalize: (value) =>
          normalizeTransportFormComparable(value, baseline, true),
      })
    ).toBe(false)
  })

  test("drops inactive sing-box source data", () => {
    const value = createTransportFormValue(singBoxTransport)
    value.spec.link = "vless://replacement"
    value.spec.display_name = "  Основной VLESS  "
    value.sourceMode = "link"

    const submission = normalizeTransportFormValue(value, true)

    expect(submission.spec.link).toBe("vless://replacement")
    expect(submission.spec.display_name).toBe("Основной VLESS")
    expect(submission.spec.outbound_json).toBeUndefined()
    expect(submission.options.createOutbound).toBe(false)
  })

  test("drops stale link and JSON data in file import mode", () => {
    const value = createTransportFormValue(singBoxTransport)
    value.spec.link = "vless://stale.example.net"
    value.sourceMode = "file"

    const submission = normalizeTransportFormValue(value, false)

    expect(submission.spec.link).toBeUndefined()
    expect(submission.spec.outbound_json).toBeUndefined()
    expect(submission.options.createOutbound).toBe(false)
  })

  test("strips sing-box-only fields from native transport submissions", () => {
    const value = createTransportFormValue({
      ...singBoxTransport,
      type: TransportSpecType.native,
      tun_address: "10.77.0.1/30",
    })

    const submission = normalizeTransportFormValue(value, true)

    expect(submission.spec.link).toBeUndefined()
    expect(submission.spec.outbound_json).toBeUndefined()
    expect(submission.spec.mtu).toBeUndefined()
    expect(submission.spec.bootstrap_dns).toBeUndefined()
    expect(submission.spec.tun_address).toBeUndefined()
  })
})

describe("transport geo selection", () => {
  test("manual geo without a country cannot be saved", () => {
    // The native <select required> used to block this; the styled Select has
    // no browser validation, so the rule has to live in code.
    expect(
      isTransportGeoSelectionInvalid({ geo_mode: "manual", country_code: "" })
    ).toBe(true)
    expect(
      isTransportGeoSelectionInvalid({ geo_mode: "manual", country_code: "  " })
    ).toBe(true)
    expect(
      isTransportGeoSelectionInvalid({
        geo_mode: "manual",
        country_code: undefined,
      })
    ).toBe(true)
  })

  test("a picked country, or any other mode, is fine", () => {
    expect(
      isTransportGeoSelectionInvalid({ geo_mode: "manual", country_code: "NL" })
    ).toBe(false)
    expect(
      isTransportGeoSelectionInvalid({ geo_mode: "auto", country_code: "" })
    ).toBe(false)
    expect(
      isTransportGeoSelectionInvalid({
        geo_mode: "disabled",
        country_code: undefined,
      })
    ).toBe(false)
  })
})
