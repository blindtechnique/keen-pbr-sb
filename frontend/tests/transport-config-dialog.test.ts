import { describe, expect, test } from "bun:test"

import {
  TransportSpecType,
  type TransportSpec,
} from "../src/api/generated/model"
import {
  createTransportFormValue,
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
    value.sourceMode = "link"

    const submission = normalizeTransportFormValue(value, true)

    expect(submission.spec.link).toBe("vless://replacement")
    expect(submission.spec.outbound_json).toBeUndefined()
    expect(submission.options.createOutbound).toBe(false)
  })

  test("strips sing-box-only fields from native transport submissions", () => {
    const value = createTransportFormValue({
      ...singBoxTransport,
      type: TransportSpecType.native,
    })

    const submission = normalizeTransportFormValue(value, true)

    expect(submission.spec.link).toBeUndefined()
    expect(submission.spec.outbound_json).toBeUndefined()
    expect(submission.spec.mtu).toBeUndefined()
  })
})
