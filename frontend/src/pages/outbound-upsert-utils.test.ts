import { describe, expect, it } from "bun:test"

import type { ConfigObject } from "@/api/generated/model/configObject"
import type { Outbound } from "@/api/generated/model/outbound"
import {
  createDefaultOutboundDraft,
  isOutboundGroupsValidationPath,
  mapOutboundToDraft,
  normalizeOutboundDraftForPersistence,
  type OutboundDraft,
  validateUrltestOutboundDraft,
} from "@/pages/outbound-upsert-utils"

function leaf(tag: string): Outbound {
  return { type: "interface", tag, interface: `nwg-${tag}` }
}

function draft(overrides: Partial<OutboundDraft> = {}): OutboundDraft {
  return {
    ...createDefaultOutboundDraft(),
    displayName: "Main group",
    tag: "main_group",
    type: "urltest",
    outboundGroups: [{ outbounds: ["vpn"], weight: "" }],
    ...overrides,
  }
}

function validate(
  candidate: OutboundDraft,
  otherOutbounds: Outbound[] = [leaf("vpn")],
  configOverrides: Partial<ConfigObject> = {}
) {
  const payload = normalizeOutboundDraftForPersistence(candidate)
  const outbounds = [...otherOutbounds, payload]
  return validateUrltestOutboundDraft(candidate, outbounds, {
    ...configOverrides,
    outbounds,
  })
}

describe("urltest conntrack persistence", () => {
  it("keeps an absent mode separate from explicit preserve", () => {
    const absent: Outbound = {
      type: "urltest",
      tag: "main_group",
      url: "https://example.test/generate_204",
      outbound_groups: [{ outbounds: ["vpn"] }],
    }
    const absentDraft = mapOutboundToDraft(absent)
    expect(absentDraft.conntrackOnSwitch).toBe("default")
    expect(
      normalizeOutboundDraftForPersistence(absentDraft).conntrack_on_switch
    ).toBeUndefined()

    const preserveDraft = mapOutboundToDraft({
      ...absent,
      conntrack_on_switch: "preserve",
    })
    expect(preserveDraft.conntrackOnSwitch).toBe("preserve")
    expect(
      normalizeOutboundDraftForPersistence(preserveDraft).conntrack_on_switch
    ).toBe("preserve")
  })
})

describe("urltest editor validation", () => {
  it("accepts the normal default group", () => {
    expect(validate(draft())).toEqual([])
  })

  it("rejects an empty step before the candidate reaches the server", () => {
    expect(
      validate(draft({ outboundGroups: [{ outbounds: [], weight: "" }] }))
    ).toContainEqual({
      field: "outboundGroups",
      code: "groupStepRequired",
      index: 1,
    })
  })

  it("rejects duplicate members and cyclic nested groups", () => {
    const duplicate = validate(
      draft({
        outboundGroups: [
          { outbounds: ["vpn"], weight: "" },
          { outbounds: ["vpn"], weight: "2" },
        ],
      })
    )
    expect(duplicate).toContainEqual({
      field: "outboundGroups",
      code: "groupDuplicate",
      target: "vpn",
    })

    const child: Outbound = {
      type: "urltest",
      tag: "child_group",
      url: "https://example.test/child",
      outbound_groups: [{ outbounds: ["main_group"] }],
    }
    const cycle = validate(
      draft({ outboundGroups: [{ outbounds: ["child_group"], weight: "" }] }),
      [leaf("vpn"), child]
    )
    expect(cycle).toContainEqual({
      field: "outboundGroups",
      code: "groupCycle",
    })
  })

  it("rejects non-HTTP URLs and every server-side numeric boundary", () => {
    const issues = validate(
      draft({
        probeUrl: "ftp://example.test/probe",
        interval: "0",
        probeTimeout: "0",
        tolerance: "-1",
        retryAttempts: "1001",
        retryInterval: "-1",
        circuitBreakerFailures: "2147483648",
        circuitBreakerSuccesses: "0",
        circuitBreakerTimeout: "-1",
        circuitBreakerHalfOpen: "0",
        outboundGroups: [{ outbounds: ["vpn"], weight: "0" }],
      })
    )
    expect(issues.map((issue) => issue.field).sort()).toEqual(
      [
        "probeUrl",
        "interval",
        "probeTimeout",
        "tolerance",
        "retryAttempts",
        "retryInterval",
        "circuitBreakerFailures",
        "circuitBreakerSuccesses",
        "circuitBreakerTimeout",
        "circuitBreakerHalfOpen",
        "outboundGroups",
      ].sort()
    )
  })

  it("rejects explicit cleanup for a nested selector but keeps default valid", () => {
    const nested: Outbound = {
      type: "urltest",
      tag: "nested",
      url: "https://example.test/nested",
      outbound_groups: [{ outbounds: ["vpn"] }],
    }
    const nestedMembers = [{ outbounds: ["nested"], weight: "" }]

    expect(
      validate(
        draft({
          conntrackOnSwitch: "delete_on_failure",
          outboundGroups: nestedMembers,
        }),
        [leaf("vpn"), nested]
      )
    ).toContainEqual({
      field: "conntrackOnSwitch",
      code: "conntrackNested",
      target: "nested",
    })
    expect(
      validate(
        draft({ conntrackOnSwitch: "default", outboundGroups: nestedMembers }),
        [leaf("vpn"), nested]
      )
    ).toEqual([])
  })

  it("rejects delete when a child mark is not exclusive", () => {
    const sharedGroup: Outbound = {
      type: "urltest",
      tag: "other_group",
      url: "https://example.test/other",
      outbound_groups: [{ outbounds: ["vpn"] }],
    }
    expect(
      validate(draft({ conntrackOnSwitch: "delete" }), [
        leaf("vpn"),
        sharedGroup,
      ])
    ).toContainEqual({
      field: "conntrackOnSwitch",
      code: "conntrackShared",
      target: "vpn",
    })
  })

  it("rejects delete for route, DNS, and effective list detours", () => {
    expect(
      validate(draft({ conntrackOnSwitch: "delete" }), [leaf("vpn")], {
        route: { rules: [{ outbound: "vpn" }] },
      })
    ).toContainEqual({
      field: "conntrackOnSwitch",
      code: "conntrackRoute",
      target: "vpn",
    })

    expect(
      validate(draft({ conntrackOnSwitch: "delete" }), [leaf("vpn")], {
        dns: { servers: [{ tag: "dns", detour: "vpn" }] },
      })
    ).toContainEqual({
      field: "conntrackOnSwitch",
      code: "conntrackDns",
      target: "vpn",
    })

    expect(
      validate(draft({ conntrackOnSwitch: "delete" }), [leaf("vpn")], {
        lists: { remote: { url: "https://example.test/list.txt" } },
        list_refresh: { detour: "vpn" },
      })
    ).toContainEqual({
      field: "conntrackOnSwitch",
      code: "conntrackList",
      target: "vpn",
    })
  })
})

describe("urltest validation paths", () => {
  it("maps group member indices as well as group-level paths", () => {
    expect(
      isOutboundGroupsValidationPath(
        "outbounds.main_group.outbound_groups[0].outbounds[1]",
        "main_group"
      )
    ).toBe(true)
    expect(
      isOutboundGroupsValidationPath(
        "outbounds.main_group.outbound_groups[0].weight",
        "main_group"
      )
    ).toBe(true)
  })
})
