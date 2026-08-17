import { describe, expect, test } from "bun:test"

import {
  createRouteRuleDraft,
  getRouteRuleDisplayName,
  getRoutingRuleRowId,
  normalizeRouteRuleDraft,
  toRouteRuleDraft,
} from "../src/pages/routing-rules-utils"

describe("routing rule aliases", () => {
  test("creates a collision-safe technical ID from a readable name", () => {
    const draft = createRouteRuleDraft("Видео и стриминг", [
      "video_i_striming",
    ])

    expect(draft.displayName).toBe("Видео и стриминг")
    expect(draft.id).toBe("video_i_striming_2")
  })

  test("round-trips an alias and stable technical ID", () => {
    const rule = {
      id: "streaming",
      display_name: "Видео и стриминг",
      enabled: true,
      list: ["video"],
      outbound: "primary_vpn",
    }

    const draft = toRouteRuleDraft(rule)
    const persisted = normalizeRouteRuleDraft({
      ...draft,
      displayName: "  Видео и стриминг  ",
    })

    expect(persisted.id).toBe("streaming")
    expect(persisted.display_name).toBe("Видео и стриминг")
    expect(getRoutingRuleRowId(persisted, 7)).toBe("id:streaming")
    expect(getRouteRuleDisplayName(persisted, 7)).toBe("Видео и стриминг")
  })

  test("keeps legacy rules readable until they are edited", () => {
    const legacy = {
      outbound: "wan",
      list: ["direct"],
    }

    expect(getRoutingRuleRowId(legacy, 2)).toBe("index:2")
    expect(getRouteRuleDisplayName(legacy, 2)).toBe("#3")
  })

  test("keeps stable and legacy row identity namespaces disjoint", () => {
    expect(
      getRoutingRuleRowId({ id: "legacy_1", outbound: "vpn" }, 0)
    ).toBe("id:legacy_1")
    expect(getRoutingRuleRowId({ outbound: "vpn" }, 1)).toBe("index:1")
  })
})
