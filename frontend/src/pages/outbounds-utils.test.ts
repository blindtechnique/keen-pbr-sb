import { describe, expect, test } from "bun:test"

import type { ConfigObject } from "@/api/generated/model/configObject"

import {
  buildUpdatedConfigForOutboundsDelete,
  getOutboundDeleteImpact,
} from "./outbounds-utils"

describe("global list refresh route outbound cleanup", () => {
  test("reports and removes a deleted fallback while preserving the primary", () => {
    const config: ConfigObject = {
      outbounds: [
        { type: "interface", tag: "primary" },
        { type: "interface", tag: "backup_a" },
        { type: "interface", tag: "backup_b" },
      ],
      list_refresh: {
        detour: "primary",
        fallback_detours: ["backup_a", "backup_b"],
      },
    }

    expect(getOutboundDeleteImpact(config, ["backup_a"]).globalListRefreshRoute)
      .toEqual({
        before: ["primary", "backup_a", "backup_b"],
        after: ["primary", "backup_b"],
      })
    expect(
      buildUpdatedConfigForOutboundsDelete(config, ["backup_a"]).list_refresh
    ).toEqual({
      detour: "primary",
      fallback_detours: ["backup_b"],
    })
  })

  test("clears the whole global chain when its primary is deleted", () => {
    const config: ConfigObject = {
      outbounds: [
        { type: "interface", tag: "primary" },
        { type: "interface", tag: "backup" },
      ],
      list_refresh: {
        detour: "primary",
        fallback_detours: ["backup"],
      },
    }

    expect(getOutboundDeleteImpact(config, ["primary"]).globalListRefreshRoute)
      .toEqual({
        before: ["primary", "backup"],
        after: [],
      })
    expect(
      buildUpdatedConfigForOutboundsDelete(config, ["primary"]).list_refresh
    ).toEqual({})
  })

  test("does not report an impact when the global route has no deleted tags", () => {
    const config: ConfigObject = {
      outbounds: [
        { type: "interface", tag: "primary" },
        { type: "interface", tag: "unrelated" },
      ],
      list_refresh: { detour: "primary" },
    }

    expect(
      getOutboundDeleteImpact(config, ["unrelated"]).globalListRefreshRoute
    ).toBeUndefined()
    expect(
      buildUpdatedConfigForOutboundsDelete(config, ["unrelated"]).list_refresh
    ).toEqual({ detour: "primary" })
  })
})
