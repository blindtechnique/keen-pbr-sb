import { describe, expect, test } from "bun:test"

import type { ListConfig } from "@/api/generated/model/listConfig"
import type { Outbound } from "@/api/generated/model/outbound"

import {
  getEffectiveListRefreshRouteChain,
  getListRefreshCapableOutbounds,
  getListRefreshDetourMode,
  normalizeListRefreshRouteChain,
} from "./list-refresh-route"

describe("list refresh route", () => {
  test("keeps only outbounds that can route list downloads", () => {
    const outbounds: Outbound[] = [
      { type: "interface", tag: "vpn" },
      { type: "table", tag: "table_route" },
      { type: "urltest", tag: "failover" },
      { type: "ignore", tag: "direct" },
      { type: "blackhole", tag: "blocked" },
    ]

    expect(
      getListRefreshCapableOutbounds(outbounds).map((outbound) => outbound.tag)
    ).toEqual(["vpn", "table_route", "failover"])
  })

  test("treats a legacy per-list detour as an override", () => {
    const list = { detour: "legacy_vpn" } satisfies ListConfig

    expect(getListRefreshDetourMode(list)).toBe("override")
    expect(
      getEffectiveListRefreshRouteChain(list, {
        detour: "global_vpn",
        fallback_detours: ["global_backup"],
      })
    ).toEqual({
      detour: "legacy_vpn",
      fallbackDetours: [],
    })
  })

  test("treats a legacy fallback-only route as an override", () => {
    const list = {
      fallback_detours: ["legacy_backup"],
    } satisfies ListConfig

    expect(getListRefreshDetourMode(list)).toBe("override")
  })

  test("explicit inherit ignores stale local route fields", () => {
    const list = {
      refresh_detour_mode: "inherit",
      detour: "stale_vpn",
      fallback_detours: ["stale_backup"],
    } satisfies ListConfig

    expect(getListRefreshDetourMode(list)).toBe("inherit")
    expect(
      getEffectiveListRefreshRouteChain(list, {
        detour: "global_vpn",
        fallback_detours: ["global_backup"],
      })
    ).toEqual({
      detour: "global_vpn",
      fallbackDetours: ["global_backup"],
    })
  })

  test("explicit override uses the normalized local route", () => {
    const list = {
      refresh_detour_mode: "override",
      detour: " local_vpn ",
      fallback_detours: ["backup", " local_vpn ", "backup"],
    } satisfies ListConfig

    expect(
      getEffectiveListRefreshRouteChain(list, {
        detour: "global_vpn",
      })
    ).toEqual({
      detour: "local_vpn",
      fallbackDetours: ["backup"],
    })
  })

  test("normalizes whitespace, duplicates, primary repeats and empty routes", () => {
    expect(
      normalizeListRefreshRouteChain({
        detour: " primary ",
        fallbackDetours: [" backup_a ", "", "primary", "backup_a", "backup_b "],
      })
    ).toEqual({
      detour: "primary",
      fallbackDetours: ["backup_a", "backup_b"],
    })

    expect(
      normalizeListRefreshRouteChain({
        detour: "   ",
        fallbackDetours: ["backup"],
      })
    ).toEqual({
      detour: "",
      fallbackDetours: [],
    })
  })
})
