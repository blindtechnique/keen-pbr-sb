import { describe, expect, test } from "bun:test"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"

import type { ConfigObject } from "@/api/generated/model/configObject"
import { getOutboundDeleteImpactItems } from "@/components/delete-impact/outbound-items"
import { enTranslation } from "@/i18n/en"
import { ruTranslation } from "@/i18n/ru"

import {
  buildUpdatedConfigForOutboundsDelete,
  filterDeletableOutboundTags,
  getOutboundDeleteImpact,
  isSystemOutboundType,
} from "./outbounds-utils"

describe("per-rule fallback outbound cleanup", () => {
  test("deleting the global download primary preserves unrelated extension settings", () => {
    const refresh = {
      detour: "primary",
      fallback_detours: ["backup"],
      future_refresh: { retries: [1, 2], enabled: false },
    }
    const config: ConfigObject = {
      outbounds: [{ type: "interface", tag: "primary" }],
      list_refresh: refresh,
    }
    expect(
      buildUpdatedConfigForOutboundsDelete(config, ["primary"]).list_refresh
    ).toEqual({ future_refresh: { retries: [1, 2], enabled: false } })
    expect(refresh.detour).toBe("primary")
    expect(refresh.fallback_detours).toEqual(["backup"])
  })

  const config: ConfigObject = {
    outbounds: [
      { type: "interface", tag: "primary" },
      { type: "interface", tag: "backup" },
      { type: "interface", tag: "unrelated" },
    ],
    route: {
      rules: [
        {
          id: "work",
          display_name: "Work sites",
          list: ["work"],
          outbound: "primary",
          failure_policy: "fallback",
          fallback_outbound: "backup",
        },
        { id: "other", outbound: "unrelated", enabled: false },
      ],
    },
    lists: { work: { domains: ["example.test"] } },
  }

  test("keeps the rule and blocks on primary failure when its reserve is deleted", () => {
    const original = structuredClone(config)
    const impact = getOutboundDeleteImpact(config, ["backup"])
    expect(impact.routeRuleIndexes).toEqual([])
    expect(impact.fallbackRuleIndexes).toEqual([0])

    const next = buildUpdatedConfigForOutboundsDelete(config, ["backup"])
    expect(next.route?.rules).toEqual([
      {
        id: "work",
        display_name: "Work sites",
        list: ["work"],
        outbound: "primary",
        failure_policy: "block",
      },
      config.route?.rules?.[1],
    ])
    expect(next.route?.rules?.[0]).not.toHaveProperty("fallback_outbound")
    expect(next.route?.rules?.[1]).toBe(config.route?.rules?.[1])
    expect(next.lists).toEqual(config.lists)
    expect(config).toEqual(original)
  })

  test("still removes rules whose primary is deleted, without reporting a fallback change", () => {
    const impact = getOutboundDeleteImpact(config, ["primary", "backup"])
    expect(impact.routeRuleIndexes).toEqual([0])
    expect(impact.fallbackRuleIndexes).toEqual([])
    expect(
      buildUpdatedConfigForOutboundsDelete(config, ["primary", "backup"]).route
        ?.rules
    ).toEqual([config.route?.rules?.[1]])
  })

  test("does not change a fallback rule when another outbound is removed", () => {
    const impact = getOutboundDeleteImpact(config, ["unrelated"])
    expect(impact.routeRuleIndexes).toEqual([1])
    expect(impact.fallbackRuleIndexes).toEqual([])
    expect(
      buildUpdatedConfigForOutboundsDelete(config, ["unrelated"]).route
        ?.rules?.[0]
    ).toBe(config.route?.rules?.[0])
  })

  test("does not change another policy because of an inactive old fallback field", () => {
    for (const policy of [undefined, null, "inherit", "block"] as const) {
      const inactive: ConfigObject = {
        ...config,
        route: {
          rules: [
            {
              outbound: "primary",
              failure_policy: policy,
              fallback_outbound: "backup",
            },
          ],
        },
      }
      expect(
        getOutboundDeleteImpact(inactive, ["backup"]).fallbackRuleIndexes
      ).toEqual([])
      expect(
        buildUpdatedConfigForOutboundsDelete(inactive, ["backup"]).route
          ?.rules?.[0]
      ).toBe(inactive.route?.rules?.[0])
    }
  })

  test("handles a fallback group removed by cascading deletion of its last member", () => {
    const grouped: ConfigObject = {
      ...config,
      outbounds: [
        ...(config.outbounds ?? []),
        {
          type: "urltest",
          tag: "reserve_group",
          outbound_groups: [{ outbounds: ["backup"] }],
        },
      ],
      route: {
        rules: [
          {
            ...config.route?.rules?.[0],
            outbound: "primary",
            fallback_outbound: "reserve_group",
          },
        ],
      },
    }
    const impact = getOutboundDeleteImpact(grouped, ["backup"])
    expect(impact.deletedOutboundTags).toEqual(["backup", "reserve_group"])
    expect(impact.routeRuleIndexes).toEqual([])
    expect(impact.fallbackRuleIndexes).toEqual([0])
    expect(
      buildUpdatedConfigForOutboundsDelete(grouped, ["backup"]).route
        ?.rules?.[0]
    ).toMatchObject({ outbound: "primary", failure_policy: "block" })
    expect(
      buildUpdatedConfigForOutboundsDelete(grouped, ["backup"]).route
        ?.rules?.[0]
    ).not.toHaveProperty("fallback_outbound")
  })

  test.each([
    ["ru", ruTranslation, "сохранится без резерва", "новые подключения"],
    ["en", enTranslation, "will be kept without a fallback", "new connections"],
  ] as const)(
    "%s explains the rule change in the existing delete impact",
    async (language, translation, kept, newConnections) => {
      const i18n = createInstance()
      await i18n.init({
        lng: language,
        resources: { [language]: { translation } },
        interpolation: { escapeValue: false },
      })
      const items = getOutboundDeleteImpactItems(
        config,
        ["backup"],
        getOutboundDeleteImpact(config, ["backup"]),
        i18n.getFixedT(language)
      )
      expect(items).toHaveLength(2)
      const label = renderToStaticMarkup(items[1].label)
      expect(label).toContain("Work sites")
      expect(label).toContain(kept)
      expect(label).toContain(newConnections)
      expect(renderToStaticMarkup(items[1].details)).toContain(
        translation.routeFailurePolicy.block
      )
    }
  )
})

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

    expect(
      getOutboundDeleteImpact(config, ["backup_a"]).globalListRefreshRoute
    ).toEqual({
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

    expect(
      getOutboundDeleteImpact(config, ["primary"]).globalListRefreshRoute
    ).toEqual({
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

describe("per-list refresh route outbound cleanup", () => {
  test("falls back to the global chain when the override primary is deleted", () => {
    const config: ConfigObject = {
      outbounds: [
        { type: "interface", tag: "primary" },
        { type: "interface", tag: "backup" },
      ],
      list_refresh: { detour: "global_primary" },
      lists: {
        remote: {
          url: "https://example.test/list.txt",
          refresh_detour_mode: "override",
          detour: "primary",
          fallback_detours: ["backup"],
        },
      },
    }

    expect(
      buildUpdatedConfigForOutboundsDelete(config, ["primary"]).lists?.remote
    ).toEqual({
      url: "https://example.test/list.txt",
    })
  })
})

describe("системные маршруты не удаляются", () => {
  const config = {
    outbounds: [
      { tag: "wan", type: "table" as const },
      { tag: "block", type: "blackhole" as const },
      { tag: "bypass", type: "ignore" as const },
      { tag: "vpn", type: "interface" as const, interface: "nwg1" },
      {
        tag: "group",
        type: "urltest" as const,
        outbound_groups: [{ outbounds: ["vpn"] }],
      },
    ],
  }

  test("отсекает всё, что не туннель и не группа", () => {
    expect(
      filterDeletableOutboundTags(config, ["wan", "block", "bypass", "vpn"])
    ).toEqual(["vpn"])
  })

  test("группу резервирования удалять можно", () => {
    expect(filterDeletableOutboundTags(config, ["group"])).toEqual(["group"])
  })

  test("расчёт последствий тоже их игнорирует", () => {
    const impact = getOutboundDeleteImpact(config, ["wan", "block"])
    expect(impact.deletedOutboundTags).toEqual([])
  })

  test("правка конфигурации системный маршрут не трогает", () => {
    const next = buildUpdatedConfigForOutboundsDelete(config, ["wan", "vpn"])
    expect(next.outbounds?.map((item) => item.tag)).toContain("wan")
    expect(next.outbounds?.map((item) => item.tag)).not.toContain("vpn")
  })

  test("тип решает, а не имя", () => {
    expect(isSystemOutboundType("table")).toBe(true)
    expect(isSystemOutboundType("blackhole")).toBe(true)
    expect(isSystemOutboundType("ignore")).toBe(true)
    expect(isSystemOutboundType("interface")).toBe(false)
    expect(isSystemOutboundType("urltest")).toBe(false)
  })
})
