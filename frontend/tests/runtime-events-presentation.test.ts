import { describe, expect, test } from "bun:test"
import { createInstance } from "i18next"

import type { Outbound } from "../src/api/generated/model/outbound"
import type { TransportStatus } from "../src/api/generated/model/transportStatus"
import type {
  RuntimeEvent,
  RuntimeEventKind,
} from "../src/components/overview/runtime-events-model"
import { presentRuntimeEvents } from "../src/components/overview/runtime-events-presentation"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

const observedAt = Date.UTC(2026, 8, 6, 11, 22, 33)
const kinds: readonly RuntimeEventKind[] = [
  "groupSwitched",
  "routeDegraded",
  "routeUnavailable",
  "routeRecovered",
  "dnsChanged",
  "dnsProblem",
  "dnsRecovered",
  "runtimeFailed",
  "runtimeRecovered",
  "serviceRestarted",
  "transportUnavailable",
  "transportRecovered",
  "transportRestarted",
]
const events: readonly RuntimeEvent[] = kinds.map((kind, index) => ({
  kind,
  id: `${index}`,
  observedAt: observedAt + index * 1000,
  tag: kind.startsWith("transport") ? "proxy" : "group",
  from: "primary",
  to: "backup",
}))
const outbounds: readonly Outbound[] = [
  { tag: "group", type: "urltest", display_name: "Домашняя группа" },
  { tag: "primary", type: "interface", display_name: "Основной VPN" },
  { tag: "backup", type: "interface", display_name: "Резервный VPN" },
  { tag: "proxy", type: "interface", display_name: "Имя маршрута" },
]
const transports: readonly TransportStatus[] = [
  {
    tag: "proxy",
    type: "sing-box",
    display_name: "Имя VPN",
    state: "up",
    interface: "sb0",
    updated_at: "2026-09-06T11:22:33Z",
    desired_up: true,
    server: "private.example.test",
    error: "private diagnostic error",
  },
]

async function translator(language: "ru" | "en") {
  const local = createInstance()
  await local.init({
    lng: language,
    interpolation: { escapeValue: false },
    resources: {
      ru: { translation: ruTranslation },
      en: { translation: enTranslation },
    },
  })
  return (key: string, options?: Record<string, unknown>) =>
    String(local.t(key, options))
}

describe("runtime event presentation", () => {
  test.each(["ru", "en"] as const)(
    "localizes every finite event kind in %s without exposing diagnostic fields",
    async (language) => {
      const t = await translator(language)
      const result = presentRuntimeEvents(
        events,
        outbounds,
        transports,
        t,
        language
      )
      expect(result).toHaveLength(kinds.length)
      for (const [index, event] of result.entries()) {
        expect(event.id).toBe(events[index].id)
        expect(event.text).not.toContain("overview.runtimeEvents.")
        expect(event.text).not.toContain("{{")
        expect(event.timestamp).not.toBe("")
      }
      expect(result[0].text).toBe(
        language === "ru"
          ? "Группа «Домашняя группа» переключилась: «Основной VPN» → «Резервный VPN»"
          : "Group “Домашняя группа” switched: “Основной VPN” → “Резервный VPN”"
      )
      expect(result[4].text).toBe(
        (language === "ru" ? ruTranslation : enTranslation).overview
          .runtimeEvents.dnsChanged
      )
      expect(result[10].text).toContain("Имя VPN")
      expect(result[10].text).not.toContain("Имя маршрута")
      expect(JSON.stringify(result)).not.toMatch(
        /private\.example|private diagnostic|sb0/
      )
    }
  )

  test("maps DNS, route and service events only to their finite diagnostic sections", async () => {
    const t = await translator("en")
    const result = presentRuntimeEvents(events, outbounds, transports, t, "en")
    expect(result.map((event) => event.href)).toEqual([
      ...Array<string>(4).fill("/?section=routing"),
      ...Array<string>(3).fill("/?section=dns"),
      ...Array<string>(6).fill("/?section=service"),
    ])
    expect(result.map((event) => event.tone)).toEqual([
      "info",
      "warning",
      "warning",
      "success",
      "info",
      "warning",
      "success",
      "warning",
      "success",
      "info",
      "warning",
      "success",
      "info",
    ])
  })

  test.each(["ru", "en"] as const)(
    "uses the display locale for observation times and built-in route names in %s",
    async (language) => {
      const t = await translator(language)
      const result = presentRuntimeEvents(
        [
          {
            id: "switch",
            observedAt,
            kind: "groupSwitched",
            tag: "group",
            from: "wan",
            to: "block",
          },
        ],
        [
          ...outbounds,
          { tag: "wan", type: "table", table: 254 },
          { tag: "block", type: "blackhole" },
        ],
        [],
        t,
        language
      )
      expect(result[0].timestamp).toBe(
        new Intl.DateTimeFormat(language, {
          month: "short",
          day: "numeric",
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }).format(observedAt)
      )
      expect(result[0].text).toContain(t("common.systemOutbounds.wan"))
      expect(result[0].text).toContain(t("common.systemOutbounds.block"))
    }
  )

  test("uses current aliases, preserves plain text for React escaping and falls back only to identity", async () => {
    const t = await translator("en")
    const event: RuntimeEvent = {
      id: "route",
      observedAt,
      kind: "routeRecovered",
      tag: "a",
    }
    const alias = '<img src=x onerror="alert(1)"> & VPN'
    const config: Outbound[] = [
      { type: "interface", tag: "a", display_name: `  ${alias}  ` },
    ]
    expect(
      presentRuntimeEvents([event], config, [], t, "en")[0].text
    ).toContain(alias)
    expect(presentRuntimeEvents([event], [], [], t, "en")[0].text).toContain(
      "“a”"
    )
    expect(
      presentRuntimeEvents([{ ...event, tag: undefined }], [], [], t, "en")[0]
        .text
    ).toContain("Unnamed")
    const changed = [{ ...config[0], display_name: "Новое имя" }]
    expect(
      presentRuntimeEvents([event], changed, [], t, "en")[0].text
    ).toContain("Новое имя")
    expect(
      presentRuntimeEvents([event], changed, [], t, "en")[0].text
    ).not.toContain(alias)
  })

  test("falls back from missing transport aliases to the route alias and then the tag", async () => {
    const t = await translator("ru")
    const event = events.find((event) => event.kind === "transportRecovered")!
    const blank = [{ ...transports[0], display_name: "  " }]
    expect(
      presentRuntimeEvents([event], outbounds, blank, t, "ru")[0].text
    ).toContain("Имя маршрута")
    expect(presentRuntimeEvents([event], [], blank, t, "ru")[0].text).toContain(
      "«proxy»"
    )
  })

  test.each(["ru", "en"] as const)(
    "distinguishes a degraded route from unavailability and keeps recovery statements historical in %s",
    async (language) => {
      const t = await translator(language)
      const result = presentRuntimeEvents(
        events,
        outbounds,
        transports,
        t,
        language
      )
      expect(result[1].text).not.toMatch(/недоступ|unavailable/i)
      expect(result[2].text).toMatch(/недоступ|unavailable/i)
      expect(result[5].text).toMatch(/Проверка состояния DNS|DNS state check/)
      expect(result[6].text).toMatch(/прошла успешно|passed again/)
      expect(result[9].text).toMatch(
        /Процесс keen-pbr-sb перезапущен|keen-pbr-sb process restarted/
      )
      expect(result[12].text).toMatch(/Процесс VPN|VPN process/)
      expect(JSON.stringify(result)).not.toMatch(
        /сейчас работает|is working now|интернет восстановлен|internet restored|password|endpoint/i
      )
    }
  )

  test("does not mutate, sort or persist the session history", async () => {
    const t = await translator("en")
    const frozen = Object.freeze(
      events.map((event) => Object.freeze({ ...event }))
    )
    const result = presentRuntimeEvents(frozen, outbounds, transports, t, "en")
    expect(result.map((event) => event.id)).toEqual(
      frozen.map((event) => event.id)
    )
    expect(presentRuntimeEvents([], [], [], t, "en")).toEqual([])
    const source = await Bun.file(
      new URL(
        "../src/components/overview/runtime-events-presentation.ts",
        import.meta.url
      )
    ).text()
    expect(source).not.toMatch(
      /localStorage|sessionStorage|useQuery|useMutation|fetch\(|setInterval|setTimeout/
    )
  })
})
