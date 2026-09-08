import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"

import {
  getListTemplateDescription,
  getListTemplateName,
  matchesListTemplateSearch,
  type ListTemplate,
} from "../src/components/lists/template-model"
import listTemplates from "../src/data/list-templates.json"
import { localizeCatalogText } from "../src/lib/catalog-localization"
import {
  getCatalogPresetNotice,
  getCatalogPresetName,
  getCatalogRoutingCompanionSourceSummaries,
  matchesCatalogSearch,
  type CatalogPreset,
} from "../src/pages/catalog-model"

const catalog: CatalogPreset[] = JSON.parse(
  readFileSync(
    new URL(
      "../../packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/catalog.json",
      import.meta.url
    ),
    "utf8"
  )
)
const templates: ListTemplate[] = listTemplates

describe("catalog description localization", () => {
  test("catalog titles switch language without changing names or identities", () => {
    const before = JSON.stringify(catalog)
    const translated = catalog.filter((preset) => preset.name_i18n)
    expect(translated.length).toBeGreaterThan(0)
    for (const preset of translated) {
      expect(getCatalogPresetName(preset, "ru-RU")).toBe(preset.name_i18n?.ru)
      expect(getCatalogPresetName(preset, "en-US")).toBe(preset.name_i18n?.en)
      expect(getCatalogPresetName(preset, "en")).not.toMatch(/[а-яё]/i)
      expect(getCatalogPresetName(preset, "de")).toBe(preset.name)
    }
    const meta = catalog.find(
      (preset) => preset.name_i18n?.en === "Meta (all services)"
    )!
    expect(meta).toBeDefined()
    expect(getCatalogPresetName(meta, "ru")).toBe("Meta (все сервисы)")
    expect(JSON.stringify(catalog)).toBe(before)
  })

  test("titles participate in search and legacy or operator names stay readable", () => {
    const preset: CatalogPreset = {
      id: "meta",
      name: "Meta (все сервисы)",
      name_i18n: { ru: "Meta (все сервисы)", en: "Meta (all services)" },
    }
    expect(matchesCatalogSearch(preset, "all services", "en")).toBe(true)
    expect(matchesCatalogSearch(preset, "all services", "ru")).toBe(false)
    expect(matchesCatalogSearch(preset, "все сервисы", "en")).toBe(true)
    expect(getCatalogPresetName({ id: "custom", name: "My list" }, "en")).toBe(
      "My list"
    )
    expect(
      getCatalogPresetName({ name: "Meta", name_i18n: { en: " " } }, "en")
    ).toBe("Meta")
  })

  test("IP companion names switch language while routing data remains unchanged", () => {
    const preset: CatalogPreset = {
      id: "telegram",
      name: "Telegram",
      routingCompanions: [
        {
          id: "telegram-ip",
          name: "Telegram IP",
          name_i18n: { ru: "IP-адреса Telegram", en: "Telegram IP addresses" },
          kind: "ip",
          url: "https://example.org/telegram.txt",
        },
      ],
    }
    const before = JSON.stringify(preset)
    const russian = getCatalogRoutingCompanionSourceSummaries(
      preset,
      [preset],
      "ru"
    )
    const english = getCatalogRoutingCompanionSourceSummaries(
      preset,
      [preset],
      "en"
    )
    expect(russian[0].name).toBe("IP-адреса Telegram")
    expect(english[0].name).toBe("Telegram IP addresses")
    expect({ ...russian[0], name: "" }).toEqual({ ...english[0], name: "" })
    expect(JSON.stringify(preset)).toBe(before)
  })

  test("template titles are localized in search without rewriting selected template data", () => {
    const before = JSON.stringify(templates)
    const translated = templates.filter((template) => template.name_i18n)
    expect(translated.length).toBeGreaterThan(0)
    for (const template of translated) {
      const english = getListTemplateName(template, "en-GB")
      expect(english).toBe(template.name_i18n?.en)
      expect(english).not.toMatch(/[а-яё]/i)
      expect(getListTemplateName(template, "ru")).toBe(template.name_i18n?.ru)
      expect(matchesListTemplateSearch(template, english, "en")).toBe(true)
    }
    expect(JSON.stringify(templates)).toBe(before)
  })

  test("every bundled notice has English copy while Russian stays unchanged", () => {
    const described = catalog.filter((preset) => preset.notice)
    expect(described).toHaveLength(22)
    for (const preset of described) {
      const english = getCatalogPresetNotice(preset, "en")
      expect(english).toBe(preset.notice_i18n?.en)
      expect(english.trim().length).toBeGreaterThan(0)
      expect(english).not.toMatch(/[а-яё]/i)
      expect(getCatalogPresetNotice(preset, "ru")).toBe(preset.notice)
      expect(getCatalogPresetNotice(preset, "en-GB")).toBe(english)
      expect(getCatalogPresetNotice(preset, "ru-RU")).toBe(preset.notice)
    }
  })

  test("every described list template has English copy and its Russian original", () => {
    const described = templates.filter((template) => template.description)
    expect(described).toHaveLength(9)
    for (const template of described) {
      const english = getListTemplateDescription(template, "en")
      expect(english).toBe(template.description_i18n?.en)
      expect(english.trim().length).toBeGreaterThan(0)
      expect(english).not.toMatch(/[а-яё]/i)
      expect(getListTemplateDescription(template, "ru")).toBe(
        template.description
      )
    }
  })

  test("the catalog and template picker share translations for identical text", () => {
    for (const template of templates.filter((item) => item.description)) {
      const preset = catalog.find(
        (item) => item.notice === template.description
      )
      if (preset) {
        expect(getListTemplateDescription(template, "en")).toBe(
          getCatalogPresetNotice(preset, "en")
        )
      }
    }
  })

  test("English descriptions participate in search without losing original or technical matches", () => {
    const kino = catalog.find((preset) => preset.id === "kinopub-core")!
    expect(matchesCatalogSearch(kino, "  HIGH-BANDWIDTH  ", "en")).toBe(true)
    expect(matchesCatalogSearch(kino, "метаданные", "en")).toBe(true)
    expect(matchesCatalogSearch(kino, "kinopub-core", "en")).toBe(true)
    expect(matchesCatalogSearch(kino, "high-bandwidth", "ru")).toBe(false)

    const template = templates.find((item) => item.id === "kino_pub")!
    expect(matchesListTemplateSearch(template, "high-bandwidth", "en")).toBe(
      true
    )
    expect(matchesListTemplateSearch(template, "тяжёлых", "en")).toBe(true)
    expect(
      matchesListTemplateSearch(template, "geosite-kinopub.srs", "en")
    ).toBe(true)
    expect(matchesListTemplateSearch(template, "high-bandwidth", "ru")).toBe(
      false
    )
  })

  test("legacy, empty and custom descriptions keep a safe original fallback", () => {
    expect(localizeCatalogText("Original", undefined, "en")).toBe("Original")
    expect(localizeCatalogText(undefined, undefined, "en")).toBe("")
    expect(localizeCatalogText("Original", { en: "  " }, "en")).toBe("Original")
    expect(localizeCatalogText("Original", { en: "English" }, "ru")).toBe(
      "Original"
    )
    expect(localizeCatalogText("Original", { en: "English" }, undefined)).toBe(
      "English"
    )
    expect(
      localizeCatalogText(
        "Original",
        { en: "English", "en-gb": "British" },
        "en-GB"
      )
    ).toBe("British")
    expect(
      getCatalogPresetNotice(
        { id: "custom", name: "Custom", notice: "Operator text" },
        "en"
      )
    ).toBe("Operator text")
    expect(getCatalogPresetNotice({ id: "empty", name: "Empty" }, "en")).toBe(
      ""
    )
  })

  test("both consumers render localized descriptions and refresh search on language changes", () => {
    const page = readFileSync(
      new URL("../src/pages/catalog-page.tsx", import.meta.url),
      "utf8"
    )
    const picker = readFileSync(
      new URL("../src/components/lists/template-picker.tsx", import.meta.url),
      "utf8"
    )
    expect(page).toContain("getCatalogPresetNotice(preset, language)")
    expect(page).toContain("getCatalogPresetName(preset, language)")
    expect(page).toContain("[presets, selected, language]")
    expect(page).not.toContain("{preset.name}")
    expect(page).not.toContain("name: installState.coveredBy.name")
    expect(page).not.toContain("name: selectedAncestor.name")
    expect(page).toContain("{notice}")
    expect(page).toContain("matchesCatalogSearch(preset, search, language)")
    expect(page).toContain("[displayPresets, category, search, language]")
    expect(page).not.toContain("{preset.notice}")
    expect(picker).toContain("{getListTemplateDescription(template, language)}")
    expect(picker).toContain("{getListTemplateName(template, language)}")
    expect(picker).toContain("onSelect(template)")
    expect(picker).not.toContain("{template.name}")
    expect(picker).toContain(
      "matchesListTemplateSearch(template, query, language)"
    )
    expect(picker).toContain("[query, language]")
    expect(picker).not.toContain("{template.description}")
  })
})
