import { describe, expect, test } from "bun:test"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"
import { NfqwsLegacyStrategies } from "../src/components/nfqws/legacy-strategies"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

const stock = "default (nfqws2 1.2.8)"
const presets = ["default", stock, "ver1", "ver1 (alt)", "ver2"]
async function render(
  language: "ru" | "en",
  activeName: string,
  names = presets
) {
  const i18n = createInstance()
  await i18n.init({
    lng: language,
    resources: {
      ru: { translation: ruTranslation },
      en: { translation: enTranslation },
    },
    interpolation: { escapeValue: false },
  })
  return renderToStaticMarkup(
    <I18nextProvider i18n={i18n}>
      <NfqwsLegacyStrategies
        names={names}
        activeName={activeName}
        headers={["Strategy"]}
        columnClassNames={[]}
        renderRow={(name) => [<span key="name">{name}</span>]}
      />
    </I18nextProvider>
  )
}

describe("unused nfqws presets stay collapsed", () => {
  test.each(["ru", "en"] as const)(
    "a recognized stock strategy does not open the whole list in %s",
    async (language) => {
      const html = await render(language, stock)
      const position = html.indexOf("<details")
      expect(position).toBeGreaterThan(0)
      const visible = html.slice(0, position)
      const collapsed = html.slice(position)
      expect(visible).toContain(stock)
      expect(visible).not.toContain(">ver1<")
      expect(collapsed).not.toContain(stock)
      expect(collapsed).toContain(">ver1<")
      expect(collapsed.match(/^<details[^>]*>/)?.[0]).not.toMatch(
        /\bopen(?:\s|=|>)/
      )
      expect(collapsed).toContain("<summary")
      expect(collapsed).toContain(
        language === "ru"
          ? "Показать старые пресеты (4)"
          : "Show legacy presets (4)"
      )
      expect(collapsed).toContain(
        language === "ru" ? "Скрыть старые пресеты" : "Hide legacy presets"
      )
      expect(html).not.toContain("nfqws.legacy")
    }
  )
  test("an active old preset is also visible without expanding unused presets", async () => {
    const html = await render("ru", "ver1")
    const position = html.indexOf("<details")
    expect(html.slice(0, position)).toContain(">ver1<")
    expect(html.slice(position)).not.toContain(">ver1<")
    expect(html.slice(position)).toContain(stock)
  })
  test("all legacy presets stay under the disclosure when a current profile is active", async () => {
    const html = await render("en", "02 balanced")
    expect(html.indexOf("<details")).toBeLessThan(html.indexOf("<table"))
    expect(html).toContain("Show legacy presets (5)")
    expect(html.match(/<details[^>]*>/)?.[0]).not.toMatch(/\bopen(?:\s|=|>)/)
  })
  test("does not offer an empty disclosure", async () => {
    expect(await render("en", stock, [stock])).not.toContain("<details")
    expect(await render("en", "", [])).toBe("")
  })
})
