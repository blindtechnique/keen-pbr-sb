import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { renderToStaticMarkup } from "react-dom/server"
import { createInstance } from "i18next"
import type { Outbound, RuntimeOutboundState } from "../src/api/generated/model"
import { OutboundSelectOption } from "../src/components/shared/outbound-select"
import { buildChoiceDisplayNames } from "../src/lib/choice-display-names"
import { ruTranslation } from "../src/i18n/ru"
import { enTranslation } from "../src/i18n/en"

async function renderOption(
  outbound: Outbound,
  language: "ru" | "en",
  displayName?: string,
  interfaceLabelFor = (name: string) => name
) {
  const local = createInstance()
  await local.init({
    lng: language,
    resources: {
      ru: { translation: ruTranslation },
      en: { translation: enTranslation },
    },
  })
  const html = renderToStaticMarkup(
    <OutboundSelectOption
      outbound={outbound}
      interfaceLabelFor={interfaceLabelFor}
      displayName={displayName}
      runtimeState={
        { tag: outbound.tag, status: "healthy" } as RuntimeOutboundState
      }
      t={local.t.bind(local)}
    />
  )
  return { html, text: html.replace(/<[^>]*>/g, "") }
}

describe("outbound selector identity presentation", () => {
  test.each(["ru", "en"] as const)(
    "shows alias and unchanged runtime status in %s, with ID only in title",
    async (language) => {
      const outbound: Outbound = {
        tag: "internal_route_17",
        type: "interface",
        display_name: "Домашний AWG",
      }
      const { html, text } = await renderOption(outbound, language)
      expect(text).toContain("Домашний AWG")
      expect(text).toContain(
        (language === "ru" ? ruTranslation : enTranslation).runtime
          .outboundStatus.healthy
      )
      expect(text).not.toContain(outbound.tag)
      expect(html).toContain('title="Домашний AWG (internal_route_17)"')
      expect(outbound.tag).toBe("internal_route_17")
    }
  )

  test("uses the existing firmware alias fallback without changing technical identity", async () => {
    const { html, text } = await renderOption(
      { tag: "legacy_route", type: "interface", interface: "nwg5" },
      "ru",
      undefined,
      (name) => (name === "nwg5" ? "Keenetic VPN" : name)
    )
    expect(text).toContain("Keenetic VPN")
    expect(text).not.toContain("legacy_route")
    expect(html).toContain("Keenetic VPN (legacy_route)")
  })

  test("keeps a usable sole fallback for an unnamed route", async () => {
    const { text } = await renderOption(
      { tag: "legacy_route", type: "interface" },
      "ru"
    )
    expect(text).toContain("legacy_route")
  })

  test("same aliases receive distinct captions but retain separate raw references", async () => {
    const outbounds: Outbound[] = [
      { tag: "a", type: "urltest", display_name: "VPN" },
      { tag: "b", type: "urltest", display_name: "VPN" },
    ]
    const names = buildChoiceDisplayNames(
      outbounds.map((item) => ({ value: item.tag, label: item.display_name! }))
    )
    const first = await renderOption(outbounds[0], "ru", names.get("a"))
    const second = await renderOption(outbounds[1], "ru", names.get("b"))
    expect(first.text).toContain("VPN · 1")
    expect(second.text).toContain("VPN · 2")
    expect(first.html).toContain('title="VPN (a)"')
    expect(second.html).toContain('title="VPN (b)"')
  })

  test("menu identity, explicit keyboard labels and group member search remain technical-value based", () => {
    const source = readFileSync(
      new URL("../src/components/shared/outbound-select.tsx", import.meta.url),
      "utf8"
    )
    expect(source).toContain("key={outbound.tag}")
    expect(source).toContain("value={outbound.tag}")
    expect(source).toContain("label={getOutboundSelectReferenceLabel(")
    expect(source).toContain(
      'onValueChange={(nextValue) => onValueChange(nextValue ?? "")}'
    )
    expect(source).toContain("choiceNames.get(selected)")
    expect(source).toContain("displayName={choiceNames.get(outbound.tag)}")
    expect(source).not.toContain("{outbound.tag}</span>")
    const editor = readFileSync(
      new URL("../src/pages/outbound-upsert-page.tsx", import.meta.url),
      "utf8"
    )
    expect(editor).toContain(
      "const groupMemberNames = buildChoiceDisplayNames("
    )
    expect(editor).toContain("getInterfaceOutboundSearchText(")
    expect(editor).toContain("value={group.outbounds}")
    expect(editor).toContain("label={groupMemberLabel(tag)}")
    expect(editor).toContain("tag={tag}")
  })
})
