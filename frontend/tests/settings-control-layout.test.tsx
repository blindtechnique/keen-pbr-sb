import { describe, expect, test } from "bun:test"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createInstance } from "i18next"
import type { ReactNode } from "react"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"

import { ListRefreshRouteFields } from "../src/components/lists/list-refresh-route-fields"
import { LoggingSettingsCard } from "../src/components/settings/logging-settings-card"
import { MultiSelectList } from "../src/components/shared/multi-select-list"
import { ruTranslation } from "../src/i18n/ru"

async function renderSettings(node: ReactNode) {
  const i18n = createInstance()
  await i18n.init({
    lng: "ru",
    resources: { ru: { translation: ruTranslation } },
    interpolation: { escapeValue: false },
  })
  const client = new QueryClient()
  try {
    return renderToStaticMarkup(
      <I18nextProvider i18n={i18n}>
        <QueryClientProvider client={client}>{node}</QueryClientProvider>
      </I18nextProvider>
    )
  } finally {
    client.clear()
  }
}

function addInput(html: string) {
  const input = html.match(/<input\b[^>]*data-size="[^"]+"[^>]*>/)?.[0]
  expect(input).toBeDefined()
  return input ?? ""
}

describe("settings control layout", () => {
  test("existing multiselect callers keep compact controls", async () => {
    const html = await renderSettings(
      <MultiSelectList
        onChange={() => undefined}
        options={["one"]}
        value={[]}
      />
    )
    expect(addInput(html)).toContain('data-size="sm"')
    expect(addInput(html)).toContain("h-8")
    expect(html).toContain("sm:w-80")
  })

  test("standard multiselect aligns the input and trigger with form selects", async () => {
    const html = await renderSettings(
      <MultiSelectList
        addControlSize="default"
        addLabel="add route"
        fullWidthAdd
        onChange={() => undefined}
        options={["one"]}
        value={[]}
      />
    )
    expect(addInput(html)).toContain('data-size="default"')
    expect(addInput(html)).toContain("h-10")
    expect(addInput(html)).toContain("rounded-[4px]")
    expect(html).not.toContain("sm:w-80")
    const trigger = html.match(
      /<button\b[^>]*aria-label="add route"[^>]*>/
    )?.[0]
    expect(trigger).toContain("h-10")
    expect(trigger).toContain("w-10")
  })

  test("General route fields use one short field width for primary and backup", async () => {
    const html = await renderSettings(
      <ListRefreshRouteFields
        addControlSize="default"
        chain={{ detour: "primary", fallbackDetours: [] }}
        fieldWidth="short"
        onChange={() => undefined}
        outbounds={[
          { tag: "primary", type: "interface", interface: "nwg0" },
          { tag: "backup", type: "interface", interface: "nwg1" },
        ]}
      />
    )
    expect(html.match(/max-w-\[480px\]/g)).toHaveLength(2)
    expect(html).not.toContain("sm:w-80")
    expect(addInput(html)).toContain("h-10")
    expect(html).toContain("Добавить резервный маршрут")
  })

  test("Log keeps a full-width section and the standard short field", async () => {
    const html = await renderSettings(
      <LoggingSettingsCard onStateChange={() => undefined} />
    )
    const card = html.match(/<div\b[^>]*data-slot="card"[^>]*>/)?.[0]
    expect(card).toContain("w-full")
    expect(card).toContain("min-w-0")
    expect(card).not.toContain("max-w-")
    expect(html.match(/max-w-\[480px\]/g)).toHaveLength(3)
    const description = html.match(
      /<[^>]+data-slot="card-description"[^>]*>/
    )?.[0]
    expect(description).toBeDefined()
    expect(description).not.toContain("max-w-")
    for (const paragraph of html.match(/<p\b[^>]*>/g) ?? []) {
      expect(paragraph).not.toContain("max-w-")
    }
    expect(html).not.toContain("sm:max-w-xs")
    expect(html).toContain('for="logging-level"')
    expect(html).toContain('id="logging-level"')
    expect(html).toContain("Подробность")
  })
})
