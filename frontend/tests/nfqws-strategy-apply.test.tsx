import { describe, expect, test } from "bun:test"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createInstance } from "i18next"
import type { ComponentProps } from "react"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"

import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"
import { StrategiesEditor } from "../src/pages/nfqws-page"

type StrategyStatus = ComponentProps<typeof StrategiesEditor>["status"]

async function renderStrategies(
  language: "ru" | "en",
  activeStrategy: string,
  strategies: StrategyStatus["strategies"]
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
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity } },
  })
  client.setQueryData(
    ["nfqws", "file", "config", "nfqws2.conf", activeStrategy],
    {
      content:
        strategies.find((item) => item.name === activeStrategy)?.content ?? "",
    }
  )
  try {
    return renderToStaticMarkup(
      <QueryClientProvider client={client}>
        <I18nextProvider i18n={i18n}>
          <StrategiesEditor
            onDirtyChange={() => undefined}
            refresh={() => undefined}
            runOperation={async () => true}
            status={{
              installed: true,
              running: true,
              process_running: true,
              queue_active: true,
              version: "1.2.8",
              files: [],
              strategies,
              active_strategy: activeStrategy,
              rotator_state: {
                schema: 1,
                status: "unsupported",
                observed_at: null,
                truncated: false,
                pools: {},
              },
            }}
          />
        </I18nextProvider>
      </QueryClientProvider>
    )
  } finally {
    client.clear()
  }
}

describe("nfqws strategy table apply button", () => {
  test.each(["ru", "en"] as const)(
    "the active stock, legacy and custom rows cannot be reapplied in %s",
    async (language) => {
      const translation = (language === "ru" ? ruTranslation : enTranslation)
        .nfqws
      for (const strategy of [
        { name: "default (nfqws2 1.2.8)", builtin: true, overridden: false },
        { name: "ver1", builtin: true, overridden: true },
        { name: "My strategy", builtin: false, overridden: false },
      ]) {
        const html = await renderStrategies(language, strategy.name, [
          { ...strategy, content: "NFQWS_ARGS='--filter-tcp=443'" },
          {
            name: "Other strategy",
            builtin: false,
            overridden: false,
            content: "NFQWS_ARGS=''",
          },
        ])
        const rows = [...html.matchAll(/<tr\b[\s\S]*?<\/tr>/g)].map(
          ([row]) => row
        )
        const activeRow = rows.find((row) =>
          row.includes(translation.strategyAlreadyApplied)
        )
        expect(activeRow).toBeDefined()
        const applyButton = activeRow?.match(
          new RegExp(
            `<button[^>]*aria-label="${translation.profiles.applied}"[^>]*>`
          )
        )?.[0]
        expect(applyButton).toContain('disabled=""')
        expect(applyButton).toContain(translation.strategyAlreadyApplied)

        const otherRow = rows.find((row) => row.includes("Other strategy"))
        const otherApplyButton = otherRow?.match(
          new RegExp(
            `<button[^>]*aria-label="${translation.applyStrategy}"[^>]*>`
          )
        )?.[0]
        expect(otherApplyButton).toBeDefined()
        expect(otherApplyButton).not.toContain('disabled=""')
      }
    }
  )
})
