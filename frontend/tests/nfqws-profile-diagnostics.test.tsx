import { describe, expect, test } from "bun:test"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"

import type {
  RoutingTestNfqws,
  RoutingTestNfqwsProfile,
} from "../src/api/generated/model"
import { TargetFacts } from "../src/components/overview/target-facts"
import { nfqwsProfileResults } from "../src/components/overview/target-facts-model"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

function profile(index: number, list_result: string): RoutingTestNfqwsProfile {
  return {
    index,
    name: "Example <profile>",
    list_result,
    filters: ["--filter-l7=tls"],
    has_actions: true,
    hostname_required: true,
    auto_hostlist: false,
    matches: [],
  }
}

async function render(nfqws: RoutingTestNfqws, language: "ru" | "en") {
  const i18n = createInstance()
  await i18n.init({
    lng: language,
    resources: {
      ru: { translation: ruTranslation },
      en: { translation: enTranslation },
    },
    interpolation: { escapeValue: false },
  })
  const client = new QueryClient()
  try {
    return renderToStaticMarkup(
      <I18nextProvider i18n={i18n}>
        <QueryClientProvider client={client}>
          <TargetFacts
            nfqws={nfqws}
            target="example.test"
            registryEnabled={false}
            browserProbe={{ status: "idle" }}
            routerProbe={{ status: "idle" }}
          />
        </QueryClientProvider>
      </I18nextProvider>
    )
  } finally {
    client.clear()
  }
}

describe("profile-aware nfqws diagnostics", () => {
  test.each(["ru", "en"] as const)(
    "different profiles are not presented as a global exclusion in %s",
    async (language) => {
      const translation = (language === "ru" ? ruTranslation : enTranslation)
        .overview.targetFacts
      const excluded = profile(2, "excluded")
      excluded.matches = [
        {
          list: "--hostlist-exclude-domains",
          role: "hostlist_exclude",
          includes: false,
          entry: "^example.test",
          matched: "example.test",
          exact: true,
        },
      ]
      const html = await render(
        {
          available: true,
          matches: [],
          profiles: [profile(1, "matched"), excluded],
        },
        language
      )
      expect(html).toContain(translation.nfqws.mixed)
      expect(html).toContain(translation.nfqwsScope)
      expect(html).toContain(translation.nfqwsVisibleHost)
      expect(html).toContain(translation.role.hostlist_exclude)
      expect(html).toContain("^example.test")
      expect(html).toContain("Example &lt;profile&gt;")
      expect(html).not.toContain("Example <profile>")
      expect(html).not.toContain("<details open")
      expect(html).not.toContain("overview.targetFacts.")
      expect(html).not.toContain(translation.nfqws.excluded)
    }
  )

  test.each(["ru", "en"] as const)(
    "all profile outcomes and pass-through are localized in %s",
    async (language) => {
      const translation = (language === "ru" ? ruTranslation : enTranslation)
        .overview.targetFacts
      const profiles = nfqwsProfileResults.map((result, index) =>
        profile(index + 1, result)
      )
      profiles[0].has_actions = false
      const html = await render(
        { available: true, matches: [], profiles },
        language
      )
      for (const result of nfqwsProfileResults) {
        expect(html).toContain(translation.nfqwsProfileResults[result])
      }
      expect(html).toContain(translation.nfqws.unknown)
      expect(html).toContain(translation.nfqwsPassThrough)
      expect(html).not.toContain("overview.targetFacts.")
    }
  )

  test("legacy responses still render without invented profiles", async () => {
    const html = await render(
      { available: false, reason: "unavailable", matches: [] },
      "ru"
    )
    expect(html).toContain(ruTranslation.overview.targetFacts.nfqws.unknown)
    expect(html).not.toContain("<details")
  })
})
