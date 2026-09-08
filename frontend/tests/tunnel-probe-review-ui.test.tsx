import { describe, expect, test } from "bun:test"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createInstance } from "i18next"
import { I18nextProvider } from "react-i18next"
import { renderToStaticMarkup } from "react-dom/server"

import { getGetTunnelProbeHostsQueryKey } from "../src/api/generated/keen-api"
import type { TunnelProbeHostsResponse } from "../src/api/generated/model/tunnelProbeHostsResponse"
import { TunnelProbeHosts } from "../src/components/shared/tunnel-probe-hosts"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

const observedState: TunnelProbeHostsResponse = {
  available: true,
  routed: ["example.org", "still-blocked.example"],
  excluded: ["excluded.example"],
  review_available: true,
  reviews: [
    {
      host: "example.org",
      direct_successes: 3,
      required_successes: 3,
      suggested: true,
    },
    {
      host: "still-blocked.example",
      direct_successes: 0,
      required_successes: 3,
      suggested: false,
    },
  ],
}

async function renderHosts(
  state: TunnelProbeHostsResponse,
  language: "ru" | "en" = "ru"
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
  const client = new QueryClient()
  client.setQueryData(getGetTunnelProbeHostsQueryKey(), {
    status: 200,
    data: state,
    headers: new Headers(),
  })
  try {
    return renderToStaticMarkup(
      <I18nextProvider i18n={i18n}>
        <QueryClientProvider client={client}>
          <TunnelProbeHosts />
        </QueryClientProvider>
      </I18nextProvider>
    )
  } finally {
    client.clear()
  }
}

describe("tunnel-probe direct-access suggestions", () => {
  test.each(["ru", "en"] as const)(
    "describes router evidence and the limited list change in %s",
    async (language) => {
      const text = (language === "ru" ? ruTranslation : enTranslation).pages
        .settings.general
      const html = await renderHosts(observedState, language)
      expect(html).toContain(text.tunnelProbeReviewSummary)
      expect(html).toContain(text.tunnelProbeReviewHint)
      expect(html.split(text.tunnelProbeReviewAction)).toHaveLength(2)
      expect(html).toContain(text.tunnelProbeReviewRefreshHint)
      expect(html).toContain(text.tunnelProbeHostExclude)
      expect(html).toContain(text.tunnelProbeHostRestore)
      expect(html).not.toContain("pages.settings.general.")
    }
  )

  test.each([undefined, false])(
    "does not suggest a route change when review availability is %s",
    async (review_available) => {
      const html = await renderHosts({ ...observedState, review_available })
      const text = ruTranslation.pages.settings.general
      expect(html).not.toContain(text.tunnelProbeReviewAction)
      expect(html).toContain("example.org")
      expect(html).toContain(text.tunnelProbeHostRemove)
      expect(html).toContain(text.tunnelProbeHostExclude)
      expect(html).toContain(text.tunnelProbeHostRestore)
      expect(html).not.toContain("disabled=")
      if (review_available === false) {
        expect(html).toContain(text.tunnelProbeReviewUnavailable)
      } else {
        expect(html).not.toContain(text.tunnelProbeReviewUnavailable)
      }
    }
  )

  test("an older server keeps the original host controls without review notices", async () => {
    const html = await renderHosts({
      available: true,
      routed: ["example.org"],
      excluded: ["excluded.example"],
    })
    const text = ruTranslation.pages.settings.general
    expect(html).toContain(text.tunnelProbeHostRemove)
    expect(html).toContain(text.tunnelProbeHostExclude)
    expect(html).toContain(text.tunnelProbeHostRestore)
    expect(html).not.toContain(text.tunnelProbeReviewAction)
    expect(html).not.toContain(text.tunnelProbeReviewUnavailable)
    expect(html).not.toContain(text.tunnelProbeReviewLimited)
  })

  test("counts alone never become a suggestion", async () => {
    const html = await renderHosts({
      ...observedState,
      reviews: [
        {
          host: "example.org",
          direct_successes: 20,
          required_successes: 3,
          suggested: false,
        },
      ],
    })
    expect(html).not.toContain(
      ruTranslation.pages.settings.general.tunnelProbeReviewAction
    )
  })

  test("stale history for an excluded or removed host does not show an action", async () => {
    const html = await renderHosts({
      ...observedState,
      reviews: ["excluded.example", "removed.example"].map((host) => ({
        host,
        direct_successes: 3,
        required_successes: 3,
        suggested: true,
      })),
    })
    expect(html).not.toContain(
      ruTranslation.pages.settings.general.tunnelProbeReviewAction
    )
    expect(html).not.toContain("removed.example")
  })

  test.each(["ru", "en"] as const)(
    "a settings draft explains the active-list action without disabling it in %s",
    async (language) => {
      const text = (language === "ru" ? ruTranslation : enTranslation).pages
        .settings.general
      const html = await renderHosts(
        {
          ...observedState,
          config_is_draft: true,
          review_limited: true,
        },
        language
      )
      expect(html).toContain(text.tunnelProbeHostsDraftNotice)
      expect(html).toContain(text.tunnelProbeReviewLimited)
      expect(html).toContain(text.tunnelProbeReviewAction)
      expect(html).not.toContain("disabled=")
    }
  )

  test("empty and unavailable automation keep their existing presentation", async () => {
    expect(
      await renderHosts({ available: false, routed: [], excluded: [] })
    ).toBe("")
    const html = await renderHosts({
      available: true,
      routed: [],
      excluded: [],
    })
    expect(html).toContain(
      ruTranslation.pages.settings.general.tunnelProbeHostsEmpty
    )
    expect(html).not.toContain(
      ruTranslation.pages.settings.general.tunnelProbeReviewAction
    )
  })

  test("the suggestion remains one explicit remove request, without new polling or confirmations", async () => {
    const source = await Bun.file(
      new URL(
        "../src/components/shared/tunnel-probe-hosts.tsx",
        import.meta.url
      )
    ).text()
    expect(source).toContain('onClick={() => void act(host, "remove", true)}')
    expect(source).toContain("await updateTunnelProbeHost({ host, action })")
    expect(source).toContain("refetchOnWindowFocus: true")
    expect(source).not.toContain("refetchInterval")
    expect(source).not.toContain("setInterval")
    expect(source).not.toContain("window.confirm")
    expect(source).not.toContain("<Dialog")
    expect(source).toContain("if (pendingRef.current) return")
    expect(source.indexOf("pendingRef.current = true")).toBeLessThan(
      source.indexOf("await updateTunnelProbeHost")
    )
    expect(source).toContain("pendingRef.current = false")
    expect(source).toContain("disabled={pending}")
  })

  test("the response is checked before cache or success feedback changes", async () => {
    const source = await Bun.file(
      new URL(
        "../src/components/shared/tunnel-probe-hosts.tsx",
        import.meta.url
      )
    ).text()
    expect(source).toContain("if (response.status !== 200)")
    expect(source).toContain("!updated.routed.includes(host)")
    expect(source).toContain("updated.excluded.includes(host)")
    expect(source).toContain("if (!reflected)")
    expect(source.indexOf("if (!reflected)")).toBeLessThan(
      source.indexOf("queryClient.setQueryData")
    )
    expect(source.indexOf("queryClient.setQueryData")).toBeLessThan(
      source.indexOf("toast.success")
    )
    expect(source).toContain("<OperationErrorMessage")
  })
})
