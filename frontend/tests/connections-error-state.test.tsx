import { describe, expect, test } from "bun:test"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"

import type { ConnectionPage } from "../src/api/generated/model"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"
import { ConnectionsPage } from "../src/pages/connections-page"

const key = ["connections", "active", ""]
const page: ConnectionPage = {
  items: [
    {
      id: "1",
      protocol: "tcp",
      state: "ESTABLISHED",
      source: "192.168.1.2",
      source_port: 50000,
      destination: "203.0.113.1",
      destination_port: 443,
      route: "vpn",
      mark: 1,
      active: true,
      device: "Test phone",
      destination_domains: [],
      first_seen: 1,
      last_seen: 2,
    },
  ],
  total: 1,
  snapshot_at: 2,
  next_cursor: "next-page",
}

async function renderState(
  mode: "initial-error" | "stale" | "next-page-error" | "loading" | "empty",
  language: "ru" | "en"
) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, retryOnMount: false } },
  })
  const i18n = createInstance()
  await i18n.init({
    lng: language,
    resources: {
      ru: { translation: ruTranslation },
      en: { translation: enTranslation },
    },
    interpolation: { escapeValue: false },
  })
  if (mode === "stale" || mode === "next-page-error" || mode === "empty") {
    client.setQueryData(key, {
      pages: [mode === "empty" ? { ...page, items: [], total: 0 } : page],
      pageParams: [undefined],
    })
  }
  if (mode.endsWith("error") || mode === "stale") {
    const query = client.getQueryCache().build(client, { queryKey: key })
    query.setState({
      status: "error",
      error: new Error("connection unavailable"),
      fetchStatus: "idle",
      fetchMeta:
        mode === "next-page-error"
          ? { fetchMore: { direction: "forward" } }
          : null,
    })
  }
  try {
    return renderToStaticMarkup(
      <I18nextProvider i18n={i18n}>
        <QueryClientProvider client={client}>
          <ConnectionsPage />
        </QueryClientProvider>
      </I18nextProvider>
    )
  } finally {
    client.clear()
  }
}

describe("connections loading and errors", () => {
  test.each(["ru", "en"] as const)(
    "first request failure shows retry, not empty state (%s)",
    async (language) => {
      const copy = language === "ru" ? ruTranslation : enTranslation
      const html = await renderState("initial-error", language)
      expect(html).toContain(copy.connections.loadFailed)
      expect(html).toContain(copy.common.retry)
      expect(html).not.toContain(copy.connections.emptyTitle)
    }
  )
  test("failed refresh retains loaded rows and identifies stale data", async () => {
    const html = await renderState("stale", "ru")
    expect(html).toContain("Test phone")
    expect(html).toContain(ruTranslation.connections.refreshFailed)
  })
  test("failed next page keeps previous rows and offers retry", async () => {
    const html = await renderState("next-page-error", "ru")
    expect(html).toContain("Test phone")
    expect(html).toContain(ruTranslation.connections.loadMoreFailed)
    const source = await Bun.file(
      new URL("../src/pages/connections-page.tsx", import.meta.url)
    ).text()
    expect(source).toContain(
      "if (query.isFetchNextPageError) void query.fetchNextPage()"
    )
  })
  test("loading is distinct from a successful empty response", async () => {
    expect(await renderState("loading", "ru")).toContain(
      ruTranslation.common.loading
    )
    const empty = await renderState("empty", "ru")
    expect(empty).toContain(ruTranslation.connections.emptyTitle)
    expect(empty).not.toContain(ruTranslation.connections.loadFailed)
  })
})
