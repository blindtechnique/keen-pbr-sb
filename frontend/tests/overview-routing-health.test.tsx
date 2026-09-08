import { afterEach, describe, expect, test } from "bun:test"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"
import { Router } from "wouter"

import { getGetHealthRoutingQueryKey } from "../src/api/generated/keen-api"
import type {
  RoutingHealthErrorResponse,
  RoutingHealthResponse,
} from "../src/api/generated/model"
import {
  routingHealthErrorPresentation,
  selectOverviewRoutingHealth,
} from "../src/components/overview/routing-health-result"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"
import { OverviewPage } from "../src/pages/overview-page"

const clients: QueryClient[] = []
afterEach(() => {
  for (const client of clients.splice(0)) client.clear()
})

const legacyError: RoutingHealthErrorResponse = {
  overall: "error",
  error:
    "runtime routing inventory is not authoritative; waiting for reconciliation",
}
const healthy: RoutingHealthResponse = {
  overall: "ok",
  firewall_backend: "iptables",
  firewall: { chain_present: true, prerouting_hook_present: true },
  firewall_rules: [],
  route_tables: [],
  policy_rules: [],
}

async function renderOverview(
  data: RoutingHealthResponse | RoutingHealthErrorResponse,
  language: "en" | "ru" = "en",
  status = 200
) {
  const client = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        retryOnMount: false,
        staleTime: Infinity,
        gcTime: Infinity,
      },
    },
  })
  clients.push(client)
  client.setQueryData(getGetHealthRoutingQueryKey(), {
    status: 200,
    data,
    headers: new Headers(),
  })
  if (status !== 200) {
    client
      .getQueryCache()
      .find({ queryKey: getGetHealthRoutingQueryKey() })!
      .setState({
        status: "error",
        data: undefined,
        error: { status, message: legacyError.error, details: legacyError },
      })
  }
  const i18n = createInstance()
  await i18n.init({
    lng: language,
    resources: {
      en: { translation: enTranslation },
      ru: { translation: ruTranslation },
    },
    interpolation: { escapeValue: false },
  })
  return renderToStaticMarkup(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <Router ssrPath="/">
          <OverviewPage />
        </Router>
      </I18nextProvider>
    </QueryClientProvider>
  )
}

describe("overview routing diagnostic errors", () => {
  test("treats the legacy HTTP 200 error as an error, not an empty report", () => {
    const result = selectOverviewRoutingHealth({
      status: 200,
      data: legacyError,
    })
    expect(result.report).toBeUndefined()
    expect(result.error).toBe(legacyError)
    expect(legacyError).not.toHaveProperty("firewall_rules")
  })

  test("keeps complete healthy, degraded, and error reports unchanged", () => {
    for (const overall of ["ok", "degraded", "error"] as const) {
      const report = { ...healthy, overall }
      const result = selectOverviewRoutingHealth({ status: 200, data: report })
      expect(result.report).toBe(report)
      expect(result.error).toBeUndefined()
    }
    expect(selectOverviewRoutingHealth(undefined)).toEqual({})
    expect(
      selectOverviewRoutingHealth({ status: 500, data: legacyError })
    ).toEqual({})
  })

  test("the real dashboard survives the incident response and retains its other cards", async () => {
    const html = await renderOverview(legacyError)
    expect(html).toContain(legacyError.error)
    expect(html).toContain('role="alert"')
    expect(html).toContain('id="dashboard-services"')
    expect(html).toContain('id="dashboard-routing"')
    expect(html).toContain(enTranslation.overview.outbounds.title)
    expect(html).not.toContain(enTranslation.overview.routing.emptyTitle)
  })

  test("a valid empty report still uses the existing empty-state presentation", async () => {
    const html = await renderOverview(healthy)
    expect(html).toContain(enTranslation.overview.routing.emptyTitle)
    expect(html).not.toContain(legacyError.error)
  })

  test.each(["ru", "en"] as const)(
    "localizes both legacy 200/error and current HTTP 500 in %s",
    async (language) => {
      const copy = (language === "ru" ? ruTranslation : enTranslation).overview
        .routing
      for (const status of [200, 500]) {
        const html = await renderOverview(legacyError, language, status)
        expect(html).toContain(copy.inventoryUnavailable)
        expect(html).toContain(copy.technicalDetails)
        const details = html.match(/<details\b[^>]*>[\s\S]*?<\/details>/g) ?? []
        expect(details.some((entry) => entry.includes(legacyError.error))).toBe(
          true
        )
        expect(
          html.replace(/<details\b[^>]*>[\s\S]*?<\/details>/g, "")
        ).not.toContain(legacyError.error)
        expect(
          details.some((entry) => /^<details\b[^>]*\bopen/.test(entry))
        ).toBe(false)
        expect(html).toContain('id="dashboard-services"')
        expect(html).not.toContain(copy.emptyTitle)
      }
    }
  )

  test("unknown and empty diagnostic failures use a translated fallback, without a false recovery promise", () => {
    const t = (key: string) => key
    for (const error of [undefined, {}, { error: "" }]) {
      expect(routingHealthErrorPresentation(error, t)).toEqual({
        summary: "overview.routing.loadError",
        detail: undefined,
      })
    }
    expect(
      routingHealthErrorPresentation({ message: "new failure <script>" }, t)
    ).toEqual({
      summary: "overview.routing.loadError",
      detail: "new failure <script>",
    })
  })
})
