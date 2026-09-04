import { describe, expect, spyOn, test } from "bun:test"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createInstance } from "i18next"
import { I18nextProvider } from "react-i18next"
import { renderToStaticMarkup } from "react-dom/server"

import {
  probeBrowserReachability,
  routerProbeRequestFailure,
  routerProbeResult,
  type SiteProbeState,
} from "../src/components/overview/site-probe-model"
import { TargetFacts } from "../src/components/overview/target-facts"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

describe("website probe results", () => {
  test.each([
    ["HTTP request failed: Could not resolve host: example.org", "dns"],
    ["HTTP request failed: SSL certificate problem", "tls"],
    [
      "HTTP request failed: Connection timed out after 10000 milliseconds",
      "timeout",
    ],
    [
      "HTTP request failed: Failed to connect: Connection refused",
      "connection",
    ],
    ["HTTP request failed: Maximum file size exceeded", "sizeLimit"],
    ["Unexpected response while reading", "unknown"],
  ])("keeps the router reason for %s", (error, reason) => {
    expect(routerProbeResult({ ok: true, reachable: false, error })).toEqual({
      status: "unconfirmed",
      reason,
      detail: error,
    })
  })

  test("HTTP rejection by the website is still a received response", () => {
    expect(
      routerProbeResult({ ok: true, reachable: false, error: "HTTP error 403" })
    ).toEqual({ status: "responded", httpStatus: 403 })
  })

  test("an API authentication error is not an answer from the website", () => {
    expect(routerProbeRequestFailure(new Error("HTTP error 401"))).toEqual({
      status: "unconfirmed",
      reason: "request",
      detail: "HTTP error 401",
    })
  })

  test("a malformed response does not claim the site failed", () => {
    expect(routerProbeResult({ ok: true })).toEqual({
      status: "unconfirmed",
      reason: "invalidResponse",
    })
  })

  test("a browser restriction does not claim the site failed", async () => {
    const fetchSpy = spyOn(globalThis, "fetch").mockRejectedValue(
      new TypeError("Failed to fetch")
    )
    try {
      expect(await probeBrowserReachability("https://example.org/")).toEqual({
        status: "unconfirmed",
        reason: "browser",
      })
    } finally {
      fetchSpy.mockRestore()
    }
  })

  test("a browser response preserves a visible HTTP status", async () => {
    const fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("", { status: 404 })
    )
    try {
      expect(await probeBrowserReachability("https://example.org/")).toEqual({
        status: "responded",
        httpStatus: 404,
      })
    } finally {
      fetchSpy.mockRestore()
    }
  })
})

async function renderFacts(
  browserProbe: SiteProbeState,
  routerProbe: SiteProbeState,
  language = "ru"
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
      <QueryClientProvider client={new QueryClient()}>
        <TargetFacts
          target="example.org"
          registryEnabled={false}
          browserProbe={browserProbe}
          routerProbe={routerProbe}
        />
      </QueryClientProvider>
    </I18nextProvider>
  )
}

describe("independent website probe presentation", () => {
  test("device success does not hide the router's DNS error", async () => {
    const markup = await renderFacts(
      { status: "responded" },
      routerProbeResult({
        reachable: false,
        error: "Could not resolve host: example.org",
      })
    )
    expect(markup).toContain("Это устройство:")
    expect(markup).toContain("Ответ получен.")
    expect(markup).toContain("Роутер:")
    expect(markup).toContain(
      "Роутер не смог определить IP-адрес сайта через DNS."
    )
    expect(markup).toContain("Could not resolve host: example.org")
  })

  test("device result is shown while the router check is still pending", async () => {
    const markup = await renderFacts(
      { status: "responded" },
      { status: "checking" },
      "en"
    )
    expect(markup).toContain("This device:")
    expect(markup).toContain("Response received.")
    expect(markup).toContain("Router:")
    expect(markup).toContain("Checking availability")
    expect(markup).not.toContain("overview.targetFacts.")
  })
})
