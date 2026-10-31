import { expect, mock, test } from "bun:test"
import { QueryClient } from "@tanstack/react-query"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"
import { Router } from "wouter"
import type { InterceptionHealth } from "../src/api/generated/model/interceptionHealth"
import { getGetHealthServiceQueryKey } from "../src/api/generated/keen-api"
import { applyStatusEvent } from "../src/api/status-event-cache"
import { DnsLearningField } from "../src/components/settings/dns-learning-field"
import { InterceptionPanel } from "../src/components/overview/interception-panel"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

const health: InterceptionHealth = {
  dns_requested: true,
  l7_requested: true,
  dns_state: "fail_open_unconfirmed",
  l7_state: "active",
  dns_detail: "<script>not executable</script>",
  l7_detail: "group bound",
  interfaces: ["br0"],
  nfqueue: "ok",
  nflog: "ok",
  fail_open: "unsupported",
  dns_packets: 0,
  dns_matched: 0,
  l7_packets: 12,
  l7_matched: 3,
  set_errors: 0,
  dns_hold_timeouts: 0,
  queue_overruns: 0,
  log_overruns: 0,
}

for (const language of ["ru", "en"] as const) {
  test(`learning controls and diagnostic reasons render in ${language}`, async () => {
    const i18n = createInstance()
    await i18n.init({
      lng: language,
      resources: {
        ru: { translation: ruTranslation },
        en: { translation: enTranslation },
      },
      interpolation: { escapeValue: false },
    })
    const copy = (language === "ru" ? ruTranslation : enTranslation).learning
    const change = mock(() => {})
    const controls = renderToStaticMarkup(
      <I18nextProvider i18n={i18n}>
        <DnsLearningField kind="dns" value={false} onChange={change} />
        <DnsLearningField kind="l7" value={true} onChange={change} />
      </I18nextProvider>
    )
    for (const kind of ["dns", "l7"]) {
      expect(controls).toContain(`id="dns-learning-${kind}"`)
      expect(controls).toContain(`for="dns-learning-${kind}"`)
      expect(controls).toContain(`aria-describedby="dns-learning-${kind}-hint"`)
    }
    expect(controls).toContain(copy.dnsLabel)
    expect(controls).toContain(copy.l7Hint)
    expect(change).not.toHaveBeenCalled()
    const panel = renderToStaticMarkup(
      <I18nextProvider i18n={i18n}>
        <Router ssrPath="/">
          <InterceptionPanel health={health} configIsDraft />
        </Router>
      </I18nextProvider>
    )
    expect(panel).toContain(copy.states.fail_open_unconfirmed)
    expect(panel).toContain(copy.states.active)
    expect(panel).toContain(copy.draftHint)
    expect(panel).toContain(copy.staleHint)
    expect(panel).toContain('href="/general#advanced"')
    expect(panel).not.toContain("<script>")
    expect(panel).toContain("&lt;script&gt;")
    expect(panel).not.toContain('role="alert"')
    const missing = renderToStaticMarkup(
      <I18nextProvider i18n={i18n}>
        <Router ssrPath="/">
          <InterceptionPanel configIsDraft={false} />
        </Router>
      </I18nextProvider>
    )
    expect(missing).toContain(copy.states.unknown)
    expect(missing).not.toContain(copy.states.unavailable)
    expect(missing).not.toContain(copy.states.active)
  })
}

test("existing SSE service updates carry learning facts without changing VPN state", () => {
  const cache = new QueryClient()
  expect(
    applyStatusEvent(
      cache,
      JSON.stringify({
        type: "service",
        data: {
          status: "running",
          runtime_state: "running",
          interception: health,
        },
      })
    )
  ).toBe(true)
  expect(cache.getQueryData(getGetHealthServiceQueryKey())).toMatchObject({
    data: { status: "running", runtime_state: "running", interception: health },
  })
  expect(
    applyStatusEvent(
      cache,
      JSON.stringify({
        type: "service",
        data: {
          status: "stopped",
          interception: {
            ...health,
            dns_state: "stopped",
            l7_state: "stopped",
          },
        },
      })
    )
  ).toBe(true)
  expect(cache.getQueryData(getGetHealthServiceQueryKey())).toMatchObject({
    data: {
      status: "stopped",
      interception: { dns_state: "stopped", l7_state: "stopped" },
    },
  })
  cache.clear()
})
