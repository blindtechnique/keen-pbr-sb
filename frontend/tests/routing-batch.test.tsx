import { describe, expect, spyOn, test } from "bun:test"
import { createInstance } from "i18next"
import { I18nextProvider } from "react-i18next"
import { renderToStaticMarkup } from "react-dom/server"
import type { ReactNode } from "react"
import type { RoutingTestResponse } from "../src/api/generated/model"
import {
  batchOutcome,
  batchReport,
  batchTarget,
  makeBatchPlan,
  runRoutingBatch,
  type BatchItem,
  type BatchRow,
} from "../src/components/overview/routing-batch-model"
import {
  RoutingBatchPanel,
  RoutingBatchResults,
} from "../src/components/overview/routing-batch-panel"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"
import appI18n from "../src/i18n"

function plan(count = 2) {
  return makeBatchPlan(
    Array.from(
      { length: count },
      (_, i) => `https://example.com/file${i}.css`
    ).join("\n"),
    [{ path: "policy", label: "По правилам" }],
    ["ipv4"]
  ).items
}
function response(
  item: BatchItem,
  extra: Partial<RoutingTestResponse> = {}
): RoutingTestResponse {
  return {
    target: item.target,
    is_domain: true,
    config_scope: "active",
    unapplied_draft: false,
    resolved_ips: ["192.0.2.1"],
    warnings: [],
    no_matching_rule: false,
    rule_diagnostics: [],
    results: [],
    http_probe: {
      status: "answered",
      reason: "http_response",
      ip: "192.0.2.1",
      url: item.options.url,
      method: "HEAD",
      scope: "router",
      interface: "nwg1",
      attempted_at: 1,
      timeout_ms: 5000,
      http_status: 200,
    },
    ...extra,
  }
}
function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((accept) => {
    resolve = accept
  })
  return { promise, resolve }
}
async function render(node: ReactNode, language = "ru") {
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
    <I18nextProvider i18n={i18n}>{node}</I18nextProvider>
  )
}

describe("manual site comparison", () => {
  test("normalizes HTTPS resources without dropping their path or query", () => {
    expect(batchTarget("https://EXAMPLE.com:443/style.css?v=2")).toEqual({
      target: "example.com",
      url: "https://example.com/style.css?v=2",
    })
    expect(batchTarget("example.com/script.js")?.url).toBe(
      "https://example.com/script.js"
    )
    expect(batchTarget("2001:db8::1")?.url).toBe("https://[2001:db8::1]/")
    expect(batchTarget("https://[2001:db8::1]/image.jpg")?.target).toBe(
      "2001:db8::1"
    )
    expect(batchTarget("сайт.рф")?.target).toBe("xn--80aswg.xn--p1ai")
  })
  test("rejects credentials, non-HTTPS ports, fragments, controls and malformed input", () => {
    for (const value of [
      "",
      "http://example.com/",
      "https://u:p@example.com/",
      "https://example.com:444/",
      "https://example.com/#f",
      "https://example.com/\nsecret",
      "https://example.com\\@evil.com/",
      "https://1.2.3.999/",
      "file:///etc/passwd",
      "fe80::1%eth0",
    ]) {
      expect(batchTarget(value)).toBeNull()
    }
  })
  test("limits total combinations, never silently truncates or probes an empty selection", () => {
    const paths = [
      { path: "policy" as const, label: "policy" },
      { path: "direct" as const, label: "direct" },
    ]
    expect(
      makeBatchPlan("a.example\nb.example\nc.example", paths, ["ipv4", "ipv6"])
        .items
    ).toHaveLength(12)
    expect(
      makeBatchPlan("a.example\nb.example\nc.example\nd.example", paths, [
        "ipv4",
        "ipv6",
      ]).error
    ).toBe("limit")
    expect(makeBatchPlan("a.example", [], ["ipv4"]).error).toBe("selection")
    expect(makeBatchPlan("a.example", paths, []).error).toBe("selection")
    expect(
      makeBatchPlan("a.example\na.example", paths, ["ipv4"]).items
    ).toHaveLength(2)
    expect(
      makeBatchPlan("https://a.example/" + "x".repeat(2048), paths, ["ipv4"])
        .error
    ).toBe("targets")
  })
  test("starts nothing on render and clearly explains influence and scope in RU and EN", async () => {
    const fetch = spyOn(globalThis, "fetch")
    try {
      for (const language of ["ru", "en"]) {
        const html = await render(
          <RoutingBatchPanel onRunning={() => {}} />,
          language
        )
        expect(html).not.toContain(" open=")
        expect(html).not.toContain("overview.batch.")
        expect(html).toContain("nfqws2")
        expect(html).toContain("12")
        expect(html).toContain('id="batch-targets"')
      }
      expect(fetch).not.toHaveBeenCalled()
    } finally {
      fetch.mockRestore()
    }
  })
  test("sequential queue drains the current request on stop and never starts the next", async () => {
    const active = new AbortController()
    const started = deferred<void>()
    const pending = deferred<RoutingTestResponse>()
    const items = plan()
    let calls = 0
    let last: BatchRow[] = []
    const finished = runRoutingBatch(
      items,
      active.signal,
      (rows) => {
        last = rows
      },
      async () => {
        calls++
        started.resolve()
        return pending.promise
      },
      async () => {}
    )
    await started.promise
    expect(last.map((row) => row.state)).toEqual(["running", "queued"])
    active.abort()
    await Promise.resolve()
    expect(calls).toBe(1)
    pending.resolve(response(items[0]))
    const result = await finished
    expect(result.map((row) => row.state)).toEqual(["done", "cancelled"])
    expect(calls).toBe(1)
    expect(result[0].finishedAt).toBeDefined()
    expect(result[1].startedAt).toBeUndefined()
  })
  test("stop before dispatch starts no work, including under an invalid large plan", async () => {
    const active = new AbortController()
    active.abort()
    let calls = 0
    const result = await runRoutingBatch(
      plan(),
      active.signal,
      () => {},
      async (item) => {
        calls++
        return response(item)
      }
    )
    expect(result.every((row) => row.state === "cancelled")).toBe(true)
    expect(calls).toBe(0)
    await expect(
      runRoutingBatch(Array(13).fill(plan(1)[0]), active.signal, () => {})
    ).rejects.toThrow()
  })
  test("localizes invalid size and incomplete DNS responses in RU and EN", async () => {
    const previousLanguage = appI18n.language
    if (!appI18n.isInitialized) await appI18n.init({ lng: "en" })
    appI18n.addResourceBundle("ru", "translation", ruTranslation, true, true)
    appI18n.addResourceBundle("en", "translation", enTranslation, true, true)
    try {
      for (const [language, copy] of [
        ["ru", ruTranslation],
        ["en", enTranslation],
      ] as const) {
        await appI18n.changeLanguage(language)
        await expect(
          runRoutingBatch([], new AbortController().signal, () => {})
        ).rejects.toThrow(copy.overview.batch.invalidSize)
        const result = await runRoutingBatch(
          plan(),
          new AbortController().signal,
          () => {},
          async (item) =>
            response(item, {
              resolved_ips: undefined,
            } as unknown as Partial<RoutingTestResponse>)
        )
        expect(result.map((row) => row.state)).toEqual(["failed", "cancelled"])
        expect(result[0].error).toBe(copy.overview.batch.invalidResponse)
        const html = await render(
          <RoutingBatchResults rows={result} />,
          language
        )
        expect(html).toContain(copy.overview.batch.invalidResponse)
      }
    } finally {
      await appI18n.changeLanguage(previousLanguage || "en")
    }
  })
  test("API failure stops the series without retries and is not a website failure", async () => {
    let calls = 0
    const result = await runRoutingBatch(
      plan(),
      new AbortController().signal,
      () => {},
      async () => {
        calls++
        throw { status: 503, message: "busy" }
      }
    )
    expect(calls).toBe(1)
    expect(result.map((row) => row.state)).toEqual(["failed", "cancelled"])
    expect(batchOutcome(result[0])).toBe("unavailable")
  })
  test("old, incomplete and wrong-target responses are not accepted as a new path check", async () => {
    for (const extra of [
      { http_probe: undefined },
      { target: "other.example" },
      {
        http_probe: {
          ...response(plan(1)[0]).http_probe!,
          url: "https://example.com/other.css",
        },
      },
    ]) {
      const result = await runRoutingBatch(
        plan(),
        new AbortController().signal,
        () => {},
        async (item) => response(item, extra)
      )
      expect(result.map((row) => row.state)).toEqual(["failed", "cancelled"])
    }
  })
  test("stop during the gap between requests prevents the next probe", async () => {
    const active = new AbortController()
    let calls = 0
    const rows = await runRoutingBatch(
      plan(),
      active.signal,
      () => {},
      async (item) => {
        calls++
        return response(item)
      },
      async () => {
        active.abort()
      }
    )
    expect(calls).toBe(1)
    expect(rows.map((row) => row.state)).toEqual(["done", "cancelled"])
  })
  test("network failures remain per-target results and do not prevent checking other addresses", async () => {
    const items = plan()
    let calls = 0
    const result = await runRoutingBatch(
      items,
      new AbortController().signal,
      () => {},
      async (item) => {
        calls++
        const data = response(item)
        if (calls === 1)
          data.http_probe = {
            ...data.http_probe!,
            status: "failed",
            reason: "tls_error",
          }
        return data
      },
      async () => {}
    )
    expect(calls).toBe(2)
    expect(result.map(batchOutcome)).toEqual(["failed", "answered"])
  })
  test("HTTP 403 is an HTTP answer, DNS failure and missing IPv6 are separate", () => {
    const item = plan(1)[0]
    const row: BatchRow = { ...item, state: "done", response: response(item) }
    row.response!.http_probe!.http_status = 403
    expect(batchOutcome(row)).toBe("httpError")
    row.response!.dns_error = "DNS timeout"
    expect(batchOutcome(row)).toBe("dns")
    row.response!.dns_error = undefined
    row.response!.http_probe!.ip = ""
    expect(batchOutcome(row)).toBe("noAddress")
  })
  test("production adapter sends one opted-in API request, not browser/CDN or registry requests", async () => {
    const items = plan(1)
    const calls: { url: string; body: unknown }[] = []
    const fetch = spyOn(globalThis, "fetch").mockImplementation(
      async (url, options) => {
        calls.push({
          url: String(url),
          body: JSON.parse(String(options?.body)),
        })
        return new Response(JSON.stringify(response(items[0])), {
          status: 200,
          headers: { "content-type": "application/json" },
        })
      }
    )
    try {
      const rows = await runRoutingBatch(
        items,
        new AbortController().signal,
        () => {}
      )
      expect(rows[0].state).toBe("done")
      expect(calls).toEqual([
        {
          url: "/api/routing/test",
          body: { target: "example.com", http_probe: items[0].options },
        },
      ])
    } finally {
      fetch.mockRestore()
    }
  })
  test("missing family does not claim changed DNS and DNS sources stay localized", async () => {
    const item = plan(1)[0]
    const data = response(item)
    data.dns_source = "configured_resolver"
    data.http_probe = {
      ...data.http_probe!,
      ip: "",
      status: "unavailable",
      reason: "destination_changed",
    }
    const html = await render(
      <RoutingBatchResults
        rows={[{ ...item, state: "done", response: data }]}
      />
    )
    expect(html).toContain("Нет адреса выбранного семейства")
    expect(html).not.toContain("DNS-ответ изменился")
    expect(html).not.toContain("destination_changed")
    expect(html).not.toContain("configured_resolver")
  })
  test("export contains selected evidence but not connection history, all rules or lists", async () => {
    const item = plan(1)[0]
    const row: BatchRow = { ...item, state: "done", response: response(item) }
    row.response!.unapplied_draft = true
    row.response!.connections = {
      snapshot_available: true,
      snapshot_at: 1,
      total: 0,
      truncated: false,
      items: [],
    }
    const report = JSON.stringify(batchReport([row]))
    expect(report).not.toContain("connections")
    expect(report).not.toContain("rule_diagnostics")
    expect(report).toContain("timeout_ms")
    expect(report).toContain("HEAD")
    expect(batchReport([row]).rows[0].configScope).toBe("active")
    expect(batchReport([row]).rows[0].unappliedDraft).toBe(true)
    for (const language of ["ru", "en"]) {
      const html = await render(<RoutingBatchResults rows={[row]} />, language)
      expect(html).not.toContain("overview.batch.")
      expect(html).toContain("HTTP 200")
      expect(html).toContain("Discord")
    }
  })
})
