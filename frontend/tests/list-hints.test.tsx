import { describe, expect, mock, spyOn, test } from "bun:test"
import { readFileSync } from "node:fs"
import { createInstance } from "i18next"
import { I18nextProvider } from "react-i18next"
import { Router } from "wouter"
import { renderToStaticMarkup } from "react-dom/server"
import type { ReactNode } from "react"
import type { ListHintsResponse } from "../src/api/generated/model/listHintsResponse"
import type { ConfigObject } from "../src/api/generated/model/configObject"
import { ListHints, ListHintsResult } from "../src/components/lists/list-hints"
import {
  listHintsIncomplete,
  runListHints,
  type ListHintsState,
} from "../src/components/lists/list-hints-model"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

function response(extra: Partial<ListHintsResponse> = {}): ListHintsResponse {
  return {
    revision: "revision",
    is_draft: false,
    items: [],
    source_issues: [],
    source_issues_limited: false,
    hints_limited: false,
    scan_limited: false,
    scanned_lists: 2,
    total_lists: 2,
    scanned_entries: 10,
    conditional_rules: 0,
    elapsed_ms: 12,
    ...extra,
  }
}
async function render(children: ReactNode, language = "ru") {
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
      <Router ssrPath="/lists">{children}</Router>
    </I18nextProvider>
  )
}
function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((yes, no) => {
    resolve = yes
    reject = no
  })
  return { promise, resolve, reject }
}

describe("optional list hints", () => {
  test("start collapsed with no network, result or mutation buttons", async () => {
    const fetch = spyOn(globalThis, "fetch")
    try {
      const html = await render(<ListHints config={{}} revision="revision" />)
      expect(html).toContain("Подсказки по спискам")
      expect(html).not.toContain(" open=")
      expect(html).not.toContain("<button")
      expect(html).not.toContain("<ul")
      expect(fetch).not.toHaveBeenCalled()
    } finally {
      fetch.mockRestore()
    }
  })

  test("one explicit request ignores repeated clicks and requires matching revision", async () => {
    const pending = deferred<ListHintsResponse>()
    const request = mock(() => pending.promise)
    const active = { current: null as AbortController | null }
    const states: ListHintsState[] = []
    const run = runListHints(active, "revision", request, (state) =>
      states.push(state)
    )
    await runListHints(active, "revision", request, (state) =>
      states.push(state)
    )
    expect(request).toHaveBeenCalledTimes(1)
    expect(states).toEqual([{ status: "pending" }])
    pending.resolve(response({ revision: "changed" }))
    await run
    expect(states.at(-1)).toEqual({ status: "stale" })
    expect(active.current).toBeNull()
    await runListHints(
      active,
      "revision",
      async () => response(),
      (state) => states.push(state)
    )
    expect(states.at(-1)?.status).toBe("ready")
  })

  for (const failure of [false, true]) {
    test(`closing or changing configuration discards a late ${failure ? "failure" : "success"}`, async () => {
      const pending = deferred<ListHintsResponse>()
      const active = { current: null as AbortController | null }
      const states: ListHintsState[] = []
      const run = runListHints(
        active,
        "revision",
        () => pending.promise,
        (state) => states.push(state)
      )
      const old = active.current
      active.current = null
      old?.abort()
      const fresh = new AbortController()
      active.current = fresh
      if (failure) pending.reject(new Error("private-url-and-token"))
      else pending.resolve(response())
      await run
      expect(states).toEqual([{ status: "pending" }])
      expect(active.current).toBe(fresh)
    })
  }

  test("request failure is local, redacted and can be retried", async () => {
    const active = { current: null as AbortController | null }
    const states: ListHintsState[] = []
    await runListHints(
      active,
      "revision",
      async () => {
        throw new Error("private-source")
      },
      (state) => states.push(state)
    )
    expect(states).toEqual([{ status: "pending" }, { status: "failed" }])
    expect(active.current).toBeNull()
    await runListHints(
      active,
      "revision",
      async () => response(),
      (state) => states.push(state)
    )
    expect(states.at(-1)?.status).toBe("ready")
    expect(JSON.stringify(states)).not.toContain("private-source")
  })

  test("all partial source and budget states are disclosed", async () => {
    expect(listHintsIncomplete(response())).toBe(false)
    for (const extra of [
      { scan_limited: true },
      { scanned_lists: 1 },
      { source_issues_limited: true },
      { source_issues: [{ list: "source", reason: "unavailable" }] },
    ]) {
      const report = response(extra)
      expect(listHintsIncomplete(report)).toBe(true)
      const html = await render(<ListHintsResult result={report} config={{}} />)
      expect(html).toContain("Проверка неполная")
      expect(html).toContain("В проверенной части")
      expect(html).not.toContain("Конфликтов нет")
    }
  })

  test("show friendly labels, rule order and escaped example text", async () => {
    const config: ConfigObject = {
      lists: {
        one: { display_name: "Каталог" },
        two: { display_name: "Мой список" },
      },
      outbounds: [
        {
          tag: "private-tag",
          type: "table",
          table: 254,
          display_name: "Напрямую",
        },
        {
          tag: "second-tag",
          type: "interface",
          interface: "tun0",
          display_name: "Мой VPN",
        },
      ],
    }
    const report = response({
      is_draft: true,
      conditional_rules: 2,
      hints_limited: true,
      items: [
        { code: "unused", list: "one" },
        { code: "wide_cidr", list: "one", entry: "10.0.0.0/8" },
        {
          code: "domain_overlap",
          list: "one",
          other_list: "two",
          entry: "<script>example.test</script>",
          other_entry: "example.test",
          outbound: "private-tag",
          other_outbound: "second-tag",
          rule_index: 1,
          other_rule_index: 4,
        },
      ],
    })
    const html = await render(
      <ListHintsResult config={config} result={report} />
    )
    expect(html).toContain("Каталог")
    expect(html).toContain("Мой список")
    expect(html).toContain("Мой VPN")
    expect(html).not.toContain("private-tag")
    expect(html).toContain("№2")
    expect(html).toContain("№5")
    expect(html).not.toContain("<script>")
    expect(html).toContain("черновик")
    expect(html).toContain("некоторые примеры")
    expect(html).toContain("удалять его необязательно")
    expect(html).not.toContain("<button")
    expect(html).toContain('href="/lists/one/edit"')
  })

  test("RU and EN translate all hint and source categories including unknown ones", async () => {
    const result = response({
      items: [{ code: "future-code-private", list: "one" }],
      source_issues: [
        { list: "one", reason: "source_changed" },
        { list: "two", reason: "size_limit" },
        { list: "three", reason: "invalid_source" },
        { list: "four", reason: "future-private" },
      ],
    })
    for (const language of ["ru", "en"]) {
      const html = await render(
        <ListHintsResult config={{}} result={result} />,
        language
      )
      expect(html).not.toContain("listHints.")
      expect(html).not.toContain("future-private")
      expect(html).not.toContain("future-code-private")
      expect(html).toContain(
        language === "ru" ? "Какие источники" : "Sources not fully"
      )
    }
  })

  test("integration has no background query, notifications or mutation hooks", () => {
    const component = readFileSync(
      new URL("../src/components/lists/list-hints.tsx", import.meta.url),
      "utf8"
    )
    const model = readFileSync(
      new URL("../src/components/lists/list-hints-model.ts", import.meta.url),
      "utf8"
    )
    const page = readFileSync(
      new URL("../src/pages/lists-page.tsx", import.meta.url),
      "utf8"
    )
    expect(component).toContain("key={revision}")
    expect(component).toContain("controller?.abort()")
    expect(component).toContain("postListHints({ signal })")
    expect(component).toContain('type="button"')
    expect(page).toContain(
      "<ListHints config={loadedConfig} revision={configRevision}"
    )
    for (const forbidden of [
      "setInterval",
      "useQuery",
      "useMutation",
      "toast",
      "postConfig",
      "postListsRefresh",
    ])
      expect(component + model).not.toContain(forbidden)
  })
})
