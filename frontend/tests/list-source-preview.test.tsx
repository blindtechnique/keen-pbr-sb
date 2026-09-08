import { describe, expect, mock, spyOn, test } from "bun:test"
import { readFileSync } from "node:fs"
import { createInstance } from "i18next"
import { I18nextProvider } from "react-i18next"
import { renderToStaticMarkup } from "react-dom/server"
import type { ReactNode } from "react"
import type { ListSourcePreviewResponse } from "../src/api/generated/model/listSourcePreviewResponse"
import {
  catalogSourcePreviewRequest,
  getCatalogPreviewSources,
  listSourcePreviewKey,
  listSourcePreviewRequest,
  runListSourcePreviewRequest,
  type ListSourcePreviewState,
} from "../src/components/lists/list-source-preview-model"
import {
  ListSourcePreview,
  ListSourcePreviewResult,
} from "../src/components/lists/list-source-preview"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

function response(
  extra: Partial<ListSourcePreviewResponse> = {}
): ListSourcePreviewResponse {
  return {
    status: "ok",
    complete: true,
    lines: 6,
    valid_entries: 3,
    unique_entries: 2,
    duplicates: 1,
    invalid_entries: 1,
    ignored_lines: 2,
    ipv4: 1,
    ipv6: 0,
    domains: 1,
    entries_limited: false,
    errors_limited: false,
    entries: [
      { line: 3, value: "192.0.2.0/24", type: "ipv4" },
      { line: 6, value: "example.org", type: "domain" },
    ],
    errors: [{ line: 5, code: "leading_zeros", value: "192.000.2.1" }],
    ...extra,
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((yes, no) => {
    resolve = yes
    reject = no
  })
  return { resolve, reject, promise }
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
    <I18nextProvider i18n={i18n}>{children}</I18nextProvider>
  )
}

describe("explicit list source preview lifecycle", () => {
  for (const settleOldWithError of [false, true]) {
    test(`source change or close discards old ${settleOldWithError ? "failure" : "success"}`, async () => {
      const active = { current: null as symbol | null }
      const shown: ListSourcePreviewState[] = []
      const old = deferred<ListSourcePreviewResponse>()
      const current = deferred<ListSourcePreviewResponse>()
      const request = mock(() => old.promise)
      const pending = runListSourcePreviewRequest(active, request, (state) =>
        shown.push(state)
      )
      await runListSourcePreviewRequest(active, request, (state) =>
        shown.push(state)
      )
      expect(request).toHaveBeenCalledTimes(1)
      active.current = null // The keyed session's unmount cleanup.
      const next = runListSourcePreviewRequest(
        active,
        () => current.promise,
        (state) => shown.push(state)
      )
      if (settleOldWithError)
        old.reject(new Error("https://name:secret@old.example"))
      else old.resolve(response({ domains: 99 }))
      await pending
      expect(shown).toEqual([{ status: "pending" }, { status: "pending" }])
      current.resolve(response())
      await next
      expect(shown.at(-1)).toEqual({ status: "ready", result: response() })
      expect(active.current).toBeNull()
    })
  }
  test("current request failures are retryable and never retain credential-bearing errors", async () => {
    const active = { current: null as symbol | null }
    const shown: ListSourcePreviewState[] = []
    await runListSourcePreviewRequest(
      active,
      async () => {
        throw new Error("https://user:secret@server")
      },
      (state) => shown.push(state)
    )
    expect(shown).toEqual([{ status: "pending" }, { status: "failed" }])
    await runListSourcePreviewRequest(
      active,
      async () => response(),
      (state) => shown.push(state)
    )
    expect(shown.at(-1)?.status).toBe("ready")
    expect(JSON.stringify(shown)).not.toContain("secret")
  })
  test("every relevant source and route field changes the session key", () => {
    const original = {
      url: "https://lists.example/a",
      refresh_detour_mode: "inherit" as const,
    }
    const key = listSourcePreviewKey(original)
    for (const change of [
      { url: "https://lists.example/b" },
      { refresh_detour_mode: "override" as const },
      { detour: "vpn" },
      { fallback_detours: ["backup"] },
      { text: "example.org" },
    ]) {
      expect(listSourcePreviewKey({ ...original, ...change })).not.toBe(key)
    }
  })
  test("rendering a panel never downloads or saves configuration", async () => {
    const fetch = spyOn(globalThis, "fetch")
    try {
      const markup = await render(
        <ListSourcePreview request={{ url: "https://lists.example/a" }} />
      )
      expect(fetch).not.toHaveBeenCalled()
      expect(markup).toContain("Проверить содержимое")
      expect(markup).toContain('type="button"')
      expect(markup).not.toContain("192.0.2.0")
    } finally {
      fetch.mockRestore()
    }
  })
})

describe("list source preview presentation", () => {
  test("counts and canonical entries preserve physical source line numbers", async () => {
    const markup = await render(<ListSourcePreviewResult result={response()} />)
    expect(markup).toContain("Уникальных записей")
    expect(markup).toContain("192.0.2.0/24")
    expect(markup).toContain("Строка 3")
    expect(markup).toContain("Строка 5: Уберите ведущие нули")
    expect(markup).toContain("192.000.2.1")
  })
  for (const status of [
    "download_failed",
    "too_large",
    "unsupported_format",
    "route_unavailable",
  ] as const) {
    test(`${status} is actionable and still allows saving in both languages`, async () => {
      for (const language of ["ru", "en"]) {
        const markup = await render(
          <ListSourcePreviewResult result={response({ status })} />,
          language
        )
        expect(markup).toContain(
          language === "ru"
            ? "Сохранение списка доступно"
            : "You can still save the list"
        )
        expect(markup).not.toContain("listSourcePreview.")
      }
    })
  }
  test("all known parser codes are localized; errors never print unsafe source excerpts", async () => {
    const codes = [
      "leading_zeros",
      "invalid_address",
      "invalid_prefix",
      "line_too_long",
      "invalid_entry",
    ]
    const markup = await render(
      <ListSourcePreviewResult
        result={response({
          errors: codes.map((code, index) => ({
            code,
            line: index + 4,
            value: "https://user:secret@host",
          })),
          errors_limited: true,
          entries_limited: true,
          complete: false,
          limit_reason: "line_limit",
        })}
      />
    )
    expect(markup).toContain("ведущие нули")
    expect(markup).toContain("префикс сети")
    expect(markup).toContain("4096 байт")
    expect(markup).toContain("Показаны первые 50 ошибок")
    expect(markup).toContain("Проверена только часть списка")
    expect(markup).not.toContain("secret")
  })
})

describe("catalog preview source wiring", () => {
  test("primary sources and IP companions are deduplicated without changing catalog data", () => {
    const presets = [
      {
        id: "primary",
        name: "Primary",
        engines: { dns: { subscriptionUrl: "https://lists.example/main" } },
        routingCompanions: [
          { id: "ip", name: "IP", url: "https://lists.example/ip" },
        ],
      },
      {
        id: "duplicate",
        name: "Duplicate",
        engines: { dns: { subscriptionUrl: "https://lists.example/ip" } },
      },
      {
        id: "inline",
        name: "Inline",
        engines: {
          dns: { domains: ["example.org"], subnets: ["192.0.2.0/24"] },
        },
      },
    ]
    const selected = new Set(["primary", "duplicate", "inline"])
    const before = JSON.stringify(presets)
    const sources = getCatalogPreviewSources(presets, selected)
    expect(sources.map((source) => source.source)).toEqual([
      { url: "https://lists.example/main" },
      { url: "https://lists.example/ip" },
      { text: "example.org\n192.0.2.0/24" },
    ])
    expect(JSON.stringify(presets)).toBe(before)
    expect([...selected]).toEqual(["primary", "duplicate", "inline"])
  })
  test("empty catalog route inherits current global route and inline text omits routing", () => {
    expect(
      listSourcePreviewRequest({
        url: "https://lists.example/a",
        refresh_detour_mode: "inherit",
        detour: "",
        fallback_detours: [],
      })
    ).toEqual({
      url: "https://lists.example/a",
      refresh_detour_mode: "inherit",
    })
    expect(
      catalogSourcePreviewRequest({ url: "https://lists.example/a" }, "")
    ).toEqual({
      url: "https://lists.example/a",
      refresh_detour_mode: "inherit",
    })
    expect(
      catalogSourcePreviewRequest({ url: "https://lists.example/a" }, "vpn")
    ).toEqual({
      url: "https://lists.example/a",
      refresh_detour_mode: "override",
      detour: "vpn",
      fallback_detours: [],
    })
    expect(catalogSourcePreviewRequest({ text: "example.org" }, "vpn")).toEqual(
      { text: "example.org" }
    )
  })
  test("editor and catalog before-save surfaces wire previews without save dependencies", () => {
    const page = readFileSync(
      new URL("../src/pages/list-upsert-page.tsx", import.meta.url),
      "utf8"
    )
    const catalog = readFileSync(
      new URL("../src/pages/catalog-page.tsx", import.meta.url),
      "utf8"
    )
    const component = readFileSync(
      new URL(
        "../src/components/lists/list-source-preview.tsx",
        import.meta.url
      ),
      "utf8"
    )
    expect(page).toContain("<ListSourcePreview")
    expect(page).toContain("fallback_detours: state.values.fallbackDetours")
    expect(catalog.match(/<CatalogSourcePreviews/g)).toHaveLength(2)
    expect(component).not.toMatch(
      /usePostConfig|postConfig|setFieldValue|invalidateQueries/
    )
    expect(component).toContain("document.activeElement === button.current")
    expect(component).toContain("active.current = null")
  })
})
