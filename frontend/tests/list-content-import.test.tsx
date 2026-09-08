import { describe, expect, mock, spyOn, test } from "bun:test"
import { readFileSync } from "node:fs"
import { createInstance } from "i18next"
import { I18nextProvider } from "react-i18next"
import { renderToStaticMarkup } from "react-dom/server"
import * as api from "../src/api/generated/keen-api"
import type { ListContentImportResponse } from "../src/api/generated/model/listContentImportResponse"
import { ListContentImport } from "../src/components/lists/list-content-import"
import {
  appendListContentImport,
  LIST_CONTENT_MAX_BYTES,
  listContentTextTooLarge,
  readListContentFile,
  runListContentImport,
  type ListContentImportState,
  type ListImportSession,
} from "../src/components/lists/list-content-import-model"
import {
  listSourcePreviewErrorMessage,
  listSourcePreviewKey,
  listSourcePreviewRequest,
} from "../src/components/lists/list-source-preview-model"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"
import {
  buildUpdatedConfigForListUpsert,
  createListDraft,
  getDraftFromMapEntry,
  getListConfigFromDraft,
  narrowDraftToSourceGroups,
  normalizeListDraftForComparison,
} from "../src/pages/list-upsert-utils"

function result(
  extra: Partial<ListContentImportResponse> = {}
): ListContentImportResponse {
  return {
    complete: true,
    domains: ["example.org"],
    ip_cidrs: ["192.0.2.0/24"],
    duplicates: 0,
    errors: [],
    errors_limited: false,
    ...extra,
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: Error) => void
  const promise = new Promise<T>((yes, no) => {
    resolve = yes
    reject = no
  })
  return { promise, resolve, reject }
}

describe("local list contents import", () => {
  test("appends all normalized entries, deduplicates and keeps existing draft bytes", () => {
    const current = {
      domains: " Example.ORG \nkept.example\n",
      ipCidrs: "192.0.2.0/24",
    }
    const imported = result({
      domains: [
        "example.org",
        ...Array.from(
          { length: 60 },
          (_, index) => "entry" + index + ".example"
        ),
      ],
      duplicates: 3,
    })
    const merged = appendListContentImport(current, imported)
    expect(merged?.fields.domains).toStartWith(current.domains)
    expect(merged?.fields.domains).toContain("entry59.example")
    expect(merged?.fields.ipCidrs).toBe(current.ipCidrs)
    expect(merged?.added).toEqual({ domains: 60, ipCidrs: 0, duplicates: 5 })
    expect(current).toEqual({
      domains: " Example.ORG \nkept.example\n",
      ipCidrs: "192.0.2.0/24",
    })
  })

  test("invalid and incomplete responses cannot add their diagnostic prefix", () => {
    const current = { domains: "keep.example", ipCidrs: "198.51.100.1" }
    for (const response of [
      result({ complete: false, limit_reason: "entry_limit" }),
      result({ errors: [{ line: 2, code: "json_entry_type", value: "123" }] }),
    ])
      expect(appendListContentImport(current, response)).toBeNull()
    expect(current).toEqual({
      domains: "keep.example",
      ipCidrs: "198.51.100.1",
    })
  })

  test("file size is checked before reading; pasted UTF-8 is bounded by bytes", async () => {
    const read = mock(async () => "")
    const states: ListContentImportState[] = []
    const setText = mock(() => {})
    await readListContentFile(
      { current: null },
      { size: LIST_CONTENT_MAX_BYTES + 1, text: read },
      setText,
      (state) => states.push(state)
    )
    expect(read).not.toHaveBeenCalled()
    expect(setText).not.toHaveBeenCalled()
    expect(states).toEqual([{ status: "failed", reason: "tooLarge" }])
    expect(listContentTextTooLarge("a".repeat(LIST_CONTENT_MAX_BYTES))).toBe(
      false
    )
    expect(
      listContentTextTooLarge("я".repeat(LIST_CONTENT_MAX_BYTES / 2 + 1))
    ).toBe(true)
  })

  test("new file or paste invalidates an older file result, including failure", async () => {
    for (const rejectOld of [false, true]) {
      const session: ListImportSession = { current: null }
      const old = deferred<string>()
      const setText = mock(() => {})
      const states: ListContentImportState[] = []
      const pending = readListContentFile(
        session,
        { size: 1, text: () => old.promise },
        setText,
        (state) => states.push(state)
      )
      await readListContentFile(
        session,
        { size: 1, text: async () => "new.example" },
        setText,
        (state) => states.push(state)
      )
      const afterNew = [...states]
      if (rejectOld) old.reject(new Error("private old file"))
      else old.resolve("old.example")
      await pending
      expect(setText.mock.calls).toEqual([["new.example"]])
      expect(states).toEqual(afterNew)
    }
  })

  test("format change or close invalidates old import responses and errors", async () => {
    for (const rejectOld of [false, true]) {
      const session: ListImportSession = { current: null }
      const old = deferred<ListContentImportResponse>()
      const add = mock(() => ({ domains: 1, ipCidrs: 1, duplicates: 0 }))
      const states: ListContentImportState[] = []
      const pending = runListContentImport(
        session,
        () => old.promise,
        add,
        (state) => states.push(state)
      )
      session.current = null
      if (rejectOld)
        old.reject(new Error("https://user:secret@example.org/private"))
      else old.resolve(result())
      await pending
      expect(add).not.toHaveBeenCalled()
      expect(states).toEqual([{ status: "pending" }])
    }
  })

  test("only an explicit successful request adds entries; pending clicks are coalesced", async () => {
    const session: ListImportSession = { current: null }
    const response = deferred<ListContentImportResponse>()
    const request = mock(() => response.promise)
    const add = mock(() => ({ domains: 1, ipCidrs: 1, duplicates: 0 }))
    const states: ListContentImportState[] = []
    const pending = runListContentImport(session, request, add, (state) =>
      states.push(state)
    )
    await runListContentImport(session, request, add, (state) =>
      states.push(state)
    )
    expect(request).toHaveBeenCalledTimes(1)
    expect(add).not.toHaveBeenCalled()
    response.resolve(result())
    await pending
    expect(add).toHaveBeenCalledTimes(1)
    expect(states.at(-1)).toEqual({
      status: "added",
      added: { domains: 1, ipCidrs: 1, duplicates: 0 },
    })
    expect(session.current).toBeNull()
  })

  test("incomplete results and transport failures are retryable without draft writes", async () => {
    const session: ListImportSession = { current: null }
    const add = mock(() => ({ domains: 0, ipCidrs: 0, duplicates: 0 }))
    const states: ListContentImportState[] = []
    await runListContentImport(
      session,
      async () => result({ complete: false }),
      add,
      (state) => states.push(state)
    )
    await runListContentImport(
      session,
      async () => {
        throw new Error("private diagnostic")
      },
      add,
      (state) => states.push(state)
    )
    expect(add).not.toHaveBeenCalled()
    expect(states.at(-1)).toEqual({ status: "failed", reason: "requestFailed" })
    expect(JSON.stringify(states)).not.toContain("private diagnostic")
    expect(session.current).toBeNull()
  })
})

describe("list contents format persistence", () => {
  test("URL and router-file formats round trip without changing inline contents or unknown properties", () => {
    for (const source of [
      { url: "https://lists.example/data" },
      { file: "/opt/etc/list.yaml" },
    ]) {
      for (const source_format of ["json-array", "yaml-payload"]) {
        const original = {
          ...source,
          source_format,
          domains: ["keep.example"],
          future_setting: 7,
        }
        const draft = getDraftFromMapEntry("manual_list", original)!
        expect(getListConfigFromDraft(draft)).toMatchObject(original)
        const narrowed = narrowDraftToSourceGroups(draft, ["inline"])
        expect(getListConfigFromDraft(narrowed)).not.toHaveProperty(
          "source_format"
        )
      }
    }
  })

  test("omitted and explicit text are semantically equal; format edits are dirty", () => {
    const draft = {
      ...createListDraft("Example"),
      url: "https://lists.example/data",
    }
    expect(
      normalizeListDraftForComparison({ ...draft, sourceFormat: undefined })
    ).toEqual(
      normalizeListDraftForComparison({ ...draft, sourceFormat: "text" })
    )
    expect(
      normalizeListDraftForComparison({ ...draft, sourceFormat: "json-array" })
    ).not.toEqual(normalizeListDraftForComparison(draft))
  })

  test("format changes drop catalog provenance but metadata-only edits keep it", () => {
    const original = {
      url: "https://lists.example/data",
      catalog_identity: "a".repeat(64),
    }
    const config = { lists: { example: original } }
    const draft = getDraftFromMapEntry("example", original)!
    expect(
      buildUpdatedConfigForListUpsert(
        config,
        "edit",
        { ...draft, displayName: "New alias" },
        "example"
      ).lists?.example.catalog_identity
    ).toBe(original.catalog_identity)
    expect(
      buildUpdatedConfigForListUpsert(
        config,
        "edit",
        { ...draft, sourceFormat: "json-array" },
        "example"
      ).lists?.example.catalog_identity
    ).toBeUndefined()
  })

  test("preview keeps explicit format and invalidates its old session without adding routing to inline text", () => {
    const source = {
      url: "https://lists.example/data",
      format: "json-array",
      detour: "hidden",
    }
    expect(listSourcePreviewRequest(source)).toEqual({
      url: source.url,
      format: "json-array",
      refresh_detour_mode: "inherit",
    })
    expect(
      listSourcePreviewRequest({
        text: "payload: []",
        format: "yaml-payload",
        detour: "hidden",
      })
    ).toEqual({ text: "payload: []", format: "yaml-payload" })
    expect(listSourcePreviewKey(source)).not.toBe(
      listSourcePreviewKey({ ...source, format: "yaml-payload" })
    )
    expect(listSourcePreviewKey({ url: source.url })).toBe(
      listSourcePreviewKey({ url: source.url, format: "text" })
    )
  })
})

describe("list contents import presentation", () => {
  test("both languages name the supported formats and local-draft action without fetching on render", async () => {
    const request = spyOn(api, "postListContentImport")
    try {
      for (const [lng, translation] of [
        ["en", enTranslation],
        ["ru", ruTranslation],
      ] as const) {
        const i18n = createInstance()
        await i18n.init({
          lng,
          resources: { [lng]: { translation } },
          interpolation: { escapeValue: false },
        })
        const markup = renderToStaticMarkup(
          <I18nextProvider i18n={i18n}>
            <ListContentImport
              onAdd={() => ({ domains: 0, ipCidrs: 0, duplicates: 0 })}
            />
          </I18nextProvider>
        )
        expect(markup).toContain(translation.listContentImport.add)
        expect(markup).toContain(translation.listContentImport.formats.text)
        expect(markup).toContain('type="button"')
        expect(markup).not.toContain('type="submit"')
        expect(translation.listContentImport.yamlHint).not.toContain("Clash")
        for (const code of [
          "unsupported_format",
          "too_large",
          "invalid_encoding",
          "line_too_long",
          "entry_limit",
          "output_limit",
          "json_syntax",
          "json_root_array",
          "json_entry_type",
          "yaml_payload_required",
          "yaml_syntax",
          "yaml_unsupported",
          "invalid_entry",
          "leading_zeros",
          "invalid_prefix",
          "invalid_address",
        ])
          expect(listSourcePreviewErrorMessage(code, i18n.t)).not.toMatch(
            /^list(ContentImport|SourcePreview)\./
          )
      }
      expect(request).not.toHaveBeenCalled()
    } finally {
      request.mockRestore()
    }
  })

  test("editor imports only to local fields and resets a selected template to legacy text", () => {
    const page = readFileSync(
      new URL("../src/pages/list-upsert-page.tsx", import.meta.url),
      "utf8"
    )
    const component = readFileSync(
      new URL(
        "../src/components/lists/list-content-import.tsx",
        import.meta.url
      ),
      "utf8"
    )
    const integration = page.slice(
      page.indexOf("<ListContentImport"),
      page.indexOf("<ListContentImport") + 1200
    )
    expect(integration).toContain("appendListContentImport")
    expect(integration).toContain("LIST_FIELD_NAMES.domains")
    expect(integration).toContain("LIST_FIELD_NAMES.ipCidrs")
    expect(integration).not.toMatch(
      /mutate|handleSubmit|LIST_FIELD_NAMES\.name/
    )
    expect(page).toContain(
      'form.setFieldValue(LIST_FIELD_NAMES.sourceFormat, "text")'
    )
    expect(component).not.toMatch(/postConfig|invalidateQueries|usePostConfig/)
    expect(component).toContain("session.current = null")
  })
})
