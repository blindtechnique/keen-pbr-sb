import { describe, expect, test } from "bun:test"
import { FieldApi, FormApi } from "@tanstack/react-form"
import { createInstance } from "i18next"
import { I18nextProvider } from "react-i18next"
import { renderToStaticMarkup } from "react-dom/server"

import { ListShrinkNotice } from "../src/components/lists/list-shrink-notice"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"
import {
  buildListRefreshRequest,
  didListRefreshComplete,
  getListShrinkPreviousError,
  getListShrinkRetainedError,
  type ListShrinkRejection,
} from "../src/lib/list-refresh-controls"
import { semanticJsonEqual } from "../src/lib/semantic-json"
import {
  buildUpdatedConfigForListUpsert,
  createListDraft,
  getDraftFromMapEntry,
  getListConfigFromDraft,
  narrowDraftToSourceGroups,
  normalizeListDraftForComparison,
} from "../src/pages/list-upsert-utils"

const rejection: ListShrinkRejection = {
  previous_entries: 1000,
  candidate_entries: 120,
  previous_sha256: "a".repeat(64),
  candidate_sha256: "b".repeat(64),
  min_previous_entries: 50,
  min_retained_fraction: 0.5,
}
const keyOnly = (key: string) => key

describe("URL list refresh intents", () => {
  test("ordinary and force refresh never include shrink acceptance", () => {
    expect(buildListRefreshRequest("work", "refresh", rejection)).toEqual({
      name: "work",
    })
    expect(buildListRefreshRequest("work", "force", rejection)).toEqual({
      name: "work",
      force_refresh: true,
    })
  })

  test("acceptance names only one list and the exact displayed comparison", () => {
    expect(buildListRefreshRequest("work", "accept", rejection)).toEqual({
      name: "work",
      accept_shrink: {
        previous_sha256: rejection.previous_sha256,
        candidate_sha256: rejection.candidate_sha256,
      },
    })
    expect(buildListRefreshRequest("work", "accept")).toBeUndefined()
    const next = {
      ...rejection,
      candidate_entries: 125,
      candidate_sha256: "c".repeat(64),
    }
    expect(
      buildListRefreshRequest("work", "accept", next)?.accept_shrink
        ?.candidate_sha256
    ).toBe(next.candidate_sha256)
    expect(rejection.candidate_entries).toBe(120)
  })

  test("an attempted or unconfirmed refresh is not reported as success", () => {
    const response = {
      status: 200,
      data: { status: "ok", refreshed_lists: ["work"], failed_lists: [] },
    }
    expect(didListRefreshComplete(response, "work")).toBe(true)
    expect(didListRefreshComplete(response)).toBe(true)
    expect(didListRefreshComplete(response, "other")).toBe(false)
    expect(didListRefreshComplete({ ...response, status: 202 }, "work")).toBe(
      false
    )
    expect(
      didListRefreshComplete(
        { ...response, data: { ...response.data, failed_lists: ["work"] } },
        "work"
      )
    ).toBe(false)
    expect(didListRefreshComplete({ status: 200, data: {} }, "work")).toBe(
      false
    )
  })

  test("a downloaded list with failed routing apply is not a completed refresh", () => {
    const data = {
      status: "ok",
      refreshed_lists: ["work"],
      changed_lists: ["work"],
      failed_lists: [],
      reloaded: false,
      code: "list_refresh_apply_failed",
      error: "Routing apply failed after refreshing lists",
      params: { stage: "terminal", runtime_result: "unknown" },
    }
    expect(didListRefreshComplete({ status: 503, data }, "work")).toBe(false)
    // A contradictory HTTP200 response must not produce a success toast either.
    expect(didListRefreshComplete({ status: 200, data }, "work")).toBe(false)
    // No reload is needed when routing is off or list contents are unchanged.
    expect(
      didListRefreshComplete(
        {
          status: 200,
          data: {
            status: "ok",
            refreshed_lists: ["work"],
            changed_lists: [],
            failed_lists: [],
            reloaded: false,
          },
        },
        "work"
      )
    ).toBe(true)
  })
})

describe("per-source shrink thresholds", () => {
  test("blank defaults stay omitted, with no effect on inline lists", () => {
    const draft = {
      ...createListDraft("Work"),
      url: "https://example.test/work.txt",
    }
    expect(getListConfigFromDraft(draft)).not.toHaveProperty("shrink_policy")
    expect(
      getListConfigFromDraft({
        ...draft,
        url: "",
        domains: "example.test",
        shrinkMinPreviousEntries: "150",
        shrinkMinRetainedPercent: "75",
      })
    ).not.toHaveProperty("shrink_policy")
  })

  test("converts percentages and preserves source-specific thresholds", () => {
    const draft = {
      ...createListDraft("Work"),
      url: "https://example.test/work.txt",
      shrinkMinPreviousEntries: " 125 ",
      shrinkMinRetainedPercent: "12.5",
    }
    expect(getListConfigFromDraft(draft).shrink_policy).toEqual({
      min_previous_entries: 125,
      min_retained_fraction: 0.125,
    })
    const restored = getDraftFromMapEntry(
      "work",
      getListConfigFromDraft(draft)
    )!
    expect(restored.shrinkMinPreviousEntries).toBe("125")
    expect(restored.shrinkMinRetainedPercent).toBe("12.5")
    const fractional = getDraftFromMapEntry("work", {
      url: "https://example.test/work.txt",
      shrink_policy: { min_retained_fraction: 0.29 },
    })!
    expect(fractional.shrinkMinRetainedPercent).toBe("29")
    expect(
      getListConfigFromDraft(fractional).shrink_policy?.min_retained_fraction
    ).toBe(0.29)
  })

  test("hidden settings round-trip exactly when editing an alias", () => {
    const list = {
      url: "https://example.test/work.txt",
      shrink_policy: {
        min_previous_entries: 123,
        min_retained_fraction: 0.3333333333333333,
      },
    }
    const draft = getDraftFromMapEntry("work", list)!
    const config = buildUpdatedConfigForListUpsert(
      { lists: { work: list } },
      "edit",
      { ...draft, displayName: "Renamed" },
      "work"
    )
    expect(config.lists?.work.shrink_policy).toEqual(list.shrink_policy)
    expect(config.lists?.work.display_name).toBe("Renamed")
  })

  test("default spellings and restoring the original values clear semantic dirty state", () => {
    const base = {
      ...createListDraft("Work"),
      url: "https://example.test/work.txt",
    }
    expect(
      semanticJsonEqual(
        normalizeListDraftForComparison(base),
        normalizeListDraftForComparison({
          ...base,
          shrinkMinPreviousEntries: "050",
          shrinkMinRetainedPercent: "50.0",
        })
      )
    ).toBe(true)
    const custom = {
      ...base,
      shrinkMinPreviousEntries: "100",
      shrinkMinRetainedPercent: "75",
    }
    expect(
      semanticJsonEqual(
        normalizeListDraftForComparison(base),
        normalizeListDraftForComparison(custom)
      )
    ).toBe(false)
    expect(
      semanticJsonEqual(
        normalizeListDraftForComparison(base),
        normalizeListDraftForComparison({
          ...custom,
          shrinkMinPreviousEntries: "",
          shrinkMinRetainedPercent: "",
        })
      )
    ).toBe(true)
  })

  test("removing the URL discards its thresholds only in the persisted draft", () => {
    const draft = getDraftFromMapEntry("work", {
      url: "https://example.test/work.txt",
      domains: ["example.test"],
      shrink_policy: { min_previous_entries: 100, min_retained_fraction: 0.75 },
    })!
    const original = structuredClone(draft)
    const narrowed = narrowDraftToSourceGroups(draft, ["inline"])
    expect(getListConfigFromDraft(narrowed)).not.toHaveProperty("shrink_policy")
    expect(narrowed.shrinkMinPreviousEntries).toBe("")
    expect(narrowed.shrinkMinRetainedPercent).toBe("")
    expect(narrowed.initialShrinkPolicy).toBeUndefined()
    expect(
      getListConfigFromDraft(narrowDraftToSourceGroups(draft, ["url"]))
        .shrink_policy
    ).toEqual({ min_previous_entries: 100, min_retained_fraction: 0.75 })
    expect(draft).toEqual(original)
  })

  test("validates only supported numeric values and allows default blanks", () => {
    for (const value of [undefined, "", "  ", "0", "50", "9999"]) {
      expect(getListShrinkPreviousError(value, keyOnly)).toBeUndefined()
    }
    for (const value of ["-1", "1.5", "NaN", "Infinity", "9007199254740992"]) {
      expect(getListShrinkPreviousError(value, keyOnly)).toBe(
        "pages.listUpsert.shrinkPolicy.invalidPrevious"
      )
    }
    for (const value of [undefined, "", "0", "12.5", "100"]) {
      expect(getListShrinkRetainedError(value, keyOnly)).toBeUndefined()
    }
    for (const value of ["-1", "100.1", "NaN", "Infinity"]) {
      expect(getListShrinkRetainedError(value, keyOnly)).toBe(
        "pages.listUpsert.shrinkPolicy.invalidRetained"
      )
    }
  })

  test("an invalid threshold can be corrected or hidden without blocking Save", () => {
    const form = new FormApi({
      defaultValues: { shrinkMinRetainedPercent: "50" },
    })
    const unmountForm = form.mount()
    const field = new FieldApi({
      form,
      name: "shrinkMinRetainedPercent",
      validators: {
        onChange: ({ value }) => getListShrinkRetainedError(value, keyOnly),
      },
    })
    const unmountField = field.mount()
    field.handleChange("101")
    expect(field.state.meta.errors).toContain(
      "pages.listUpsert.shrinkPolicy.invalidRetained"
    )
    field.handleChange("75")
    expect(field.state.meta.errors).toEqual([])
    expect(form.state.canSubmit).toBe(true)
    field.handleChange("101")
    form.setFieldMeta("shrinkMinRetainedPercent", (meta) => ({
      ...meta,
      errorMap: {},
    }))
    expect(form.state.values.shrinkMinRetainedPercent).toBe("101")
    expect(form.state.canSubmit).toBe(true)
    unmountField()
    unmountForm()
  })
})

describe("shrink notice", () => {
  test.each(["ru", "en"] as const)(
    "%s shows exact counts and one acceptance action without hashes",
    async (language) => {
      const i18n = createInstance()
      const translation = language === "ru" ? ruTranslation : enTranslation
      await i18n.init({
        lng: language,
        resources: { [language]: { translation } },
      })
      const html = renderToStaticMarkup(
        <I18nextProvider i18n={i18n}>
          <ListShrinkNotice
            rejection={rejection}
            disabled={false}
            pending={false}
            onAccept={() => undefined}
          />
        </I18nextProvider>
      )
      expect(html).toContain("1000")
      expect(html).toContain("120")
      expect(html).toContain(translation.pages.lists.shrink.accept)
      expect(html.match(/<button\b/g)).toHaveLength(1)
      expect(html).not.toContain(rejection.previous_sha256)
      expect(html).not.toContain(rejection.candidate_sha256)
      const pending = renderToStaticMarkup(
        <I18nextProvider i18n={i18n}>
          <ListShrinkNotice
            rejection={rejection}
            disabled
            pending
            onAccept={() => undefined}
          />
        </I18nextProvider>
      )
      expect(pending).toContain(' disabled=""')
      expect(pending).toContain(translation.pages.lists.shrink.pending)
    }
  )
})
