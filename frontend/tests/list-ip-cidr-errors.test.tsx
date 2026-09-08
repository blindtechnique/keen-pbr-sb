import { describe, expect, spyOn, test } from "bun:test"
import { FieldApi, FormApi } from "@tanstack/react-form"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"

import { ListIpCidrsField } from "../src/components/lists/list-ip-cidrs-field"
import { focusCodeEditorSelection } from "../src/components/shared/code-editor-selection"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"
import {
  setFormServerErrors,
  splitFormApiErrors,
} from "../src/lib/form-api-errors"
import {
  getListIpCidrEntryIndex,
  isListIpCidrsPath,
  presentListIpCidrError,
} from "../src/lib/list-ip-cidr-errors"
import { splitLines } from "../src/pages/list-upsert-utils"
import { apiFetch, type ApiError } from "../src/api/client"

const source =
  "\n  # Office\r\n\r\n10.0.0.1\r\n10.0.0.1\r\n \t\r\n 192.168.001.1 \r\n2001:db8::/129\r\n"
const entries = [
  {
    path: "lists.office.ip_cidrs[3]",
    message: "IPv4 addresses must not contain leading zeros",
  },
  {
    path: "lists.office.ip_cidrs[4]",
    message: "IP/CIDR prefix length is invalid",
  },
]
function presented() {
  return presentListIpCidrError(
    { kind: "server-validation", entries },
    "office",
    source
  )
}

describe("IP list server error line mapping", () => {
  test("real HTTP normalization and FormApi retain structured reasons, raw details and physical lines", async () => {
    const raw = {
      path: "lists.office.ip_cidrs[3]",
      message: "Сервер изменил формулировку\nChanged prose",
      code: "config.ip_cidr.leading_zeros",
      params: {},
    }
    const fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json(
        {
          code: "validation",
          error: "Changed top-level prose",
          validation_errors: [raw],
        },
        { status: 400 }
      )
    )
    const form = new FormApi({ defaultValues: { ipCidrs: source } })
    const unmountForm = form.mount()
    const field = new FieldApi({ form, name: "ipCidrs" })
    const unmountField = field.mount()
    try {
      const failure = await apiFetch("/api/config", { method: "POST" }).catch(
        (error: unknown) => error
      )
      const split = splitFormApiErrors({
        error: failure as ApiError,
        fieldNames: ["ipCidrs"],
        resolvePath: (path) =>
          isListIpCidrsPath(path, "office") ? "ipCidrs" : undefined,
      })
      const mapped = presentListIpCidrError(
        split.fieldErrors.ipCidrs,
        "office",
        source
      )
      setFormServerErrors(form, { fields: { ipCidrs: mapped.error } })
      expect(field.state.meta.errors).toContainEqual(mapped.error)
      expect(mapped.error.entries).toEqual([raw])
      expect(mapped.error.lineNumbers).toEqual({ [raw.path]: 7 })
      const local = createInstance()
      await local.init({
        lng: "ru",
        resources: {
          ru: { translation: ruTranslation },
          en: { translation: enTranslation },
        },
      })
      const render = () =>
        renderToStaticMarkup(
          <I18nextProvider i18n={local}>
            <ListIpCidrsField
              value={form.state.values.ipCidrs}
              errors={field.state.meta.errors}
              onChange={() => {}}
              onBlur={() => {}}
            />
          </I18nextProvider>
        )
      const ru = render()
      expect(ru).toContain("Строка 7: Уберите ведущие нули")
      expect(ru.split("<details")[0]).not.toContain(raw.message)
      expect(ru).toContain(raw.message)
      expect(ru).toContain(`code: ${raw.code}`)
      await local.changeLanguage("en")
      expect(render()).toContain("Line 7: Remove leading zeros")
      expect(form.state.values.ipCidrs).toBe(source)
      expect(fetchSpy).toHaveBeenCalledTimes(1)
    } finally {
      unmountField()
      unmountForm()
      fetchSpy.mockRestore()
    }
  })
  test("physical lines follow unchanged submitted indices, including comments and duplicates", () => {
    const sent = splitLines(source)
    expect(sent).toEqual([
      "# Office",
      "10.0.0.1",
      "10.0.0.1",
      "192.168.001.1",
      "2001:db8::/129",
    ])
    const result = presented()
    expect(result.error.entries).toBe(entries)
    expect(result.error.entries).toEqual(entries)
    expect(result.error.lineNumbers).toEqual({
      [entries[0].path]: 7,
      [entries[1].path]: 8,
    })
    expect(result.selection?.line).toBe(7)
    expect(
      result.selection?.value.slice(
        result.selection.start,
        result.selection.end
      )
    ).toBe(" 192.168.001.1 ")
    expect(result.selection?.value).not.toContain("\r")
    expect(entries[0]).toEqual({
      path: "lists.office.ip_cidrs[3]",
      message: "IPv4 addresses must not contain leading zeros",
    })
    expect(splitLines(source)).toEqual(sent)
  })

  test("only exact list entry paths map to indices; unknown or whole-field errors do not invent a line", () => {
    expect(isListIpCidrsPath("lists.office.ip_cidrs", "office")).toBe(true)
    expect(isListIpCidrsPath(entries[0].path, " office ")).toBe(true)
    expect(getListIpCidrEntryIndex("lists.office.ip_cidrs[0]", "office")).toBe(
      0
    )
    for (const path of [
      "lists.other.ip_cidrs[3]",
      "lists.office.ip_cidrs[-1]",
      "lists.office.ip_cidrs[01]",
      "lists.office.ip_cidrs[3].other",
      "lists.office.ip_cidrs[9007199254740992]",
    ]) {
      expect(isListIpCidrsPath(path, "office")).toBe(false)
    }
    for (const path of ["lists.office.ip_cidrs", "lists.office.ip_cidrs[99]"]) {
      const result = presentListIpCidrError(
        {
          kind: "server-validation",
          entries: [{ path, message: "Future server reason" }],
        },
        "office",
        source
      )
      expect(result.error.lineNumbers).toEqual({})
      expect(result.selection).toBeNull()
    }
  })

  test("mapped errors survive actual TanStack field storage without changing the input", () => {
    const form = new FormApi({ defaultValues: { ipCidrs: source } })
    const unmountForm = form.mount()
    const field = new FieldApi({ form, name: "ipCidrs" })
    const unmountField = field.mount()
    const result = splitFormApiErrors({
      error: {
        status: 400,
        message: "Configuration validation failed",
        details: { validation_errors: entries },
      },
      fieldNames: ["ipCidrs"],
      resolvePath: (path) =>
        isListIpCidrsPath(path, "office") ? "ipCidrs" : undefined,
    })
    expect(result.unmappedErrors).toEqual([])
    const error = presentListIpCidrError(
      result.fieldErrors.ipCidrs,
      "office",
      source
    ).error
    setFormServerErrors(form, { fields: { ipCidrs: error } })
    expect(field.state.meta.errors).toContainEqual(error)
    expect(form.state.values.ipCidrs).toBe(source)
    unmountField()
    unmountForm()
  })
})

describe("IP list field presentation", () => {
  test("the same stored server errors render in RU and EN with line numbers and unchanged details", async () => {
    const local = createInstance()
    await local.init({
      lng: "ru",
      resources: {
        ru: { translation: ruTranslation },
        en: { translation: enTranslation },
      },
    })
    const result = presented()
    const render = () =>
      renderToStaticMarkup(
        <I18nextProvider i18n={local}>
          <ListIpCidrsField
            value={source}
            onChange={() => {}}
            onBlur={() => {}}
            errors={[result.error]}
            selection={result.selection}
          />
        </I18nextProvider>
      )
    const ru = render()
    expect(ru).toContain('aria-invalid="true"')
    expect(ru).toContain('aria-describedby="list-ip-cidrs-hint"')
    expect(ru).toContain('id="list-ip-cidrs-hint"')
    expect(ru).toContain('role="alert"')
    expect(ru).toContain("Строка 7: Уберите ведущие нули")
    expect(ru).toContain("Строка 8: После / укажите")
    expect(ru).toContain(`- ${entries[0].path}: ${entries[0].message}`)
    expect(ru).not.toMatch(/<details[^>]*\bopen/)
    expect(ru.match(/<textarea[^>]*>([\s\S]*?)<\/textarea>/)?.[1]).toContain(
      "192.168.001.1"
    )
    await local.changeLanguage("en")
    const en = render()
    expect(en).toContain("Line 7: Remove leading zeros")
    expect(en).toContain("Line 8: Enter a whole prefix length")
    expect(en).not.toContain("Строка")
    expect(result.error.entries).toBe(entries)
  })

  test("invalid address uses the existing localized cause; no error retains the usual hint", async () => {
    const local = createInstance()
    await local.init({
      lng: "en",
      resources: { en: { translation: enTranslation } },
    })
    const render = (errors: unknown[]) =>
      renderToStaticMarkup(
        <I18nextProvider i18n={local}>
          <ListIpCidrsField
            value="bad"
            onChange={() => {}}
            onBlur={() => {}}
            errors={errors}
          />
        </I18nextProvider>
      )
    const error = presentListIpCidrError(
      {
        kind: "server-validation",
        entries: [
          {
            path: "lists.office.ip_cidrs[0]",
            message: "IP/CIDR address is invalid",
          },
        ],
      },
      "office",
      "bad"
    ).error
    expect(render([error])).toContain(
      "Line 1: Enter an IPv4/IPv6 address or subnet"
    )
    const empty = render([])
    expect(empty).toContain('aria-invalid="false"')
    expect(empty).toContain(enTranslation.pages.listUpsert.fields.ipCidrsHint)
    expect(empty).not.toContain('role="alert"')
    expect(empty).not.toContain("border-destructive")
  })
})

describe("failed submit editor focus", () => {
  function elements(value: string) {
    const calls: unknown[] = []
    const textarea = {
      value,
      scrollTop: 0,
      clientHeight: 100,
      focus: (options: unknown) => calls.push(["focus", options]),
      setSelectionRange: (start: number, end: number) =>
        calls.push(["selection", start, end]),
      scrollIntoView: (options: unknown) => calls.push(["scroll", options]),
    }
    const highlight = {
      scrollTop: 200,
      getBoundingClientRect: () => ({ top: 10 }),
      children: {
        item: (index: number) => {
          calls.push(["line", index])
          return { getBoundingClientRect: () => ({ top: 70, height: 40 }) }
        },
      },
    }
    return { calls, textarea, highlight }
  }

  test("focuses and selects the physical line and scrolls both layers using its wrapped height", () => {
    const selection = presented().selection!
    const { calls, textarea, highlight } = elements(selection.value)
    expect(
      focusCodeEditorSelection(
        textarea as unknown as HTMLTextAreaElement,
        highlight as unknown as HTMLPreElement,
        selection
      )
    ).toBe(true)
    expect(calls).toEqual([
      ["focus", { preventScroll: true }],
      ["selection", selection.start, selection.end],
      ["scroll", { block: "center" }],
      ["line", 6],
    ])
    expect(textarea.scrollTop).toBe(230)
    expect(highlight.scrollTop).toBe(230)
    expect(textarea.value).toBe(selection.value)
  })

  test("late errors never focus, scroll, select or replace edited text", () => {
    const selection = presented().selection!
    const { calls, textarea, highlight } = elements("192.168.1.1")
    expect(
      focusCodeEditorSelection(
        textarea as unknown as HTMLTextAreaElement,
        highlight as unknown as HTMLPreElement,
        selection
      )
    ).toBe(false)
    expect(calls).toEqual([])
    expect(textarea.value).toBe("192.168.1.1")
    expect(focusCodeEditorSelection(null, null, selection)).toBe(false)
  })
})
