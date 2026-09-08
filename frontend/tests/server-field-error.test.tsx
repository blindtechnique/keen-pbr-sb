import { describe, expect, test } from "bun:test"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"

import { ServerFieldError } from "../src/components/shared/server-field-error"
import { ServerValidationAlert } from "../src/components/shared/server-validation-alert"
import { FieldHint } from "../src/components/shared/field"
import { getFirstFieldError } from "../src/lib/form-field-error"
import { splitFormApiErrors } from "../src/lib/form-api-errors"
import { ruTranslation } from "../src/i18n/ru"
import { enTranslation } from "../src/i18n/en"
import type { ReactNode } from "react"

async function renderer(language: "ru" | "en") {
  const local = createInstance()
  await local.init({
    lng: language,
    resources: {
      ru: { translation: ruTranslation },
      en: { translation: enTranslation },
    },
  })
  return {
    local,
    render: (children: ReactNode) => {
      const html = renderToStaticMarkup(
        <I18nextProvider i18n={local}>{children}</I18nextProvider>
      )
      return { html, primary: html.replace(/<details[\s\S]*?<\/details>/g, "") }
    },
  }
}

describe("server validation field presentation", () => {
  test("unknown codes stay generic in both languages while code, params and physical line remain visible", async () => {
    const entry = {
      path: "lists.office.ip_cidrs[2]",
      message: "IPv4 addresses must not contain leading zeros",
      code: "config.future_<kind>",
      params: { max: "24" },
    }
    for (const language of ["ru", "en"] as const) {
      const { render } = await renderer(language)
      const { primary, html } = render(
        <ServerFieldError errors={[entry]} lineNumbers={{ [entry.path]: 5 }} />
      )
      expect(primary).toContain(language === "ru" ? "Строка 5:" : "Line 5:")
      expect(primary).toContain(
        (language === "ru" ? ruTranslation : enTranslation).serverValidation
          .unknown
      )
      expect(primary).not.toContain(
        (language === "ru" ? ruTranslation : enTranslation).serverValidation
          .ipv4LeadingZeros
      )
      expect(html).toContain(entry.message)
      expect(html).toContain("code: config.future_&lt;kind&gt;")
      expect(html).toContain("params: {&quot;max&quot;:&quot;24&quot;}")
      const malformed = render(
        <ServerFieldError
          errors={[{ ...entry, code: { invalid: true }, params: ["invalid"] }]}
        />
      )
      expect(malformed.primary).toContain(
        (language === "ru" ? ruTranslation : enTranslation).serverValidation
          .unknown
      )
    }
  })
  test.each(["ru", "en"] as const)(
    "renders known limits in %s with the unchanged raw cause in closed details",
    async (language) => {
      const { render } = await renderer(language)
      const entry = {
        path: "daemon.port",
        message: "daemon.port must be between 1 and 65535",
      }
      const { primary, html } = render(<ServerFieldError errors={[entry]} />)
      expect(primary).toContain(
        language === "ru"
          ? "Укажите значение от 1 до 65535."
          : "Enter a value from 1 to 65535."
      )
      expect(primary).not.toContain("daemon.port")
      expect(primary).not.toContain(entry.message)
      expect(html).toContain(`- ${entry.path}: ${entry.message}`)
      expect(html).not.toMatch(/<details[^>]*\bopen/)
    }
  )

  test.each(["ru", "en"] as const)(
    "unknown errors do not invent a rule or expose raw technical paths in the %s summary",
    async (language) => {
      const { render } = await renderer(language)
      const entry = {
        path: "future.option[3]",
        message: "Unexpected backend rule <script>unsafe()</script>",
      }
      const { primary, html } = render(
        <ServerValidationAlert errors={[entry]} />
      )
      expect(primary).toContain(
        (language === "ru" ? ruTranslation : enTranslation).serverValidation
          .unknown
      )
      expect(primary).not.toContain(entry.path)
      expect(primary).not.toContain("Unexpected backend rule")
      expect(html).toContain(entry.path)
      expect(html).toContain(
        "Unexpected backend rule &lt;script&gt;unsafe()&lt;/script&gt;"
      )
      expect(html).not.toContain("<script>")
    }
  )

  test("stored mapped errors follow the selected language without remapping or another request", async () => {
    const raw = {
      path: "dns.servers[0].address",
      message: "Invalid DNS server address: 'host:abc' (non-numeric port)",
    }
    const seen: string[][] = []
    const split = splitFormApiErrors({
      error: {
        status: 400,
        message: "Configuration validation failed",
        details: { validation_errors: [raw] },
      },
      fieldNames: ["address"],
      resolvePath: (path, message) => {
        seen.push([path, message])
        return "address"
      },
    })
    const node = (
      <FieldHint error={getFirstFieldError([split.fieldErrors.address])} />
    )
    const { local, render } = await renderer("ru")
    expect(render(node).primary).toContain(
      ruTranslation.serverValidation.dnsPort
    )
    await local.changeLanguage("en")
    expect(render(node).primary).toContain(
      enTranslation.serverValidation.dnsPort
    )
    expect(render(node).html).toContain('role="alert"')
    expect(seen).toEqual([[raw.path, raw.message]])
    expect(split.fieldErrors.address.entries).toEqual([raw])
  })

  test("multiple raw causes survive even when their displayed explanation is the same", async () => {
    const { render } = await renderer("ru")
    const entries = [
      { path: "field.first", message: "Future reason one" },
      { path: "field.second", message: "Future reason two" },
    ]
    const { primary, html } = render(<ServerFieldError errors={entries} />)
    expect(primary.split(ruTranslation.serverValidation.unknown)).toHaveLength(
      2
    )
    expect(html).toContain("field.first: Future reason one")
    expect(html).toContain("field.second: Future reason two")
  })

  test("local form messages remain unchanged, including a message that resembles server text", async () => {
    const local = "Use comma-separated ports or ranges."
    const { render } = await renderer("ru")
    expect(getFirstFieldError([local])).toBe(local)
    const { html } = render(<FieldHint error={getFirstFieldError([local])} />)
    expect(html).toContain(local)
    expect(html).not.toContain("<details")
    const alert = render(
      <ServerValidationAlert
        errors={[]}
        message="Выберите список перед сохранением."
      />
    )
    expect(alert.primary).toContain("Выберите список перед сохранением.")
    expect(alert.html).not.toContain("<details")
  })

  test("first renderable error order is retained and malformed non-errors are ignored", () => {
    const server = {
      kind: "server-validation",
      entries: [{ path: "x", message: "x must be an integer" }],
    }
    expect(getFirstFieldError([null, "Local", server])).toBe("Local")
    expect(getFirstFieldError([server, "Local"])).not.toBe("Local")
    expect(getFirstFieldError(["", server])).toBe("")
    expect(
      getFirstFieldError([{ kind: "server-validation", entries: [] }])
    ).toBeNull()
    expect(
      getFirstFieldError([{ kind: "server-validation", entries: [null] }])
    ).toBeNull()
    expect(
      getFirstFieldError([
        {
          kind: "server-validation",
          entries: [{ path: 4, message: "broken" }],
        },
      ])
    ).toBeNull()
    expect(getFirstFieldError([])).toBeNull()
  })

  test("empty field and unmapped alerts produce no message", async () => {
    const { render } = await renderer("ru")
    expect(render(<ServerFieldError errors={[]} />).html).toBe("")
    expect(render(<ServerValidationAlert errors={[]} />).html).toBe("")
  })
})
