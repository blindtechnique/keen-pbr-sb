import { describe, expect, test } from "bun:test"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"

import type {
  RoutingTestResponse,
  RoutingTestEntry,
} from "../src/api/generated/model"
import { RoutingDiagnosticsResult } from "../src/components/overview/routing-diagnostics-result"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

async function render(
  language: "ru" | "en",
  overrides: Partial<RoutingTestResponse> = {}
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
      <RoutingDiagnosticsResult
        outbounds={[{ tag: "nwg0", type: "interface", interface: "nwg0" }]}
        interfaceLabelFor={(name) =>
          name === "nwg0" ? "techcorner.ignorelist.com" : name
        }
        diagnostics={{
          target: "youtube.com",
          is_domain: true,
          config_scope: "active",
          unapplied_draft: false,
          resolved_ips: ["203.0.113.1"],
          warnings: [],
          no_matching_rule: true,
          rule_diagnostics: [],
          results: [],
          ...overrides,
        }}
      />
    </I18nextProvider>
  )
}

describe("routing notices remain separate from nfqws lists", () => {
  test.each(["ru", "en"] as const)(
    "list membership, friendly VPN name and OK share one table in %s",
    async (language) => {
      const result: RoutingTestEntry = {
        ip: "203.0.113.1",
        expected_outbound: "nwg0",
        actual_outbound: "nwg0",
        ok: true,
        evaluation: "matched",
        unknown_conditions: [],
        kernel_route: {
          route_status: "resolved",
          interface: "nwg0",
          detail: "",
        },
        list_matches: [{ list: "User sites", via: "youtube.com" }],
      }
      const html = await render(language, {
        no_matching_rule: false,
        results: [result],
        rule_diagnostics: [
          {
            rule_index: 0,
            rule: { outbound: "nwg0", display_name: "Video VPN" },
            outbound: "nwg0",
            interface_name: "nwg0",
            target_in_lists: false,
            ip_rows: [
              {
                ip: result.ip,
                in_lists: false,
                in_ipset: false,
                evaluation: "matched",
                unknown_conditions: [],
              },
            ],
          },
        ],
      })
      expect(html.match(/<table\b/g)).toHaveLength(1)
      const table = html.slice(html.indexOf("<table"), html.indexOf("</table>"))
      expect(table).toContain("User sites")
      expect(table).toContain("techcorner.ignorelist.com")
      expect(table).not.toContain(">nwg0<")
      expect(table).toContain("OK")
      expect(table).not.toContain("(unknown)")
      expect(table).not.toContain("(default)")
    }
  )

  test("conditional rules are not errors or a false OK", async () => {
    const html = await render("ru", {
      no_matching_rule: false,
      results: [
        {
          ip: "203.0.113.1",
          expected_outbound: "(unknown)",
          actual_outbound: "(unknown)",
          ok: true,
          evaluation: "insufficient_context",
          unknown_conditions: ["source_address"],
          kernel_route: {
            route_status: "unavailable",
            interface: "",
            detail: "",
          },
        },
      ],
    })
    const table = html.slice(html.indexOf("<table"), html.indexOf("</table>"))
    expect(table).not.toContain("OK")
    expect(table).not.toContain("(unknown)")
    expect(html).not.toContain('role="alert"')
    const details = html.indexOf("<details")
    expect(html.slice(0, details)).not.toContain(
      ruTranslation.overview.routingDiagnostics.insufficientContext
    )
    expect(html.slice(details)).toContain(
      ruTranslation.overview.routingDiagnostics.insufficientContext
    )
  })
  test.each(["ru", "en"] as const)(
    "no separate PBR rule is neutral, not a warning in %s",
    async (language) => {
      const translation = (language === "ru" ? ruTranslation : enTranslation)
        .overview.routingDiagnostics
      const html = await render(language)
      expect(html).toContain(translation.noMatchingRule)
      expect(html).not.toContain('role="alert"')
      expect(html).not.toContain("border-amber-400/40")
      expect(html).not.toContain("overview.routingDiagnostics.")
    }
  )

  test("actual DNS errors remain warnings", async () => {
    const html = await render("en", { dns_error: "Diagnostic DNS failed" })
    expect(html).toContain('role="alert"')
    expect(html).toContain("Diagnostic DNS failed")
    expect(html).toContain(
      enTranslation.overview.routingDiagnostics.noMatchingRule
    )
  })

  test("an unapplied draft still has its own warning", async () => {
    const html = await render("ru", { unapplied_draft: true })
    expect(html).toContain('role="alert"')
    expect(html).toContain(
      ruTranslation.overview.routingDiagnostics.unappliedDraft
    )
  })
})
