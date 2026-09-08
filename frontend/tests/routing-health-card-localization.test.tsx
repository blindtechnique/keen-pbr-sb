import { describe, expect, test } from "bun:test"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"

import type { RoutingHealthResponse } from "../src/api/generated/model"
import { RoutingHealthCard } from "../src/components/overview/routing-health-card"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

const health: RoutingHealthResponse = {
  overall: "degraded",
  firewall_backend: "iptables",
  firewall: { chain_present: true, prerouting_hook_present: true },
  firewall_rules: [
    {
      set_name: "kpbr4s_example",
      action: "mark",
      expected_fwmark: "0x00040000",
      status: "missing",
      detail: "rule not found in iptables raw table (family=ipv4 criteria=any)",
    },
  ],
  route_tables: [
    {
      table_id: 120,
      outbound_tag: "My VPN",
      expected_destination: "default",
      expected_route_type: "blackhole",
      table_exists: true,
      default_route_present: true,
      interface_matches: true,
      gateway_matches: true,
      status: "mismatch",
      detail: "unexpected route present in table",
    },
  ],
  policy_rules: [],
}

async function render(value: RoutingHealthResponse, language: "ru" | "en") {
  const local = createInstance()
  await local.init({
    lng: language,
    resources: {
      [language]: {
        translation: language === "ru" ? ruTranslation : enTranslation,
      },
    },
  })
  return renderToStaticMarkup(
    <I18nextProvider i18n={local}>
      <RoutingHealthCard routingHealth={value} />
    </I18nextProvider>
  )
}

describe("dashboard diagnostic localization", () => {
  test.each(["ru", "en"] as const)(
    "renders known diagnostics in %s while preserving identifiers",
    async (language) => {
      const text = (language === "ru" ? ruTranslation : enTranslation).overview
        .routing
      const html = await render(health, language)
      expect(html).toContain(text.statuses.degraded)
      expect(html).toContain(text.statuses.missing)
      expect(html).toContain(text.routeTypes.blackhole)
      expect(html).toContain(text.defaultRoute)
      expect(html).toContain(text.details.unexpectedRoute)
      expect(html).toContain("iptables")
      expect(html).toContain("kpbr4s_example")
      expect(html).toContain("0x00040000")
      expect(html).not.toContain("overview.routing.")
      expect(html).not.toContain(">degraded<")
      expect(html).not.toContain(">missing<")
      expect(html).not.toContain(">default<")
      expect(html).not.toContain(">blackhole<")
    }
  )

  test("preserves unknown status/action/cause as escaped technical details", async () => {
    const unknown = {
      ...health,
      overall: "future_status",
      firewall_rules: [
        {
          ...health.firewall_rules[0],
          action: "future_action",
          detail: "future backend error <script>",
        },
      ],
    } as unknown as RoutingHealthResponse
    const html = await render(unknown, "ru")
    expect(html).toContain(ruTranslation.overview.routing.statuses.unknown)
    expect(html).toContain(ruTranslation.overview.routing.actions.unknown)
    expect(html).toContain("<details")
    expect(html).toContain(ruTranslation.overview.routing.technicalDetails)
    expect(html).toContain("future_status")
    expect(html).toContain("future_action")
    expect(html).toContain("future backend error &lt;script&gt;")
    expect(html).not.toContain("<script>")
  })

  test("keeps route mismatch causes while leaving healthy-row filtering unchanged", async () => {
    const html = await render(
      {
        ...health,
        firewall_rules: [
          {
            ...health.firewall_rules[0],
            set_name: "healthy_hidden",
            status: "ok",
          },
        ],
        route_tables: [
          {
            ...health.route_tables[0],
            expected_route_type: "future_type",
            interface_matches: false,
            detail: "interface mismatch: expected 'nwg5', got 'eth1'.",
          },
        ],
      },
      "ru"
    )
    expect(html).not.toContain("healthy_hidden")
    expect(html).toContain(
      ruTranslation.overview.routing.issues.interfaceMismatch
    )
    expect(html).toContain(ruTranslation.overview.routing.routeTypes.unknown)
    expect(html).toContain("future_type")
    expect(html).toContain("nwg5")
    expect(html).toContain("eth1")
  })
})
