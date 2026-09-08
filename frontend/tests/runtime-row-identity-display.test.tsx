import { describe, expect, test } from "bun:test"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createInstance } from "i18next"
import { readFileSync } from "node:fs"
import type { ReactNode } from "react"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"

import { queryKeys } from "../src/api/query-keys"
import {
  OutboundMemberChain,
  OutboundName,
} from "../src/components/outbounds/outbound-cells"
import { ruTranslation } from "../src/i18n/ru"

const outbound = {
  type: "interface" as const,
  tag: "route_internal_5",
  display_name: "Домашний VPN",
  interface: "nwg5",
}

async function renderRow(node: ReactNode, interfaceAlias?: string) {
  const i18n = createInstance()
  await i18n.init({
    lng: "ru",
    resources: { ru: { translation: ruTranslation } },
    interpolation: { escapeValue: false },
  })
  const client = new QueryClient({
    defaultOptions: { queries: { enabled: false } },
  })
  client.setQueryData(["interface-names"], {
    available: true,
    names: interfaceAlias ? { nwg5: { label: interfaceAlias } } : {},
  })
  client.setQueryData(queryKeys.transports(), { status: 200, data: [] })
  try {
    return renderToStaticMarkup(
      <I18nextProvider i18n={i18n}>
        <QueryClientProvider client={client}>{node}</QueryClientProvider>
      </I18nextProvider>
    )
  } finally {
    client.clear()
  }
}

function visibleText(html: string) {
  return html.replace(/<[^>]*>/g, "")
}

describe("runtime row identity display", () => {
  test("keeps route alias visible and raw tag/interface only in title", async () => {
    const html = await renderRow(
      <OutboundName outbound={outbound} withInterface />
    )
    expect(visibleText(html)).toBe("Домашний VPN")
    expect(html).toContain('title="Домашний VPN (route_internal_5) · nwg5"')
  })

  test("keeps a different real interface alias as useful secondary context", async () => {
    const html = await renderRow(
      <OutboundName outbound={outbound} withInterface />,
      "Резервный сервер"
    )
    expect(visibleText(html)).toContain("Резервный сервер")
    expect(visibleText(html)).not.toContain("nwg5")
  })

  test("does not repeat the same friendly name under the route", async () => {
    const html = await renderRow(
      <OutboundName outbound={outbound} withInterface />,
      " домашний vpn "
    )
    expect(visibleText(html)).toBe("Домашний VPN")
  })

  test("does not remove the sole stable fallback when a route has no alias", async () => {
    const html = await renderRow(
      <OutboundName
        outbound={{ ...outbound, display_name: undefined }}
        withInterface
      />
    )
    expect(visibleText(html)).toBe("route_internal_5")
    expect(html).toContain('title="route_internal_5 · nwg5"')
  })

  test("retains protocol labels while hiding redundant technical interface labels", async () => {
    const html = await renderRow(
      <OutboundName outbound={outbound} protocol="AWG" withInterface />
    )
    expect(visibleText(html)).toBe("Домашний VPNAWG")
  })

  test("runtime chain preserves duplicate aliases, technical titles, and aliasless members", async () => {
    const html = await renderRow(
      <OutboundMemberChain
        outboundDisplayNames={
          new Map([
            ["member_a", "VPN"],
            ["member_b", "VPN"],
          ])
        }
        runtimeState={{
          tag: "group_internal",
          type: "urltest",
          status: "healthy",
          interfaces: [
            { outbound_tag: "member_a", status: "active", latency_ms: 12 },
            { outbound_tag: "member_b", status: "backup", latency_ms: 23 },
            { outbound_tag: "legacy_member", status: "unknown" },
          ],
        }}
      />
    )
    expect(html).toContain('title="member_a">VPN</span>')
    expect(html).toContain('title="member_b">VPN</span>')
    expect(visibleText(html)).not.toContain("member_a")
    expect(visibleText(html)).not.toContain("member_b")
    expect(visibleText(html)).toContain("legacy_member")
    expect(visibleText(html)).toContain("12")
    expect(visibleText(html)).toContain("23")
  })

  test("orphan name cell hides raw interface subline but preserves technical title and edit identity", () => {
    const page = readFileSync(
      new URL("../src/pages/transports-page.tsx", import.meta.url),
      "utf8"
    )
    const orphanRows = page.slice(
      page.indexOf("const orphanRows ="),
      page.indexOf("const transportRows =")
    )
    const nameCell = orphanRows.slice(
      orphanRows.indexOf('<span\n        className="min-w-0'),
      orphanRows.indexOf("<KeeneticStatus")
    )
    expect(nameCell).toContain("getOutboundReferenceLabel(outbound)")
    expect(nameCell).toContain("outbound.interface")
    expect(nameCell).toContain("{getOutboundDisplayName(outbound)}")
    expect(nameCell).not.toContain("{outbound.interface}")
    expect(nameCell).not.toContain("font-mono")
    expect(orphanRows).toContain("encodeURIComponent(outbound.tag)")

    const cells = readFileSync(
      new URL(
        "../src/components/outbounds/outbound-cells.tsx",
        import.meta.url
      ),
      "utf8"
    )
    expect(cells).toContain("key={member.outbound_tag}")
    expect(cells).toContain("title={member.outbound_tag}")
  })
})
