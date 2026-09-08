import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createInstance } from "i18next"
import type { ReactNode } from "react"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"

import { getGetTransportsQueryKey } from "../src/api/generated/keen-api"
import {
  InterfacePicker,
  InterfaceRowContent,
  OutboundInterfaceLabel,
} from "../src/components/shared/interface-picker"
import { TooltipProvider } from "../src/components/ui/tooltip"
import { ruTranslation } from "../src/i18n/ru"

type NameIndex = Record<string, { label: string }>

async function renderLabel(
  node: ReactNode,
  names: NameIndex = {},
  transports: { interface: string; display_name: string }[] = []
) {
  const i18n = createInstance()
  await i18n.init({
    lng: "ru",
    resources: { ru: { translation: ruTranslation } },
    interpolation: { escapeValue: false },
  })
  const client = new QueryClient()
  client.setQueryData(["interface-names"], { available: true, names })
  client.setQueryData(getGetTransportsQueryKey(), {
    status: 200,
    data: transports,
  })
  try {
    return renderToStaticMarkup(
      <I18nextProvider i18n={i18n}>
        <QueryClientProvider client={client}>
          <TooltipProvider>{node}</TooltipProvider>
        </QueryClientProvider>
      </I18nextProvider>
    )
  } finally {
    client.clear()
  }
}

function visibleText(html: string) {
  return html.replace(/<[^>]*>/g, "")
}

describe("interface selector display names", () => {
  test("a human name hides the kernel suffix but keeps it in the no-address title", async () => {
    const html = await renderLabel(
      <InterfaceRowContent
        interfaceEntry={{ name: "nwg2", status: "up" }}
        name="nwg2"
      />,
      { nwg2: { label: "Домашний VPN" } }
    )
    expect(visibleText(html)).toContain("Домашний VPN")
    expect(visibleText(html)).not.toContain("nwg2")
    expect(html).toContain('title="Домашний VPN · nwg2"')
    expect(visibleText(html)).toContain(
      ruTranslation.pages.settings.general.inboundInterfacesStatusUp
    )
  })

  test("the address-tooltip branch also retains the kernel name in its title", async () => {
    const html = await renderLabel(
      <InterfaceRowContent
        interfaceEntry={{
          name: "nwg2",
          status: "down",
          ipv4_addresses: ["192.0.2.1/24"],
        }}
        name="nwg2"
      />,
      { nwg2: { label: "Домашний VPN" } }
    )
    expect(html).toContain('data-slot="tooltip-trigger"')
    expect(html).toContain('title="Домашний VPN · nwg2"')
    expect(visibleText(html)).not.toContain("nwg2")
    expect(visibleText(html)).toContain(
      ruTranslation.pages.settings.general.inboundInterfacesStatusDown
    )
  })

  test("inline addresses and protocol stay visible with the chosen transport alias", async () => {
    const html = await renderLabel(
      <InterfaceRowContent
        interfaceEntry={{
          name: "nwg2",
          status: "up",
          ipv4_addresses: ["192.0.2.1/24"],
          ipv6_addresses: ["2001:db8::1/64"],
        }}
        name="nwg2"
        protocol="AWG"
        showAddressesInline
      />,
      { nwg2: { label: "Firmware name" } },
      [{ interface: "nwg2", display_name: "Выбранное имя" }]
    )
    const text = visibleText(html)
    expect(text).toContain("Выбранное имя")
    expect(text).not.toContain("Firmware name")
    expect(text).not.toContain("nwg2")
    expect(text).toContain("192.0.2.1/24")
    expect(text).toContain("2001:db8::1/64")
    expect(text).toContain("AWG")
  })

  test("without an alias the actual name and known kind remain visible", async () => {
    const html = await renderLabel(
      <InterfaceRowContent
        interfaceEntry={{ name: "br0", status: "up" }}
        name="br0"
      />
    )
    expect(visibleText(html)).toContain("br0")
    expect(visibleText(html)).toContain(
      ruTranslation.common.interfacePicker.kinds.bridge
    )
    expect(html).toContain('title="br0"')
  })

  test("a custom unknown name is not replaced by an invented label", async () => {
    const html = await renderLabel(
      <InterfaceRowContent isVirtual name="custom-port" />
    )
    expect(visibleText(html)).toContain("custom-port")
    expect(visibleText(html)).toContain(
      ruTranslation.common.interfacePicker.notExists
    )
  })

  test("duplicate names use the full name index, including hidden picker items", async () => {
    const names = {
      nwg2: { label: "VPN" },
      nwg1: { label: "VPN" },
    }
    const row = await renderLabel(
      <InterfaceRowContent
        interfaceEntry={{ name: "nwg2", status: "up" }}
        name="nwg2"
      />,
      names
    )
    const selected = await renderLabel(
      <InterfacePicker
        interfaces={[{ name: "nwg2", status: "up" }]}
        onChange={() => undefined}
        renderSelectedInline
        showDetails={false}
        value="nwg2"
      />,
      names
    )
    expect(visibleText(row)).toContain("VPN · 2")
    expect(visibleText(selected)).toContain("VPN · 2")
    expect(visibleText(selected)).not.toContain("nwg2")
    expect(selected).toContain('value="nwg2"')
  })

  test("outbound rows put route and interface identities only in the title", async () => {
    const html = await renderLabel(
      <OutboundInterfaceLabel
        interfaceName="nwg2"
        label="Мой VPN"
        runtimeInterface={{
          name: "nwg2",
          status: "up",
          ipv4_addresses: ["192.0.2.1/24"],
          ipv6_addresses: ["fe80::1/64", "2001:db8::1/64"],
        }}
        t={(key) => key}
        tag="route_internal"
      />
    )
    const text = visibleText(html)
    expect(text).toContain("Мой VPN")
    expect(text).not.toContain("route_internal")
    expect(text).not.toContain("nwg2")
    expect(html).toContain('title="Мой VPN · route_internal · nwg2"')
    expect(text).toContain("192.0.2.1/24")
    expect(text).toContain("2001:db8::1/64")
    expect(text).not.toContain("fe80::1/64")
  })

  test("an outbound without a human label retains its actual tag fallback", async () => {
    const html = await renderLabel(
      <OutboundInterfaceLabel
        interfaceName="nwg2"
        label="  "
        t={(key) => key}
        tag="route_internal"
      />
    )
    expect(visibleText(html)).toContain("route_internal")
    expect(visibleText(html)).not.toContain("nwg2")
    expect(html).toContain('title="route_internal · nwg2"')
  })

  test("autocomplete keeps raw identity, selection callbacks, and full search inputs", () => {
    const source = readFileSync(
      new URL("../src/components/shared/interface-picker.tsx", import.meta.url),
      "utf8"
    )
    expect(source).toContain("itemToStringValue={(item) => item.name}")
    expect(source).toContain("onChange(nextValue)")
    expect(source).toContain("onSelect?.(nextValue)")
    expect(source).toContain("value={value}")
    expect(source).toContain("name={name}")
    expect(source).toContain("names[item.name]?.label")
    expect(source).toContain("names[item.name]?.type")
    expect(source).toContain("...(item.ipv4_addresses ?? [])")
    expect(source).toContain("...(item.ipv6_addresses ?? [])")
  })
})
