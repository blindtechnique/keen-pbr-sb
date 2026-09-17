import { describe, expect, test } from "bun:test"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"
import { Router } from "wouter"

import type { ConfigObject } from "../src/api/generated/model"
import { queryKeys } from "../src/api/query-keys"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"
import SetupWizardPage from "../src/pages/setup-wizard-page"

async function renderWizard(
  config: ConfigObject,
  language: "ru" | "en",
  singBoxInstalled = false
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
  const client = new QueryClient()
  client.setQueryData(["transport-environment"], {
    sing_box_installed: singBoxInstalled,
    transport_api_version: 2,
  })
  client.setQueryData(queryKeys.config(), {
    status: 200,
    data: { config, is_draft: false },
    headers: new Headers(),
  })
  client.setQueryData(queryKeys.transportConfig(), {
    status: 200,
    data: [],
    headers: new Headers(),
  })
  try {
    return renderToStaticMarkup(
      <I18nextProvider i18n={i18n}>
        <QueryClientProvider client={client}>
          <Router ssrPath="/setup">
            <SetupWizardPage />
          </Router>
        </QueryClientProvider>
      </I18nextProvider>
    )
  } finally {
    client.clear()
  }
}

const source = () =>
  Bun.file(
    new URL("../src/pages/setup-wizard-page.tsx", import.meta.url)
  ).text()

describe("setup wizard continuation", () => {
  test.each(["ru", "en"] as const)(
    "embeds native import without sing-box on a clean configuration in %s",
    async (language) => {
      const html = await renderWizard(
        {
          outbounds: [],
          lists: {},
          dns: { servers: [] },
          route: { rules: [] },
        },
        language
      )
      const copy = (language === "ru" ? ruTranslation : enTranslation).pages
        .setupWizard.connection

      const transportCopy = (language === "ru" ? ruTranslation : enTranslation)
        .transports
      expect(html).toContain(transportCopy.form.importFile)
      expect(html).toContain(transportCopy.form.shareLink)
      expect(html).not.toContain(transportCopy.form.outboundJson)
      expect(html).not.toContain(copy.otherImportHint)
      expect(html).not.toContain("pages.setupWizard.")
      expect(html).not.toContain(transportCopy.form.countryDisplay)
      expect(html).not.toContain('aria-invalid="true"')
      expect(html).not.toContain(copy.inventoryUnavailable)
    }
  )

  test("can resume using a native VPN created in the existing importer", async () => {
    const html = await renderWizard(
      {
        outbounds: [
          {
            tag: "native_vpn",
            type: "interface",
            interface: "nwg1",
            display_name: "Imported AWG",
          },
        ],
      },
      "en"
    )

    expect(html).toContain('value="native_vpn"')
    expect(html).toContain("Imported AWG")
    expect(html).toContain(
      enTranslation.pages.setupWizard.connection.useExisting
    )
  })

  test("offers JSON only with installed sing-box", async () => {
    const html = await renderWizard({ outbounds: [] }, "en", true)
    expect(html).toContain(enTranslation.transports.form.outboundJson)
    expect(html).not.toContain('aria-invalid="true"')
    expect(html).not.toContain('id="transport-create-outbound"')
    expect(html).not.toContain('id="transport-auto-start"')
  })

  test("uses shared import and recovery rather than leaving the wizard", async () => {
    const page = await source()
    const connection = await Bun.file(
      new URL(
        "../src/components/transports/setup-vpn-connection.tsx",
        import.meta.url
      )
    ).text()
    expect(page).toContain("<SetupVpnConnection")
    expect(page).not.toContain("createSetupWizardTransport(")
    expect(connection).toContain("<TransportConfigForm")
    expect(connection).toContain("<NativeMutationRecovery")
    expect(connection).toContain("createLinkedTransportApplyRequest(transport)")
    expect(connection).toContain("stagedNativeWireGuardLinkState(")
    expect(connection).toContain("onImportCompletionStalled=")
    expect(connection).toContain("await reconnect().catch(")
    expect(connection).toContain(
      't("pages.setupWizard.connection.completionPaused")'
    )
  })

  test("focuses the next step and explains the existing automatic DNS setup", async () => {
    const page = await source()

    expect(page).toContain("if (step > 1) stepHeadingRef.current?.focus()")
    expect(page.match(/ref=\{stepHeadingRef\}/g)).toHaveLength(3)
    expect(page.match(/tabIndex=\{-1\}/g)).toHaveLength(3)
    expect(page).toContain('t("pages.setupWizard.services.dnsHint")')
    expect(page).toContain("previewSetupWizardCatalog(intent")
    expect(page).not.toContain("localStorage")
    expect(page).not.toContain("setInterval")
  })

  test("offers a real site check and verified existing destination pages", async () => {
    const page = await source()
    const routes = await Bun.file(
      new URL("../src/App.tsx", import.meta.url)
    ).text()

    expect(page).toContain('navigate("/?check=1")')
    expect(page).toContain('t("pages.setupWizard.done.checkHint")')
    for (const route of ["/transports", "/dns-servers", "/catalog"]) {
      expect(page).toContain(`navigate("${route}")`)
      expect(routes).toContain(`path="${route}"`)
    }
    expect(page).not.toContain('navigate("/dns/servers")')
  })
})
