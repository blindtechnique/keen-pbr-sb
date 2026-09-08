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

async function renderWizard(config: ConfigObject, language: "ru" | "en") {
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
    "offers the existing importer on a clean configuration in %s",
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

      expect(html).toContain(copy.otherImport)
      expect(html).toContain(copy.otherImportHint)
      expect(html).not.toContain("pages.setupWizard.")
      expect(html).toContain('id="setup-name"')
      expect(html).not.toContain('id="setup-name-error"')
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

  test("explains and focuses invalid names instead of leaving Create unavailable", async () => {
    const page = await source()
    const handler = page.slice(
      page.indexOf("const createTunnel = async"),
      page.indexOf("const setupMutation =")
    )
    const createButton = page.slice(
      page.indexOf("!link.trim() ||"),
      page.indexOf("onClick={() => void createTunnel()}")
    )

    expect(handler).toContain("if (nameError)")
    expect(handler).toContain("setNameTouched(true)")
    expect(handler).toContain("nameInputRef.current?.focus()")
    expect(handler.indexOf("if (nameError)")).toBeLessThan(
      handler.indexOf("createSetupWizardTransport(")
    )
    expect(createButton).not.toContain("nameError")
    expect(createButton).not.toContain("!tunnelName.trim()")
    expect(page).toContain("aria-invalid={showNameError}")
    expect(page).toContain('"setup-name-error"')
    expect(page).toContain('t("transports.form.displayNameInvalid")')
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
