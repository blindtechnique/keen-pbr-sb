import { describe, expect, test } from "bun:test"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"
import { Router } from "wouter"
import type { ReactNode } from "react"

import { PostApplyDescription } from "../src/components/layout/post-apply-feedback"
import { WarningBanner } from "../src/components/layout/warning-banner"
import type { WarningBannerState } from "../src/components/layout/warning-banner-state"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

async function render(node: ReactNode, language: "ru" | "en") {
  const local = createInstance()
  const translation = language === "ru" ? ruTranslation : enTranslation
  await local.init({
    lng: language,
    resources: { [language]: { translation } },
  })
  const client = new QueryClient()
  try {
    return renderToStaticMarkup(
      <I18nextProvider i18n={local}>
        <QueryClientProvider client={client}>
          <Router ssrPath="/">{node}</Router>
        </QueryClientProvider>
      </I18nextProvider>
    )
  } finally {
    client.clear()
  }
}

const state: WarningBannerState = {
  actionPending: false,
  dismissFailure: () => undefined,
  hasDraftConfig: false,
  isActionDisabled: false,
  isVisible: true,
  mode: "lifecycle-error",
  operationType: "apply_config",
  operationError: "Failure diagnostic detail",
  operationSteps: [],
  progressPercent: 0,
}

describe("post-apply feedback", () => {
  test.each(["ru", "en"] as const)(
    "shows only relevant localized next steps in %s",
    async (language) => {
      const copy = (language === "ru" ? ruTranslation : enTranslation).postApply
      expect(
        await render(<PostApplyDescription impact="dns" />, language)
      ).toContain(copy.dns)
      expect(
        await render(<PostApplyDescription impact="routing" />, language)
      ).toContain(copy.routing)
      expect(
        await render(
          <PostApplyDescription impact="routing-and-dns" />,
          language
        )
      ).toContain(copy.routing)
      expect(
        await render(<PostApplyDescription impact="none" />, language)
      ).toBe("")
      expect(
        await render(<PostApplyDescription impact="unknown" />, language)
      ).toBe("")
    }
  )

  test.each(["ru", "en"] as const)(
    "keeps existing failure details and links to routing diagnosis in %s",
    async (language) => {
      const html = await render(<WarningBanner state={state} />, language)
      expect(html).toContain('href="/?section=routing"')
      expect(html).toContain("Failure diagnostic detail")
      expect(html).toContain(
        (language === "ru" ? ruTranslation : enTranslation).postApply
          .openDiagnostics
      )
      expect(html).not.toContain("postApply.")
    }
  )

  test("DNS errors link to DNS, while a running operation never offers a success action", async () => {
    const dns = await render(
      <WarningBanner state={{ ...state, mode: "dnsmasq-error" }} />,
      "ru"
    )
    expect(dns).toContain('href="/?section=dns"')
    const pending = await render(
      <WarningBanner state={{ ...state, mode: "lifecycle-running" }} />,
      "ru"
    )
    expect(pending).not.toContain("?check=1")
    expect(pending).not.toContain("?section=")
    expect(pending).not.toContain(ruTranslation.postApply.applied)
  })

  test("apply feedback does not wait for diagnostic cache refresh or repeat the mutation", async () => {
    const mutations = await Bun.file(
      new URL("../src/api/mutations.ts", import.meta.url)
    ).text()
    const apply = mutations
      .split("export const useApplyConfigMutation")[1]
      .split("export const useDiscardConfigMutation")[0]
    expect(apply).toContain("void Promise.all(")
    expect(apply).not.toContain("await Promise.all(")
    const banner = await Bun.file(
      new URL("../src/components/layout/warning-banner.tsx", import.meta.url)
    ).text()
    expect(banner).toContain("if (!confirmedConfigApply(response)) return")
    expect(banner.match(/applyConfigMutation\.mutate\(/g)).toHaveLength(1)
    expect(banner).not.toContain("localStorage")
    expect(banner).not.toContain("sessionStorage")
  })
})
