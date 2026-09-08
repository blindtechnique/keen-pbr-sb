import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { renderToStaticMarkup } from "react-dom/server"
import { createInstance } from "i18next"
import { I18nextProvider } from "react-i18next"
import { ServiceRestartError } from "../src/components/overview/service-restart-error"
import { ruTranslation } from "../src/i18n/ru"
import { enTranslation } from "../src/i18n/en"

async function render(error: unknown, language: "ru" | "en") {
  const local = createInstance()
  const translation = language === "ru" ? ruTranslation : enTranslation
  await local.init({
    lng: language,
    resources: { [language]: { translation } },
  })
  const html = renderToStaticMarkup(
    <I18nextProvider i18n={local}>
      <ServiceRestartError error={error} />
    </I18nextProvider>
  )
  return {
    html,
    primary: html.replace(/<details[\s\S]*?<\/details>/g, ""),
    translation,
  }
}

describe("service operation explanations", () => {
  test.each(["ru", "en"] as const)(
    "keeps unknown reasons in closed details, with a %s summary",
    async (language) => {
      const error = new Error("socket closed while restarting private-worker")
      const { html, primary, translation } = await render(error, language)
      expect(primary).toContain(translation.overview.services.restartFailed)
      expect(primary).not.toContain(error.message)
      expect(html).toContain(error.message)
      expect(html).toContain("<details")
      expect(html).not.toMatch(/<details[^>]*\bopen/)
      expect(error.message).toBe(
        "socket closed while restarting private-worker"
      )
    }
  )
  test.each(["ru", "en"] as const)(
    "does not call an unconfirmed readiness timeout a failed restart (%s)",
    async (language) => {
      const { html, primary, translation } = await render(
        new Error("Runtime did not become ready: transport vpn is missing"),
        language
      )
      expect(primary).toContain(
        translation.overview.services.readinessUnconfirmed
      )
      expect(primary).not.toContain("transport vpn is missing")
      expect(html).toContain("transport vpn is missing")
      const process = await render(
        new Error("service_process_restart_timeout"),
        language
      )
      expect(process.primary).toContain(
        translation.overview.services.processRestartUnconfirmed
      )
    }
  )
  test.each(["ru", "en"] as const)(
    "retains structured authentication and busy classifications (%s)",
    async (language) => {
      const busy = {
        status: 409,
        message:
          "Another runtime mutation is already in progress: runtime-firewall-worker",
        details: { code: "busy" },
      }
      const { primary, translation } = await render(busy, language)
      expect(primary).toContain(translation.operationErrors.busy)
      expect(primary).not.toContain("runtime-firewall-worker")
      const auth = await render(
        {
          status: 401,
          message: "Authentication required",
          details: { code: "unauthenticated" },
        },
        language
      )
      expect(auth.primary).toContain(
        translation.operationErrors.unauthenticated
      )
    }
  )
  test("restart callers pass the original error while producer reasons and scheduling stay intact", () => {
    const source = readFileSync(
      new URL(
        "../src/components/overview/services-status-card.tsx",
        import.meta.url
      ),
      "utf8"
    )
    expect(
      source.match(/<ServiceRestartError error=\{error\} \/>/g)
    ).toHaveLength(3)
    expect(source).not.toContain('t("overview.services.restartFailedDetail"')
    expect(source).toContain(
      'throw new Error("routing health endpoint returned an error")'
    )
    expect(source).toContain(
      'throw new Error("transport manager is unavailable")'
    )
    expect(source).toContain(
      "await waitForRuntimeReadiness(runtimeReadinessProbe"
    )
    expect(source).toContain("await waitForServiceProcessRestart(")
  })
  test("ordinary labels distinguish a failed probe from complete unavailability", () => {
    expect(ruTranslation.overview.outbounds.status.degraded).toBe(
      "Есть проблемы"
    )
    expect(ruTranslation.overview.outbounds.member.degraded).toBe(
      "Проверка не прошла"
    )
    expect(ruTranslation.overview.outbounds.status.unavailable).not.toBe(
      ruTranslation.overview.outbounds.status.degraded
    )
    const labels = [
      ruTranslation.pages.dnsServers.description,
      ruTranslation.pages.dnsServers.fallbackSaved,
      ruTranslation.pages.dnsServerUpsert.description,
      ruTranslation.transports.form.backendUpdateRequired,
      ruTranslation.transports.nativeMutation.recovery.pendingTitle,
      ruTranslation.transports.loopProtection.confirm,
    ]
    for (const label of labels)
      expect(label).not.toMatch(
        /\b(?:fallback|upstream|backend|native|pass-through|ignore)\b/i
      )
  })
})
