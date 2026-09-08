import { describe, expect, spyOn, test } from "bun:test"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createInstance } from "i18next"
import type { ReactNode } from "react"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"

import {
  DEFAULT_LOG_FILE_BYTES,
  DEFAULT_LOG_MAX_AGE_DAYS,
  LOG_FILE_SIZE_CHOICES,
  LOG_SETTINGS_QUERY_KEY,
  loadLogSettings,
  logFileSizeChoices,
  logAgeChoices,
  logSizeUnit,
  saveLogSettings,
  updateLogSettingsDraft,
} from "../src/lib/log-settings"
import { LoggingSettingsCard } from "../src/components/settings/logging-settings-card"
import { NfqwsLogLimitSettings } from "../src/pages/nfqws-page"
import { ruTranslation } from "../src/i18n/ru"
import type { LogSettings } from "../src/api/generated/model"

const settings = {
  file_enabled: true,
  level: "info" as const,
  max_file_bytes: 2 * DEFAULT_LOG_FILE_BYTES,
  nfqws_max_file_bytes: 256 * 1024,
}

async function renderLogSetting(
  node: ReactNode,
  overrides: Partial<LogSettings> = {}
) {
  const i18n = createInstance()
  await i18n.init({
    lng: "ru",
    resources: { ru: { translation: ruTranslation } },
    interpolation: { escapeValue: false },
  })
  const client = new QueryClient()
  client.setQueryData(LOG_SETTINGS_QUERY_KEY, { ...settings, ...overrides })
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

describe("log size settings", () => {
  test("choices stay bounded and preserve an existing non-preset value", () => {
    expect(LOG_FILE_SIZE_CHOICES[0]).toBe(65536)
    expect(LOG_FILE_SIZE_CHOICES.at(-1)).toBe(16777216)
    expect(logFileSizeChoices(DEFAULT_LOG_FILE_BYTES)).toHaveLength(
      LOG_FILE_SIZE_CHOICES.length
    )
    expect(logFileSizeChoices(100000)).toContain(100000)
    expect(logSizeUnit(65536)).toEqual({
      key: "pages.settings.logging.sizeKiB",
      size: 64,
    })
    expect(logSizeUnit(2097152)).toEqual({
      key: "pages.settings.logging.sizeMiB",
      size: 2,
    })
  })

  test("retention age defaults off and day choices remain configurable within bounds", () => {
    expect(DEFAULT_LOG_MAX_AGE_DAYS).toBe(7)
    expect(logAgeChoices(7)[0]).toBe(1)
    expect(logAgeChoices(7).at(-1)).toBe(365)
    expect(logAgeChoices(42)).toContain(42)
    const baseline = {
      size_limit_enabled: true,
      age_limit_enabled: false,
      max_age_days: 7,
    }
    const changed = updateLogSettingsDraft(
      {},
      { age_limit_enabled: true, max_age_days: 30 },
      baseline
    )
    expect(changed).toEqual({ age_limit_enabled: true, max_age_days: 30 })
    expect(
      updateLogSettingsDraft(
        changed,
        { age_limit_enabled: false, max_age_days: 7 },
        baseline
      )
    ).toEqual({})
  })

  test("reverting a local size draft clears it without losing another change", () => {
    const changed = updateLogSettingsDraft(
      {},
      { max_file_bytes: 1048576 },
      settings
    )
    expect(changed).toEqual({ max_file_bytes: 1048576 })
    const twoChanges = updateLogSettingsDraft(
      changed,
      { level: "warn" },
      settings
    )
    expect(
      updateLogSettingsDraft(
        twoChanges,
        { max_file_bytes: settings.max_file_bytes },
        settings
      )
    ).toEqual({ level: "warn" })
    expect(
      updateLogSettingsDraft(
        changed,
        { max_file_bytes: settings.max_file_bytes },
        settings
      )
    ).toEqual({})
  })

  test("nfqws save sends only its size field and uses no service action", async () => {
    const calls: { url: string; init?: RequestInit }[] = []
    const fetchMock = spyOn(globalThis, "fetch").mockImplementation(
      async (input, init) => {
        calls.push({ url: String(input), init })
        return Response.json({ ok: true, settings })
      }
    )
    try {
      expect(await saveLogSettings({ nfqws_max_file_bytes: 262144 })).toEqual(
        settings
      )
      expect(calls).toHaveLength(1)
      expect(calls[0].url).toBe("/api/logs/settings")
      expect(JSON.parse(String(calls[0].init?.body))).toEqual({
        nfqws_max_file_bytes: 262144,
      })
    } finally {
      fetchMock.mockRestore()
    }
  })

  test("HTTP-200 settings errors remain failures and are not retried", async () => {
    const fetchMock = spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({ error: "cannot write logging.json" })
    )
    try {
      await expect(saveLogSettings({ max_file_bytes: 65536 })).rejects.toThrow(
        "cannot write logging.json"
      )
      expect(fetchMock).toHaveBeenCalledTimes(1)
    } finally {
      fetchMock.mockRestore()
    }
  })

  test("read returns persisted size values rather than inferred defaults", async () => {
    const fetchMock = spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json(settings)
    )
    try {
      expect(await loadLogSettings()).toEqual(settings)
      expect(fetchMock).toHaveBeenCalledWith("/api/logs/settings")
    } finally {
      fetchMock.mockRestore()
    }
  })

  test("General log cap has a standard labelled field and total-generation hint", async () => {
    const html = await renderLogSetting(
      <LoggingSettingsCard onStateChange={() => undefined} />
    )
    expect(html).toContain('for="logging-max-bytes"')
    expect(html).toContain('id="logging-max-bytes"')
    expect(html).toContain("2 МиБ")
    expect(html).toContain("4 МиБ")
    expect(html).toContain("max-w-[480px]")
    expect(html).toContain('id="logging-size-enabled"')
    expect(html).toContain('id="logging-age-enabled"')
    expect(html).toContain('for="logging-max-age"')
  })

  test("nfqws log tab shows its own stored limit without a restart action", async () => {
    const html = await renderLogSetting(<NfqwsLogLimitSettings />)
    expect(html).toContain('for="nfqws-log-max-bytes"')
    expect(html).toContain('id="nfqws-log-max-bytes"')
    expect(html).toContain("256 КиБ")
    expect(html).toContain("Сохранить")
    expect(html).toContain('id="nfqws-log-size-enabled"')
    expect(html).toContain('id="nfqws-log-age-enabled"')
    expect(html).toContain('for="nfqws-log-max-age"')
    expect(html).not.toContain("Сохранить и перезапустить")
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>[^]*?Сохранить/)
  })

  test("turning both retention modes off is clearly described as unlimited", async () => {
    const general = await renderLogSetting(
      <LoggingSettingsCard onStateChange={() => undefined} />,
      {
        size_limit_enabled: false,
        age_limit_enabled: false,
      }
    )
    const nfqws = await renderLogSetting(<NfqwsLogLimitSettings />, {
      nfqws_size_limit_enabled: false,
      nfqws_age_limit_enabled: false,
    })
    expect(general).toContain("Автоматическая очистка отключена")
    expect(nfqws).toContain("Автоматическая очистка отключена")
    expect(nfqws).toContain("строки технического журнала без даты сохраняются")
  })
})
