import { describe, expect, mock, spyOn, test } from "bun:test"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"
import type { ReactNode } from "react"
import type { RuleCountersResponse } from "../src/api/generated/model/ruleCountersResponse"
import type { RoutingTestFirewallCounters } from "../src/api/generated/model/routingTestFirewallCounters"
import {
  RuleCountersResult,
  RuleCountersSession,
  RuleCounterDetails,
} from "../src/components/rules/rule-counters"
import { AdvancedRoutingDiagnostics } from "../src/components/overview/advanced-routing-diagnostics"
import {
  isRuleCountersResponse,
  runRuleCounters,
  type RuleCountersState,
} from "../src/components/rules/rule-counters-model"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

function counter(
  extra: Partial<RoutingTestFirewallCounters> = {}
): RoutingTestFirewallCounters {
  return {
    scope: "prerouting",
    status: "observed",
    snapshot_at: 1700000000,
    total: 1,
    truncated: false,
    rules: [
      {
        family: "ipv4",
        table: "raw",
        chain: "KeenPbrRaw_B",
        position: 7,
        action: "mark",
        set_name: "kpbr4_example",
        fwmark: 0x40000,
        fwmask: 0xffff0000,
        packets: "0",
        bytes: "18446744073709551615",
      },
    ],
    ...extra,
  }
}
function response(): RuleCountersResponse {
  return {
    captured_at: 1700000000,
    unapplied_draft: false,
    total: 1,
    truncated: false,
    rules: [
      {
        rule_index: 0,
        name: "Applied work",
        outbound: "vpn",
        outbound_name: "Applied VPN",
        enabled: true,
        ipv4: counter(),
        ipv6: counter({ status: "unavailable", total: 0, rules: [] }),
      },
    ],
  }
}
async function render(children: ReactNode, language = "ru") {
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
    <I18nextProvider i18n={i18n}>{children}</I18nextProvider>
  )
}
function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((yes, no) => {
    resolve = yes
    reject = no
  })
  return { promise, resolve, reject }
}

describe("MET-01 rule counters", () => {
  test("closed and opened idle panel perform no requests", async () => {
    const fetch = spyOn(globalThis, "fetch")
    try {
      const collapsed = await render(<AdvancedRoutingDiagnostics />)
      expect(collapsed).toContain("Расширенная диагностика")
      expect(collapsed).not.toContain("Показатели правил — частичный учёт")
      expect(collapsed).not.toContain(" open=")
      expect(collapsed).not.toContain("<button")
      const open = await render(<RuleCountersSession localChanges />)
      expect(open).toContain("Снять показания")
      expect(open).toContain("несохранённые изменения")
      expect(open).toContain("аппаратное ускорение Keenetic")
      expect(open).toContain("Время сброса неизвестно")
      expect(open).toContain("несколько доменов")
      expect(open).toContain("RX/TX")
      expect(open).not.toContain('role="alert"')
      expect(fetch).not.toHaveBeenCalled()
    } finally {
      fetch.mockRestore()
    }
  })

  test("counter tools belong to advanced dashboard diagnostics, not rule editing", async () => {
    const rules = await Bun.file(
      new URL("../src/pages/routing-rules-page.tsx", import.meta.url)
    ).text()
    const overview = await Bun.file(
      new URL("../src/pages/overview-page.tsx", import.meta.url)
    ).text()
    expect(rules).not.toContain("RuleCounters")
    expect(rules).not.toContain("AdvancedRoutingDiagnostics")
    const start = overview.indexOf("id={dashboardSectionIds.routing}")
    expect(start).toBeGreaterThan(0)
    const diagnosticsCard = overview.slice(
      start,
      overview.indexOf("</SectionCard>", start)
    )
    expect(diagnosticsCard).toContain("<AdvancedRoutingDiagnostics />")
  })

  test("exact counts and read time are separate from unavailable family and reset time", async () => {
    const html = await render(<RuleCountersResult result={response()} />)
    expect(html).toContain("Пакетов: 0; байтов: 18446744073709551615")
    expect(html).not.toContain("18446744073709552000")
    expect(html).toContain("Нет показаний")
    expect(html).not.toContain("KeenPbrRaw_B")
    const details = await render(
      <RuleCounterDetails rule={response().rules[0]} />
    )
    expect(details).toContain("KeenPbrRaw_B")
    expect(details).toContain("позиция 7")
    expect(details).toContain("Пакетов: 0; байтов: 18446744073709551615")
    expect(html).toContain("Applied work")
    expect(html).toContain("Выход в настройках: Applied VPN")
    expect(html).toContain("Данные обновляются только по кнопке")
    expect(html).not.toContain("0 бит/с")
  })

  test("multiple physical rows are not summed and truncation is visible", async () => {
    const result = response()
    const ipv4 = result.rules[0].ipv4
    ipv4.rules.push({
      ...ipv4.rules[0],
      position: 8,
      packets: "2",
      bytes: "17",
    })
    ipv4.total = 40
    ipv4.truncated = true
    result.total = 140
    result.truncated = true
    result.unapplied_draft = true
    const html = await render(<RuleCountersResult result={result} />)
    expect(html).toContain("Строк firewall: 2 из 40")
    expect(html).not.toContain("Пакетов: 2; байтов: 17")
    expect(html).not.toContain("18446744073709551632")
    expect(html).toContain("Показаны первые 128 правил")
    expect(html).toContain("Есть неприменённый черновик")
    const details = await render(<RuleCounterDetails rule={result.rules[0]} />)
    expect(details).toContain("Пакетов: 2; байтов: 17")
    expect(details).toContain("показаны не все строки")
    expect(details).not.toContain("18446744073709551632")
  })

  test("a large closed snapshot does not mount thousands of physical details", async () => {
    const result = response()
    const template = result.rules[0]
    result.total = 128
    result.rules = Array.from({ length: 128 }, (_, rule_index) => ({
      ...template,
      rule_index,
      ipv4: counter({
        total: 32,
        rules: Array.from({ length: 32 }, (_, index) => ({
          ...template.ipv4.rules[0],
          position: index + 1,
        })),
      }),
    }))
    expect(isRuleCountersResponse(result)).toBe(true)
    const html = await render(<RuleCountersResult result={result} />)
    expect((html.match(/<summary/g) ?? []).length).toBe(128)
    expect(html).not.toContain("KeenPbrRaw_B")
    expect(html).not.toContain("kpbr4_example")
  })

  test("ambiguous and disabled rules never look like measured zeros", async () => {
    const result = response()
    result.rules[0].enabled = false
    result.rules[0].name = ""
    result.rules[0].ipv4 = counter({ status: "ambiguous", total: 0, rules: [] })
    result.rules[0].ipv6 = counter({
      status: "not_applicable",
      total: 0,
      rules: [],
    })
    const html = await render(<RuleCountersResult result={result} />)
    expect(html).toContain("Без названия")
    expect(html).toContain("Отключено в настройках")
    expect(html).toContain("Неоднозначное соответствие")
    expect(html).toContain("Не применяется")
    expect(html).not.toContain("Пакетов: 0")
  })

  test("English scope and empty report are localized", async () => {
    const html = await render(<RuleCountersSession localChanges />, "en")
    expect(html).toContain("Read counters")
    expect(html).toContain("not a connectivity test")
    expect(html).toContain("no per-VPN totals")
    expect(html).not.toContain("ruleCounters.")
    const result = response()
    result.rules = []
    result.total = 0
    expect(isRuleCountersResponse(result)).toBe(true)
    expect(
      await render(<RuleCountersResult result={result} />, "en")
    ).toContain("has no routing rules")
  })

  test("one click sends one request, repeated clicks do not enqueue or retry", async () => {
    const pending = deferred<unknown>()
    const request = mock(() => pending.promise)
    const active = { current: null as AbortController | null }
    const states: RuleCountersState[] = []
    const run = runRuleCounters(active, request, (state) => states.push(state))
    await runRuleCounters(active, request, (state) => states.push(state))
    expect(request).toHaveBeenCalledTimes(1)
    expect(states).toEqual([{ status: "pending" }])
    pending.resolve(response())
    await run
    expect(states.at(-1)?.status).toBe("ready")
    expect(active.current).toBeNull()
  })

  test("failed refresh removes the old result and does not expose internal errors", async () => {
    const states: RuleCountersState[] = []
    const active = { current: null as AbortController | null }
    await runRuleCounters(
      active,
      async () => response(),
      (state) => states.push(state)
    )
    const request = mock(async () => {
      throw new Error("private path or credentials")
    })
    await runRuleCounters(active, request, (state) => states.push(state))
    expect(states.slice(-2)).toEqual([
      { status: "pending" },
      { status: "failed" },
    ])
    expect(request).toHaveBeenCalledTimes(1)
    expect(JSON.stringify(states)).not.toContain("private path")
  })

  test("closing the panel discards a late result", async () => {
    const pending = deferred<unknown>()
    const active = { current: null as AbortController | null }
    const states: RuleCountersState[] = []
    const run = runRuleCounters(
      active,
      () => pending.promise,
      (state) => states.push(state)
    )
    active.current!.abort()
    active.current = null
    pending.resolve(response())
    await run
    expect(states).toEqual([{ status: "pending" }])
  })

  test("per-request timeout does not start another request", async () => {
    const active = { current: null as AbortController | null }
    const states: RuleCountersState[] = []
    const request = mock(
      (signal: AbortSignal) =>
        new Promise((_, reject) => {
          signal.addEventListener("abort", () => reject(new Error("timeout")), {
            once: true,
          })
        })
    )
    await runRuleCounters(active, request, (state) => states.push(state), 5)
    expect(states).toEqual([{ status: "pending" }, { status: "failed" }])
    expect(active.current).toBeNull()
    expect(request).toHaveBeenCalledTimes(1)
  })

  test("missing old and malformed responses fail without a misleading result", async () => {
    for (const value of [
      null,
      {},
      { rules: [] },
      "<html>old UI</html>",
      undefined,
    ]) {
      expect(isRuleCountersResponse(value)).toBe(false)
      const states: RuleCountersState[] = []
      await runRuleCounters(
        { current: null },
        async () => value,
        (state) => states.push(state)
      )
      expect(states.at(-1)).toEqual({ status: "failed" })
    }
  })

  test("wire validation retains uint64 and rejects incomplete cross-family or duplicate rows", () => {
    expect(isRuleCountersResponse(response())).toBe(true)
    const invalid: ((result: RuleCountersResponse) => void)[] = [
      (r) => {
        r.rules[0].ipv4.rules[0].packets = "18446744073709551616"
      },
      (r) => {
        r.rules[0].ipv4.rules[0].bytes = "1e3"
      },
      (r) => {
        r.rules[0].ipv4.rules[0].bytes = "-1"
      },
      (r) => {
        r.rules[0].ipv4.rules[0].family = "ipv6"
      },
      (r) => {
        r.rules[0].ipv4.rules[0].fwmask = 0x100000000
      },
      (r) => {
        r.rules[0].ipv4.total = 2
      },
      (r) => {
        r.rules[0].ipv4.rules = []
      },
      (r) => {
        r.rules[0].ipv4.snapshot_at = 0
      },
      (r) => {
        r.rules[0].ipv6.rules = r.rules[0].ipv4.rules
      },
      (r) => {
        r.rules[0].rule_index = 9
      },
      (r) => {
        r.total = 0
      },
      (r) => {
        r.truncated = true
      },
      (r) => {
        r.rules[0].ipv4.total = 2
        r.rules[0].ipv4.rules.push(r.rules[0].ipv4.rules[0])
      },
    ]
    for (const modify of invalid) {
      const value = response()
      modify(value)
      expect(isRuleCountersResponse(value)).toBe(false)
    }
  })
})
