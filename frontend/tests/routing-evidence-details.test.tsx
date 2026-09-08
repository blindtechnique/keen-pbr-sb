import { describe, expect, spyOn, test } from "bun:test"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"

import type {
  RoutingTestConnection,
  RoutingTestFirewallCounters,
  RoutingTestHttpProbe,
  RoutingTestResponse,
} from "../src/api/generated/model"
import { RoutingDiagnosticsResult } from "../src/components/overview/routing-diagnostics-result"
import { RoutingEvidenceDetails } from "../src/components/overview/routing-evidence-details"
import type { RoutingHttpProbeControls } from "../src/components/overview/routing-http-probe-state"
import {
  compareConnectionMark,
  formatEvidenceTime,
  getConnectionEvidence,
} from "../src/components/overview/routing-evidence-model"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

function connection(
  overrides: Partial<RoutingTestConnection> = {}
): RoutingTestConnection {
  return {
    protocol: "tcp",
    state: "ESTABLISHED",
    source: "192.168.1.12",
    source_port: 43210,
    destination: "2001:db8::1",
    destination_port: 443,
    mark: 0x80040001,
    last_seen: 1700000000,
    ...overrides,
  }
}

function report(): RoutingTestResponse {
  return {
    target: "example.com",
    is_domain: true,
    config_scope: "active",
    unapplied_draft: false,
    resolved_ips: ["2001:db8::1"],
    warnings: [],
    no_matching_rule: false,
    dns_source: "configured_resolver",
    dns_server: "127.0.0.1:53",
    fwmark_mask: 0x00ff0000,
    results: [
      {
        ip: "2001:db8::1",
        list_match: { list: "sites", via: "example.com" },
        expected_rule_index: 0,
        actual_rule_index: 0,
        expected_outbound: "vpn",
        actual_outbound: "vpn",
        ok: true,
        evaluation: "matched",
        unknown_conditions: [],
        kernel_route: {
          route_status: "resolved",
          fwmark: 0x40000,
          table: 152,
          interface: "nwg1",
          detail: "lookup detail",
        },
      },
    ],
    rule_diagnostics: [
      {
        rule_index: 0,
        rule: { display_name: "Sites", list: ["sites"], outbound: "vpn" },
        outbound: "vpn",
        interface_name: "nwg1",
        target_in_lists: true,
        target_match: { list: "sites", via: "example.com" },
        ip_rows: [
          {
            ip: "2001:db8::1",
            in_lists: true,
            in_ipset: true,
            evaluation: "matched",
            unknown_conditions: [],
          },
        ],
      },
    ],
    connections: {
      snapshot_available: true,
      snapshot_at: 1700000001,
      total: 1,
      truncated: false,
      items: [connection()],
    },
  }
}

async function render(
  data: RoutingTestResponse,
  language: "ru" | "en",
  full = false,
  controls: RoutingHttpProbeControls = {}
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
      {full ? (
        <RoutingDiagnosticsResult diagnostics={data} {...controls} />
      ) : (
        <RoutingEvidenceDetails diagnostics={data} {...controls} />
      )}
    </I18nextProvider>
  )
}

function counterSnapshot(
  overrides: Partial<RoutingTestFirewallCounters> = {}
): RoutingTestFirewallCounters {
  return {
    status: "observed",
    scope: "prerouting",
    snapshot_at: 1700000003,
    total: 1,
    truncated: false,
    rules: [
      {
        family: "ipv6",
        table: "raw",
        chain: "KeenPbr",
        position: 3,
        action: "mark",
        set_name: "kpbr6_sites",
        fwmark: 0x40000,
        fwmask: 0x00ff0000,
        packets: "18446744073709551615",
        bytes: "9007199254740993",
      },
    ],
    ...overrides,
  }
}

function policySnapshot(
  overrides: Partial<
    NonNullable<RoutingTestResponse["results"][number]["policy_rules"]>
  > = {}
): NonNullable<RoutingTestResponse["results"][number]["policy_rules"]> {
  return {
    status: "observed",
    snapshot_at: 1700000002,
    total: 1,
    truncated: false,
    rules: [
      {
        family: "ipv6",
        priority: 14000,
        table: 152,
        fwmark: 0x40000,
        fwmask: 0x00ff0000,
        details_complete: true,
      },
    ],
    ...overrides,
  }
}

describe("bounded routing evidence", () => {
  test("compares owned mark bits only, including the unsigned high bit", () => {
    expect(compareConnectionMark(0x80040001, 0x40000, 0xff0000)).toBe(
      "matching"
    )
    expect(compareConnectionMark(0x80050001, 0x40000, 0xff0000)).toBe(
      "different"
    )
    expect(compareConnectionMark(0xffffffff, 0x80000000, 0x80000000)).toBe(
      "matching"
    )
    expect(compareConnectionMark(0x7fffffff, 0x80000000, 0x80000000)).toBe(
      "different"
    )
    expect(compareConnectionMark(0, 0, 0xff0000)).toBe("matching")
  })

  test("missing marks and empty or invalid masks are not mismatches", () => {
    for (const invalid of [
      undefined,
      null,
      NaN,
      Infinity,
      -1,
      0x100000000,
      0.5,
      "262144",
    ]) {
      expect(compareConnectionMark(invalid, 0, 0xff0000)).toBe("unconfirmed")
      expect(compareConnectionMark(0, invalid, 0xff0000)).toBe("unconfirmed")
      expect(compareConnectionMark(0, 0, invalid)).toBe("unconfirmed")
    }
    expect(compareConnectionMark(0, 0, 0)).toBe("unconfirmed")
  })

  test("matches exact canonical IPv6 destinations without rewriting the tuple", () => {
    const data = report()
    const expanded = connection({ destination: "2001:0DB8:0:0:0:0:0:1" })
    data.connections!.items = [
      expanded,
      connection({ destination: "2001:db8::10" }),
      connection({ destination: "2001:db8::1:invalid" }),
    ]
    const evidence = getConnectionEvidence(data, data.results[0])
    expect(evidence).toEqual([{ connection: expanded, mark: "matching" }])
    expect(evidence[0].connection).toBe(expanded)
    data.results[0].ip = "::ffff:c000:201"
    data.connections!.items = [connection({ destination: "::ffff:192.0.2.1" })]
    expect(getConnectionEvidence(data, data.results[0])).toHaveLength(1)
  })

  test("does not associate adjacent IPv4 addresses or unavailable snapshot rows", () => {
    const data = report()
    data.results[0].ip = "192.0.2.1"
    data.connections!.items = [
      connection({ destination: "192.0.2.10" }),
      connection({ destination: "192.0.2.1" }),
    ]
    expect(getConnectionEvidence(data, data.results[0])).toHaveLength(1)
    data.connections!.snapshot_available = false
    expect(getConnectionEvidence(data, data.results[0])).toEqual([])
  })

  test("never converts a missing realized mark into an unmarked route", () => {
    const data = report()
    data.results[0].kernel_route.fwmark = null
    data.connections!.items[0].mark = 0
    expect(getConnectionEvidence(data, data.results[0])[0].mark).toBe(
      "unconfirmed"
    )
    data.results[0].kernel_route.fwmark = 0
    delete data.fwmark_mask
    expect(getConnectionEvidence(data, data.results[0])[0].mark).toBe(
      "unconfirmed"
    )
  })

  test("formats supplied snapshot timestamps without a live clock or timer", () => {
    expect(formatEvidenceTime(1700000000)).toBe("2023-11-14T22:13:20.000Z")
    for (const invalid of [undefined, 0, -1, NaN, Infinity, 1e30])
      expect(formatEvidenceTime(invalid)).toBeNull()
  })

  test("keeps the advanced block closed in the existing result, with no additional request", async () => {
    const fetch = spyOn(globalThis, "fetch").mockRejectedValue(
      new Error("No requests are allowed")
    )
    try {
      for (const language of ["ru", "en"] as const) {
        const data = report()
        data.results[0].policy_rules = policySnapshot()
        data.results[0].firewall_counters = counterSnapshot()
        const html = await render(data, language, true)
        const text = (language === "ru" ? ruTranslation : enTranslation)
          .overview.routingDiagnostics
        expect(html).toContain(text.evidence.title)
        expect(html).toContain(text.resultTitle)
        expect(html).toContain(text.ruleDetailsTitle)
        expect(html).not.toContain(text.pathTitle)
        expect(html).toMatch(/<details\s[^>]*>/)
        expect(html).not.toMatch(/<details\s[^>]*\bopen(?:[\s=>])/)
        expect(html).toContain(text.evidence.markMatching)
        expect(html).toContain("[192.168.1.12]:43210")
        expect(html).toContain("ESTABLISHED")
        expect(html).toContain("2023-11-14T22:13:20.000Z")
        expect(html).toContain("0x80040001")
        expect(html).toContain(Bun.escapeHTML(text.evidence.scope))
        expect(html).toContain(text.evidence.policy)
        expect(html).toContain(text.evidence.policyMarkMatching)
        expect(html).toContain(text.evidence.counterTitle)
        expect(html.indexOf(text.evidence.mark)).toBeLessThan(
          html.indexOf(text.evidence.counterTitle)
        )
        expect(html.indexOf(text.evidence.counterTitle)).toBeLessThan(
          html.indexOf(text.evidence.policy)
        )
        expect(html.indexOf(text.evidence.mark)).toBeLessThan(
          html.indexOf(text.evidence.policy)
        )
        expect(html.indexOf(text.evidence.policy)).toBeLessThan(
          html.indexOf(text.evidence.fib)
        )
      }
      expect(fetch).not.toHaveBeenCalled()
    } finally {
      fetch.mockRestore()
    }
  })

  test("does not treat expected/actual equality as a successful FIB lookup", async () => {
    const data = report()
    data.results[0].kernel_route.route_status = "unroutable"
    data.results[0].kernel_route.detail = "<script>diagnostic detail</script>"
    const html = await render(data, "en")
    expect(html).toContain(
      enTranslation.overview.routingDiagnostics.evidence.fibUnroutable
    )
    expect(html).not.toContain(
      enTranslation.overview.routingDiagnostics.evidence.fibResolved
    )
    expect(html).toContain("&lt;script&gt;diagnostic detail&lt;/script&gt;")
    expect(html).not.toContain("<script>")
  })

  test("keeps configured and realized rule identities separate from observed mark evidence", async () => {
    const data = report()
    data.results[0].actual_rule_index = 2
    data.rule_diagnostics.push({
      ...data.rule_diagnostics[0],
      rule_index: 2,
      rule: { display_name: "Other rule", outbound: "vpn" },
    })
    data.connections!.items[0].mark = 0x50000
    const html = await render(data, "en")
    expect(html).toContain("Active configuration rule: Sites")
    expect(html).toContain("Rule from current firewall sets: Other rule")
    expect(html).toContain(
      enTranslation.overview.routingDiagnostics.evidence.markDifferent
    )
    expect(html).not.toContain(
      enTranslation.overview.routingDiagnostics.evidence.markMatching
    )
  })

  test("legacy responses honestly show unavailable optional evidence", async () => {
    const data = report()
    delete data.connections
    delete data.dns_source
    delete data.dns_server
    delete data.fwmark_mask
    delete data.results[0].expected_rule_index
    delete data.results[0].actual_rule_index
    for (const language of ["ru", "en"] as const) {
      const text = (language === "ru" ? ruTranslation : enTranslation).overview
        .routingDiagnostics.evidence
      const html = await render(data, language)
      expect(html).toContain(text.dnsUnknown)
      expect(html).toContain(text.snapshotUnavailable)
      expect(html).not.toContain(text.noConnections)
      expect(html).not.toContain(text.markMatching)
      expect(html).not.toContain("undefined")
      expect(html).toContain(text.policyMissing)
      expect(html).toContain(text.counterMissing)
      expect(html).not.toContain(text.counterEmpty)
      expect(html).not.toContain(text.counterUnavailable)
    }
  })

  test("empty and truncated snapshots are not presented as offline", async () => {
    const data = report()
    data.connections!.items = []
    data.connections!.total = 0
    data.connections!.truncated = true
    for (const language of ["ru", "en"] as const) {
      const text = (language === "ru" ? ruTranslation : enTranslation).overview
        .routingDiagnostics.evidence
      const html = await render(data, language)
      expect(html).toContain(text.noConnections)
      expect(html).toContain(text.truncated)
      expect(html).not.toContain(text.snapshotUnavailable)
    }
  })

  test("IP targets skip DNS and absent context leaves mark comparison unconfirmed", async () => {
    const data = report()
    data.is_domain = false
    data.target = data.results[0].ip
    data.results[0].evaluation = "insufficient_context"
    data.results[0].kernel_route = {
      route_status: "not_applicable",
      fwmark: null,
      interface: "",
      detail: "",
    }
    const html = await render(data, "en")
    const text = enTranslation.overview.routingDiagnostics
    expect(html).toContain(text.evidence.dnsLiteral)
    expect(html).not.toContain("127.0.0.1:53")
    expect(html).toContain(text.packetContextRequired)
    expect(html).toContain(text.evidence.fibNotApplicable)
    expect(html).toContain(text.evidence.markUnconfirmed)
    expect(html).not.toContain(text.evidence.markMatching)
  })
})

function httpProbeResult(
  overrides: Partial<RoutingTestHttpProbe> = {}
): RoutingTestHttpProbe {
  return {
    status: "answered",
    reason: "http_response",
    ip: "2001:db8::1",
    url: "https://example.com/",
    method: "HEAD",
    scope: "router",
    interface: "fresh-http-iface",
    fwmark: 0x50000,
    table: 153,
    attempted_at: 1700000004,
    http_status: 403,
    elapsed_ms: 30,
    connect_ms: 5,
    tls_ms: 20,
    connected_ip: "2001:db8::1",
    ...overrides,
  }
}

describe("manual route HTTPS presentation", () => {
  test("renders only an explicit action in closed pure details without a QueryClient or any request", async () => {
    let clicks = 0
    const fetch = spyOn(globalThis, "fetch").mockRejectedValue(
      new Error("No implicit request")
    )
    try {
      for (const language of ["ru", "en"] as const) {
        const text = (language === "ru" ? ruTranslation : enTranslation)
          .overview.routingDiagnostics.evidence
        const html = await render(report(), language, true, {
          onHttpProbe: () => {
            clicks += 1
          },
        })
        expect(html).toContain(text.httpCheck)
        expect(html).toContain(Bun.escapeHTML(text.httpScope))
        expect(html).not.toMatch(/<details\s[^>]*\bopen(?:[\s=>])/)
        expect(html).toMatch(/<button[^>]*type="button"/)
        expect(html).not.toContain(text.httpAnswered)
      }
      expect(clicks).toBe(0)
      expect(fetch).not.toHaveBeenCalled()
    } finally {
      fetch.mockRestore()
    }
  })

  test("all HTTP codes are response evidence and use the attempt's freshly resolved route and timings", async () => {
    for (const language of ["ru", "en"] as const) {
      const text = (language === "ru" ? ruTranslation : enTranslation).overview
        .routingDiagnostics.evidence
      for (const status of [200, 301, 403, 405]) {
        const html = await render(report(), language, false, {
          httpProbe: httpProbeResult({ http_status: status }),
        })
        expect(html).toContain(text.httpAnswered)
        expect(html).toContain(`HTTP ${status}`)
        expect(html).toContain(Bun.escapeHTML(text.httpResponse))
        expect(html).toContain(text.httpFresh)
        expect(html).toContain("fresh-http-iface")
        expect(html).toContain("0x00050000")
        expect(html).toContain("153")
        expect(html).toContain("HEAD https://example.com/")
        expect(html).toContain("2023-11-14T22:13:24.000Z")
        expect(html).toContain(
          language === "ru"
            ? "До установления соединения, от начала запроса: 5 мс"
            : "Until connection established, from request start: 5 ms"
        )
        expect(html).toContain(
          language === "ru"
            ? "До завершения TLS, от начала запроса: 20 мс"
            : "Until TLS completed, from request start: 20 ms"
        )
      }
    }
  })

  test("localizes each unavailable or failed reason without converting TLS and timeouts into routing failure", async () => {
    for (const language of ["ru", "en"] as const) {
      const text = (language === "ru" ? ruTranslation : enTranslation).overview
        .routingDiagnostics.evidence
      const reasons = {
        context_required: text.httpContextRequired,
        no_route: text.httpNoRoute,
        destination_changed: text.httpDestinationChanged,
        blocked_route: text.httpBlockedRoute,
        binding_failed: text.httpBindingFailed,
        tls_error: text.httpTlsError,
        timeout: text.httpTimeout,
        connection_failed: text.httpConnectionFailed,
        unsupported_target: text.httpUnsupportedTarget,
        transport_error: text.httpTransportError,
        budget_exhausted: text.httpBudgetExhausted,
        response_limit: text.httpResponseLimit,
      } as const
      for (const [reason, message] of Object.entries(reasons)) {
        const html = await render(report(), language, false, {
          httpProbe: httpProbeResult({
            status: "failed",
            reason: reason as RoutingTestHttpProbe["reason"],
            http_status: undefined,
          }),
        })
        expect(html).toContain(text.httpIncomplete)
        expect(html).toContain(Bun.escapeHTML(message))
        expect(html).not.toContain(text.httpAnswered)
      }
    }
  })

  test("pending and request errors remain inline without removing the base result, and other IPs do not get the result", async () => {
    const text = enTranslation.overview.routingDiagnostics
    const data = report()
    let html = await render(data, "en", true, {
      onHttpProbe: () => undefined,
      httpPendingIp: "2001:db8::1",
    })
    expect(html).toContain(text.evidence.httpPending)
    expect(html).toMatch(/<button[^>]*\sdisabled(?:=|\s|>)/)
    expect(html).toContain(text.resultTitle)
    expect(html).toContain(text.ruleDetailsTitle)
    expect(html).toContain("nwg1")
    html = await render(data, "en", true, {
      onHttpProbe: () => undefined,
      httpError: { ip: "2001:db8::1" },
    })
    expect(html).toContain(text.evidence.httpRequestFailed)
    expect(html).toContain(text.resultTitle)
    expect(html).not.toMatch(/<button[^>]*\sdisabled(?:=|\s|>)/)
    html = await render(data, "en", false, {
      onHttpProbe: () => undefined,
      httpError: { ip: "2001:db8::2" },
      httpProbe: httpProbeResult({ ip: "2001:db8::2" }),
    })
    expect(html).not.toContain(text.evidence.httpRequestFailed)
    expect(html).not.toContain(text.evidence.httpAnswered)
  })

  test("attaches canonical IPv6 probe evidence to the original literal without accepting a different address", async () => {
    const data = report()
    data.target = "2001:DB8:0:0::8"
    data.is_domain = false
    data.results[0].ip = data.target
    const text = enTranslation.overview.routingDiagnostics.evidence
    let html = await render(data, "en", false, {
      httpProbe: httpProbeResult({ ip: "2001:db8::8" }),
    })
    expect(html).toContain(text.httpAnswered)
    expect(html).toContain("fresh-http-iface")
    expect(html).toContain("2001:DB8:0:0::8")
    html = await render(data, "en", false, {
      httpProbe: httpProbeResult({ ip: "2001:db8::9" }),
    })
    expect(html).not.toContain(text.httpAnswered)
    expect(html).not.toContain("fresh-http-iface")
  })

  test("not attempted and unavailable probes preserve optional fields as unknown without stale base fallback", async () => {
    const text = enTranslation.overview.routingDiagnostics.evidence
    for (const status of ["not_applicable", "unavailable"] as const) {
      const html = await render(report(), "en", false, {
        httpProbe: httpProbeResult({
          status,
          reason: "context_required",
          interface: "",
          fwmark: undefined,
          table: undefined,
          attempted_at: 0,
          http_status: undefined,
          elapsed_ms: undefined,
          connect_ms: undefined,
          tls_ms: undefined,
          url: "",
        }),
      })
      expect(html).toContain(
        status === "not_applicable"
          ? text.httpNotAttempted
          : text.httpUnavailable
      )
      expect(html).toContain(
        "interface: Unknown; mark: Unknown; table: Unknown"
      )
      expect(html).not.toContain("HEAD https://example.com/")
      expect(html).not.toContain("Total time:")
    }
    const html = await render(report(), "en", false, {
      httpProbe: httpProbeResult({ elapsed_ms: 0, connect_ms: 0, tls_ms: 0 }),
    })
    expect(html).toContain("Total time: 0 ms")
    expect(html).toContain("Until TLS completed, from request start: 0 ms")
  })
})

describe("firewall counter details", () => {
  test("preserves exact uint64 strings for each physical rule without summing or formatting as speed", async () => {
    const data = report()
    const counters = counterSnapshot()
    counters.rules.push({
      ...counters.rules[0],
      position: 4,
      packets: "9007199254740993",
      bytes: "18446744073709551615",
    })
    counters.total = 2
    data.results[0].firewall_counters = counters
    const original = JSON.stringify(data)
    for (const language of ["ru", "en"] as const) {
      const text = (language === "ru" ? ruTranslation : enTranslation).overview
        .routingDiagnostics.evidence
      const html = await render(data, language)
      expect(html).toContain(
        language === "ru"
          ? "Пакетов: 18446744073709551615; байтов: 9007199254740993"
          : "Packets: 18446744073709551615; bytes: 9007199254740993"
      )
      expect(html).toContain(
        language === "ru"
          ? "Пакетов: 9007199254740993; байтов: 18446744073709551615"
          : "Packets: 9007199254740993; bytes: 18446744073709551615"
      )
      expect(html).toContain(Bun.escapeHTML(text.counterScope))
      expect(html).not.toContain("18446744073709552000")
      expect(html).not.toContain("1.8446744073709552e+19")
      expect(html).not.toContain("bytes/s")
      expect(html).not.toContain("байт/с")
      expect(html).not.toContain("since boot")
    }
    expect(JSON.stringify(data)).toBe(original)
  })

  test("distinguishes unreadable, ambiguous and inapplicable evidence without showing stale values as zero", async () => {
    for (const language of ["ru", "en"] as const) {
      const text = (language === "ru" ? ruTranslation : enTranslation).overview
        .routingDiagnostics.evidence
      for (const [status, expected] of [
        ["unavailable", text.counterUnavailable],
        ["ambiguous", text.counterAmbiguous],
        ["not_applicable", text.counterNotApplicable],
      ] as const) {
        const data = report()
        data.results[0].firewall_counters = counterSnapshot({ status })
        const html = await render(data, language)
        expect(html).toContain(expected)
        expect(html).not.toContain(text.counterEmpty)
        expect(html).not.toContain(text.counterMissing)
        expect(html).not.toContain("18446744073709551615")
        expect(html).not.toContain("Packets: 0")
        expect(html).not.toContain("Пакетов: 0")
        expect(html).not.toContain("kpbr6_sites")
      }
    }
  })

  test("keeps a readable empty snapshot distinct from observed zero traffic", async () => {
    for (const language of ["ru", "en"] as const) {
      const text = (language === "ru" ? ruTranslation : enTranslation).overview
        .routingDiagnostics.evidence
      const data = report()
      data.results[0].firewall_counters = counterSnapshot({
        rules: [],
        total: 0,
      })
      let html = await render(data, language)
      expect(html).toContain(text.counterEmpty)
      expect(html).not.toContain(text.counterUnavailable)
      const counters = counterSnapshot()
      counters.rules[0].packets = "0"
      counters.rules[0].bytes = "0"
      data.results[0].firewall_counters = counters
      html = await render(data, language)
      expect(html).toContain(
        language === "ru" ? "Пакетов: 0; байтов: 0" : "Packets: 0; bytes: 0"
      )
      expect(html).toContain(Bun.escapeHTML(text.counterScope))
      expect(html).not.toContain(text.counterEmpty)
      expect(html).not.toContain(text.counterUnavailable)
      expect(html).not.toContain(text.counterAmbiguous)
    }
  })

  test("shows family, physical position, table, chain, set and localized actions without inferring missing marks", async () => {
    const data = report()
    data.results[0].ip = "192.0.2.1"
    const counters = counterSnapshot({ total: 3 })
    counters.rules = [
      {
        ...counters.rules[0],
        family: "ipv4",
        table: "mangle",
        position: 7,
        fwmark: 0xffffffff,
        fwmask: 0xffffffff,
      },
      {
        family: "ipv4",
        table: "raw",
        chain: "KeenPbr",
        position: 8,
        action: "drop",
        set_name: "",
        packets: "12",
        bytes: "24",
      },
      {
        family: "ipv4",
        table: "raw",
        chain: "KeenPbr",
        position: 9,
        action: "pass",
        set_name: "",
        packets: "34",
        bytes: "56",
      },
    ]
    data.results[0].firewall_counters = counters
    for (const language of ["ru", "en"] as const) {
      const text = (language === "ru" ? ruTranslation : enTranslation).overview
        .routingDiagnostics.evidence
      const html = await render(data, language)
      expect(html).toContain(
        language === "ru"
          ? "IPv4 · mangle / KeenPbr · позиция 7"
          : "IPv4 · mangle / KeenPbr · position 7"
      )
      expect(html).toContain(text.counterMarkAction)
      expect(html).toContain(text.counterDropAction)
      expect(html).toContain(text.counterPassAction)
      expect(html).toContain(
        language === "ru"
          ? "Метка: 0xffffffff; маска: 0xffffffff"
          : "Mark: 0xffffffff; mask: 0xffffffff"
      )
      expect(html).toContain(language === "ru" ? "IP-набор: —" : "IP set: —")
      expect(html).not.toContain(
        language === "ru"
          ? "Метка: 0x00000000; маска: 0x00000000"
          : "Mark: 0x00000000; mask: 0x00000000"
      )
    }
  })

  test("shows missing optional mark fields as unknown and escapes raw classifier names", async () => {
    const data = report()
    const counters = counterSnapshot()
    delete counters.rules[0].fwmark
    delete counters.rules[0].fwmask
    counters.rules[0].chain = "KeenPbr<script>"
    counters.rules[0].set_name = "<img src=x>"
    data.results[0].firewall_counters = counters
    const html = await render(data, "en")
    expect(html).toContain("Mark: Unknown; mask: Unknown")
    expect(html).toContain("KeenPbr&lt;script&gt;")
    expect(html).toContain("&lt;img src=x&gt;")
    expect(html).not.toContain("<script>")
    expect(html).not.toContain("<img src=x>")
  })

  test("shows its own snapshot timestamp and truncation without changing physical row values", async () => {
    const data = report()
    data.results[0].firewall_counters = counterSnapshot({
      total: 33,
      truncated: true,
    })
    for (const language of ["ru", "en"] as const) {
      const text = (language === "ru" ? ruTranslation : enTranslation).overview
        .routingDiagnostics.evidence
      const html = await render(data, language)
      expect(html).toContain("2023-11-14T22:13:23.000Z")
      expect(html).toContain(
        language === "ru" ? "Показано 1 из 33" : "Showing 1 of 33"
      )
      expect(html).toContain(text.counterTruncated)
      expect(html).toContain("18446744073709551615")
      expect(html).not.toContain(text.counterEmpty)
    }
  })
})

describe("policy routing candidate details", () => {
  test("distinguishes unavailable, inapplicable and readable empty snapshots in both languages", async () => {
    for (const language of ["ru", "en"] as const) {
      const text = (language === "ru" ? ruTranslation : enTranslation).overview
        .routingDiagnostics.evidence
      const data = report()
      data.results[0].policy_rules = policySnapshot({ status: "unavailable" })
      let html = await render(data, language)
      expect(html).toContain(text.policyUnavailable)
      expect(html).not.toContain(text.policyEmpty)
      expect(html).not.toContain(text.policyMarkMatching)
      expect(html).not.toContain("14000")
      data.results[0].policy_rules!.status = "not_applicable"
      html = await render(data, language)
      expect(html).toContain(text.policyNotApplicable)
      expect(html).not.toContain(text.policyUnavailable)
      expect(html).not.toContain(text.policyMarkMatching)
      data.results[0].policy_rules = policySnapshot({ rules: [], total: 0 })
      html = await render(data, language)
      expect(html).toContain(text.policyEmpty)
      expect(html).not.toContain(text.policyUnavailable)
      expect(html).not.toContain(text.policyMissing)
    }
  })

  test("presents the backend candidate order without selecting a winning table", async () => {
    const data = report()
    data.results[0].policy_rules = policySnapshot({
      total: 2,
      rules: [
        {
          family: "ipv6",
          priority: 14000,
          table: 153,
          fwmark: 0x40000,
          fwmask: 0xffff0000,
          details_complete: true,
        },
        {
          family: "ipv6",
          priority: 14001,
          table: 152,
          fwmark: 0x40000,
          fwmask: 0x00ff0000,
          details_complete: true,
        },
      ],
    })
    const originalRules = data.results[0].policy_rules.rules.map((rule) => ({
      ...rule,
    }))
    const html = await render(data, "en")
    const text = enTranslation.overview.routingDiagnostics.evidence
    expect(html).toContain(text.policyScope)
    expect(html).toContain("IPv6 · priority 14000 · table 153")
    expect(html).toContain("IPv6 · priority 14001 · table 152")
    expect(html.indexOf("priority 14000")).toBeLessThan(
      html.indexOf("priority 14001")
    )
    expect(html.split(text.policyMarkMatching)).toHaveLength(3)
    expect(html).toContain("Interface: nwg1; table: 152")
    expect(data.results[0].policy_rules.rules).toEqual(originalRules)
  })

  test("incomplete conditions are unconfirmed even when their visible marks differ", async () => {
    const data = report()
    const policy = policySnapshot()
    policy.rules[0] = {
      ...policy.rules[0],
      fwmark: 0x90000000,
      fwmask: 0xffffffff,
      details_complete: false,
    }
    data.results[0].policy_rules = policy
    for (const language of ["ru", "en"] as const) {
      const text = (language === "ru" ? ruTranslation : enTranslation).overview
        .routingDiagnostics.evidence
      const html = await render(data, language)
      expect(html).toContain(text.policyIncomplete)
      expect(html).not.toContain(text.policyMarkMatching)
      expect(html).toContain("0x90000000")
      expect(html).toContain("0xffffffff")
    }
  })

  test("shows full uint32 rule marks and zero masks without reusing conntrack comparison semantics", async () => {
    const data = report()
    data.results[0].policy_rules = policySnapshot({
      rules: [
        {
          family: "ipv6",
          priority: 14000,
          table: 152,
          fwmark: 0xffffffff,
          fwmask: 0xffffffff,
          details_complete: true,
        },
      ],
    })
    data.results[0].kernel_route.fwmark = 0xffffffff
    const text = enTranslation.overview.routingDiagnostics.evidence
    let html = await render(data, "en")
    expect(html).toContain("Rule mark: 0xffffffff; rule mask: 0xffffffff")
    expect(html).toContain(text.policyMarkMatching)
    data.results[0].kernel_route.fwmark = null
    data.results[0].expected_outbound = "(default)"
    data.results[0].actual_outbound = "(default)"
    data.results[0].ip = "192.0.2.1"
    data.results[0].policy_rules!.rules[0] = {
      family: "ipv4",
      priority: 32766,
      table: 254,
      fwmark: 0,
      fwmask: 0,
      details_complete: true,
    }
    delete data.fwmark_mask
    html = await render(data, "en")
    expect(html).toContain("IPv4 · priority 32766 · table 254")
    expect(html).toContain("Rule mark: 0x00000000; rule mask: 0x00000000")
    expect(html).toContain(text.policyMarkMatching)
    expect(html).not.toContain(text.policyIncomplete)
  })

  test("labels a truncated candidate snapshot with its own timestamp and bounded count", async () => {
    const data = report()
    data.results[0].policy_rules = policySnapshot({
      total: 65,
      truncated: true,
    })
    for (const language of ["ru", "en"] as const) {
      const text = (language === "ru" ? ruTranslation : enTranslation).overview
        .routingDiagnostics.evidence
      const html = await render(data, language)
      expect(html).toContain("2023-11-14T22:13:22.000Z")
      expect(html).toContain(text.policyTruncated)
      expect(html).toContain(
        language === "ru" ? "Показано 1 из 65" : "Showing 1 of 65"
      )
      expect(html).not.toContain(text.policyEmpty)
    }
  })
})
