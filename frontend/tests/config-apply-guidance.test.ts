import { describe, expect, test } from "bun:test"

import type { ConfigObject } from "../src/api/generated/model/configObject"
import {
  compareConfigEffects,
  configFailureDestination,
  confirmedConfigApply,
  summarizeConfigEffects,
} from "../src/lib/config-apply-guidance"

const initial: ConfigObject = {
  outbounds: [
    { tag: "vpn", type: "interface", interface: "nwg0" },
    { tag: "backup", type: "interface", interface: "nwg1" },
    {
      tag: "group",
      type: "urltest",
      url: "https://probe.invalid/",
      outbound_groups: [{ weight: 1, outbounds: ["vpn", "backup"] }],
    },
  ],
  lists: {
    sites: { domains: ["one.example", "two.example"] },
    other: { ip_cidrs: ["192.0.2.0/24"] },
  },
  route: { rules: [{ list: ["sites"], outbound: "group" }] },
  dns: {
    servers: [{ tag: "primary", address: "192.0.2.53" }],
    fallback: ["primary"],
  },
}

function changed(edit: (config: ConfigObject) => void) {
  const config = structuredClone(initial)
  edit(config)
  return compareConfigEffects(
    summarizeConfigEffects(initial),
    summarizeConfigEffects(config)
  )
}

describe("config apply effects", () => {
  test("Firefox automatic DoH canary is a DNS-only effect with enabled legacy defaults", () => {
    const baseline = summarizeConfigEffects(initial)
    for (const value of [undefined, null, true]) {
      const config = structuredClone(initial)
      config.dns!.firefox_doh_canary = value
      expect(
        compareConfigEffects(baseline, summarizeConfigEffects(config))
      ).toBe("none")
    }
    const config = structuredClone(initial)
    config.dns!.firefox_doh_canary = false
    expect(compareConfigEffects(baseline, summarizeConfigEffects(config))).toBe(
      "dns"
    )
    config.dns!.firefox_doh_canary = true
    expect(compareConfigEffects(baseline, summarizeConfigEffects(config))).toBe(
      "none"
    )
  })
  test("returns unknown without an observed active baseline or candidate", () => {
    const summary = summarizeConfigEffects(initial)
    expect(compareConfigEffects(undefined, summary)).toBe("unknown")
    expect(compareConfigEffects(summary, undefined)).toBe("unknown")
    expect(compareConfigEffects(undefined, undefined)).toBe("unknown")
  })

  test("restoring the original routing values clears the recommendation", () => {
    const baseline = summarizeConfigEffects(initial)
    const candidate = structuredClone(initial)
    candidate.route!.rules![0].outbound = "backup"
    expect(
      compareConfigEffects(baseline, summarizeConfigEffects(candidate))
    ).toBe("routing")
    candidate.route!.rules![0].outbound = "group"
    expect(
      compareConfigEffects(baseline, summarizeConfigEffects(candidate))
    ).toBe("none")
  })

  test("ignores presentation metadata, logs, UI preferences and diagnostic probes", () => {
    expect(
      changed((config) => {
        Object.assign(config, {
          logging: { retention_days: 7, max_size_bytes: 1048576 },
          log: { level: "debug" },
        })
        config.api = { enabled: true, listen: "127.0.0.1:12121" }
        config.daemon = { pid_file: "/new/pid", cache_dir: "/new/cache" }
        config.ui_preferences = {}
        config.tunnel_probe = { enabled: true, interval_ms: 60000 }
        Object.assign(config.outbounds![0], {
          display_name: "Friendly alias",
          country: "DE",
          country_auto: true,
          label: "Label",
        })
        Object.assign(config.outbounds![2], {
          url: "https://new-probe.invalid/",
          interval_ms: 30000,
          probe_timeout_ms: 1000,
        })
        config.lists!.sites.display_name = "Sites"
        config.route!.rules![0].display_name = "Rule"
        config.route!.rules![0].id = "rule_id"
        config.dns!.servers![0].display_name = "DNS alias"
        config.dns!.dns_test_server = { listen: "192.0.2.54:5353" }
      })
    ).toBe("none")
  })

  test("normalizes omitted objects and empty collections", () => {
    expect(
      compareConfigEffects(
        summarizeConfigEffects({}),
        summarizeConfigEffects({
          outbounds: [],
          lists: {},
          route: {
            rules: [],
            inbound_interfaces: [],
            internal_vpn_servers: [],
            internal_vpn_services: [],
          },
          dns: {
            servers: [],
            rules: [],
            fallback: [],
            client_dns_enforcement: { enabled: false, block_dot: true },
          },
          daemon: {},
          fwmark: {},
          iproute: {},
        })
      )
    ).toBe("none")
  })

  test("normalizes map key order, set membership order and explicit rule defaults", () => {
    expect(
      changed((config) => {
        config.lists = {
          other: { ip_cidrs: ["192.0.2.0/24"] },
          sites: { domains: ["two.example", "one.example", "one.example"] },
        }
        config.route!.rules![0].enabled = true
        config.route!.rules![0].failure_policy = "inherit"
        config.outbounds![2].selection_mode = "latency"
        config.outbounds![2].conntrack_on_switch = "delete_on_failure"
      })
    ).toBe("none")
  })

  test("detects route, interface, gateway and native ingress participation changes", () => {
    const edits: ((config: ConfigObject) => void)[] = [
      (config) => {
        config.route!.rules![0].outbound = "backup"
      },
      (config) => {
        config.route!.rules![0].enabled = false
      },
      (config) => {
        config.outbounds![0].interface = "nwg2"
      },
      (config) => {
        config.outbounds![0].gateway = "192.0.2.1"
      },
      (config) => {
        config.route!.inbound_interfaces = ["br0"]
      },
      (config) => {
        config.route!.internal_vpn_services = [
          { service_id: "OpenConnect0", process_clients: false },
        ]
      },
      (config) => {
        config.daemon = { ipv6_enabled: false }
      },
      (config) => {
        config.fwmark = { start: "0x10000" }
      },
    ]
    for (const edit of edits) expect(changed(edit)).toBe("routing")
  })

  test("preserves route precedence and group member and group precedence", () => {
    const baseline = structuredClone(initial)
    baseline.route!.rules!.push({ list: ["other"], outbound: "backup" })
    const candidate = structuredClone(baseline)
    candidate.route!.rules!.reverse()
    expect(
      compareConfigEffects(
        summarizeConfigEffects(baseline),
        summarizeConfigEffects(candidate)
      )
    ).toBe("routing")
    expect(
      changed((config) => {
        config.outbounds![2].outbound_groups![0].outbounds.reverse()
      })
    ).toBe("routing")
    baseline.outbounds![2].outbound_groups = [
      { weight: 1, outbounds: ["vpn"] },
      { weight: 1, outbounds: ["backup"] },
    ]
    const groupsChanged = structuredClone(baseline)
    groupsChanged.outbounds![2].outbound_groups!.reverse()
    expect(
      compareConfigEffects(
        summarizeConfigEffects(baseline),
        summarizeConfigEffects(groupsChanged)
      )
    ).toBe("routing")
  })

  test("includes selection policy and recovery thresholds but not probe presentation", () => {
    expect(
      changed((config) => {
        config.outbounds![2].selection_mode = "priority"
      })
    ).toBe("routing")
    expect(
      changed((config) => {
        config.outbounds![2].retry = { attempts: 2 }
      })
    ).toBe("routing")
    expect(
      changed((config) => {
        config.outbounds![2].circuit_breaker = { failure_threshold: 2 }
      })
    ).toBe("routing")
  })

  test("detects inline and remote list source changes", () => {
    expect(
      changed((config) => {
        config.lists!.sites.domains!.push("new.example")
      })
    ).toBe("routing")
    expect(
      changed((config) => {
        config.lists!.other.ip_cidrs!.push("198.51.100.0/24")
      })
    ).toBe("routing")
    expect(
      changed((config) => {
        config.lists!.sites.url = "https://source.invalid/list"
      })
    ).toBe("routing")
    expect(
      changed((config) => {
        config.lists!.sites.file = "/opt/etc/lists/sites.txt"
      })
    ).toBe("routing")
  })

  test("detects DNS upstream, detour, direct bindings and enforcement changes", () => {
    const edits: ((config: ConfigObject) => void)[] = [
      (config) => {
        config.dns!.servers![0].address = "192.0.2.54"
      },
      (config) => {
        config.dns!.servers![0].detour = "vpn"
      },
      (config) => {
        config.dns!.servers![0].domains = ["example.com"]
      },
      (config) => {
        config.dns!.fallback = []
      },
      (config) => {
        config.dns!.client_dns_enforcement = { enabled: true }
      },
      (config) => {
        config.dns!.system_resolver = { address: "127.0.0.1:5353" }
      },
      (config) => {
        config.dns!.rules = [{ list: ["sites"], server: "primary" }]
      },
    ]
    for (const edit of edits) expect(changed(edit)).toBe("dns")
  })

  test("list contents used by DNS rules affect both routing and DNS", () => {
    const baseline = structuredClone(initial)
    baseline.dns!.rules = [{ list: ["sites"], server: "primary" }]
    const candidate = structuredClone(baseline)
    candidate.lists!.sites.domains!.push("new.example")
    expect(
      compareConfigEffects(
        summarizeConfigEffects(baseline),
        summarizeConfigEffects(candidate)
      )
    ).toBe("routing-and-dns")
  })

  test("disabled rules and their cosmetic edits do not create guidance", () => {
    expect(
      changed((config) => {
        config.route!.rules!.push({ enabled: false, outbound: "vpn" })
        config.dns!.rules = [
          { enabled: false, list: ["sites"], server: "primary" },
        ]
      })
    ).toBe("none")
  })

  test("summary retains no source tokens, URLs, hosts or configuration objects", () => {
    const config = structuredClone(initial)
    config.lists!.sites.url =
      "https://user:SECRET@example.invalid/list?token=PRIVATE"
    const summary = summarizeConfigEffects(config)
    expect(Object.keys(summary).sort()).toEqual(["dns", "routing"])
    expect(summary.routing).toMatch(/^[0-9a-f]{16}$/)
    expect(summary.dns).toMatch(/^[0-9a-f]{16}$/)
    for (const secret of [
      "SECRET",
      "PRIVATE",
      "example.invalid",
      "https:",
      "one.example",
    ]) {
      expect(JSON.stringify(summary)).not.toContain(secret)
    }
    expect(config.lists!.sites.url).toContain("SECRET")
  })
})

describe("confirmed config apply", () => {
  const completed = {
    status: 200,
    data: { status: "ok", saved: true, applied: true, rolled_back: false },
  }

  test("accepts the actual completed config-save response", () => {
    expect(confirmedConfigApply(completed)).toBe(true)
  })

  test("does not infer apply from a fieldless response, HTTP success or lifecycle text", () => {
    for (const response of [
      undefined,
      null,
      {},
      { status: 200 },
      {
        status: 200,
        data: { status: "ok", message: "Config saved and applied" },
      },
      { status: 200, data: { status: "ok", applied: true } },
      { status: 200, data: { status: "ok", saved: true } },
      { status: 202, data: completed.data },
      { status: 500, data: completed.data },
      { status: 200, data: { ...completed.data, status: "pending" } },
    ])
      expect(confirmedConfigApply(response)).toBe(false)
  })

  test("rejects rollback, failed apply and required recovery", () => {
    for (const override of [
      { saved: false },
      { applied: false },
      { rolled_back: true },
      { recovery_required: true },
    ]) {
      expect(
        confirmedConfigApply({
          ...completed,
          data: { ...completed.data, ...override },
        })
      ).toBe(false)
    }
  })
})

describe("config failure destinations", () => {
  test("does not send validation, permission or draft conflicts to diagnostics", () => {
    for (const code of [
      "unauthenticated",
      "reauthentication_required",
      "forbidden",
      "busy",
      "draft_pending",
      "draft_changed",
      "validation",
    ]) {
      expect(configFailureDestination({ details: { code } })).toBeNull()
    }
  })

  test("points connection and service errors to service diagnostics", () => {
    expect(configFailureDestination({ details: { code: "network" } })).toBe(
      "service"
    )
    expect(
      configFailureDestination({ details: { code: "service_unavailable" } })
    ).toBe("service")
    expect(configFailureDestination(new Error("Failed to fetch"))).toBe(
      "service"
    )
  })

  test("points runtime apply or recovery failures to routing diagnostics", () => {
    expect(
      configFailureDestination({ details: { recovery_required: true } })
    ).toBe("routing")
    expect(
      configFailureDestination({
        details: {
          code: "rolled_back",
          saved: false,
          applied: false,
          file_rolled_back: true,
          rolled_back: true,
          runtime_unchanged: false,
          recovery_required: false,
        },
      })
    ).toBe("routing")
    expect(
      configFailureDestination(new Error("Unrecognized apply failure"))
    ).toBe("routing")
  })
})
