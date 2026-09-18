import { describe, expect, test } from "bun:test"
import type {
  Outbound,
  RoutingTestEntry,
  RoutingTestRuleDiagnostic,
  RuntimeOutboundState,
} from "../src/api/generated/model"
import {
  getConfiguredRoutingOutbounds,
  getRoutingOutboundLabel,
  getSelectedRoutingGroupPath,
  isKnownRoutingOutbound,
} from "../src/components/overview/routing-diagnostics-path"

const ip = "149.154.167.99"
const unknown: RoutingTestEntry = {
  ip,
  expected_outbound: "(unknown)",
  actual_outbound: "(unknown)",
  ok: false,
  evaluation: "insufficient_context",
  unknown_conditions: ["inbound_interface"],
  kernel_route: { route_status: "unavailable", interface: "", detail: "" },
}
function rule(
  outbound: string,
  rule_index = 0,
  evaluation:
    | "matched"
    | "not_matched"
    | "insufficient_context" = "insufficient_context"
): RoutingTestRuleDiagnostic {
  return {
    rule_index,
    rule: { outbound, list: ["telegram"] },
    outbound,
    interface_name: "-",
    target_in_lists: true,
    ip_rows: [
      {
        ip,
        in_lists: true,
        in_ipset: true,
        evaluation,
        unknown_conditions: [],
      },
    ],
  }
}
function group(tag: string, child: string): RuntimeOutboundState {
  return {
    tag,
    type: "urltest",
    status: "healthy",
    interfaces: [
      { outbound_tag: child, status: "active", interface_name: "nwg0" },
      { outbound_tag: "backup", status: "available", interface_name: "vless1" },
    ],
  }
}

describe("routing diagnostic names", () => {
  test("a group without a display alias keeps its tag, not the missing-interface marker", () => {
    expect(
      getRoutingOutboundLabel(
        "gr1",
        [{ tag: "gr1", type: "urltest" }],
        (name) => name,
        "-"
      )
    ).toBe("gr1")
    expect(getRoutingOutboundLabel("gr1", [], (name) => name, "-")).toBe("gr1")
  })
  test("uses explicit aliases first and native or managed interface aliases second", () => {
    const alias = () => "techcorner.ignorelist.com"
    const outbound: Outbound = {
      tag: "vpn",
      type: "interface",
      interface: "nwg0",
    }
    expect(
      getRoutingOutboundLabel(
        "vpn",
        [{ ...outbound, display_name: "My VPN" }],
        alias,
        "nwg0"
      )
    ).toBe("My VPN")
    expect(getRoutingOutboundLabel("vpn", [outbound], alias)).toBe(
      "techcorner.ignorelist.com"
    )
    expect(getRoutingOutboundLabel("vpn", [], alias, "nwg0")).toBe(
      "techcorner.ignorelist.com"
    )
    expect(
      getRoutingOutboundLabel("vpn", [outbound], (name) => name, "nwg0")
    ).toBe("vpn")
  })
  test("does not treat a missing path as a name", () => {
    for (const value of [undefined, "", " ", "-", "(unknown)"])
      expect(isKnownRoutingOutbound(value)).toBe(false)
    expect(isKnownRoutingOutbound("(default)")).toBe(true)
  })
})

describe("configured routes remain separate from actual routing evidence", () => {
  test.each(["awg", "gr1"])(
    "keeps %s visible when packet context is missing",
    (tag) => {
      expect(getConfiguredRoutingOutbounds(unknown, ip, [rule(tag)])).toEqual([
        tag,
      ])
    }
  )
  test("uses a known expected route without inventing other matches", () => {
    expect(
      getConfiguredRoutingOutbounds(
        { ...unknown, expected_outbound: "gr1" },
        ip,
        [rule("other")]
      )
    ).toEqual(["gr1"])
    expect(
      getConfiguredRoutingOutbounds(
        { ...unknown, expected_outbound: "(default)" },
        ip,
        []
      )
    ).toEqual(["(default)"])
  })
  test("keeps conditional candidates in priority order and stops at the first certain match", () => {
    const unrelated = rule("irrelevant", 0, "not_matched")
    const disabled = rule("disabled", 1, "matched")
    disabled.rule.enabled = false
    const conditional = rule("gr1", 2)
    const fallback = rule("backup", 3, "matched")
    const lowerPriority = rule("never", 4, "matched")
    const rules = [lowerPriority, conditional, disabled, fallback, unrelated]
    expect(getConfiguredRoutingOutbounds(unknown, ip, rules)).toEqual([
      "gr1",
      "backup",
    ])
    expect(rules[0]).toBe(lowerPriority)
  })
  test("does not turn catalog or firewall membership into a matching rule", () => {
    expect(
      getConfiguredRoutingOutbounds(unknown, ip, [
        rule("gr1", 0, "not_matched"),
      ])
    ).toEqual([])
    expect(getConfiguredRoutingOutbounds(unknown, ip, [])).toEqual([])
  })
  test("deduplicates destinations and includes catch-all rules without lists", () => {
    const catchAll = rule("wan", 2, "matched")
    catchAll.rule = { outbound: "wan" }
    catchAll.target_in_lists = false
    catchAll.ip_rows[0].in_lists = false
    expect(
      getConfiguredRoutingOutbounds(unknown, ip, [
        rule("gr1"),
        rule("gr1", 1),
        catchAll,
      ])
    ).toEqual(["gr1", "wan"])
  })
  test("a domain match still identifies the configured path when DNS returns no IPs", () => {
    const domainRule = rule("gr1")
    domainRule.ip_rows = []
    expect(
      getConfiguredRoutingOutbounds(unknown, "(no IPs resolved)", [domainRule])
    ).toEqual(["gr1"])
    domainRule.target_in_lists = false
    expect(
      getConfiguredRoutingOutbounds(unknown, "(no IPs resolved)", [domainRule])
    ).toEqual([])
  })
})

describe("selected VPN in a group", () => {
  test("uses the live active child, including a backup after failover", () => {
    const state = group("gr1", "awg")
    expect(
      getSelectedRoutingGroupPath("gr1", [state]).map(
        (child) => child.outbound_tag
      )
    ).toEqual(["awg"])
    state.interfaces[0].status = "unavailable"
    state.interfaces[1].status = "active"
    expect(
      getSelectedRoutingGroupPath("gr1", [state]).map(
        (child) => child.outbound_tag
      )
    ).toEqual(["backup"])
  })
  test("does not guess from candidate order or an unavailable runtime response", () => {
    expect(getSelectedRoutingGroupPath("gr1", [])).toEqual([])
    const state = group("gr1", "awg")
    state.interfaces[0].status = "available"
    expect(getSelectedRoutingGroupPath("gr1", [state])).toEqual([])
    state.interfaces.forEach((child) => {
      child.status = "active"
    })
    expect(getSelectedRoutingGroupPath("gr1", [state])).toEqual([])
  })
  test("follows nested groups without looping on inconsistent runtime data", () => {
    const outer = group("gr1", "gr2")
    const inner = group("gr2", "awg")
    expect(
      getSelectedRoutingGroupPath("gr1", [outer, inner]).map(
        (child) => child.outbound_tag
      )
    ).toEqual(["gr2", "awg"])
    inner.interfaces[0].outbound_tag = "gr1"
    expect(
      getSelectedRoutingGroupPath("gr1", [outer, inner]).map(
        (child) => child.outbound_tag
      )
    ).toEqual(["gr2"])
  })
})
