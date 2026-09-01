import { describe, expect, test } from "bun:test"

import type { Dependency } from "@/lib/dependencies"
import { summarizeNativeDeleteDependencies } from "@/components/transports/native-interface-delete-guard"

describe("native interface delete dependency warning", () => {
  test("keeps the first three unique user-facing dependency names", () => {
    const dependencies: Dependency[] = [
      { kind: "failoverGroup", label: "group-awg" },
      { kind: "routingRule", label: "rule-b2ip" },
      { kind: "failoverGroup", label: "group-awg" },
      { kind: "list", label: "list-blocked" },
      { kind: "dnsServer", label: "dns-secure" },
    ]

    expect(summarizeNativeDeleteDependencies(dependencies)).toEqual({
      labels: ["group-awg", "rule-b2ip", "list-blocked"],
      remainingCount: 1,
    })
  })

  test("ignores blank dependency labels", () => {
    expect(
      summarizeNativeDeleteDependencies([
        { kind: "failoverGroup", label: "  " },
      ])
    ).toEqual({ labels: [], remainingCount: 0 })
  })
})
