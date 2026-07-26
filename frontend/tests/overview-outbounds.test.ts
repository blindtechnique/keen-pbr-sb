import { describe, expect, test } from "bun:test"

import { outboundTrafficBucket } from "@/components/overview/outbound-state-model"

describe("dashboard outbound traffic classification", () => {
  test("does not call a tunnel-backed routing table direct", () => {
    expect(outboundTrafficBucket({ type: "table" }, "AWG")).toBe("tunnels")
    expect(outboundTrafficBucket({ type: "table" }, "")).toBe("direct")
  })

  test("classifies interface routes by proven protocol", () => {
    expect(outboundTrafficBucket({ type: "interface" }, "VLESS")).toBe(
      "tunnels"
    )
    expect(outboundTrafficBucket({ type: "interface" }, "")).toBe("direct")
  })

  test("keeps blackhole separate from route transport", () => {
    expect(outboundTrafficBucket({ type: "blackhole" }, "VLESS")).toBe(
      "blocked"
    )
  })
})
