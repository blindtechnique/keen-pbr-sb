import { describe, expect, test } from "bun:test"

import {
  generateTechnicalId,
  generateTransportIdentity,
  inferTransportProtocol,
  makeTechnicalId,
  normalizeTechnicalId,
} from "../src/lib/technical-id"

describe("technical id generation", () => {
  test("normalizes human-readable Latin and Cyrillic names", () => {
    expect(normalizeTechnicalId("Cloudflare DNS", "dns")).toBe("cloudflare_dns")
    expect(normalizeTechnicalId("Мой резервный DNS", "dns")).toBe(
      "moy_rezervnyy_dns"
    )
  })

  test("keeps the id inside the backend tag contract", () => {
    const id = normalizeTechnicalId("123 очень длинное название DNS", "dns")

    expect(id).toMatch(/^[a-z][a-z0-9_]*$/)
    expect(id.length).toBeLessThanOrEqual(24)
  })

  test("adds a collision suffix without exceeding the limit", () => {
    const first = "cloudflare"
    const second = makeTechnicalId("cloudflare", [first], { prefix: "dns" })
    const third = makeTechnicalId("cloudflare", [first, second], {
      prefix: "dns",
    })

    expect(second).toBe("cloudflare_2")
    expect(third).toBe("cloudflare_3")
  })

  test("retries random auto-ID collisions instead of returning an occupied id", () => {
    const tokens = [
      new Uint8Array([0x11, 0x11, 0x11, 0x11]),
      new Uint8Array([0x22, 0x22, 0x22, 0x22]),
    ]
    let attempt = 0

    const id = generateTechnicalId({
      prefix: "dns_",
      existing: ["dns_11111111"],
      randomBytes: () => tokens[attempt++]!,
    })

    expect(id).toBe("dns_22222222")
    expect(attempt).toBe(2)
  })

  test("transport identity is readable and skips collisions in either namespace", () => {
    const identity = generateTransportIdentity({
      existingTags: ["vless1"],
      existingInterfaces: ["vless2"],
      protocol: "vless",
    })

    expect(identity).toEqual({
      tag: "vless3",
      interfaceName: "vless3",
    })
  })

  test("uses compact readable names for Hysteria2 and a safe generic fallback", () => {
    expect(generateTransportIdentity({ protocol: "hysteria2" })).toEqual({
      tag: "hys1",
      interfaceName: "hys1",
    })
    expect(generateTransportIdentity({ protocol: "unknown" })).toEqual({
      tag: "proxy1",
      interfaceName: "proxy1",
    })
  })

  test("infers transport protocols from links and outbound JSON", () => {
    expect(
      inferTransportProtocol(
        "vless://user@example.net:443",
        '{"type":"hysteria2"}'
      )
    ).toBe("vless")
    expect(inferTransportProtocol(undefined, '{"type":"hysteria2"}')).toBe(
      "hysteria2"
    )
    expect(inferTransportProtocol(undefined, "{not-json")).toBeUndefined()
  })
})
