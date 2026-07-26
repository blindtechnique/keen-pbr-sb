import { describe, expect, test } from "bun:test"

import {
  generateTechnicalId,
  generateTransportIdentity,
  makeTechnicalId,
  normalizeTechnicalId,
} from "../src/lib/technical-id"

describe("technical id generation", () => {
  test("normalizes human-readable Latin and Cyrillic names", () => {
    expect(normalizeTechnicalId("Cloudflare DNS", "dns")).toBe(
      "cloudflare_dns"
    )
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

  test("transport identity retries when either half of the generated pair collides", () => {
    const tokens = [
      new Uint8Array([0x11, 0x11, 0x11, 0x11]),
      new Uint8Array([0x22, 0x22, 0x22, 0x22]),
      new Uint8Array([0x33, 0x33, 0x33, 0x33]),
    ]
    let attempt = 0

    const identity = generateTransportIdentity({
      existingTags: ["tr_11111111"],
      existingInterfaces: ["kpbr22222222"],
      randomBytes: () => tokens[attempt++]!,
    })

    expect(identity).toEqual({
      tag: "tr_33333333",
      interfaceName: "kpbr33333333",
    })
    expect(attempt).toBe(3)
  })
})
