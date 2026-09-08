import { describe, expect, test } from "bun:test"
import { buildChoiceDisplayNames } from "../src/lib/choice-display-names"

describe("ordinary choice captions", () => {
  test("keeps distinct aliases and identifiable aliasless fallbacks without changing inputs", () => {
    const choices = [
      { value: "vpn_1", label: "Домашний AWG" },
      { value: "nwg2", label: "  " },
    ]
    const before = JSON.stringify(choices)
    expect([...buildChoiceDisplayNames(choices)]).toEqual([
      ["vpn_1", "Домашний AWG"],
      ["nwg2", "nwg2"],
    ])
    expect(JSON.stringify(choices)).toBe(before)
  })
  test("disambiguates identical names by stable values rather than display or filter order", () => {
    const choices = [
      { value: "second", label: "VPN" },
      { value: "first", label: "VPN" },
    ]
    const names = buildChoiceDisplayNames(choices)
    expect(names.get("first")).toBe("VPN · 1")
    expect(names.get("second")).toBe("VPN · 2")
    expect(buildChoiceDisplayNames([...choices].reverse()).get("first")).toBe(
      names.get("first")
    )
    expect(["second"].map((value) => names.get(value))).toEqual(["VPN · 2"])
    expect([...names.keys()]).toEqual(["second", "first"])
  })
  test("case and Unicode-equivalent captions are distinguishable, with original spelling retained", () => {
    const names = buildChoiceDisplayNames([
      { value: "a", label: "VPN" },
      { value: "b", label: "vpn" },
      { value: "c", label: "ＶＰＮ" },
    ])
    expect([...names.values()]).toEqual(["VPN · 1", "vpn · 2", "ＶＰＮ · 3"])
  })
  test("numbered captions cannot collide with a real alias or duplicate inventory entry", () => {
    const names = buildChoiceDisplayNames([
      { value: "a", label: "VPN" },
      { value: "b", label: "VPN" },
      { value: "c", label: "VPN · 1" },
      { value: "a", label: "VPN" },
    ])
    expect(names.size).toBe(3)
    expect(names.get("a")).toBe("VPN · 2")
    expect(names.get("b")).toBe("VPN · 3")
    expect(names.get("c")).toBe("VPN · 1")
    expect(new Set(names.values()).size).toBe(names.size)
  })
  test("empty inventories stay empty", () => {
    expect(buildChoiceDisplayNames([]).size).toBe(0)
  })
})
