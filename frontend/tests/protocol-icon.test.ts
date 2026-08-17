import { describe, expect, test } from "bun:test"

import {
  getProtocolVisualMark,
  normalizeProtocolVisualKind,
} from "../src/components/transports/protocol-visual"

describe("normalizeProtocolVisualKind", () => {
  test.each([
    ["VLESS", "vless"],
    ["hy1", "hysteria1"],
    ["Hysteria2", "hysteria2"],
    ["AWG", "amneziawg"],
    ["AWG/WG", "wireguard_ambiguous"],
    ["WG/AWG", "wireguard_ambiguous"],
    ["AmneziaWG 2", "amneziawg"],
    ["WireGuard", "wireguard"],
    ["IKEv2", "ipsec"],
    ["SOCKS5", "socks"],
    ["HTTPS", "http"],
    ["qWDTT Plus", "wdtt"],
  ] as const)("%s maps to %s", (protocol, expected) => {
    expect(normalizeProtocolVisualKind(protocol)).toBe(expected)
  })

  test("keeps arbitrary outbound JSON safe", () => {
    expect(normalizeProtocolVisualKind("custom experimental")).toBe("unknown")
    expect(normalizeProtocolVisualKind(undefined)).toBe("unknown")
  })

  test.each([
    ["WireGuard", "WG"],
    ["WG", "WG"],
    ["AmneziaWG", "AWG"],
    ["AWG", "AWG"],
    ["AWG/WG", "AWG/WG"],
    ["WG/AWG", "AWG/WG"],
  ] as const)("%s renders the %s mark", (protocol, expected) => {
    expect(getProtocolVisualMark(protocol)).toBe(expected)
  })
})
