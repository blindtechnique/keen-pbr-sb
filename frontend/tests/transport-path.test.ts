import { describe, expect, test } from "bun:test"

import { formatTransportPath } from "../src/components/transports/transport-path"

describe("formatTransportPath", () => {
  test("formats every structured path dimension without conflating them", () => {
    expect(
      formatTransportPath({
        protocol: "hysteria2",
        network: "tcp",
        path: {
          wire_transport: "udp",
          framing: "quic",
          payload_networks: ["udp", "tcp", "udp"],
          confidence: "declared",
        },
      })
    ).toEqual({
      confidence: "declared",
      framing: "QUIC",
      payloadNetworks: ["TCP", "UDP"],
      source: "path",
      text: "UDP · QUIC · payload TCP/UDP",
      wireTransport: "UDP",
    })
  })

  test.each(["hysteria", "hysteria2", "tuic"])(
    "does not repeat the legacy TCP guess for %s",
    (protocol) => {
      expect(
        formatTransportPath({
          protocol,
          network: "tcp",
          path: undefined,
        })
      ).toMatchObject({
        confidence: "derived",
        framing: "QUIC",
        source: "legacy",
        text: "UDP · QUIC",
        wireTransport: "UDP",
      })
    }
  )

  test("keeps legacy Naive ambiguous instead of guessing TCP", () => {
    expect(
      formatTransportPath({
        protocol: "naive",
        network: "tcp",
        path: undefined,
      })
    ).toMatchObject({
      confidence: "ambiguous",
      framing: "HTTP/2/QUIC",
      source: "legacy",
      text: "TCP/UDP · HTTP/2/QUIC",
      wireTransport: "TCP/UDP",
    })
  })

  test.each(["WireGuard", "AmneziaWG", "AWG/WG"])(
    "derives the UDP WireGuard path for legacy %s",
    (protocol) => {
      expect(
        formatTransportPath({
          protocol,
          network: "tcp",
          path: undefined,
        })
      ).toMatchObject({
        confidence: "derived",
        framing: "WireGuard",
        source: "legacy",
        text: "UDP · WireGuard",
        wireTransport: "UDP",
      })
    }
  )

  test("uses a meaningful legacy framing but stays silent when unknown", () => {
    expect(
      formatTransportPath({
        protocol: "vless",
        network: "ws",
        path: undefined,
      })?.text
    ).toBe("TCP · WebSocket")
    expect(
      formatTransportPath({
        protocol: "custom",
        network: undefined,
        path: undefined,
      })
    ).toBeNull()
  })

  test("preserves an unknown custom framing name instead of hiding it", () => {
    expect(
      formatTransportPath({
        protocol: "custom",
        network: "future-stream",
      })
    ).toMatchObject({
      source: "legacy",
      confidence: "ambiguous",
      text: "future-stream",
      framing: "future-stream",
    })
  })
})
