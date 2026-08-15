import { describe, expect, test } from "bun:test"
import { deflateSync } from "node:zlib"

import { parseNativeWireGuardInputPreview } from "@/lib/native-wireguard-vpn-uri-preview"

const PRIVATE_KEY = `${"A".repeat(43)}=`
const PUBLIC_KEY = `${"B".repeat(42)}A=`
const PRESHARED_KEY = `${"C".repeat(42)}A=`

function conf(awg: boolean): string {
  return [
    "[Interface]",
    `PrivateKey = ${PRIVATE_KEY}`,
    "Address = 10.0.0.2/32",
    "DNS = $PRIMARY_DNS, $SECONDARY_DNS",
    ...(awg
      ? [
          "Jc = 4",
          "Jmin = 40",
          "Jmax = 70",
          "S1 = 100",
          "S2 = 200",
          "H1 = 101",
          "H2 = 202",
          "H3 = 303",
          "H4 = 404",
        ]
      : []),
    "[Peer]",
    `PublicKey = ${PUBLIC_KEY}`,
    `PresharedKey = ${PRESHARED_KEY}`,
    "AllowedIPs = 0.0.0.0/0, ::/0",
    "Endpoint = vpn.example:443",
    "PersistentKeepalive = 25",
  ].join("\n")
}

function qCompressUri(value: string): string {
  const input = Buffer.from(value, "utf8")
  const size = Buffer.alloc(4)
  size.writeUInt32BE(input.byteLength)
  return `vpn://${Buffer.concat([size, deflateSync(input, { level: 8 })]).toString("base64url")}`
}

function amneziaUri({
  protocol = "awg",
  config = conf(protocol === "awg"),
}: {
  protocol?: "awg" | "wireguard"
  config?: string
} = {}): string {
  return qCompressUri(
    JSON.stringify({
      dns1: "1.1.1.1",
      dns2: "2606:4700:4700::1111",
      containers: [
        {
          container: `amnezia-${protocol}`,
          [protocol]: {
            last_config: JSON.stringify({ config, mtu: "1420", port: 51820 }),
          },
        },
      ],
    })
  )
}

describe("Amnezia vpn URI redacted preview", () => {
  test("decodes one AWG container without returning key material", async () => {
    const result = await parseNativeWireGuardInputPreview(amneziaUri())
    expect(result).toEqual({
      ok: true,
      preview: {
        kind: "amnezia_wireguard",
        address_count: 1,
        dns_count: 2,
        peer_count: 1,
        allowed_ip_count: 2,
        private_key_present: true,
        preshared_key_peer_count: 1,
        endpoint_host: "vpn.example",
        endpoint_port: 443,
        persistent_keepalive: 25,
        listen_port: 51820,
        mtu: 1420,
        amnezia_parameter_names: [
          "Jc",
          "Jmin",
          "Jmax",
          "S1",
          "S2",
          "H1",
          "H2",
          "H3",
          "H4",
        ],
      },
    })
    const serialized = JSON.stringify(result)
    expect(serialized).not.toContain(PRIVATE_KEY)
    expect(serialized).not.toContain(PUBLIC_KEY)
    expect(serialized).not.toContain(PRESHARED_KEY)
  })

  test("accepts an unambiguous vanilla WireGuard container", async () => {
    const result = await parseNativeWireGuardInputPreview(
      amneziaUri({ protocol: "wireguard" })
    )
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.preview.kind).toBe("wireguard")
  })

  test("fails closed for malformed and ambiguous envelopes", async () => {
    await expect(
      parseNativeWireGuardInputPreview("vpn://%%%%")
    ).resolves.toEqual({
      ok: false,
      code: "invalid_base64",
    })
    await expect(
      parseNativeWireGuardInputPreview("vpn://AAAAAA")
    ).resolves.toEqual({
      ok: false,
      code: "invalid_compression",
    })
    await expect(
      parseNativeWireGuardInputPreview(qCompressUri("not-json"))
    ).resolves.toEqual({ ok: false, code: "invalid_json" })
    await expect(
      parseNativeWireGuardInputPreview(qCompressUri('{"containers":[]}'))
    ).resolves.toEqual({ ok: false, code: "unsupported_json_schema" })

    const lastConfig = { last_config: JSON.stringify({ config: conf(false) }) }
    const ambiguous = qCompressUri(
      JSON.stringify({
        containers: [{ wireguard: lastConfig }, { wireguard: lastConfig }],
      })
    )
    await expect(parseNativeWireGuardInputPreview(ambiguous)).resolves.toEqual({
      ok: false,
      code: "unsupported_json_schema",
    })
  })

  test("rejects a protocol/container mismatch", async () => {
    await expect(
      parseNativeWireGuardInputPreview(
        amneziaUri({ protocol: "wireguard", config: conf(true) })
      )
    ).resolves.toEqual({ ok: false, code: "unsupported_json_schema" })
  })
})
