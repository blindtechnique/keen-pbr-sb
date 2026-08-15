import { describe, expect, test } from "bun:test"

import { parseNativeWireGuardConfigPreview } from "@/lib/native-wireguard-config-preview"

const PRIVATE_KEY = `${"A".repeat(43)}=`
const PUBLIC_KEY = `${"B".repeat(42)}A=`
const PRESHARED_KEY = `${"C".repeat(42)}A=`
const SECOND_PUBLIC_KEY = `${"D".repeat(42)}A=`

function indexedPublicKey(index: number): string {
  return Buffer.alloc(32, index).toString("base64")
}

function peerConfig({
  publicKey = PUBLIC_KEY,
  allowedIps = "0.0.0.0/0",
  endpoint = "vpn.example:51820",
  extra = "",
}: {
  publicKey?: string
  allowedIps?: string
  endpoint?: string | null
  extra?: string
} = {}) {
  return [
    "[Peer]",
    `PublicKey = ${publicKey}`,
    `AllowedIPs = ${allowedIps}`,
    ...(endpoint === null ? [] : [`Endpoint = ${endpoint}`]),
    extra,
  ]
    .filter(Boolean)
    .join("\n")
}

function nativeConfig({
  address = "10.0.0.2/32",
  interfaceExtra = "",
  peers = [peerConfig()],
}: {
  address?: string | null
  interfaceExtra?: string
  peers?: string[]
} = {}) {
  return [
    "[Interface]",
    `PrivateKey = ${PRIVATE_KEY}`,
    ...(address === null ? [] : [`Address = ${address}`]),
    interfaceExtra,
    ...peers,
  ]
    .filter(Boolean)
    .join("\n")
}

describe("redacted native WireGuard config preview", () => {
  test("returns only non-secret WG metadata", () => {
    const result = parseNativeWireGuardConfigPreview(`
[Interface]
PrivateKey = ${PRIVATE_KEY}
Address = 10.0.0.2/32, fd00::2/128
DNS = 1.1.1.1, 2606:4700:4700::1111

[Peer]
PublicKey = ${PUBLIC_KEY}
PresharedKey = ${PRESHARED_KEY}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example:51820
PersistentKeepalive = 25
`)

    expect(result).toEqual({
      ok: true,
      preview: {
        kind: "wireguard",
        address_count: 2,
        dns_count: 2,
        peer_count: 1,
        allowed_ip_count: 2,
        private_key_present: true,
        preshared_key_peer_count: 1,
        endpoint_host: "vpn.example",
        endpoint_port: 51820,
        persistent_keepalive: 25,
        amnezia_parameter_names: [],
      },
    })
    const serialized = JSON.stringify(result)
    expect(serialized).not.toContain(PRIVATE_KEY)
    expect(serialized).not.toContain(PUBLIC_KEY)
    expect(serialized).not.toContain(PRESHARED_KEY)
  })

  test("recognizes AWG parameters by names without returning their values", () => {
    const result = parseNativeWireGuardConfigPreview(`
[Interface]
PrivateKey = ${PRIVATE_KEY}
Address = 10.0.0.2/32
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 123
S2 = 124
S3 = 321
S4 = 322
H1 = 453
H2 = 454
H3 = 455
H4 = 456
ListenPort = 13231

[Peer]
PublicKey = ${PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
Endpoint = awg.example:13231
`)

    expect(result).toEqual({
      ok: true,
      preview: {
        kind: "amnezia_wireguard",
        address_count: 1,
        dns_count: 0,
        peer_count: 1,
        allowed_ip_count: 1,
        private_key_present: true,
        preshared_key_peer_count: 0,
        endpoint_host: "awg.example",
        endpoint_port: 13231,
        listen_port: 13231,
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
          "S3",
          "S4",
        ],
      },
    })
    expect(JSON.stringify(result)).not.toContain("1000")
  })

  test("keeps the preliminary numeric bounds aligned with the backend", () => {
    const result = parseNativeWireGuardConfigPreview(`
[Interface]
PrivateKey = ${PRIVATE_KEY}
Address = 10.0.0.2/32
ListenPort = 0
MTU = 65535

[Peer]
PublicKey = ${PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example:51820
`)

    expect(result.ok).toBe(true)
  })

  test("rejects directives that could execute commands", () => {
    expect(
      parseNativeWireGuardConfigPreview(`
[Interface]
PrivateKey = ${PRIVATE_KEY}
PostUp = send-secrets-somewhere
[Peer]
PublicKey = ${PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
`)
    ).toEqual({ ok: false, code: "dangerous_directive", line: 4 })
  })

  test("does not expose an endpoint when the config has multiple peers", () => {
    const result = parseNativeWireGuardConfigPreview(`
[Interface]
PrivateKey = ${PRIVATE_KEY}
Address = 10.0.0.2/32

[Peer]
PublicKey = ${PUBLIC_KEY}
AllowedIPs = 10.1.0.0/16
Endpoint = first.example:51820

[Peer]
PublicKey = ${SECOND_PUBLIC_KEY}
AllowedIPs = 10.2.0.0/16
Endpoint = second.example:51820
`)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.preview.peer_count).toBe(2)
    expect(result.preview.endpoint_host).toBeUndefined()
    expect(result.preview.endpoint_port).toBeUndefined()
    expect(result.preview.persistent_keepalive).toBeUndefined()
  })

  test("rejects duplicate peer public keys before save", () => {
    expect(
      parseNativeWireGuardConfigPreview(
        nativeConfig({ peers: [peerConfig(), peerConfig()] })
      )
    ).toEqual({ ok: false, code: "duplicate_peer" })
  })

  test("validates key shape without returning the rejected value", () => {
    const invalidKey = "not-a-wireguard-key"
    const result = parseNativeWireGuardConfigPreview(`
[Interface]
PrivateKey = ${invalidKey}
Address = 10.0.0.2/32
[Peer]
PublicKey = ${PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example:51820
`)
    expect(result).toEqual({ ok: false, code: "invalid_field" })
    expect(JSON.stringify(result)).not.toContain(invalidKey)
  })

  test("keeps URI decoding out of the plain .conf parser", () => {
    expect(parseNativeWireGuardConfigPreview("vpn://secret-payload")).toEqual({
      ok: false,
      code: "unsupported_uri",
    })
    expect(
      parseNativeWireGuardConfigPreview("wireguard://not-a-standard-link")
    ).toEqual({ ok: false, code: "unsupported_uri" })
  })

  test("reports only a stable code and safe line number on invalid content", () => {
    const result = parseNativeWireGuardConfigPreview(`
[Interface]
PrivateKey = ${PRIVATE_KEY}
UnknownSecret = value-that-must-not-be-returned
`)
    expect(result).toEqual({ ok: false, code: "unknown_field", line: 4 })
    expect(JSON.stringify(result)).not.toContain("value-that")
  })

  test("requires Address and a valid Endpoint on every peer", () => {
    expect(
      parseNativeWireGuardConfigPreview(nativeConfig({ address: null }))
    ).toEqual({ ok: false, code: "missing_required_field" })
    expect(
      parseNativeWireGuardConfigPreview(
        nativeConfig({ peers: [peerConfig({ endpoint: null })] })
      )
    ).toEqual({ ok: false, code: "missing_required_field" })
    expect(
      parseNativeWireGuardConfigPreview(
        nativeConfig({
          peers: [
            peerConfig(),
            peerConfig({
              publicKey: SECOND_PUBLIC_KEY,
              endpoint: "not an endpoint",
            }),
          ],
        })
      )
    ).toEqual({ ok: false, code: "invalid_field" })
  })

  test("validates CIDR, literal DNS, endpoint and keepalive semantics", () => {
    expect(
      parseNativeWireGuardConfigPreview(
        nativeConfig({ address: "10.0.0.999/32" })
      )
    ).toEqual({ ok: false, code: "invalid_field" })
    expect(
      parseNativeWireGuardConfigPreview(
        nativeConfig({ interfaceExtra: "DNS = resolver.example" })
      )
    ).toEqual({ ok: false, code: "invalid_field" })
    expect(
      parseNativeWireGuardConfigPreview(
        nativeConfig({
          peers: [peerConfig({ allowedIps: "10.0.0.0/8," })],
        })
      )
    ).toEqual({ ok: false, code: "invalid_field" })
    expect(
      parseNativeWireGuardConfigPreview(
        nativeConfig({
          peers: [peerConfig({ extra: "PersistentKeepalive = 65536" })],
        })
      )
    ).toEqual({ ok: false, code: "invalid_field" })

    const ipv6 = parseNativeWireGuardConfigPreview(
      nativeConfig({
        address: "2001:db8::2/128",
        interfaceExtra: "DNS = 2001:4860:4860::8888",
        peers: [
          peerConfig({
            allowedIps: "::/0",
            endpoint: "[2001:db8::1]:443",
          }),
        ],
      })
    )
    expect(ipv6.ok).toBe(true)
    if (ipv6.ok) {
      expect(ipv6.preview.endpoint_host).toBe("2001:db8::1")
      expect(ipv6.preview.endpoint_port).toBe(443)
    }
  })

  test("matches the authoritative list, peer, line and total bounds", () => {
    const addresses = Array.from(
      { length: 17 },
      (_, index) => `10.0.0.${index + 1}/32`
    ).join(",")
    expect(
      parseNativeWireGuardConfigPreview(nativeConfig({ address: addresses }))
    ).toEqual({ ok: false, code: "limit_exceeded" })

    const dns = Array.from(
      { length: 9 },
      (_, index) => `192.0.2.${index + 1}`
    ).join(",")
    expect(
      parseNativeWireGuardConfigPreview(
        nativeConfig({ interfaceExtra: `DNS = ${dns}` })
      )
    ).toEqual({ ok: false, code: "limit_exceeded" })

    const allowed = Array.from(
      { length: 129 },
      (_, index) => `10.${Math.floor(index / 256)}.${index % 256}.0/24`
    ).join(",")
    expect(
      parseNativeWireGuardConfigPreview(
        nativeConfig({ peers: [peerConfig({ allowedIps: allowed })] })
      )
    ).toEqual({ ok: false, code: "limit_exceeded" })

    const block = Array.from(
      { length: 128 },
      (_, index) => `10.0.${index}.0/24`
    ).join(",")
    const fivePeers = Array.from({ length: 5 }, (_, index) =>
      peerConfig({
        publicKey: indexedPublicKey(index),
        allowedIps: block,
        endpoint: `peer-${index}.example:51820`,
      })
    )
    expect(
      parseNativeWireGuardConfigPreview(nativeConfig({ peers: fivePeers }))
    ).toEqual({ ok: false, code: "limit_exceeded" })

    const tooManyPeers = Array.from({ length: 65 }, (_, index) =>
      peerConfig({
        publicKey: indexedPublicKey(index),
        endpoint: `peer-${index}.example:51820`,
      })
    )
    const peerLimit = parseNativeWireGuardConfigPreview(
      nativeConfig({ peers: tooManyPeers })
    )
    expect(peerLimit.ok).toBe(false)
    if (!peerLimit.ok) expect(peerLimit.code).toBe("limit_exceeded")

    const longLine = `# ${"x".repeat(8_191)}`
    const lineLimit = parseNativeWireGuardConfigPreview(
      `${nativeConfig()}\n${longLine}`
    )
    expect(lineLimit.ok).toBe(false)
    if (!lineLimit.ok) expect(lineLimit.code).toBe("limit_exceeded")

    const tooManyLines = nativeConfig().replace(
      "[Peer]",
      `${"\n".repeat(4_096)}[Peer]`
    )
    expect(parseNativeWireGuardConfigPreview(tooManyLines)).toEqual({
      ok: false,
      code: "limit_exceeded",
    })
  })

  test("requires Interface before Peer and keeps inline-comment parity", () => {
    expect(
      parseNativeWireGuardConfigPreview(
        `${peerConfig()}\n${nativeConfig({ peers: [] })}`
      )
    ).toEqual({ ok: false, code: "malformed_line", line: 1 })

    const result = parseNativeWireGuardConfigPreview(`
[Interface] ; exported profile
PrivateKey = ${PRIVATE_KEY} # redacted locally
Address = 10.0.0.2/32 ; client address
DNS = 1.1.1.1 # resolver
[Peer] # primary
PublicKey = ${PUBLIC_KEY} ; server key
AllowedIPs = 0.0.0.0/0, ::/0 # routes
Endpoint = vpn.example:443 ; WAN endpoint
PersistentKeepalive = 25 # seconds
`)
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.preview.allowed_ip_count).toBe(2)
      expect(result.preview.endpoint_host).toBe("vpn.example")
      expect(result.preview.persistent_keepalive).toBe(25)
    }
  })

  test("enforces complete AWG tuples, ranges and S3/S4 pairing", () => {
    expect(
      parseNativeWireGuardConfigPreview(
        nativeConfig({ interfaceExtra: "Jc = 5" })
      )
    ).toEqual({ ok: false, code: "missing_required_field" })

    const awg = [
      "Jc = 5",
      "Jmin = 50",
      "Jmax = 100",
      "S1 = 123",
      "S2 = 124",
      "H1 = 1",
      "H2 = 2",
      "H3 = 3",
      "H4 = 4",
    ]
    expect(
      parseNativeWireGuardConfigPreview(
        nativeConfig({
          interfaceExtra: [...awg, "S3 = 1"].join("\n"),
        })
      )
    ).toEqual({ ok: false, code: "missing_required_field" })
    expect(
      parseNativeWireGuardConfigPreview(
        nativeConfig({
          interfaceExtra: awg
            .map((line) => (line.startsWith("Jmax") ? "Jmax = 50" : line))
            .join("\n"),
        })
      )
    ).toEqual({ ok: false, code: "invalid_field" })
    expect(
      parseNativeWireGuardConfigPreview(
        nativeConfig({
          interfaceExtra: awg
            .map((line) =>
              line.startsWith("H1") ? `H1 = ${"x".repeat(257)}` : line
            )
            .join("\n"),
        })
      )
    ).toEqual({ ok: false, code: "invalid_field" })
  })

  test("keeps structural error codes aligned without echoing field values", () => {
    const cases = [
      {
        input: nativeConfig({ interfaceExtra: "PostUp =" }),
        code: "dangerous_directive",
      },
      {
        input: nativeConfig({ interfaceExtra: "UnknownSecret =" }),
        code: "unknown_field",
      },
      {
        input: nativeConfig({ interfaceExtra: "Bad.Name = value" }),
        code: "malformed_line",
      },
      {
        input: nativeConfig({
          peers: [
            peerConfig({
              extra: `PresharedKey = ${PRESHARED_KEY}\nPresharedKey =`,
            }),
          ],
        }),
        code: "duplicate_field",
      },
    ] as const
    for (const entry of cases) {
      const result = parseNativeWireGuardConfigPreview(entry.input)
      expect(result.ok).toBe(false)
      if (!result.ok) expect(result.code).toBe(entry.code)
      expect(JSON.stringify(result)).not.toContain(PRESHARED_KEY)
    }
  })
})
