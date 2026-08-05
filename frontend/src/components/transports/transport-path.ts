import type {
  TransportPathPayloadNetworksItem,
  TransportPathConfidence,
  TransportStatus,
} from "@/api/generated/model"
import {
  normalizeProtocolVisualKind,
  type ProtocolVisualKind,
} from "@/components/transports/protocol-visual"

type TransportPathStatus = Pick<
  TransportStatus,
  "network" | "path" | "protocol"
>

export type TransportPathDisplay = {
  confidence: TransportPathConfidence
  framing: string | null
  payloadNetworks: string[]
  source: "path" | "legacy"
  text: string
  wireTransport: string | null
}

const wireTransportLabels = {
  tcp: "TCP",
  udp: "UDP",
  tcp_udp: "TCP/UDP",
  unknown: null,
} as const

const framingLabels = {
  raw: null,
  websocket: "WebSocket",
  http: "HTTP",
  http2: "HTTP/2",
  grpc: "gRPC",
  http_upgrade: "HTTP Upgrade",
  quic: "QUIC",
  wireguard: "WireGuard",
  unknown: null,
} as const

const legacyNetworkPaths: Record<
  string,
  Pick<TransportPathDisplay, "framing" | "wireTransport">
> = {
  tcp: { wireTransport: "TCP", framing: null },
  udp: { wireTransport: "UDP", framing: null },
  tcpudp: { wireTransport: "TCP/UDP", framing: null },
  ws: { wireTransport: "TCP", framing: "WebSocket" },
  websocket: { wireTransport: "TCP", framing: "WebSocket" },
  grpc: { wireTransport: "TCP", framing: "gRPC" },
  http: { wireTransport: "TCP", framing: "HTTP" },
  h2: { wireTransport: "TCP", framing: "HTTP/2" },
  http2: { wireTransport: "TCP", framing: "HTTP/2" },
  httpupgrade: { wireTransport: "TCP", framing: "HTTP Upgrade" },
  xhttp: { wireTransport: "TCP", framing: "XHTTP" },
  quic: { wireTransport: "UDP", framing: "QUIC" },
  wireguard: { wireTransport: "UDP", framing: "WireGuard" },
}

/**
 * Formats the structured path returned by current transport-manager versions.
 * Legacy statuses are handled conservatively: protocol semantics are preferred
 * over the old mixed `network` field where that field was historically wrong.
 */
export function formatTransportPath(
  status: TransportPathStatus
): TransportPathDisplay | null {
  const structured = formatStructuredPath(status)
  if (structured) {
    return structured
  }

  return formatLegacyPath(status)
}

function formatStructuredPath(
  status: TransportPathStatus
): TransportPathDisplay | null {
  const path = status.path
  if (!path) {
    return null
  }

  const wireTransport = wireTransportLabels[path.wire_transport]
  const framing = framingLabels[path.framing]
  const payloadNetworks = normalizePayloadNetworks(path.payload_networks)

  return createDisplay({
    confidence: path.confidence,
    framing,
    payloadNetworks,
    source: "path",
    wireTransport,
  })
}

function formatLegacyPath(
  status: TransportPathStatus
): TransportPathDisplay | null {
  const protocolKind = normalizeProtocolVisualKind(status.protocol)
  const semanticPath = getLegacyProtocolPath(protocolKind)
  if (semanticPath) {
    return createDisplay({
      ...semanticPath,
      payloadNetworks: [],
      source: "legacy",
    })
  }

  const network = normalizeLegacyToken(status.network)
  const legacyNetworkPath = network ? legacyNetworkPaths[network] : undefined
  if (!network) {
    return null
  }

  return createDisplay({
    ...(legacyNetworkPath ?? {
      wireTransport: null,
      framing: status.network?.trim() || network,
    }),
    confidence: "ambiguous",
    payloadNetworks: [],
    source: "legacy",
  })
}

function getLegacyProtocolPath(
  kind: ProtocolVisualKind
):
  | Pick<TransportPathDisplay, "confidence" | "framing" | "wireTransport">
  | undefined {
  switch (kind) {
    case "hysteria1":
    case "hysteria2":
    case "tuic":
      return {
        confidence: "derived",
        wireTransport: "UDP",
        framing: "QUIC",
      }
    case "naive":
      return {
        confidence: "ambiguous",
        wireTransport: "TCP/UDP",
        framing: "HTTP/2/QUIC",
      }
    case "wireguard":
    case "amneziawg":
    case "wireguard_ambiguous":
      return {
        confidence: "derived",
        wireTransport: "UDP",
        framing: "WireGuard",
      }
    default:
      return undefined
  }
}

function createDisplay({
  confidence,
  framing,
  payloadNetworks,
  source,
  wireTransport,
}: Omit<TransportPathDisplay, "text">): TransportPathDisplay | null {
  const parts = [wireTransport, framing].filter((part): part is string =>
    Boolean(part)
  )
  if (payloadNetworks.length > 0) {
    parts.push(`payload ${payloadNetworks.join("/")}`)
  }
  if (parts.length === 0) {
    return null
  }

  return {
    confidence,
    framing,
    payloadNetworks,
    source,
    text: parts.join(" · "),
    wireTransport,
  }
}

function normalizePayloadNetworks(
  networks: TransportPathPayloadNetworksItem[] | undefined
): string[] {
  if (!networks) {
    return []
  }

  const values = new Set(networks)
  return ["tcp", "udp"]
    .filter((network) =>
      values.has(network as TransportPathPayloadNetworksItem)
    )
    .map((network) => network.toUpperCase())
}

function normalizeLegacyToken(value: string | null | undefined) {
  return value
    ?.trim()
    .toLowerCase()
    .replaceAll(/[\s_./-]+/g, "")
}

/**
 * Короткая пилюля «как это идёт по проводу»: UDP · QUIC, TCP · Reality.
 *
 * В шапке карточки раньше стояло техническое имя интерфейса — hy1, nwg3,
 * kpbr85f462c5. Человеку оно не говорит ничего: имя выдаёт ядро, а вопрос у
 * него другой — что это за туннель и переживёт ли он блокировку. Тип шифрования
 * на этот вопрос отвечает, техническое имя нет; оно уехало в раскрытую часть,
 * где ему и место.
 *
 * TLS показывается только там, где он что-то добавляет. У QUIC он всегда, и
 * писать его — шум; Reality пишем всегда, потому что это и есть ответ.
 */
export function describeTransportWire(
  status: Pick<TransportStatus, "network" | "path" | "protocol" | "security">
): string | null {
  const path = formatTransportPath(status)
  if (!path) {
    return null
  }

  const parts = [path.wireTransport, path.framing].filter(
    (part): part is string => Boolean(part)
  )
  const security = securityLabel(status.security, path.framing)
  if (security) {
    parts.push(security)
  }

  return parts.length > 0 ? parts.join(" · ") : null
}

function securityLabel(
  security: TransportStatus["security"],
  framing: string | null
): string | null {
  if (security === "reality") return "Reality"
  // QUIC без TLS не бывает, WireGuard шифруется сам — подпись «TLS» рядом с
  // ними ничего не уточняет.
  if (framing === "QUIC" || framing === "WireGuard") return null
  if (security === "tls") return "TLS"
  return null
}
