import type {
  NdmsTunnelInterface,
  NdmsTunnelKind,
  TransportStatus,
} from "@/api/generated/model"
import {
  getProtocolVisualMark,
  getProtocolVisualMarkForKind,
  normalizeProtocolVisualKind,
  type ProtocolVisualKind,
  type ProtocolVisualMark,
} from "@/components/transports/protocol-visual"

export type InterfaceProtocolEvidence =
  | "managed-transport"
  | "ndms-kind"
  | "firmware-type"
  | "kernel-name"

export interface InterfaceProtocolDisplay {
  readonly kind: ProtocolVisualKind
  readonly label: ProtocolVisualMark
  readonly evidence: InterfaceProtocolEvidence
  readonly exact: boolean
}

const NDMS_KIND_PROTOCOLS = {
  amnezia_wireguard: "amneziawg",
  // Current NDMS inventory reports both vanilla WireGuard and AmneziaWG as
  // the broad `Wireguard` family unless an explicit Amnezia marker is present.
  // Keep that uncertainty visible instead of labelling a real AWG tunnel WG.
  wireguard: "wireguard_ambiguous",
  openvpn: "openvpn",
  ike: "ipsec",
  l2tp: "l2tp",
  sstp: "sstp",
  openconnect: "openconnect",
  http_proxy: "http",
  https_proxy: "http",
  socks5_proxy: "socks",
} as const satisfies Readonly<Record<NdmsTunnelKind, ProtocolVisualKind>>

/**
 * Authoritative protocol display for the typed Keenetic inventory.
 *
 * NDMS can prove AmneziaWG, but on current KeeneticOS a generic `Wireguard`
 * record does not prove vanilla WireGuard. That family stays explicitly
 * ambiguous until the API carries stronger protocol evidence.
 */
export function protocolForNdmsKind(
  kind: NdmsTunnelKind
): InterfaceProtocolDisplay {
  const protocolKind = NDMS_KIND_PROTOCOLS[kind]
  return {
    kind: protocolKind,
    label: getProtocolVisualMarkForKind(protocolKind),
    evidence: "ndms-kind",
    exact: protocolKind !== "wireguard_ambiguous",
  }
}

export function protocolForManagedTransport(
  protocol: string | null | undefined
): InterfaceProtocolDisplay | undefined {
  const kind = normalizeProtocolVisualKind(protocol)
  if (kind === "unknown") {
    return undefined
  }
  return {
    kind,
    label: getProtocolVisualMark(protocol),
    evidence: "managed-transport",
    exact: kind !== "wireguard_ambiguous",
  }
}

export function protocolForFirmwareType(
  firmwareType: string | null | undefined
): InterfaceProtocolDisplay | undefined {
  const normalized = firmwareType?.trim().toLowerCase() ?? ""
  if (!normalized) {
    return undefined
  }

  if (normalized.includes("amnezia")) {
    return display("amneziawg", "firmware-type", true)
  }
  if (normalized.includes("wireguard")) {
    // The legacy names endpoint exposes only the broad firmware type. It is a
    // fallback and cannot override the typed NDMS kind.
    return display("wireguard_ambiguous", "firmware-type", false)
  }
  if (normalized.includes("ike") || normalized.includes("ipsec")) {
    return display("ipsec", "firmware-type", true)
  }
  if (normalized.includes("openvpn")) {
    return display("openvpn", "firmware-type", true)
  }
  if (normalized.includes("l2tp")) {
    return display("l2tp", "firmware-type", true)
  }
  if (normalized.includes("sstp")) {
    return display("sstp", "firmware-type", true)
  }
  if (normalized.includes("openconnect")) {
    return display("openconnect", "firmware-type", true)
  }
  if (normalized.includes("socks")) {
    return display("socks", "firmware-type", true)
  }
  if (normalized.includes("http") || normalized.includes("proxy")) {
    return display("http", "firmware-type", true)
  }
  return undefined
}

export function protocolForKernelName(
  interfaceName: string
): InterfaceProtocolDisplay | undefined {
  const normalized = interfaceName.trim().toLowerCase()
  if (normalized.startsWith("nwg")) {
    return display("wireguard_ambiguous", "kernel-name", false)
  }
  if (normalized.startsWith("wg")) {
    return display("wireguard", "kernel-name", false)
  }
  return undefined
}

/**
 * Build the common protocol index used by routes, dashboard rows and pickers.
 * Typed NDMS evidence intentionally overwrites a legacy native transport row.
 */
export function buildInterfaceProtocolIndex(
  transports: readonly TransportStatus[],
  nativeInterfaces: readonly NdmsTunnelInterface[]
): ReadonlyMap<string, InterfaceProtocolDisplay> {
  const byInterface = new Map<string, InterfaceProtocolDisplay>()

  for (const transport of transports) {
    const interfaceName = nonEmpty(transport.interface)
    const protocol = protocolForManagedTransport(transport.protocol)
    if (interfaceName && protocol) {
      byInterface.set(interfaceName, protocol)
    }
  }

  for (const nativeInterface of nativeInterfaces) {
    const interfaceName = nonEmpty(nativeInterface.kernel_name)
    if (interfaceName) {
      byInterface.set(interfaceName, protocolForNdmsKind(nativeInterface.kind))
    }
  }

  return byInterface
}

function display(
  kind: ProtocolVisualKind,
  evidence: InterfaceProtocolEvidence,
  exact: boolean
): InterfaceProtocolDisplay {
  return {
    kind,
    label: getProtocolVisualMarkForKind(kind),
    evidence,
    exact,
  }
}

function nonEmpty(value: string | null | undefined): string | undefined {
  const normalized = value?.trim()
  return normalized ? normalized : undefined
}
