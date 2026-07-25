import type {
  NdmsTunnelInterface,
  NdmsTunnelKind,
  RuntimeInterfaceInventoryEntry,
  TransportStatus,
} from "@/api/generated/model"

/**
 * The generated contract intentionally distinguishes the required logical
 * identifier reported by KeeneticOS from the optional Linux device name.
 */
export type KeeneticNativeInterface = Readonly<NdmsTunnelInterface>

export const NATIVE_TUNNEL_KIND_LABELS = {
  amnezia_wireguard: "AmneziaWG",
  // KeeneticOS exposes both vanilla WireGuard and AmneziaWG through the same
  // Wireguard/nwg family on current firmware. Do not claim a variant that the
  // typed RCI response did not prove.
  wireguard: "AWG/WG",
  openvpn: "OpenVPN",
  ike: "IPsec / IKE",
  l2tp: "L2TP",
  sstp: "SSTP",
  openconnect: "OpenConnect",
  http_proxy: "HTTP proxy",
  https_proxy: "HTTPS proxy",
  socks5_proxy: "SOCKS5 proxy",
} as const satisfies Readonly<Record<NdmsTunnelKind, string>>

export interface NativeInterfaceModel {
  readonly source: KeeneticNativeInterface
  readonly id: string
  readonly label: string
  readonly logicalName: string
  readonly kernelName?: string
  readonly protocol: string
  readonly runtime?: RuntimeInterfaceInventoryEntry
  readonly live: boolean
  readonly connected?: boolean
  readonly link?: boolean
}

export type NativeRouteBlockReason =
  | "not-client"
  | "unresolved"
  | "not-live"
  | "already-bound"
  | "no-config"

export type NativeRouteActionability =
  | {
      readonly enabled: true
      readonly interfaceName: string
    }
  | {
      readonly enabled: false
      readonly reason: NativeRouteBlockReason
    }

export function nativeTunnelKindLabel(kind: NdmsTunnelKind): string {
  return NATIVE_TUNNEL_KIND_LABELS[kind]
}

/**
 * Resolve the Linux device name without falling back to the firmware logical
 * identifier. A logical name such as Wireguard0 is not safe input for routing
 * when NDMS has not resolved its nwg/wg device.
 */
export function resolveNativeKernelName(
  nativeInterface: KeeneticNativeInterface
): string | undefined {
  return nonEmpty(nativeInterface.kernel_name)
}

/**
 * Join the relatively static NDMS catalog to the live kernel inventory.
 * Linux interface names are case-sensitive, so only surrounding whitespace is
 * normalized and the join is exclusively on the resolved kernel name.
 */
export function mapNativeInterfaces(
  nativeInterfaces: readonly KeeneticNativeInterface[],
  runtimeInterfaces: readonly RuntimeInterfaceInventoryEntry[]
): NativeInterfaceModel[] {
  const runtimeByKernelName = new Map<string, RuntimeInterfaceInventoryEntry>()

  for (const runtimeInterface of runtimeInterfaces) {
    const name = nonEmpty(runtimeInterface.name)
    if (name && !runtimeByKernelName.has(name)) {
      runtimeByKernelName.set(name, runtimeInterface)
    }
  }

  return nativeInterfaces.map((nativeInterface) => {
    const logicalName =
      nonEmpty(nativeInterface.firmware_interface_name) ??
      nonEmpty(nativeInterface.id) ??
      ""
    const kernelName = resolveNativeKernelName(nativeInterface)
    const runtime = kernelName ? runtimeByKernelName.get(kernelName) : undefined

    return {
      source: nativeInterface,
      id: nonEmpty(nativeInterface.id) ?? logicalName,
      label:
        nonEmpty(nativeInterface.label) ??
        nonEmpty(logicalName) ??
        kernelName ??
        nativeTunnelKindLabel(nativeInterface.kind),
      logicalName,
      kernelName,
      protocol: nativeTunnelKindLabel(nativeInterface.kind),
      runtime,
      live: runtime?.status === "up",
      connected: nativeInterface.connected,
      link: nativeInterface.link,
    }
  })
}

/**
 * Remove legacy managed-native rows already represented by the typed NDMS
 * inventory. If the legacy endpoint itself reports the same native interface
 * more than once, prefer the newest status and use its tag as a stable tie
 * breaker. Managed sing-box transports are never affected.
 */
export function dedupeLegacyNativeTransports(
  transports: readonly TransportStatus[],
  nativeInterfaces: readonly NativeInterfaceModel[]
): TransportStatus[] {
  const representedKernelNames = new Set(
    nativeInterfaces.flatMap((nativeInterface) =>
      nativeInterface.kernelName ? [nativeInterface.kernelName] : []
    )
  )
  const winnerByInterface = new Map<
    string,
    { index: number; transport: TransportStatus }
  >()

  transports.forEach((transport, index) => {
    if (!isLegacyNativeTransport(transport)) {
      return
    }

    const interfaceName = nonEmpty(transport.interface)
    if (!interfaceName || representedKernelNames.has(interfaceName)) {
      return
    }

    const current = winnerByInterface.get(interfaceName)
    if (
      !current ||
      compareLegacyNativeTransports(transport, current.transport) < 0
    ) {
      winnerByInterface.set(interfaceName, { index, transport })
    }
  })

  return transports.filter((transport, index) => {
    if (!isLegacyNativeTransport(transport)) {
      return true
    }

    const interfaceName = nonEmpty(transport.interface)
    if (!interfaceName) {
      return true
    }
    if (representedKernelNames.has(interfaceName)) {
      return false
    }
    return winnerByInterface.get(interfaceName)?.index === index
  })
}

export function getNativeRouteActionability(
  nativeInterface: NativeInterfaceModel,
  {
    hasConfig,
    boundOutboundTag,
  }: {
    readonly hasConfig: boolean
    readonly boundOutboundTag?: string
  }
): NativeRouteActionability {
  if (nativeInterface.source.role !== "client") {
    return { enabled: false, reason: "not-client" }
  }
  if (!nativeInterface.kernelName) {
    return { enabled: false, reason: "unresolved" }
  }
  if (!nativeInterface.live) {
    return { enabled: false, reason: "not-live" }
  }
  if (nonEmpty(boundOutboundTag)) {
    return { enabled: false, reason: "already-bound" }
  }
  if (!hasConfig) {
    return { enabled: false, reason: "no-config" }
  }
  return {
    enabled: true,
    interfaceName: nativeInterface.kernelName,
  }
}

function isLegacyNativeTransport(transport: TransportStatus): boolean {
  return transport.type.trim().toLowerCase() === "native"
}

/**
 * Sort preference only; the returned collection retains the source endpoint's
 * order. ISO timestamps sort lexically, and malformed timestamps still get a
 * deterministic lexical ordering.
 */
function compareLegacyNativeTransports(
  left: TransportStatus,
  right: TransportStatus
): number {
  const updatedAt = right.updated_at.localeCompare(left.updated_at)
  if (updatedAt !== 0) {
    return updatedAt
  }

  const tag = left.tag.localeCompare(right.tag)
  if (tag !== 0) {
    return tag
  }

  return left.state.localeCompare(right.state)
}

function nonEmpty(value: string | null | undefined): string | undefined {
  const normalized = value?.trim()
  return normalized ? normalized : undefined
}
