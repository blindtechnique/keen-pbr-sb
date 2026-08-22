import type {
  NdmsTunnelInterface,
  NdmsTunnelKind,
  RuntimeInterfaceInventoryEntry,
  TransportStatus,
} from "@/api/generated/model"
import {
  protocolForNdmsKind,
  type InterfaceProtocolDisplay,
} from "@/lib/interface-protocol"

/**
 * The generated contract intentionally distinguishes the required logical
 * identifier reported by KeeneticOS from the optional Linux device name.
 */
export type KeeneticNativeInterface = Readonly<NdmsTunnelInterface>

export const NATIVE_TUNNEL_KIND_LABELS = {
  amnezia_wireguard: "AmneziaWG",
  wireguard: "WireGuard",
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
  readonly protocol: InterfaceProtocolDisplay
  readonly runtime?: RuntimeInterfaceInventoryEntry
  readonly live: boolean
  readonly connected?: boolean
  readonly link?: boolean
}

export type NativeRouteBlockReason =
  | "not-client"
  | "unresolved"
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
      protocol: protocolForNdmsKind(nativeInterface.kind),
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
  nativeInterfaces: readonly NativeInterfaceModel[],
  inventoryAuthoritative = false
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

    // When the typed NDMS inventory is available it is the complete source
    // of native interfaces, including stopped ones. A legacy tracker that is
    // absent from that inventory is therefore deleted local metadata, not a
    // live KeeneticOS tunnel. Keeping it would resurrect a removed VPN as an
    // unusable "KeeneticOS" row.
    if (inventoryAuthoritative) {
      return false
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

/**
 * Причина, по которой интерфейс нельзя привязать к маршруту, — единая для
 * кнопки в строке туннеля, выпадающего списка в форме добавления и вопроса
 * «использовать как VPN?». Раньше правила были разными, и один и тот же
 * туннель в одном месте выглядел доступным, а в другом — нет.
 *
 * - `server`: прошивка явно назвала интерфейс сервером либо распознала
 *   серверную форму WireGuard (internal_vpn_server_candidate). Направить
 *   исходящий трафик во входящий сервер нельзя. Роль «не определена»
 *   не блокирует: KeeneticOS часто вовсе не сообщает роль клиентских
 *   туннелей, и только что добавленный AWG оставался «недоступным».
 * - `unresolved`: нет системного имени — маршруту не к чему привязаться.
 *   Обычно это значит, что туннель выключен в KeeneticOS.
 *
 * «Выключен, но присутствует в системе» больше не блокирует: маршрут к
 * временно неподключённому туннелю — нормальное состояние, ровно как у
 * управляемых туннелей (выключенный туннель сохраняет свой маршрут).
 */
export type NativeBindBlockReason = "server" | "unresolved"

export function getNativeBindBlockReason(
  nativeInterface: NativeInterfaceModel
): NativeBindBlockReason | undefined {
  if (
    nativeInterface.source.role === "server" ||
    nativeInterface.source.internal_vpn_server_candidate
  ) {
    return "server"
  }
  if (!nativeInterface.kernelName) {
    return "unresolved"
  }
  return undefined
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
  const blockReason = getNativeBindBlockReason(nativeInterface)
  if (blockReason === "server") {
    return { enabled: false, reason: "not-client" }
  }
  if (blockReason === "unresolved" || !nativeInterface.kernelName) {
    return { enabled: false, reason: "unresolved" }
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

/**
 * Интерфейсы, на которые имеет смысл направлять трафик.
 *
 * В выборе интерфейса для маршрута прошивка показывала всё подряд, включая
 * свои входящие VPN-серверы: направить исходящий трафик в интерфейс, который
 * принимает чужие подключения, нельзя — маршрут молча не заработает.
 *
 * Отсекаем ровно то, про что прошивка сама сказала «это сервер». Всё
 * остальное остаётся: свои туннели sing-box в инвентаре прошивки не значатся
 * вовсе, и фильтр по принципу «показывать только знакомое» убрал бы как раз
 * их. Если инвентарь недоступен, не убираем ничего — пустой список хуже
 * лишних строк.
 */
export function excludeIngressServerInterfaces<T extends { name: string }>(
  interfaces: T[],
  ndmsInterfaces: readonly {
    kernel_name?: string | null
    role?: string
  }[]
): T[] {
  const ingress = new Set(
    ndmsInterfaces
      .filter((item) => item.role === "server")
      .map((item) => item.kernel_name?.trim())
      .filter((name): name is string => Boolean(name))
  )
  if (ingress.size === 0) return interfaces
  return interfaces.filter((item) => !ingress.has(item.name))
}
