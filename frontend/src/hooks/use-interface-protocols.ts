import type { Outbound } from "@/api/generated/model"
import { useGetTransports } from "@/api/queries"
import { useInterfaceNames } from "@/hooks/use-interface-names"

/**
 * Короткая метка протокола для интерфейса: VLESS, AWG, WG, IKEV2, OPENVPN.
 *
 * Источников два, и они не пересекаются. Про туннели, которые поднимает
 * sing-box, знает он сам — протокол приезжает в статусе транспорта. Про
 * нативные интерфейсы прошивки sing-box не знает ничего, зато знает NDMS:
 * там у каждого интерфейса есть тип. Ни одного списка протоколов в коде
 * держать не нужно, кроме короткого словаря сокращений.
 */
export function useInterfaceProtocols() {
  const transportsQuery = useGetTransports()
  const { names } = useInterfaceNames()

  const byInterface = new Map<string, string>()

  if (transportsQuery.data?.status === 200) {
    for (const transport of transportsQuery.data.data) {
      if (transport.interface && transport.protocol) {
        byInterface.set(transport.interface, transport.protocol.toUpperCase())
      }
    }
  }

  const protocolOf = (interfaceName?: string): string => {
    if (!interfaceName) return ""
    const fromTransport = byInterface.get(interfaceName)
    if (fromTransport) return fromTransport
    const fromFirmware = shortenFirmwareType(names[interfaceName]?.type)
    if (fromFirmware) return fromFirmware
    return guessFromKernelName(interfaceName)
  }

  return {
    protocolOf,
    /** Для группы резервирования — метки её участников через плюс. */
    protocolOfGroup: (outbound: Outbound, interfaceOf: (tag: string) => string) => {
      const members = (outbound.outbound_groups ?? []).flatMap(
        (group) => group.outbounds ?? []
      )
      const labels = members
        .map((tag) => protocolOf(interfaceOf(tag)))
        .filter(Boolean)
      return labels.join("+")
    },
  }
}

/**
 * Когда прошивка молчит — читаем имя устройства.
 *
 * Keenetic поднимает и WireGuard, и AmneziaWG одним драйвером и называет оба
 * `nwgN`: различить их по имени невозможно в принципе, поэтому честнее
 * написать «AWG/WG», чем угадывать и ошибаться в половине случаев.
 */
function guessFromKernelName(name: string): string {
  const normalized = name.toLowerCase()
  if (normalized.startsWith("nwg")) return "AWG/WG"
  if (normalized.startsWith("wg")) return "WG"
  if (normalized.startsWith("ppp")) return "PPP"
  if (normalized.startsWith("tun") || normalized.startsWith("tap")) return "VPN"
  return ""
}

/**
 * NDMS пишет типы полными словами. В строке рядом с названием нужен ярлык,
 * а не термин, поэтому длинные приводятся к привычным сокращениям, а
 * незнакомые остаются как есть — лучше показать чужое слово, чем ничего.
 */
function shortenFirmwareType(type?: string): string {
  if (!type) return ""
  const normalized = type.toLowerCase()
  if (normalized.includes("amnezia")) return "AWG"
  // Прошивка зовёт AmneziaWG вайргардом: под ним он и работает. Показать
  // одно из двух наугад значило бы врать половине пользователей.
  if (normalized.includes("wireguard")) return "AWG/WG"
  if (normalized.includes("ikev2")) return "IKEV2"
  if (normalized.includes("openvpn")) return "OPENVPN"
  if (normalized.includes("l2tp")) return "L2TP"
  if (normalized.includes("pptp")) return "PPTP"
  if (normalized.includes("sstp")) return "SSTP"
  if (normalized.includes("proxy")) return "PROXY"
  return type.toUpperCase()
}
