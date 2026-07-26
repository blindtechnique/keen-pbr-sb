import type { Outbound } from "@/api/generated/model"
import {
  useGetNdmsInterfaceInventory,
  useGetTransports,
} from "@/api/queries"
import { useInterfaceNames } from "@/hooks/use-interface-names"
import {
  buildInterfaceProtocolIndex,
  protocolForFirmwareType,
  protocolForKernelName,
} from "@/lib/interface-protocol"

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
  const ndmsInventoryQuery = useGetNdmsInterfaceInventory()
  const { names } = useInterfaceNames()

  const transports =
    transportsQuery.data?.status === 200 ? transportsQuery.data.data : []
  const nativeInterfaces =
    ndmsInventoryQuery.data?.status === 200
      ? ndmsInventoryQuery.data.data.interfaces
      : []
  const byInterface = buildInterfaceProtocolIndex(
    transports,
    nativeInterfaces
  )

  const protocolOf = (interfaceName?: string): string => {
    if (!interfaceName) return ""
    const fromInventory = byInterface.get(interfaceName)
    if (fromInventory) return fromInventory.label
    const fromFirmware = protocolForFirmwareType(names[interfaceName]?.type)
    if (fromFirmware) return fromFirmware.label
    return protocolForKernelName(interfaceName)?.label ?? ""
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
