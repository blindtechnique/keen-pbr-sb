import type {
  Outbound,
  TransportSpec,
  TransportStatus,
} from "@/api/generated/model"
import type { NativeInterfaceModel } from "@/lib/native-interfaces"

/** Keep retained routes manageable after firmware removes their native VPN. */
export function selectTransportOrphanOutbounds({
  outbounds,
  managedTransports,
  configuredTransports,
  nativeInterfaces,
  inventoryAuthoritative,
}: {
  outbounds: readonly Outbound[]
  managedTransports: readonly Pick<TransportStatus, "tag" | "interface">[]
  configuredTransports: readonly Pick<
    TransportSpec,
    "tag" | "interface" | "type"
  >[]
  nativeInterfaces: readonly Pick<NativeInterfaceModel, "kernelName">[]
  inventoryAuthoritative: boolean
}): {
  outbounds: Outbound[]
  unrepresentedNativeInterfaces: ReadonlySet<string>
} {
  const nativeNames = new Set(
    nativeInterfaces.flatMap((item) =>
      item.kernelName ? [item.kernelName] : []
    )
  )
  const unrepresentedNativeInterfaces = new Set(
    configuredTransports
      .filter(
        (spec) =>
          inventoryAuthoritative &&
          spec.type === "native" &&
          Boolean(spec.interface) &&
          !nativeNames.has(spec.interface)
      )
      .map((spec) => spec.interface)
  )
  const linkedTags = new Set<string>()
  const interfaceOutbounds = new Map(
    outbounds
      .filter((outbound) => outbound.type === "interface")
      .map((outbound) => [outbound.interface, outbound])
  )
  const link = (tag: string, interfaceName: string) => {
    if (tag) linkedTags.add(tag)
    const bound = interfaceOutbounds.get(interfaceName)
    if (bound) linkedTags.add(bound.tag)
  }
  for (const transport of managedTransports) {
    link(transport.tag, transport.interface)
  }
  for (const spec of configuredTransports) {
    if (
      spec.type === "native" &&
      unrepresentedNativeInterfaces.has(spec.interface)
    )
      continue
    link(spec.tag, spec.interface)
  }
  for (const name of nativeNames) link("", name)

  const groupMembers = new Set(
    outbounds.flatMap((outbound) =>
      outbound.type === "urltest"
        ? (outbound.outbound_groups ?? []).flatMap((group) => group.outbounds)
        : []
    )
  )
  return {
    outbounds: outbounds.filter(
      (outbound) =>
        outbound.type === "interface" &&
        !linkedTags.has(outbound.tag) &&
        (!groupMembers.has(outbound.tag) ||
          unrepresentedNativeInterfaces.has(outbound.interface ?? ""))
    ),
    unrepresentedNativeInterfaces,
  }
}
