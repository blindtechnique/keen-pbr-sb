import { useQuery } from "@tanstack/react-query"

export type InterfaceName = {
  label: string
  id?: string
  firmware_interface_name?: string
  type?: string
  connected?: boolean
  link?: boolean
}

type InterfaceNamesResponse = {
  available?: boolean
  names?: Record<string, InterfaceName>
}

export function resolveInterfaceDisplayName(
  names: Record<string, InterfaceName>,
  kernelName?: string
) {
  if (!kernelName) {
    return ""
  }

  return names[kernelName]?.label?.trim() || kernelName
}

/**
 * Ищет понятное имя по логическому идентификатору NDMS (например `Bridge0`),
 * а не по kernel-имени: каталог ключуется kernel-именами, но каждая запись
 * несёт свои NDMS-идентификаторы. Возвращает undefined, когда прошивка имени
 * не дала — выдумывать «Домашняя сеть» по одному только `Bridge0` нельзя:
 * сегмент могли переименовать.
 */
export function resolveNdmsInterfaceLabel(
  names: Record<string, InterfaceName>,
  ndmsId?: string | null
): string | undefined {
  const wanted = ndmsId?.trim()
  if (!wanted) {
    return undefined
  }

  for (const entry of Object.values(names)) {
    if (entry.id === wanted || entry.firmware_interface_name === wanted) {
      const label = entry.label?.trim()
      if (label && label !== wanted) {
        return label
      }
    }
  }

  return undefined
}

/**
 * The router's own names for its interfaces, keyed by kernel name.
 *
 * keen-pbr has to work in kernel names because that is what routing uses, but
 * nobody chose "nwg2" - they named it "sddvpn.mooo.com AWG2" in NDMS. Where a
 * label exists we should show it, and fall back silently otherwise: this is a
 * nicety, never a dependency, and OpenWrt builds have no firmware API at all.
 */
export function useInterfaceNames() {
  const query = useQuery<InterfaceNamesResponse>({
    queryKey: ["interface-names"],
    queryFn: async () => {
      const response = await fetch("/api/system/interface-names")
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json()
    },
    // Names change when someone edits the router's configuration, which is
    // rare enough that a long stale time costs nothing.
    staleTime: 5 * 60 * 1000,
    retry: false,
  })

  const names = query.data?.names ?? {}

  return {
    names,
    available: Boolean(query.data?.available),
    /** The router's label for an interface, or the kernel name unchanged. */
    labelFor: (kernelName?: string) =>
      resolveInterfaceDisplayName(names, kernelName),
    /** "sddvpn.mooo.com AWG2 (nwg2)" where a label exists, "nwg2" otherwise. */
    describe: (kernelName?: string) => {
      if (!kernelName) return ""
      const label = names[kernelName]?.label
      return label && label !== kernelName
        ? `${label} (${kernelName})`
        : kernelName
    },
  }
}
