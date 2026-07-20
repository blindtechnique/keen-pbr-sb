import { useQuery } from "@tanstack/react-query"

export type InterfaceName = {
  label: string
  id?: string
  type?: string
  connected?: boolean
  link?: boolean
}

type InterfaceNamesResponse = {
  available?: boolean
  names?: Record<string, InterfaceName>
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
      (kernelName && names[kernelName]?.label) || kernelName || "",
    /** "sddvpn.mooo.com AWG2 (nwg2)" where a label exists, "nwg2" otherwise. */
    describe: (kernelName?: string) => {
      if (!kernelName) return ""
      const label = names[kernelName]?.label
      return label && label !== kernelName ? `${label} (${kernelName})` : kernelName
    },
  }
}
