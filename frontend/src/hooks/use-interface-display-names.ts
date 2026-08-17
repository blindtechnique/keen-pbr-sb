import { useMemo } from "react"

import type { TransportStatus } from "@/api/generated/model"
import { useGetTransports } from "@/api/queries"
import {
  type InterfaceName,
  resolveInterfaceDisplayName,
  useInterfaceNames,
} from "@/hooks/use-interface-names"

/**
 * Builds the UI name index without changing the kernel interface identity.
 *
 * A managed transport alias is the most specific name chosen inside
 * keen-pbr-sb. NDMS is the next-best source for native interfaces. The kernel
 * name remains the final fallback and is still used as every persisted value.
 */
export function buildInterfaceDisplayNameIndex(
  ndmsNames: Readonly<Record<string, InterfaceName>>,
  transports: readonly TransportStatus[]
): Record<string, InterfaceName> {
  const names: Record<string, InterfaceName> = { ...ndmsNames }

  for (const transport of transports) {
    const interfaceName = transport.interface.trim()
    const displayName = transport.display_name?.trim()
    if (!interfaceName || !displayName) {
      continue
    }

    names[interfaceName] = {
      ...names[interfaceName],
      label: displayName,
    }
  }

  return names
}

export function useInterfaceDisplayNames() {
  const ndms = useInterfaceNames()
  const transportsQuery = useGetTransports()
  const transportResponse = transportsQuery.data
  const names = useMemo(
    () =>
      buildInterfaceDisplayNameIndex(
        ndms.names,
        transportResponse?.status === 200 ? transportResponse.data : []
      ),
    [ndms.names, transportResponse]
  )

  return {
    names,
    labelFor: (kernelName?: string) =>
      resolveInterfaceDisplayName(names, kernelName),
    describe: (kernelName?: string) => {
      if (!kernelName) {
        return ""
      }
      const label = resolveInterfaceDisplayName(names, kernelName)
      return label === kernelName ? kernelName : `${label} (${kernelName})`
    },
  }
}
