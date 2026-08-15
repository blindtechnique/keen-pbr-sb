export type NativeWireGuardAliasInventoryItem = {
  readonly id: string
  readonly firmware_interface_name: string
  readonly label: string
}

/** A derived suggestion only; callers must never write it into a draft. */
export function suggestNativeWireGuardImportAlias({
  fileName,
  endpointHost,
}: {
  readonly fileName?: string
  readonly endpointHost?: string
}): string | undefined {
  const fileStem = fileName
    ?.trim()
    .replace(/\.(?:conf|vpn)$/i, "")
    .trim()
  return nonEmpty(fileStem) ?? nonEmpty(endpointHost)
}

export function findNativeWireGuardAliasConflict(
  suggestion: string | undefined,
  interfaces: readonly NativeWireGuardAliasInventoryItem[]
): NativeWireGuardAliasInventoryItem | undefined {
  const normalized = normalize(suggestion)
  if (!normalized) return undefined
  return interfaces.find((item) =>
    [item.label, item.firmware_interface_name, item.id].some(
      (candidate) => normalize(candidate) === normalized
    )
  )
}

function nonEmpty(value: string | undefined): string | undefined {
  const normalized = value?.trim()
  return normalized ? normalized : undefined
}

function normalize(value: string | undefined): string | undefined {
  return nonEmpty(value)?.toLocaleLowerCase("en-US")
}
