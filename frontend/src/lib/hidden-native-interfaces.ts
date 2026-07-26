import type { ConfigObject } from "@/api/generated/model/configObject"
import type { NativeInterfaceModel } from "@/lib/native-interfaces"

export interface NativeTransportCandidate {
  readonly id: string
  readonly interfaceName?: string
  readonly label: string
  readonly protocol: string
  readonly hidden: boolean
  readonly selectable: boolean
}

export function normalizeHiddenNativeInterfaceIds(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return []
  }

  return [
    ...new Set(
      value
        .filter((item): item is string => typeof item === "string")
        .map((item) => item.trim())
        .filter(Boolean)
    ),
  ].sort()
}

export function getHiddenNativeInterfaceIds(config?: ConfigObject) {
  return new Set(
    normalizeHiddenNativeInterfaceIds(
      config?.ui_preferences?.hidden_native_interface_ids
    )
  )
}

export function updateHiddenNativeInterfacePreference(
  config: ConfigObject,
  interfaceId: string,
  hidden: boolean
): ConfigObject {
  const normalizedInterfaceId = interfaceId.trim()
  if (!normalizedInterfaceId) {
    return config
  }

  const hiddenIds = getHiddenNativeInterfaceIds(config)
  if (hidden) {
    hiddenIds.add(normalizedInterfaceId)
  } else {
    hiddenIds.delete(normalizedInterfaceId)
  }

  return {
    ...config,
    ui_preferences: {
      ...(config.ui_preferences ?? {}),
      hidden_native_interface_ids: normalizeHiddenNativeInterfaceIds([
        ...hiddenIds,
      ]),
    },
  }
}

/**
 * The persisted preference controls only the ordinary inventory cards. The
 * same typed NDMS inventory remains the source for creation candidates so a
 * hidden interface can always be found and restored without browser-local
 * state.
 */
export function buildNativeTransportCandidates(
  nativeInterfaces: readonly NativeInterfaceModel[],
  config?: ConfigObject
): NativeTransportCandidate[] {
  const hiddenIds = getHiddenNativeInterfaceIds(config)

  return nativeInterfaces.map((nativeInterface) => ({
    id: nativeInterface.id,
    interfaceName: nativeInterface.kernelName,
    label: nativeInterface.label,
    protocol: nativeInterface.protocol.label,
    hidden: hiddenIds.has(nativeInterface.id),
    selectable:
      nativeInterface.source.role === "client" &&
      Boolean(nativeInterface.kernelName),
  }))
}

export function formatNativeTransportCandidate(
  candidate: NativeTransportCandidate,
  labels: {
    readonly hidden: string
    readonly unavailable: string
  }
): string {
  return [
    candidate.label,
    candidate.protocol,
    candidate.hidden ? labels.hidden : undefined,
    !candidate.selectable ? labels.unavailable : undefined,
  ]
    .filter((part): part is string => Boolean(part))
    .join(" · ")
}
