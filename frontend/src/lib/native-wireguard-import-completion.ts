import {
  TransportSpecType,
  type NdmsTunnelInterface,
  type TransportSpec,
} from "@/api/generated/model"

export type NativeWireGuardImportedIdentity = Readonly<{
  firmwareInterface: string
  kernelInterface: string
  kind: "wireguard" | "amnezia_wireguard"
}>

export type NativeWireGuardImportCompletionPlan = Readonly<{
  tag: string
  displayName: string
  createOutbound: boolean
  strictEnforcement?: boolean
  autoStart: boolean
  geoMode?: TransportSpec["geo_mode"]
  countryCode?: string
  country?: string
  endpointHost?: string
}>

type ActiveImportCompletionHandler = (
  identity: NativeWireGuardImportedIdentity | null
) => boolean

let activeHandler:
  | Readonly<{
      token: symbol
      handle: ActiveImportCompletionHandler
    }>
  | undefined

let stagedPlan: NativeWireGuardImportCompletionPlan | undefined
const COMPLETION_PLAN_KEY = "keen-pbr.native-wireguard-import-completion.v1"

const completionStorage = (): Storage | undefined => {
  try {
    return typeof window === "undefined" ? undefined : window.sessionStorage
  } catch {
    return undefined
  }
}

const parseStoredPlan = (
  raw: string | null
): NativeWireGuardImportCompletionPlan | undefined => {
  if (!raw) return undefined
  try {
    const value = JSON.parse(raw) as Record<string, unknown>
    if (
      value.version !== 1 ||
      typeof value.tag !== "string" ||
      typeof value.displayName !== "string" ||
      typeof value.createOutbound !== "boolean" ||
      typeof value.autoStart !== "boolean"
    ) {
      return undefined
    }
    return {
      tag: value.tag,
      displayName: value.displayName,
      createOutbound: value.createOutbound,
      strictEnforcement:
        typeof value.strictEnforcement === "boolean"
          ? value.strictEnforcement
          : undefined,
      autoStart: value.autoStart,
      geoMode:
        value.geoMode === "auto" ||
        value.geoMode === "manual" ||
        value.geoMode === "disabled"
          ? value.geoMode
          : undefined,
      countryCode:
        typeof value.countryCode === "string" ? value.countryCode : undefined,
      country: typeof value.country === "string" ? value.country : undefined,
      endpointHost:
        typeof value.endpointHost === "string" ? value.endpointHost : undefined,
    }
  } catch {
    return undefined
  }
}

/**
 * The import dialog and the page-level bodyless recovery worker live in
 * separate React branches. Keep a same-document hand-off so a recovery that
 * finishes while the dialog is still open can use the alias/country already
 * entered there. The non-secret completion plan is retained in this document
 * even if the modal closes, so the page-level recovery worker does not replace
 * the user's alias/route/country choices with a technical WireguardN fallback.
 */
export function registerActiveNativeWireGuardImportCompletion(
  handle: ActiveImportCompletionHandler
): () => void {
  const token = Symbol("native-wireguard-import-completion")
  activeHandler = { token, handle }
  return () => {
    if (activeHandler?.token === token) activeHandler = undefined
  }
}

export function offerNativeWireGuardImportCompletion(
  identity: NativeWireGuardImportedIdentity
): boolean {
  return activeHandler?.handle(identity) === true
}

export function cancelActiveNativeWireGuardImportCompletion(): void {
  activeHandler?.handle(null)
}

export function stageNativeWireGuardImportCompletion(
  plan: NativeWireGuardImportCompletionPlan
): void {
  stagedPlan = {
    ...plan,
    displayName: plan.displayName.trim(),
    endpointHost: plan.endpointHost?.trim() || undefined,
  }
  try {
    completionStorage()?.setItem(
      COMPLETION_PLAN_KEY,
      JSON.stringify({ version: 1, ...stagedPlan })
    )
  } catch {
    // Same-document completion remains available when storage is disabled.
  }
}

export function readStagedNativeWireGuardImportCompletion():
  | NativeWireGuardImportCompletionPlan
  | undefined {
  if (!stagedPlan) {
    try {
      stagedPlan = parseStoredPlan(
        completionStorage()?.getItem(COMPLETION_PLAN_KEY) ?? null
      )
    } catch {
      stagedPlan = undefined
    }
  }
  return stagedPlan ? { ...stagedPlan } : undefined
}

export function clearStagedNativeWireGuardImportCompletion(
  expectedTag?: string
): void {
  const current = readStagedNativeWireGuardImportCompletion()
  if (expectedTag && current?.tag !== expectedTag) return
  stagedPlan = undefined
  try {
    completionStorage()?.removeItem(COMPLETION_PLAN_KEY)
  } catch {
    // The in-memory plan is already cleared.
  }
}

export function buildStagedNativeWireGuardTransport(
  plan: NativeWireGuardImportCompletionPlan,
  identity: NativeWireGuardImportedIdentity
): TransportSpec {
  return {
    tag: plan.tag,
    display_name: plan.displayName,
    type: TransportSpecType.native,
    interface: identity.kernelInterface,
    auto_start: plan.autoStart,
    geo_mode: plan.geoMode ?? "disabled",
    country_code: plan.countryCode,
    country: plan.country,
  }
}

/**
 * A completed import can outlive its HTTP response: the durable recovery route
 * then truthfully answers `no_work` because its WAL has already been retired.
 * Reconnect the still-staged, non-secret UI plan only to one exact newly
 * panel-owned inventory row with the alias Keenetic accepted. Existing tracked
 * interfaces and ambiguous duplicate labels are deliberately excluded.
 */
export function findStagedNativeWireGuardImportIdentity(
  plan: NativeWireGuardImportCompletionPlan,
  interfaces: readonly NdmsTunnelInterface[],
  trackedKernelInterfaces: readonly string[]
): NativeWireGuardImportedIdentity | undefined {
  const tracked = new Set(
    trackedKernelInterfaces.map((value) => value.trim()).filter(Boolean)
  )
  const matches = interfaces.filter((item) => {
    const kernelInterface = item.kernel_name?.trim()
    return (
      item.label.trim() === plan.displayName &&
      /^Wireguard(?:[5-9]|[1-8][0-9]|9[0-8])$/.test(
        item.firmware_interface_name
      ) &&
      Boolean(kernelInterface) &&
      !tracked.has(kernelInterface ?? "") &&
      item.native_mutation.ownership_state === "panel_owned_active" &&
      (item.kind === "wireguard" || item.kind === "amnezia_wireguard")
    )
  })
  if (matches.length !== 1) return undefined
  const match = matches[0]!
  return {
    firmwareInterface: match.firmware_interface_name,
    kernelInterface: match.kernel_name!.trim(),
    kind: match.kind === "wireguard" ? "wireguard" : "amnezia_wireguard",
  }
}
