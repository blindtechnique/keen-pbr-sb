export type NfqwsUpgradeCapability = {
  available: boolean
  mode: string
  exact_previous_ipk: boolean
  verified_target_ipk: boolean
  exact_opkg_metadata_rollback: boolean
  boot_recovery: boolean
  reason?: string
  blocked_reason?: string
  limitation?: string
}

export type NfqwsUpgradeBlockKind = "metadata_unverified" | "unavailable"

export function nfqwsUpgradeBlockKind(
  capability: NfqwsUpgradeCapability | undefined
): NfqwsUpgradeBlockKind {
  return capability?.blocked_reason === "nfqws_package_metadata_unverified"
    ? "metadata_unverified"
    : "unavailable"
}

// Older backends did not publish a capability. Unknown is therefore not
// permission, while a current backend may explicitly expose its guarded opkg
// path without pretending that its file restore is an exact package rollback.
export function nfqwsUpgradeAllowed(
  capability: NfqwsUpgradeCapability | undefined
): boolean {
  return capability?.available === true && capability.mode === "guarded_opkg"
}
