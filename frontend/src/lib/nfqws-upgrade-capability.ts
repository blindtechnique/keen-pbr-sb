export type NfqwsUpgradeCapability = {
  available: boolean
  mode: string
  exact_previous_ipk: boolean
  verified_target_ipk: boolean
  exact_opkg_metadata_rollback: boolean
  boot_recovery: boolean
  reason: string
}

// Older backends did not publish a capability and implemented the unsafe
// opkg-only path. Unknown is therefore not permission: only an explicit,
// fully-capable backend may enable package mutation.
export function nfqwsUpgradeAllowed(
  capability: NfqwsUpgradeCapability | undefined
): boolean {
  return capability?.available === true
}
