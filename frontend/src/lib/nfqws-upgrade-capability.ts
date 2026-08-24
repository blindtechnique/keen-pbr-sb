import { classifyNfqwsUpdateNotice, type NfqwsUpdateStatus } from "@/api/nfqws"

// What the daemon's boot-time recovery decided and did after the last
// reboot that found an interrupted package transaction. Absent (null) until
// one ever ran.
export type NfqwsBootRecoveryLast = {
  at: number
  outcome: string
  plan: string
  reason: string
  journal_cleared: boolean
}

export type NfqwsUpgradeCapability = {
  available: boolean
  mode: string
  exact_previous_ipk: boolean
  verified_target_ipk: boolean
  exact_opkg_metadata_rollback: boolean
  boot_recovery: boolean
  boot_recovery_last?: NfqwsBootRecoveryLast | null
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

// Everything the upgrade control decides, as one pure function.
//
// It lives beside the capability predicates because "may this be pressed" and
// "why not" are the same question asked twice, and answering them in two
// places is how the two answers drift apart. The shape deliberately mirrors
// singBoxInstallButton: two update controls that disagreed about what
// "nothing to do" looks like would teach an operator that the difference
// means something.
export type NfqwsUpgradeButtonState = {
  enabled: boolean
  tooltipKey: string
}

function blockedTooltipKey(
  capability: NfqwsUpgradeCapability | undefined
): string {
  return nfqwsUpgradeBlockKind(capability) === "metadata_unverified"
    ? "nfqws.upgradeTip.metadataUnverified"
    : "nfqws.upgradeTip.blocked"
}

export function nfqwsUpgradeButton(
  update: NfqwsUpdateStatus | undefined,
  capability: NfqwsUpgradeCapability | undefined,
  busy: boolean,
  checking: boolean
): NfqwsUpgradeButtonState {
  if (busy) {
    return { enabled: false, tooltipKey: "nfqws.upgradeTip.busy" }
  }
  // No answer yet is not the same as "nothing to do". Saying "you are up to
  // date" before the check returns would be a claim this build has not earned.
  if (checking || !update) {
    return { enabled: false, tooltipKey: "nfqws.upgradeTip.checking" }
  }

  // classifyNfqwsUpdateNotice, not `update.available`, on purpose: after a
  // captured file restore the backend withholds current/latest, and reading
  // that absence as "up to date" would offer reassurance where the panel
  // does not actually know which binary is installed.
  const notice = classifyNfqwsUpdateNotice(update)
  if (notice === "degraded") {
    return { enabled: false, tooltipKey: blockedTooltipKey(capability) }
  }
  if (notice === "up_to_date") {
    return { enabled: false, tooltipKey: "nfqws.upgradeTip.upToDate" }
  }
  if (!nfqwsUpgradeAllowed(capability)) {
    return { enabled: false, tooltipKey: blockedTooltipKey(capability) }
  }

  return { enabled: true, tooltipKey: "nfqws.upgradeTip.available" }
}

// Which guarantees the upgrade path does NOT provide right now. The
// limitation alert exists to warn about what is missing; keying it on the
// mode string alone made it outlive the guarantees it was written for - the
// build that pins and verifies the target IPK, keeps the exact previous one
// and repairs an interrupted attempt at the next start still told the
// operator that none of that happens. These flags are what the backend
// publishes for exactly this question, so the warning follows the state
// rather than the era the text was written in.
export type NfqwsUpgradeGuarantee =
  | "exactPrevious"
  | "verifiedTarget"
  | "metadataRollback"
  | "bootRecovery"

export function nfqwsUpgradeMissingGuarantees(
  capability: NfqwsUpgradeCapability | undefined
): NfqwsUpgradeGuarantee[] {
  // No capability at all promises nothing, so everything counts as missing.
  if (!capability) {
    return [
      "exactPrevious",
      "verifiedTarget",
      "metadataRollback",
      "bootRecovery",
    ]
  }
  const missing: NfqwsUpgradeGuarantee[] = []
  if (!capability.exact_previous_ipk) missing.push("exactPrevious")
  if (!capability.verified_target_ipk) missing.push("verifiedTarget")
  if (!capability.exact_opkg_metadata_rollback) {
    missing.push("metadataRollback")
  }
  if (!capability.boot_recovery) missing.push("bootRecovery")
  return missing
}
