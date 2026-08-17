// Every decision the sing-box install card makes, as pure functions.
//
// They are here rather than inside the component because what matters about
// this card is which of several honest-but-different things it says, and that
// is worth testing without rendering anything.

import type {
  SingBoxInstallCapability,
  SingBoxInstallCapabilityBlockersItem,
  SingBoxInstallCapabilityOperation,
  SingBoxInstallResult,
  SingBoxInstallResultInstallOutcome,
} from "@/api/generated/model"

// The daemon's phase names. The list is closed on purpose: a phase this build
// has never heard of renders as the generic running text rather than as a step
// whose meaning the page invented.
const PHASE_KEYS: Record<string, string> = {
  reading_release: "transports.singBoxInstall.phaseReadingRelease",
  downloading_archive: "transports.singBoxInstall.phaseDownloadingArchive",
  downloading_checksums: "transports.singBoxInstall.phaseDownloadingChecksums",
  verifying_archive: "transports.singBoxInstall.phaseVerifyingArchive",
  unpacking: "transports.singBoxInstall.phaseUnpacking",
  checking_staged_version: "transports.singBoxInstall.phaseCheckingStagedVersion",
  installing: "transports.singBoxInstall.phaseInstalling",
  recording_marker: "transports.singBoxInstall.phaseRecordingMarker",
}

export function singBoxInstallPhaseKey(phase: string): string | null {
  return PHASE_KEYS[phase] ?? null
}

export function singBoxInstallBlockerKey(
  blocker: SingBoxInstallCapabilityBlockersItem
): string {
  return `transports.singBoxInstall.blocker.${blocker}`
}

const KNOWN_BLOCKERS: ReadonlySet<string> = new Set([
  "architecture_unsupported",
  "entware_absent",
  "target_not_writable",
  "foreign_binary_present",
  "transports_running",
  "transport_state_unknown",
])

// The install re-measures the router before doing anything, so its refusal is
// newer than whatever the capability query last read - an operator can start a
// tunnel between the two. These blockers are therefore the authoritative ones
// and must be shown, not collapsed into the error message.
//
// A name this build does not know is dropped rather than rendered: it would
// otherwise reach t() as a key that resolves to nothing and print itself.
export function singBoxInstallRefusedBlockers(details: unknown): string[] {
  if (typeof details !== "object" || details === null) return []
  const body = details as Record<string, unknown>
  if (body.reason !== "install_unavailable") return []
  if (!Array.isArray(body.blockers)) return []
  return body.blockers.filter(
    (blocker): blocker is string =>
      typeof blocker === "string" && KNOWN_BLOCKERS.has(blocker)
  )
}

export function singBoxInstallOperationKey(
  operation: SingBoxInstallCapabilityOperation
): string {
  return `transports.singBoxInstall.operation.${operation}`
}

export function singBoxInstallOutcomeKey(
  outcome: SingBoxInstallResultInstallOutcome
): string {
  return `transports.singBoxInstall.outcome.${outcome}`
}

// `marker_not_written` is deliberately neither. The binary is in place and
// correct, so calling it a failure would tell an operator to retry something
// that already worked; calling it a success would hide that the next
// capability read will refuse to touch the binary because the record saying it
// is ours never got written.
export type ResultTone = "success" | "warning" | "failure"

export function singBoxInstallResultTone(
  outcome: SingBoxInstallResultInstallOutcome
): ResultTone {
  if (outcome === "installed") return "success"
  if (outcome === "marker_not_written") return "warning"
  return "failure"
}

// Why the release was refused, when the outcome alone does not say.
//
// Shown for both outcomes that carry a real judgement. `release_refused`
// separates "no checksums file published" from "no such archive in the
// release", and `checksum_mismatch` separates "the digest did not match" from
// "the checksums file had no usable line for this archive" - the first is a
// corrupt or substituted download, the second is a release published in a
// shape this daemon cannot read, and an operator does different things about
// them.
//
// Not shown for the rest: a verdict printed beside a download failure or a
// failed rename would name a judgement that never happened.
export function singBoxInstallVerdictKey(
  result: SingBoxInstallResult
): string | null {
  if (
    result.install_outcome !== "release_refused" &&
    result.install_outcome !== "checksum_mismatch"
  ) {
    return null
  }
  if (!result.release_verdict) return null
  return `transports.singBoxInstall.verdict.${result.release_verdict}`
}

// What the archive actually contained, shown only where it explains the
// outcome. Everywhere else it is noise that invites the reading that the
// install got further than it did.
export function singBoxInstallStagedVersion(
  result: SingBoxInstallResult
): string | null {
  if (result.install_outcome !== "staged_version_mismatch") return null
  return result.staged_version ?? null
}

// What to call a failed install request.
//
// "The install did not start" is only true for the refusal that happens before
// anything is attempted, and the daemon emits that body (reason
// install_unavailable) exclusively from the capability re-check, before the
// maintenance lease and before any work - so a refusal with blockers proves
// nothing started.
//
// Everything else can have failed at any point, including after the binary was
// already replaced: the daemon verifies it still holds the lease AFTER the
// swap (handler_transports.cpp), so a lease lost during a minute-long install
// surfaces here as an error even though the install succeeded. Telling an
// operator it never started would leave them believing their transports still
// run the old binary.
export function singBoxInstallFailureTitleKey(
  refusedBlockerCount: number
): string {
  return refusedBlockerCount > 0
    ? "transports.singBoxInstall.requestRefused"
    : "transports.singBoxInstall.requestFailed"
}

// Whether to warn that the install may have gone through despite the error.
//
// Keyed off the daemon's own terminal frame rather than anything the page
// tracked. `aborted` is published by the RAII reporter exactly when the request
// died with the install already under way - which is the case this warning is
// for. Every other ending names a real outcome and comes back in the response
// body, not as an error.
//
// A refusal that named blockers never began, whatever the stream says.
export function singBoxInstallMayHaveApplied(
  refusedBlockerCount: number,
  lastOutcome: string | null
): boolean {
  return refusedBlockerCount === 0 && lastOutcome === "aborted"
}

export type InstallButtonState = {
  readonly enabled: boolean
  // Why the button cannot be pressed, when it cannot. Rendered near the button
  // rather than only in a list further up: a control disabled for a reason the
  // operator has to go looking for reads as broken.
  readonly disabledReasonKey: string | null
}

export function singBoxInstallButtonState(
  capability: SingBoxInstallCapability | undefined,
  running: boolean,
  pending: boolean
): InstallButtonState {
  if (running) {
    return { enabled: false, disabledReasonKey: "transports.singBoxInstall.running" }
  }
  if (pending) return { enabled: false, disabledReasonKey: null }
  if (!capability) return { enabled: false, disabledReasonKey: null }
  if (!capability.available) {
    // The blockers are listed in full elsewhere in the card. Naming the first
    // one here as well would repeat one reason and imply it is the only one.
    return { enabled: false, disabledReasonKey: "transports.singBoxInstall.unavailable" }
  }
  return { enabled: true, disabledReasonKey: null }
}

// The promises item 7 asks for that this build does not keep. Rendered from
// the capability rather than from a constant here, so a build that starts
// keeping one stops advertising the gap without anybody editing this list.
export function singBoxInstallUnmetPromiseKeys(
  capability: SingBoxInstallCapability
): string[] {
  const unmet: string[] = []
  if (!capability.verified_archive_checksum) {
    unmet.push("transports.singBoxInstall.promiseChecksum")
  }
  if (!capability.signed_release) unmet.push("transports.singBoxInstall.promiseSignature")
  if (!capability.exact_rollback) unmet.push("transports.singBoxInstall.promiseRollback")
  return unmet
}
