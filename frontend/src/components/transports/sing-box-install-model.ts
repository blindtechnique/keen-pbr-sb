// Every decision the sing-box install control makes, as pure functions.
//
// They are here rather than inside the component because what matters about
// this control is which of several honest-but-different things it says, and
// that is worth testing without rendering anything.

import { SingBoxInstallCapabilityBlockersItem } from "@/api/generated/model"
import type {
  SingBoxInstallCapability,
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
  checking_staged_version:
    "transports.singBoxInstall.phaseCheckingStagedVersion",
  installing: "transports.singBoxInstall.phaseInstalling",
  recording_marker: "transports.singBoxInstall.phaseRecordingMarker",
}

export function singBoxInstallPhaseKey(phase: string): string | null {
  return PHASE_KEYS[phase] ?? null
}

export function singBoxInstallBlockerKey(blocker: string): string {
  return `transports.singBoxInstall.blocker.${blocker}`
}

const KNOWN_BLOCKERS: ReadonlySet<string> = new Set(
  Object.values(SingBoxInstallCapabilityBlockersItem)
)

// A blocker name this build cannot translate reaches t() as a key that
// resolves to nothing and prints itself at the operator. Applied to BOTH
// sources of blockers - the capability and the refusal - because a daemon
// newer than this frontend can name one in either, and a filter on one of two
// paths is the same defect as no filter.
export function singBoxInstallDisplayableBlockers(
  blockers: readonly unknown[]
): string[] {
  return blockers.filter(
    (blocker): blocker is string =>
      typeof blocker === "string" && KNOWN_BLOCKERS.has(blocker)
  )
}

// The install re-measures the router before doing anything, so its refusal is
// newer than whatever the capability query last read.
export function singBoxInstallRefusedBlockers(details: unknown): string[] {
  if (typeof details !== "object" || details === null) return []
  const body = details as Record<string, unknown>
  if (body.reason !== "install_unavailable") return []
  if (!Array.isArray(body.blockers)) return []
  return singBoxInstallDisplayableBlockers(body.blockers)
}

// Whether the operator can agree this away. Mirrors
// sing_box_install_awaits_transport_consent in the daemon, which is the
// authority: this copy exists only because the decision has to be made before
// the request is sent, and it is pinned against the generated blocker union so
// a blocker added to the schema cannot silently become consentable here.
export function singBoxInstallNeedsTransportConsent(
  capability: SingBoxInstallCapability | undefined
): boolean {
  if (!capability || capability.available) return false
  const blockers = capability.blockers
  if (blockers.length === 0) return false
  return blockers.every((blocker) => blocker === "transports_running")
}

export type SingBoxButtonAction = "install" | "update"

export type SingBoxButtonState = {
  readonly action: SingBoxButtonAction
  readonly enabled: boolean
  readonly labelKey: string
  // Always present. A disabled control with no explanation reads as broken,
  // and the reason it is disabled is the thing the operator most needs.
  readonly tooltipKey: string
  // Pressing this will stop the operator's tunnels, so they have to be asked
  // first.
  readonly needsConsent: boolean
}

// What the one control says and whether it can be pressed.
//
// There is no card and no menu entry: sing-box is not a feature an operator
// manages, it is the program their transports run on, so the only thing they
// ever need is one button that knows what it would do.
export function singBoxInstallButton(
  capability: SingBoxInstallCapability | undefined,
  installing: boolean,
  pending: boolean
): SingBoxButtonState {
  const installed = Boolean(capability?.installed_version)
  const action: SingBoxButtonAction = installed ? "update" : "install"
  const labelKey = installed
    ? "transports.singBoxInstall.actionUpdate"
    : "transports.singBoxInstall.actionInstall"

  if (installing) {
    return {
      action,
      enabled: false,
      labelKey,
      tooltipKey: "transports.singBoxInstall.tipRunning",
      needsConsent: false,
    }
  }
  if (pending || !capability) {
    return {
      action,
      enabled: false,
      labelKey,
      tooltipKey: "transports.singBoxInstall.tipChecking",
      needsConsent: false,
    }
  }

  // Already on the release this build installs. The button stays visible and
  // says why it does nothing, rather than disappearing - a control that
  // vanishes leaves the operator wondering whether it ever existed.
  if (capability.operation === "reinstall_same_version") {
    return {
      action: "update",
      enabled: false,
      labelKey,
      tooltipKey: "transports.singBoxInstall.tipUpToDate",
      needsConsent: false,
    }
  }

  const needsConsent = singBoxInstallNeedsTransportConsent(capability)
  if (!capability.available && !needsConsent) {
    return {
      action,
      enabled: false,
      labelKey,
      tooltipKey: "transports.singBoxInstall.tipBlocked",
      needsConsent: false,
    }
  }

  return {
    action,
    enabled: true,
    labelKey,
    tooltipKey: needsConsent
      ? "transports.singBoxInstall.tipWillStopTunnels"
      : installed
        ? "transports.singBoxInstall.tipUpdate"
        : "transports.singBoxInstall.tipInstall",
    needsConsent,
  }
}

// `marker_not_written` is deliberately neither. The binary is in place and
// correct, so calling it a failure tells an operator to retry something that
// already worked; calling it a success hides that the next capability read
// will refuse to touch the binary.
export type ResultTone = "success" | "warning" | "failure" | "info"

export function singBoxInstallResultTone(
  outcome: SingBoxInstallResultInstallOutcome,
  durable?: boolean
): ResultTone {
  if (outcome === "installed") return durable === false ? "warning" : "success"
  if (outcome === "marker_not_written") return "warning"
  // The operator stopped it. Reporting their own decision back to them in red
  // would teach them to distrust red, which is the one habit an install report
  // must not build.
  if (outcome === "cancelled") return "info"
  return "failure"
}

export function singBoxInstallDurabilityKey(
  result: SingBoxInstallResult
): string | null {
  return result.durable === false
    ? "transports.singBoxInstall.notDurable"
    : null
}

export function singBoxInstallOutcomeKey(
  outcome: SingBoxInstallResultInstallOutcome
): string {
  return `transports.singBoxInstall.outcome.${outcome}`
}

// Why the release was refused, when the outcome alone does not say. Shown for
// both outcomes that carry a real judgement and for no others: a verdict
// printed beside a download failure would name a judgement that never
// happened.
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
// outcome.
export function singBoxInstallStagedVersion(
  result: SingBoxInstallResult
): string | null {
  if (result.install_outcome !== "staged_version_mismatch") return null
  return result.staged_version ?? null
}

// "The install did not start" is only true for the refusal that happens before
// anything is attempted, and the daemon emits that body exclusively from the
// capability re-check - before the lease and before any work. Everything else
// can have failed at any point, including after the binary was replaced.
export function singBoxInstallFailureTitleKey(
  refusedBlockerCount: number
): string {
  return refusedBlockerCount > 0
    ? "transports.singBoxInstall.requestRefused"
    : "transports.singBoxInstall.requestFailed"
}

// Keyed off the daemon's own terminal frame rather than anything the page
// tracked. `aborted` is published exactly when the request died with the
// install already under way.
export function singBoxInstallMayHaveApplied(
  refusedBlockerCount: number,
  lastOutcome: string | null
): boolean {
  return refusedBlockerCount === 0 && lastOutcome === "aborted"
}

// Transports that were stopped for the install and did not start again. The
// operator has to be told by name: their traffic has nowhere to go, and only
// they can put it back.
export function singBoxInstallLeftDown(result: SingBoxInstallResult): string[] {
  const left = (result as { transports_left_down?: unknown })
    .transports_left_down
  if (!Array.isArray(left)) return []
  return left.filter((tag): tag is string => typeof tag === "string")
}

// How far the current download has got, as a suffix for the phase label.
//
// Two honest shapes and no third. When the server said how big the body is,
// a percentage is meaningful; when it did not - a chunked response has no
// length - the only true statement is how much has arrived. Substituting the
// bytes so far for the missing total would render every chunked download as
// 100%, which is worse than saying nothing.
export function singBoxDownloadLabel(
  received: number | undefined,
  total: number | undefined
): { readonly kind: "percent"; readonly percent: number } | {
  readonly kind: "received"
  readonly megabytes: string
} | null {
  if (typeof received !== "number" || received <= 0) return null
  if (typeof total === "number" && total > 0) {
    // Clamped: a server that under-reports its own length must not produce
    // "137%".
    const percent = Math.min(100, Math.round((received / total) * 100))
    return { kind: "percent", percent }
  }
  return {
    kind: "received",
    megabytes: (received / (1024 * 1024)).toFixed(1),
  }
}
