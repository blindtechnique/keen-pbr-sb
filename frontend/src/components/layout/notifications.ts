import type { ConfigStateResponseListRefreshState } from "@/api/generated/model"
import type { NfqwsUpdateStatus } from "@/api/nfqws"

export type SoftwareUpdateResponse = {
  available?: boolean
  latest?: string
}

export type Notice = {
  id: string
  level: "error" | "warning" | "info"
  text: string
  timestamp?: string
}

type Translate = (key: string, options?: Record<string, unknown>) => string

const MAX_NOTICES = 20

const LEGACY_INTERNAL_RECOVERY_PREFIXES = [
  "safe_exec_pipe_input cmd=",
  "safe_exec_pipe_failed cmd=",
  "Best-effort conntrack cleanup failed",
  "iptables dispatcher chains are missing; recreating the firewall scaffold",
  "Restoring vanished managed route",
] as const

const LEGACY_TRANSIENT_FIREWALL_MARKERS = [
  "(rule: COMMIT)",
  "xtables lock",
  "temporarily unavailable",
  "Device or resource busy",
  "failed to inspect live iptables dispatcher",
  "live iptables generation changed while preparing apply",
  "failed to synchronize live iptables",
] as const

const LEGACY_KEENETIC_REMOTE_ACCESS_INCOMPATIBILITY =
  "Cannot reconcile remote-access firewall state: remote access is unavailable with the Keenetic authentication provider because router credentials would traverse plaintext WAN HTTP"

const SAFE_SRS_CONVERSION =
  /^List '[^'\r\n]+': SRS import is lossy: (?:mapped [1-9]\d* exact domain\(s\) to keen-pbr root-and-subdomain semantics|skipped [1-9]\d* unsupported condition\(s\))(?:; (?:mapped [1-9]\d* exact domain\(s\) to keen-pbr root-and-subdomain semantics|skipped [1-9]\d* unsupported condition\(s\)))*$/

function isDiagnosticOnlyMessage(text: string): boolean {
  // Current builds normalize this old incompatible desired state to durable
  // `enabled: false` and then verify that both owned WAN chains are absent.
  // Keep the historical line in the downloadable log, but do not keep showing
  // a resolved compatibility condition in the bell. A real cleanup failure
  // has different text and remains actionable below.
  if (text === LEGACY_KEENETIC_REMOTE_ACCESS_INCOMPATIBILITY) {
    return true
  }

  // Exact-domain widening and unsupported destination alternatives are
  // successful, bounded SRS conversions. New builds log them at info level;
  // filter historical warning lines as well. Complete skipped rules and
  // invalid domain values remain visible as actionable incidents.
  if (SAFE_SRS_CONVERSION.test(text)) {
    return true
  }

  if (
    LEGACY_INTERNAL_RECOVERY_PREFIXES.some((prefix) => text.startsWith(prefix))
  ) {
    return true
  }

  // A rules-only firewall refresh declining and streaming the lists instead
  // is the designed fallback, and the very apply that logged the line
  // performed the repair. Current builds log the routine causes (an NDMS
  // netfilter rebuild) at info level and use different wording
  // ("unexpected refusal") for causes that deserve the bell; these two
  // prefixes are what older builds wrote at warn for both, so they are
  // history, not a claim about the present.
  if (
    text.startsWith("Set-reusing firewall refresh is not possible") ||
    text.startsWith("Set-reusing firewall refresh was refused by the backend")
  ) {
    return true
  }

  if (
    text.startsWith("Runtime iproute and firewall refresh failed:") ||
    text.startsWith("Error rebuilding routing/firewall after urltest change:")
  ) {
    return LEGACY_TRANSIENT_FIREWALL_MARKERS.some((marker) =>
      text.includes(marker)
    )
  }

  return (
    (text.startsWith("Firewall retry ") && text.includes(" failed:")) ||
    (text.startsWith("Urltest '") && text.includes(" was rolled back;"))
  )
}

// Which lists a refresh-outcome warning is about, or null when the line is not
// a refresh outcome at all.
//
// Deliberately narrow. "List 'x': could not persist refresh failure status"
// also names a list, but its truth is not what last_error records - that
// warning fires precisely when the daemon could not write last_error, so
// clearing it against an empty state would hide the one failure that erased
// its own evidence.
export function listsInRefreshOutcome(text: string): string[] | null {
  const single = text.match(/^List '([^']+)': failed to refresh /)
  if (single) {
    return [single[1]]
  }
  if (!text.startsWith("Lists refresh")) {
    return null
  }
  const summary = text.match(/list\(s\): (.+)$/)
  if (!summary) {
    return null
  }
  const names = summary[1]
    .split(",")
    .map((name) => name.trim())
    .filter(Boolean)
  return names.length > 0 ? names : null
}

// A logged warning records a moment; a notification claims something is wrong
// at this one. For list refresh the daemon publishes the current answer per
// list, and the schema is explicit that last_error is "omitted after a
// successful attempt" - so a warning about a list the daemon now reports as
// healthy is history. This is the same source the Lists page already trusts,
// which is why that page stayed silent while the bell kept accusing.
export function refreshOutcomeIsResolved(
  names: readonly string[],
  state: ConfigStateResponseListRefreshState | undefined
): boolean {
  if (!state) {
    return false
  }
  // A name the daemon no longer reports is not evidence of recovery: the map
  // carries only URL-backed lists still present in the returned config.
  return names.every((name) => {
    const entry = state[name]
    return entry !== undefined && !entry.last_error?.trim()
  })
}

export function collectNotices(
  lines: string[],
  softwareUpdate: SoftwareUpdateResponse | undefined,
  nfqwsUpdate: NfqwsUpdateStatus | undefined,
  listRefreshState: ConfigStateResponseListRefreshState | undefined,
  dismissedUntil: number,
  dismissedIds: ReadonlySet<string>,
  t: Translate
): Notice[] {
  const notices: Notice[] = []

  addSyntheticNotice(
    notices,
    softwareUpdate?.available && softwareUpdate.latest
      ? {
          id: `system-update-${softwareUpdate.latest}`,
          level: "info",
          text: t("notifications.updateAvailable", {
            version: softwareUpdate.latest,
          }),
        }
      : undefined,
    dismissedIds
  )

  const nfqwsInstalled =
    nfqwsUpdate?.installed ??
    Boolean(nfqwsUpdate?.current && nfqwsUpdate.current.trim())
  addSyntheticNotice(
    notices,
    nfqwsInstalled && nfqwsUpdate?.available && nfqwsUpdate.latest
      ? {
          id: `nfqws-update-${nfqwsUpdate.latest}`,
          level: "info",
          text: t("notifications.nfqwsUpdateAvailable", {
            version: nfqwsUpdate.latest,
          }),
        }
      : undefined,
    dismissedIds
  )

  // Newest first: the tail of the file is the most recent.
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    if (notices.length >= MAX_NOTICES) {
      break
    }
    const line = lines[index]
    const match = line.match(/^(\S+ \S+)\s+\[([EW])\]\s+(.*)$/)
    if (!match) {
      continue
    }
    const [, timestamp, marker, text] = match
    // Older builds recorded automatic recovery as warnings/errors. Keep those
    // historical details in the downloadable journal without showing them as
    // current, actionable notifications after an upgrade.
    if (isDiagnosticOnlyMessage(text)) {
      continue
    }
    // Already fixed: the daemon's current per-list state outranks what the log
    // remembers about a night when it was broken.
    const refreshedLists = listsInRefreshOutcome(text)
    if (
      refreshedLists &&
      refreshOutcomeIsResolved(refreshedLists, listRefreshState)
    ) {
      continue
    }
    // The log keeps its history; dismissing only hides what was already read.
    if (
      dismissedUntil > 0 &&
      Date.parse(timestamp.replace(" ", "T")) <= dismissedUntil
    ) {
      continue
    }
    notices.push({
      id: `${timestamp}-${index}`,
      level: marker === "E" ? "error" : "warning",
      text,
      timestamp,
    })
  }

  return notices
}

function addSyntheticNotice(
  notices: Notice[],
  notice: Notice | undefined,
  dismissedIds: ReadonlySet<string>
) {
  if (notice && !dismissedIds.has(notice.id)) {
    notices.push(notice)
  }
}
