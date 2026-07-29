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

const BENIGN_SRS_EXACT_DOMAIN_MAPPING =
  /^List '[^'\r\n]+': SRS import is lossy: mapped [1-9]\d* exact domain\(s\) to keen-pbr root-and-subdomain semantics$/

function isDiagnosticOnlyMessage(text: string): boolean {
  // Mapping an exact SRS domain to keen-pbr's root-and-subdomain semantics is
  // the only expected conversion warning. Keep it in the journal, but do not
  // treat it as an incident. Any additional clause means that data was skipped
  // or changed materially and must remain visible in the notification bell.
  if (BENIGN_SRS_EXACT_DOMAIN_MAPPING.test(text)) {
    return true
  }

  if (
    LEGACY_INTERNAL_RECOVERY_PREFIXES.some((prefix) =>
      text.startsWith(prefix)
    )
  ) {
    return true
  }

  if (
    text.startsWith("Runtime iproute and firewall refresh failed:") ||
    text.startsWith(
      "Error rebuilding routing/firewall after urltest change:"
    )
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

export function collectNotices(
  lines: string[],
  softwareUpdate: SoftwareUpdateResponse | undefined,
  nfqwsUpdate: NfqwsUpdateStatus | undefined,
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
