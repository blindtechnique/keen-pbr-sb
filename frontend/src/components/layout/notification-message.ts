import { getOperationErrorPresentation } from "@/lib/api-errors"

export type NotificationMessageLevel = "error" | "warning" | "info"
export type NotificationMessagePresentation = {
  text: string
  details?: string
}
export type NotificationMessageTranslate = (
  key: string,
  options?: Record<string, unknown>
) => string

// Presentation only. The caller decides whether a log incident is current,
// resolved or dismissed before asking for its readable summary. A log record
// describes that operation, not the current health of the service.
export function presentNotificationMessage(
  rawText: string,
  level: NotificationMessageLevel,
  t: NotificationMessageTranslate
): NotificationMessagePresentation {
  const raw = rawText.trim()
  const summary = summarizeKnownMessage(raw, t)
  const text =
    summary ??
    (level === "error"
      ? t("notifications.messages.unknownError")
      : level === "warning"
        ? t("notifications.messages.unknownWarning")
        : t("notifications.messages.unknownInfo"))
  return { text, ...(raw ? { details: rawText } : {}) }
}

function summarizeKnownMessage(
  raw: string,
  t: NotificationMessageTranslate
): string | undefined {
  if (raw === "Subscription auto-refresh failed") {
    return t("notifications.messages.subscriptionRefreshFailed")
  }
  let match =
    /^Urltest '([^'\r\n]+)' candidate was rejected; the previous selection remains verified: .+$/.exec(
      raw
    )
  if (match)
    return t("notifications.messages.groupSwitchRejected", { name: match[1] })

  match =
    /^Urltest '([^'\r\n]+)' candidate and exact rollback were not verified: .+$/.exec(
      raw
    )
  if (match)
    return t("notifications.messages.groupSwitchUnverified", { name: match[1] })

  if (
    /^Config apply failed: staged configuration changed before candidate admission; rolled_back=false; runtime_unchanged=true$/.test(
      raw
    )
  ) {
    return t("notifications.messages.configDraftChanged")
  }
  if (
    /^Config apply failed: .+; rolled_back=(?:true|false); runtime_unchanged=(?:true|false)$/.test(
      raw
    )
  ) {
    return t("notifications.messages.configApplyFailed")
  }
  if (
    /^Config save recovery required: .+; apply: .+; recovery: .+transport manager restart failed$/.test(
      raw
    )
  ) {
    return t("notifications.messages.configRecoveryVpnRestartFailed")
  }
  if (
    /^Config save recovery required: .+; apply: .+; recovery: .+$/.test(raw)
  ) {
    return t("notifications.messages.configRecoveryUnverified")
  }
  if (/^Cannot quiesce routing after unsafe config save: .+$/.test(raw)) {
    return t("notifications.messages.routingStopFailed")
  }
  if (
    /^Delayed runtime firewall refresh failed: candidate rule has no owned route anchor or external table authority(?:\.|$)/.test(
      raw
    )
  ) {
    return t("notifications.messages.routingAnchorMissing")
  }
  if (
    /^(?:Delayed runtime firewall refresh failed|Runtime iproute and firewall refresh failed|Error rebuilding routing\/firewall after urltest change): .+$/.test(
      raw
    )
  ) {
    return t("notifications.messages.firewallRefreshFailed")
  }
  if (
    raw === "control response failed: control socket write failed: Broken pipe"
  ) {
    return t("notifications.messages.controlResponseInterrupted")
  }

  match = /^List '([^'\r\n]+)': failed to refresh (\S+): (.+)$/.exec(raw)
  if (match) return summarizeListRefresh(match[1], match[2], match[3], t)

  match =
    /^Lists refresh(?: \([^)\r\n]+\))?: (?:failed list\(s\)|failed to refresh list\(s\)): (.+)$/.exec(
      raw
    )
  if (match)
    return t("notifications.messages.listsRefreshFailed", { names: match[1] })

  match =
    /^List '([^'\r\n]+)': could not persist refresh failure status: (.+)$/.exec(
      raw
    )
  if (match) {
    return /(?:No space left on device|disk full)/i.test(match[2])
      ? t("notifications.messages.listStatusDiskFull", { name: match[1] })
      : t("notifications.messages.listStatusSaveFailed", { name: match[1] })
  }
  match = /^List '([^'\r\n]+)': SRS import is lossy: (.+)$/.exec(raw)
  if (
    match &&
    /skipped [1-9]\d* (?:rule\(s\)|invalid domain value\(s\))/.test(match[2])
  ) {
    return t("notifications.messages.listSrsIncomplete", { name: match[1] })
  }

  if (
    /^Meta\/WhatsApp (?:UDP\/443 policy state is degraded|messages-first recovery remains degraded): .+$/.test(
      raw
    )
  ) {
    return t("notifications.messages.metaPolicyUnverified")
  }
  if (/^PPE de-offload reconciliation degraded: .+$/.test(raw)) {
    return t("notifications.messages.accelerationRulesUnverified")
  }
  match =
    /^Tunnel probe routed (\d+) host\(s\) through '([^'\r\n]+)': .+$/.exec(raw)
  if (match)
    return t("notifications.messages.tunnelProbeRouted", {
      count: Number(match[1]),
      name: match[2],
    })
  if (/^Tunnel probe pass failed: .+$/.test(raw)) {
    return t("notifications.messages.tunnelProbeFailed")
  }
  match = /^System resolver hook failed \(exit code: (\d+)\): .*$/.exec(raw)
  if (match)
    return t("notifications.messages.resolverHookFailed", { code: match[1] })

  // Reuse only stable whole-message API classifications. Never extract a
  // nested "busy" or rollback phrase from an otherwise unknown log line.
  switch (getOperationErrorPresentation(raw)?.kind) {
    case "busy":
      return t("notifications.messages.operationWasBusy")
    case "draft_pending":
      return t("notifications.messages.operationHadDraft")
    case "recovery_required":
      return t("operationErrors.recovery_required")
    case "validation":
      return t("operationErrors.validation")
    case "unauthenticated":
      return t("notifications.messages.operationNeededLogin")
    case "reauthentication_required":
      return t("notifications.messages.operationNeededLogin")
    case "subscription_unavailable":
      return t("operationErrors.subscription_unavailable")
    case "service_unavailable":
      return t("notifications.messages.vpnServiceUnavailable")
    case "network":
      return t("notifications.messages.responseUnavailable")
    default:
      return undefined
  }
}

function summarizeListRefresh(
  name: string,
  endpoint: string,
  reason: string,
  t: NotificationMessageTranslate
): string {
  let source = endpoint
  try {
    source = new URL(endpoint).host
  } catch {
    /* Preserve a non-URL source as reported. */
  }
  const params = { name, source }

  if (/^Could not resolve host(?:: .+)?$/i.test(reason)) {
    return t("notifications.messages.listDnsFailed", params)
  }
  if (
    /^(?:Operation timed out|Timeout was reached|Connection timed out)(?:[ :].*)?$/i.test(
      reason
    )
  ) {
    return t("notifications.messages.listTimedOut", params)
  }
  if (
    /^(?:Failed to connect to .+|Could not connect to server|Connection refused)$/i.test(
      reason
    )
  ) {
    return t("notifications.messages.listConnectionFailed", params)
  }
  const http = /^HTTP(?: error)? (\d{3})$/.exec(reason)
  if (http)
    return t("notifications.messages.listHttpFailed", {
      ...params,
      code: http[1],
    })
  if (
    /^HTTP 304 received without a matching local cache validator$/.test(reason)
  ) {
    return t("notifications.messages.listNotModifiedWithoutCache", params)
  }
  let shrink =
    /^the update decoded (\d+) entries against (\d+) cached, keeping \d+% - below the \d+% this source is allowed to lose; keeping the cached list$/.exec(
      reason
    )
  if (shrink)
    return t("notifications.messages.listShrinkKept", {
      name,
      previous: shrink[2],
      candidate: shrink[1],
    })
  shrink =
    /^the update decoded no entries at all while the cached list has (\d+); keeping the cached list$/.exec(
      reason
    )
  if (shrink)
    return t("notifications.messages.listEmptyKept", {
      name,
      previous: shrink[1],
    })
  if (
    reason ===
    "SRS contains no safely representable domain, domain suffix or IP/CIDR entries"
  ) {
    return t("notifications.messages.listSrsUnsupported", params)
  }
  if (reason === "no configured download outbound has a routing mark") {
    return t("notifications.messages.listDownloadRouteUnavailable", params)
  }
  return t("notifications.messages.listRefreshFailed", params)
}
