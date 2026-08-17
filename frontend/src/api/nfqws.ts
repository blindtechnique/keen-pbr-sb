import { queryOptions } from "@tanstack/react-query"

import { fetchWithStepUp } from "@/lib/step-up"

export type NfqwsActionResult = {
  ok: boolean
  output?: string
  strategy_created?: string
}

export type NfqwsUpdateStatus = {
  ok: boolean
  installed?: boolean
  current: string
  latest: string
  available: boolean
  release_url?: string
  package_metadata_verified?: boolean
  blocked_reason?: string
  transaction_state?: string
}

export type NfqwsUpdateNotice = "degraded" | "available" | "up_to_date"

// `available: false` is not always an up-to-date verdict. After a captured
// file restore the backend deliberately withholds current/latest because opkg
// metadata may describe a different binary. Keep that fail-closed state ahead
// of every optimistic toast, including if a malformed response also says an
// update is available.
export function classifyNfqwsUpdateNotice(
  status: NfqwsUpdateStatus
): NfqwsUpdateNotice {
  if (
    status.package_metadata_verified === false ||
    Boolean(status.blocked_reason?.trim())
  ) {
    return "degraded"
  }
  return status.available ? "available" : "up_to_date"
}

export type NfqwsRotatorHistogramEntry = {
  value: number
  targets: number
}

export type NfqwsRotatorPoolState = {
  tracked_targets: number
  active_slot: number | null
  slot_count: number | null
  pending_failures: number | null
  max_pending_failures: number | null
  active_slot_histogram: NfqwsRotatorHistogramEntry[]
  slot_count_histogram: NfqwsRotatorHistogramEntry[]
  pending_failure_histogram: NfqwsRotatorHistogramEntry[]
}

export type NfqwsRotatorState = {
  schema: 1
  status: "ready" | "warming" | "stale" | "unsupported"
  observed_at: number | null
  truncated: boolean
  pools: Record<string, NfqwsRotatorPoolState>
}

export const NFQWS_UPDATE_QUERY_KEY = ["nfqws", "update"] as const
export const NFQWS_UPDATE_INTERVAL_MS = 30 * 60 * 1_000

const MAX_VALIDATION_ERRORS = 5
const MAX_VALIDATION_PATH_LENGTH = 160
const MAX_VALIDATION_MESSAGE_LENGTH = 480

function boundedText(value: string, limit: number): string {
  const normalized = value.trim()
  return normalized.length <= limit
    ? normalized
    : `${normalized.slice(0, limit - 1)}…`
}

function validationErrorDetails(payload: unknown): string[] {
  if (!payload || typeof payload !== "object") return []
  const entries = (payload as { validation_errors?: unknown }).validation_errors
  if (!Array.isArray(entries)) return []

  const details: string[] = []
  for (const entry of entries) {
    if (details.length >= MAX_VALIDATION_ERRORS) break
    if (!entry || typeof entry !== "object") continue
    const path = (entry as { path?: unknown }).path
    const message = (entry as { message?: unknown }).message
    if (typeof message !== "string" || message.trim().length === 0) continue

    const renderedPath =
      typeof path === "string"
        ? boundedText(path, MAX_VALIDATION_PATH_LENGTH)
        : ""
    const renderedMessage = boundedText(message, MAX_VALIDATION_MESSAGE_LENGTH)
    details.push(
      renderedPath
        ? `- ${renderedPath}: ${renderedMessage}`
        : `- ${renderedMessage}`
    )
  }
  return details
}

export async function nfqwsAction<T = NfqwsActionResult>(
  payload: Record<string, unknown>
): Promise<T> {
  const response = await fetchWithStepUp("/api/nfqws", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  })
  const data = await response.json().catch(() => ({}))
  if (!response.ok || data.ok === false) {
    const message =
      data.error ??
      data.message ??
      data.output?.trim() ??
      `HTTP ${response.status}`
    const details = validationErrorDetails(data)
    throw new Error(
      details.length > 0 ? `${message}\n${details.join("\n")}` : message
    )
  }
  return data as T
}

export function nfqwsUpdateQueryOptions() {
  return queryOptions({
    queryKey: NFQWS_UPDATE_QUERY_KEY,
    queryFn: () => nfqwsAction<NfqwsUpdateStatus>({ action: "check_update" }),
    retry: false,
    staleTime: NFQWS_UPDATE_INTERVAL_MS,
    refetchInterval: NFQWS_UPDATE_INTERVAL_MS,
    refetchIntervalInBackground: false,
    refetchOnWindowFocus: false,
  })
}
