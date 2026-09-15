import { postRoutingTest } from "@/api/generated/keen-api"
import type {
  RoutingProbeOptions,
  RoutingTestResponse,
} from "@/api/generated/model"
import i18n from "@/i18n"
import { sanitizeRoutingTarget } from "./sanitize-routing-target"

export const MAX_BATCH_PROBES = 12
export type BatchPath = Pick<RoutingProbeOptions, "path" | "outbound"> & {
  label: string
}
export type BatchItem = {
  target: string
  options: RoutingProbeOptions
  pathLabel: string
}
export type BatchRow = BatchItem & {
  state: "queued" | "running" | "done" | "failed" | "cancelled"
  startedAt?: string
  finishedAt?: string
  response?: RoutingTestResponse
  error?: string
}

export function batchTarget(
  input: string
): { target: string; url: string } | null {
  const value = input.trim()
  if (!value || /[\s\\]/.test(value)) return null
  for (const character of value) {
    const code = character.charCodeAt(0)
    if (code < 32 || code === 127) return null
  }
  const target = sanitizeRoutingTarget(value)
  if (!target || target.includes("%")) return null
  try {
    const host = target.includes(":") ? `[${target}]` : target
    const url = new URL(
      value.includes("://")
        ? value
        : value === target
          ? `https://${host}/`
          : `https://${value}`
    )
    if (
      url.protocol !== "https:" ||
      url.port ||
      url.username ||
      url.password ||
      url.hash
    )
      return null
    // URL normalizes IDN, bracketed IPv6 and a default :443 consistently.
    url.hostname = host
    return { target, url: url.href }
  } catch {
    return null
  }
}

export function makeBatchPlan(
  text: string,
  paths: readonly BatchPath[],
  families: readonly ("ipv4" | "ipv6")[]
): { items: BatchItem[]; error?: "targets" | "selection" | "limit" } {
  if (text.length > MAX_BATCH_PROBES * 2049)
    return { items: [], error: "limit" }
  const lines = [
    ...new Set(
      text
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean)
    ),
  ]
  const targets = lines.map(batchTarget)
  if (
    !targets.length ||
    targets.some((item) => !item || item.url.length > 2048)
  )
    return { items: [], error: "targets" }
  if (!paths.length || !families.length)
    return { items: [], error: "selection" }
  if (targets.length * paths.length * families.length > MAX_BATCH_PROBES)
    return { items: [], error: "limit" }
  return {
    items: targets.flatMap((item) =>
      paths.flatMap((path) =>
        families.map((family) => ({
          target: item!.target,
          options: {
            url: item!.url,
            family,
            path: path.path,
            ...(path.outbound ? { outbound: path.outbound } : {}),
          },
          pathLabel: path.label,
        }))
      )
    ),
  }
}

async function requestOne(item: BatchItem): Promise<RoutingTestResponse> {
  // No mutation retries, cache, browser/CDN parallel requests or registry calls.
  const response = await postRoutingTest(
    { target: item.target, http_probe: item.options },
    {
      signal: AbortSignal.timeout(60_000),
    }
  )
  if (response.status !== 200)
    throw new Error(i18n.t("overview.batch.invalidResponse"))
  return response.data
}

function pause(signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.resolve()
  return new Promise((resolve) => {
    const finish = () => {
      clearTimeout(timer)
      signal.removeEventListener("abort", finish)
      resolve()
    }
    const timer = setTimeout(finish, 1000)
    signal.addEventListener("abort", finish, { once: true })
  })
}

export async function runRoutingBatch(
  items: readonly BatchItem[],
  signal: AbortSignal,
  onRows: (rows: BatchRow[]) => void,
  request = requestOne,
  between = pause,
  now = () => new Date().toISOString()
): Promise<BatchRow[]> {
  if (!items.length || items.length > MAX_BATCH_PROBES)
    throw new Error(i18n.t("overview.batch.invalidSize"))
  const rows: BatchRow[] = items.map((item) => ({
    ...item,
    options: { ...item.options },
    state: "queued",
  }))
  const publish = () => onRows(rows.map((row) => ({ ...row })))
  let apiFailed = false
  publish()
  for (const row of rows) {
    if (signal.aborted || apiFailed) {
      row.state = "cancelled"
      continue
    }
    row.state = "running"
    row.startedAt = now()
    publish()
    try {
      const response = await request(row)
      if (
        response.target !== row.target ||
        !Array.isArray(response.resolved_ips) ||
        !response.resolved_ips.every((ip) => typeof ip === "string") ||
        !response.http_probe ||
        response.http_probe.method !== "HEAD" ||
        response.http_probe.scope !== "router" ||
        response.http_probe.url !== row.options.url
      )
        throw new Error(i18n.t("overview.batch.invalidResponse"))
      row.response = response
      row.state = "done"
    } catch (error) {
      row.state = "failed"
      row.error =
        error instanceof Error
          ? error.message
          : typeof error === "object" && error && "message" in error
            ? String(error.message)
            : i18n.t("overview.batch.apiFailed")
      // Failure to reach the diagnostic API is not a failed website. Do not
      // hammer a busy/offline/older service with the remaining queue.
      apiFailed = true
    }
    row.finishedAt = now()
    publish()
    if (row !== rows[rows.length - 1] && !apiFailed) await between(signal)
  }
  publish()
  return rows
}

export function batchOutcome(
  row: BatchRow
): "answered" | "httpError" | "dns" | "noAddress" | "failed" | "unavailable" {
  if (row.state !== "done" || !row.response) return "unavailable"
  if (row.response.dns_error) return "dns"
  const probe = row.response.http_probe
  if (!probe?.ip) return "noAddress"
  if (probe.status === "answered")
    return (probe.http_status ?? 0) >= 400 ? "httpError" : "answered"
  return probe.status === "failed" ? "failed" : "unavailable"
}

export function batchReport(rows: readonly BatchRow[]) {
  // Deliberate export only; no localStorage, config, clients/conntrack or
  // unrelated lists/rules from the broad routing response in the report.
  return {
    format: "keen-pbr-site-comparison-v1",
    scope: "router",
    method: "HEAD",
    rows: rows.map((row) => ({
      target: row.target,
      options: row.options,
      pathLabel: row.pathLabel,
      state: row.state,
      startedAt: row.startedAt,
      finishedAt: row.finishedAt,
      error: row.error,
      configScope: row.response?.config_scope,
      unappliedDraft: row.response?.unapplied_draft,
      dns: row.response
        ? {
            source: row.response.dns_source,
            server: row.response.dns_server,
            error: row.response.dns_error,
            addresses: row.response.resolved_ips,
          }
        : undefined,
      http: row.response?.http_probe,
    })),
  }
}
