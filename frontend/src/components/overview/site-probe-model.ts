import type { NfqwsActionResult } from "@/api/generated/model"

export type SiteProbeFailure =
  | "browser"
  | "timeout"
  | "dns"
  | "tls"
  | "connection"
  | "sizeLimit"
  | "request"
  | "invalidResponse"
  | "unknown"

export type SiteProbeResult =
  | { status: "responded"; httpStatus?: number }
  | { status: "unconfirmed"; reason: SiteProbeFailure; detail?: string }

export type SiteProbeState = { status: "idle" | "checking" } | SiteProbeResult

function errorText(error: unknown): string | undefined {
  const value = error instanceof Error ? error.message : error
  return typeof value === "string" && value.trim() ? value.trim() : undefined
}

/** A failed API request says nothing about the website being checked. */
export function routerProbeRequestFailure(error: unknown): SiteProbeResult {
  return { status: "unconfirmed", reason: "request", detail: errorText(error) }
}

export function routerProbeResult(
  response: NfqwsActionResult
): SiteProbeResult {
  if (typeof response.reachable !== "boolean") {
    return { status: "unconfirmed", reason: "invalidResponse" }
  }
  if (response.reachable) return { status: "responded" }

  const detail = errorText(response.error)
  // The backend's HTTP client throws for 4xx/5xx, but those codes are still
  // evidence of an HTTP response. Do not classify an API's HTTP 401 this way.
  const httpStatus = detail?.match(/^HTTP error ([45]\d{2})$/)?.[1]
  if (httpStatus) return { status: "responded", httpStatus: Number(httpStatus) }

  let reason: SiteProbeFailure = "unknown"
  if (/timed? ?out|timeout/i.test(detail ?? "")) reason = "timeout"
  else if (/resolve|resolution|name or service not known/i.test(detail ?? ""))
    reason = "dns"
  else if (/ssl|tls|certificate/i.test(detail ?? "")) reason = "tls"
  else if (
    /connect|no route to host|network is unreachable|empty reply/i.test(
      detail ?? ""
    )
  )
    reason = "connection"
  else if (
    /size limit|too large|maximum.*size|exceeds.*size/i.test(detail ?? "")
  )
    reason = "sizeLimit"
  return { status: "unconfirmed", reason, detail }
}

export async function probeBrowserReachability(
  url: string
): Promise<SiteProbeResult> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 10_000)
  try {
    const response = await fetch(url, {
      cache: "no-store",
      credentials: "omit",
      mode: "no-cors",
      referrerPolicy: "no-referrer",
      signal: controller.signal,
    })
    await response.body?.cancel().catch(() => undefined)
    return {
      status: "responded",
      ...(response.status >= 400 ? { httpStatus: response.status } : {}),
    }
  } catch {
    // Browsers intentionally hide the distinction between network failures
    // and security restrictions (mixed content, CSP, etc.) for this request.
    return {
      status: "unconfirmed",
      reason: controller.signal.aborted ? "timeout" : "browser",
    }
  } finally {
    clearTimeout(timeout)
  }
}
