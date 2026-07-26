export type JsonPrimitive = boolean | number | string | null

export type JsonValue =
  | JsonPrimitive
  | JsonValue[]
  | { [key: string]: JsonValue }

export type FetchLike = (
  input: RequestInfo | URL,
  init?: RequestInit
) => Promise<Response>

export const LOG_DIAGNOSTICS_ENDPOINTS = {
  router: "/api/system/router",
  logs: "/api/logs?lines=5000",
  service_health: "/api/health/service",
  routing_health: "/api/health/routing",
  runtime_outbounds: "/api/runtime/outbounds",
  runtime_interfaces: "/api/runtime/interfaces",
  transports: "/api/transports",
  config: "/api/config",
} as const

export type LogDiagnosticsSectionName = keyof typeof LOG_DIAGNOSTICS_ENDPOINTS

export type DiagnosticSectionCapture =
  | {
      ok: true
      endpoint: string
      http_status: number
      data: JsonValue
    }
  | {
      ok: false
      endpoint: string
      http_status: number | null
      error: string
      details?: JsonValue
    }

export type LogDiagnosticsBundle = {
  format_version: 1
  generated_at: string
  privacy: {
    list_contents_redacted: boolean
    contains_log_lines: true
  }
  sections: Record<LogDiagnosticsSectionName, DiagnosticSectionCapture>
}

export type LogTail = {
  path: string | null
  exists: boolean | null
  size_bytes: number | null
  lines: string[]
}

export type CollectLogDiagnosticsOptions = {
  fetcher?: FetchLike
  generatedAt?: Date
  includeListContents?: boolean
  requestTimeoutMs?: number
}

const defaultFetch: FetchLike = (input, init) => fetch(input, init)

export async function collectLogDiagnostics({
  fetcher = defaultFetch,
  generatedAt = new Date(),
  includeListContents = false,
  requestTimeoutMs = 10_000,
}: CollectLogDiagnosticsOptions = {}): Promise<LogDiagnosticsBundle> {
  const capture = (name: LogDiagnosticsSectionName) =>
    captureJsonEndpoint(
      LOG_DIAGNOSTICS_ENDPOINTS[name],
      fetcher,
      requestTimeoutMs
    )

  const [
    router,
    logs,
    serviceHealth,
    routingHealth,
    runtimeOutbounds,
    runtimeInterfaces,
    transports,
    rawConfig,
  ] = await Promise.all([
    capture("router"),
    capture("logs"),
    capture("service_health"),
    capture("routing_health"),
    capture("runtime_outbounds"),
    capture("runtime_interfaces"),
    capture("transports"),
    capture("config"),
  ])
  const config = includeListContents
    ? rawConfig
    : redactListContentsCapture(rawConfig)

  return {
    format_version: 1,
    generated_at: generatedAt.toISOString(),
    privacy: {
      list_contents_redacted: !includeListContents,
      contains_log_lines: true,
    },
    sections: {
      router,
      logs,
      service_health: serviceHealth,
      routing_health: routingHealth,
      runtime_outbounds: runtimeOutbounds,
      runtime_interfaces: runtimeInterfaces,
      transports,
      config,
    },
  }
}

function redactListContentsCapture(
  capture: DiagnosticSectionCapture
): DiagnosticSectionCapture {
  if (!capture.ok || !isRecord(capture.data)) {
    return capture
  }

  const wrappedConfig = isRecord(capture.data.config)
    ? capture.data.config
    : capture.data
  const lists = wrappedConfig.lists
  if (!isRecord(lists)) {
    return capture
  }

  const redactedLists: Record<string, JsonValue> = {}
  for (const [name, rawList] of Object.entries(lists)) {
    if (!isRecord(rawList)) {
      redactedLists[name] = rawList as JsonValue
      continue
    }

    redactedLists[name] = {
      ...rawList,
      ...(typeof rawList.url === "string" ? { url: "<redacted>" } : {}),
      ...(Array.isArray(rawList.domains) ? { domains: ["<redacted>"] } : {}),
      ...(Array.isArray(rawList.ip_cidrs) ? { ip_cidrs: ["<redacted>"] } : {}),
    }
  }

  return {
    ...capture,
    data: {
      ...capture.data,
      ...(wrappedConfig === capture.data
        ? { lists: redactedLists }
        : {
            config: {
              ...wrappedConfig,
              lists: redactedLists,
            },
          }),
    },
  }
}

export async function loadLogTail(
  fetcher: FetchLike = defaultFetch,
  signal?: AbortSignal
): Promise<LogTail> {
  const endpoint = "/api/logs?lines=1000"
  const response = await fetcher(endpoint, jsonRequest(signal))
  const parsed = await parseResponseBody(response)

  if (!response.ok) {
    throw new Error(errorMessage(response.status, parsed))
  }
  if (!parsed.ok || !isRecord(parsed.value)) {
    throw new Error(parsed.ok ? "Invalid log response" : parsed.error)
  }

  const lines = parsed.value.lines
  if (!Array.isArray(lines) || !lines.every(isString)) {
    throw new Error("Invalid log response: lines must be an array of strings")
  }

  return {
    path: optionalString(parsed.value.path),
    exists: optionalBoolean(parsed.value.exists),
    size_bytes: optionalNumber(parsed.value.size_bytes),
    lines,
  }
}

export function errorText(error: unknown): string {
  if (error instanceof Error && error.message) {
    return error.message
  }
  return String(error)
}

async function captureJsonEndpoint(
  endpoint: string,
  fetcher: FetchLike,
  timeoutMs: number
): Promise<DiagnosticSectionCapture> {
  let response: Response
  const controller = new AbortController()
  let timeout: ReturnType<typeof setTimeout> | undefined
  try {
    response = await Promise.race([
      fetcher(endpoint, jsonRequest(controller.signal)),
      new Promise<never>((_, reject) => {
        timeout = setTimeout(
          () => {
            controller.abort()
            reject(new Error(`Request timed out after ${timeoutMs} ms`))
          },
          Math.max(1, timeoutMs)
        )
      }),
    ])
  } catch (error) {
    return {
      ok: false,
      endpoint,
      http_status: null,
      error: errorText(error),
    }
  } finally {
    if (timeout) {
      clearTimeout(timeout)
    }
  }

  const parsed = await parseResponseBody(response)
  if (!response.ok) {
    return {
      ok: false,
      endpoint,
      http_status: response.status,
      error: errorMessage(response.status, parsed),
      ...(parsed.ok ? { details: parsed.value } : {}),
    }
  }
  if (!parsed.ok) {
    return {
      ok: false,
      endpoint,
      http_status: response.status,
      error: parsed.error,
    }
  }

  return {
    ok: true,
    endpoint,
    http_status: response.status,
    data: parsed.value,
  }
}

function jsonRequest(signal?: AbortSignal): RequestInit {
  return {
    method: "GET",
    cache: "no-store",
    headers: {
      Accept: "application/json",
    },
    ...(signal ? { signal } : {}),
  }
}

type ParsedBody =
  | {
      ok: true
      value: JsonValue
    }
  | {
      ok: false
      error: string
    }

async function parseResponseBody(response: Response): Promise<ParsedBody> {
  let body: string
  try {
    body = await response.text()
  } catch (error) {
    return {
      ok: false,
      error: `Cannot read response: ${errorText(error)}`,
    }
  }

  if (!body.trim()) {
    return { ok: true, value: null }
  }

  try {
    const parsed: unknown = JSON.parse(body)
    if (!isJsonValue(parsed)) {
      return {
        ok: false,
        error: "Response contains a value that cannot be stored as JSON",
      }
    }
    return { ok: true, value: parsed }
  } catch (error) {
    return {
      ok: false,
      error: `Invalid JSON response: ${errorText(error)}`,
    }
  }
}

function errorMessage(status: number, parsed: ParsedBody): string {
  if (parsed.ok && isRecord(parsed.value)) {
    const error = parsed.value.error
    if (typeof error === "string" && error) {
      return error
    }

    const message = parsed.value.message
    if (typeof message === "string" && message) {
      return message
    }
  }

  return parsed.ok ? `HTTP ${status}` : `HTTP ${status}: ${parsed.error}`
}

function isJsonValue(value: unknown): value is JsonValue {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "number" ||
    typeof value === "string"
  ) {
    return true
  }
  if (Array.isArray(value)) {
    return value.every(isJsonValue)
  }
  if (isRecord(value)) {
    return Object.values(value).every(isJsonValue)
  }
  return false
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function isString(value: unknown): value is string {
  return typeof value === "string"
}

function optionalString(value: unknown): string | null {
  return typeof value === "string" ? value : null
}

function optionalBoolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null
}

function optionalNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null
}
