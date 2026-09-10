import type { ApiError } from "@/api/client"

export type ValidationErrorEntry = {
  path: string
  message: string
  // Wire metadata is untrusted until the finite presenter checks it. Keeping
  // malformed present codes prevents an accidental fallback to legacy prose.
  code?: unknown
  params?: unknown
}

export function getValidationErrorMetadata(entry: {
  code?: unknown
  params?: unknown
}): Pick<ValidationErrorEntry, "code" | "params"> {
  return {
    ...("code" in entry ? { code: entry.code } : {}),
    ...("params" in entry ? { params: entry.params } : {}),
  }
}

function getValidationErrors(details: unknown): ValidationErrorEntry[] {
  if (!details || typeof details !== "object") {
    return []
  }

  const validationErrors = (details as { validation_errors?: unknown })
    .validation_errors

  if (!Array.isArray(validationErrors)) {
    return []
  }

  return validationErrors.filter(
    (item): item is ValidationErrorEntry =>
      Boolean(item) &&
      typeof item === "object" &&
      typeof (item as { path?: unknown }).path === "string" &&
      typeof (item as { message?: unknown }).message === "string"
  )
}

export function getApiValidationErrors(
  error: ApiError | null
): ValidationErrorEntry[] {
  if (!error) {
    return []
  }

  return getValidationErrors(error.details).map((item) => ({
    path: item.path.trim(),
    message: item.message.trim(),
    ...getValidationErrorMetadata(item),
  }))
}

export function formatValidationErrors(errors: ValidationErrorEntry[]): string {
  return errors
    .map((item) => {
      const lines = [
        item.path ? `- ${item.path}: ${item.message}` : `- ${item.message}`,
      ]
      if (typeof item.code === "string" && item.code)
        lines.push(`  code: ${item.code}`)
      if (
        item.params &&
        typeof item.params === "object" &&
        !Array.isArray(item.params)
      ) {
        // Only the declared string-map metadata, never an arbitrary response
        // object (or its toJSON), is included in the diagnostic details.
        const params = Object.entries(item.params).filter(
          ([, value]) => typeof value === "string"
        )
        if (params.length)
          lines.push(`  params: ${JSON.stringify(Object.fromEntries(params))}`)
      }
      return lines.join("\n")
    })
    .join("\n")
}

export function getApiErrorMessage(error: ApiError | null): string {
  if (!error) {
    return ""
  }

  const validationErrors = getApiValidationErrors(error)
  if (validationErrors.length === 0) {
    return error.message
  }

  return [error.message, formatValidationErrors(validationErrors)].join("\n")
}

export type OperationErrorKind =
  | "busy"
  | "draft_pending"
  | "draft_changed"
  | "recovery_required"
  | "list_refresh_apply_failed"
  | "apply_unchanged"
  | "rolled_back"
  | "validation"
  | "unauthenticated"
  | "reauthentication_required"
  | "forbidden"
  | "preview_expired"
  | "name_in_use"
  | "no_interface_name"
  | "invalid_connection"
  | "subscription_unavailable"
  | "service_unavailable"
  | "network"
  | "unknown"

function operationErrorRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null
}

function operationErrorText(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null
}

function confirmedConfigFailure(
  payload: Record<string, unknown> | null
): "rolled_back" | "apply_unchanged" | null {
  // These are the complete negative terminal tuples from config/save. One
  // rollback flag, a missing field, or HTTP 500 cannot prove restoration.
  if (
    payload?.saved === false &&
    payload.applied === false &&
    payload.file_rolled_back === true &&
    payload.recovery_required === false
  ) {
    if (payload.rolled_back === true && payload.runtime_unchanged === false) {
      return "rolled_back"
    }
    if (payload.rolled_back === false && payload.runtime_unchanged === true) {
      return "apply_unchanged"
    }
  }
  return null
}

function operationErrorKind(
  payload: Record<string, unknown> | null,
  message: string,
  hasValidationErrors: boolean
): OperationErrorKind {
  // Explicit recovery failures outrank even a conflicting code. The original
  // apply cause remains diagnostic evidence, never an alternate primary code.
  if (
    payload?.recovery_required === true ||
    operationErrorText(payload?.recovery_error) ||
    operationErrorText(payload?.rollback_error)
  ) {
    return "recovery_required"
  }

  const confirmedFailure = confirmedConfigFailure(payload)
  const code = payload?.code
  if (code !== undefined && code !== null && code !== "") {
    if (typeof code !== "string") return "unknown"
    // Stable server codes own the summary. An unfamiliar or malformed code
    // must not become a familiar outcome just because its prose looks similar.
    switch (code) {
      case "rolled_back":
      case "apply_unchanged":
        return confirmedFailure === code ? code : "unknown"
      case "busy":
      case "draft_pending":
      case "draft_changed":
      case "recovery_required":
      case "list_refresh_apply_failed":
      case "validation":
      case "unauthenticated":
      case "reauthentication_required":
      case "forbidden":
      case "preview_expired":
      case "name_in_use":
      case "no_interface_name":
      case "invalid_connection":
      case "subscription_unavailable":
      case "service_unavailable":
      case "network":
        return code
      default:
        return "unknown"
    }
  }

  // Older servers have no code. Keep their finite exact-message fallback,
  // without reclassifying nested apply/recovery diagnostic strings.
  if (
    message === "Persistent recovery required" ||
    message === "sing-box process mode switch failed and rollback also failed"
  ) {
    return "recovery_required"
  }
  if (confirmedFailure) return confirmedFailure

  if (
    payload?.reason === "draft_base_revision_mismatch" ||
    payload?.reason === "base_revision_mismatch"
  ) {
    return "draft_changed"
  }
  if (
    hasValidationErrors ||
    /^Config validation failed(?: with \d+ errors)?$/.test(message)
  ) {
    return "validation"
  }
  if (
    /^Another runtime mutation is already in progress(?:: .+)?$/.test(message)
  ) {
    return "busy"
  }
  if (
    /^subscription fetch failed(?:: HTTP \d{3}|: destination policy)?$/.test(
      message
    )
  ) {
    return "subscription_unavailable"
  }

  switch (message) {
    case "A lifecycle operation is already active":
    case "Routing runtime initialization or shutdown is in progress":
      return "busy"
    case "Save or discard the current configuration draft before creating a linked transport":
    case "List refresh is unavailable while a draft config is staged":
    case "Backup restore is unavailable while a draft config is staged":
      return "draft_pending"
    case "The active configuration changed after this draft was created":
      return "draft_changed"
    case "authentication required":
      return "unauthenticated"
    case "step_up_required":
      return "reauthentication_required"
    case "the subscription preview has expired; fetch it again":
      return "preview_expired"
    case "name is already in use":
      return "name_in_use"
    case "no free interface name could be derived":
      return "no_interface_name"
    case "cannot derive link identity":
    case "connection data was not accepted":
      return "invalid_connection"
    case "transport manager is unavailable":
      return "service_unavailable"
    case "Failed to fetch":
    case "NetworkError when attempting to fetch resource.":
    case "Load failed":
    case "fetch failed":
      return "network"
    default:
      return "unknown"
  }
}

// Opt-in presentation for save/apply/import flows. The existing raw formatter
// above stays unchanged for other callers. No request, URL, credential, or
// arbitrary response object is serialized into the operator's details.
export function getOperationErrorPresentation(
  error: unknown
): { kind: OperationErrorKind; details: string } | null {
  if (error === null || error === undefined) return null
  if (typeof error === "string" && !error.trim()) return null

  const outer = operationErrorRecord(error)
  const payload =
    operationErrorRecord(outer?.details) ??
    (typeof outer?.status === "number"
      ? operationErrorRecord(outer.data)
      : null) ??
    outer
  const thrownText =
    typeof error === "string"
      ? error
      : typeof error === "number" ||
          typeof error === "boolean" ||
          typeof error === "bigint"
        ? String(error)
        : null
  const primary =
    operationErrorText(payload?.error) ??
    operationErrorText(payload?.message) ??
    operationErrorText(outer?.message) ??
    operationErrorText(outer?.error) ??
    thrownText ??
    ""
  const parts = new Set<string>()
  for (const value of [
    thrownText,
    outer?.message,
    outer?.error,
    payload?.error,
    payload?.message,
  ]) {
    const text = operationErrorText(value)
    if (text) parts.add(text)
  }
  for (const field of [
    "apply_error",
    "recovery_error",
    "rollback_error",
    "reason",
    "code",
  ] as const) {
    const text = operationErrorText(payload?.[field])
    if (text) parts.add(`${field}: ${text}`)
  }
  if (payload?.code === "list_refresh_apply_failed") {
    const params = operationErrorRecord(payload.params)
    // Only these finite diagnostic fields belong to this error contract.
    // Do not serialize arbitrary API metadata or a request payload.
    if (
      params?.stage === "prepare" ||
      params?.stage === "owner_handoff" ||
      params?.stage === "terminal_wait" ||
      params?.stage === "terminal"
    ) {
      parts.add(`stage: ${params.stage}`)
    }
    if (
      params?.runtime_result === "unchanged" ||
      params?.runtime_result === "rolled_back" ||
      params?.runtime_result === "unknown"
    ) {
      parts.add(`runtime_result: ${params.runtime_result}`)
    }
  }
  const validationErrors = getValidationErrors(payload)
  if (validationErrors.length > 0) {
    parts.add(formatValidationErrors(validationErrors))
  }

  return {
    kind: operationErrorKind(
      payload,
      primary.trim(),
      validationErrors.length > 0
    ),
    details: [...parts].join("\n"),
  }
}
