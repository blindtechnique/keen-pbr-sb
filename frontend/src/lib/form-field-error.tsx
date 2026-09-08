import type { ReactNode } from "react"

import { ServerFieldError } from "@/components/shared/server-field-error"
import { OperationErrorMessage } from "@/components/shared/operation-error-message"
import {
  isServerOperationError,
  type ServerFieldValidationError,
} from "@/lib/form-api-errors"

function isServerFieldValidationError(
  value: unknown
): value is ServerFieldValidationError {
  if (!value || typeof value !== "object") return false
  const candidate = value as Partial<ServerFieldValidationError>
  return (
    candidate.kind === "server-validation" &&
    Array.isArray(candidate.entries) &&
    candidate.entries.length > 0 &&
    candidate.entries.every(
      (entry) =>
        entry &&
        typeof entry.path === "string" &&
        typeof entry.message === "string"
    )
  )
}

export function getFirstFieldError(errors: unknown[]): ReactNode {
  const error = errors.find(
    (entry) => typeof entry === "string" || isServerFieldValidationError(entry)
  )
  if (typeof error === "string") return error
  if (isServerFieldValidationError(error)) {
    return (
      <ServerFieldError
        errors={error.entries}
        lineNumbers={error.lineNumbers}
      />
    )
  }
  return null
}

// Local validation strings keep their meaning; only API-tagged failures use
// the shared operation presenter, with the original code and terminal facts.
export function getFormErrorMessage(error: unknown): ReactNode {
  if (typeof error === "string") return error
  if (isServerOperationError(error)) {
    return <OperationErrorMessage error={error.error} />
  }
  return null
}
