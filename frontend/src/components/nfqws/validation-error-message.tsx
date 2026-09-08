import type { ApiError } from "@/api/client"
import { OperationErrorMessage } from "@/components/shared/operation-error-message"
import { ServerFieldError } from "@/components/shared/server-field-error"
import { getApiValidationErrors } from "@/lib/api-errors"

// Candidate errors need the existing field-error translations even though
// nfqws edits a strategy/file instead of a schema-driven configuration form.
export function NfqwsValidationErrorMessage({
  error,
  summary,
  fallbackSummary,
}: {
  error: unknown
  summary?: string
  fallbackSummary?: string
}) {
  const errors = getApiValidationErrors(error as ApiError)
  if (errors.length > 0 && !summary) {
    return <ServerFieldError errors={errors} />
  }
  return (
    <OperationErrorMessage
      error={error}
      summary={summary}
      fallbackSummary={fallbackSummary}
    />
  )
}
