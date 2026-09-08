import type { ReactNode } from "react"
import type { ValidationErrorEntry } from "@/lib/api-errors"
import { ServerFieldError } from "@/components/shared/server-field-error"
import { Alert, AlertDescription } from "@/components/ui/alert"

export function ServerValidationAlert({
  errors,
  message,
}: {
  errors: ValidationErrorEntry[]
  message?: ReactNode
}) {
  if (errors.length === 0 && !message) {
    return null
  }

  return (
    <Alert className="border-destructive/30 bg-destructive/5 text-destructive">
      <AlertDescription>
        <div className="space-y-2">
          {message ? (
            <div className="whitespace-pre-wrap">{message}</div>
          ) : null}
          {errors.length > 0 ? <ServerFieldError errors={errors} /> : null}
        </div>
      </AlertDescription>
    </Alert>
  )
}
