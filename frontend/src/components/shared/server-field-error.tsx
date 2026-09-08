import { useTranslation } from "react-i18next"

import {
  formatValidationErrors,
  type ValidationErrorEntry,
} from "@/lib/api-errors"
import { getServerValidationPresentation } from "@/lib/server-validation-presentation"

// Translate during rendering, not during field resolution or validation.
// The server entries remain intact even when the panel language changes.
export function ServerFieldError({
  errors,
  lineNumbers,
}: {
  errors: ValidationErrorEntry[]
  lineNumbers?: Readonly<Record<string, number>>
}) {
  const { t } = useTranslation()
  if (!errors.length) return null

  const messages = [
    ...new Set(
      errors.map((error) => {
        const presentation = getServerValidationPresentation(error)
        const message = t(presentation.key, presentation.values ?? {})
        const line = lineNumbers?.[error.path]
        return Number.isSafeInteger(line) && Number(line) > 0
          ? t("serverValidation.atLine", {
              line,
              message,
              // React escapes the result; do not encode the translated text twice.
              interpolation: { escapeValue: false },
            })
          : message
      })
    ),
  ]

  return (
    <div className="min-w-0 space-y-1 text-left font-normal">
      {messages.length === 1 ? (
        <div>{messages[0]}</div>
      ) : (
        <ul className="list-disc space-y-1 pl-5">
          {messages.map((message) => (
            <li key={message}>{message}</li>
          ))}
        </ul>
      )}
      <details className="min-w-0 text-xs">
        <summary className="cursor-pointer rounded-sm font-medium focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring">
          {t("operationErrors.details")}
        </summary>
        <pre className="mt-2 max-h-48 overflow-auto font-mono [overflow-wrap:anywhere] whitespace-pre-wrap">
          {formatValidationErrors(errors)}
        </pre>
      </details>
    </div>
  )
}
