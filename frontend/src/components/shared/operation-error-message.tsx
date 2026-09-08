import { useTranslation } from "react-i18next"

import type { ApiError } from "@/api/client"
import {
  getApiValidationErrors,
  getOperationErrorPresentation,
} from "@/lib/api-errors"
import { getServerValidationPresentation } from "@/lib/server-validation-presentation"

// Presentation only: the caller still owns the operation and its retry policy.
// Keep the original cause available without putting internal worker names or
// an unrecognised server response in the main user-facing message.
export function OperationErrorMessage({
  error,
  summary,
  fallbackSummary,
}: {
  error: unknown
  summary?: string
  fallbackSummary?: string
}) {
  const { t } = useTranslation()
  const presentation = getOperationErrorPresentation(error)
  if (!presentation) return null

  // Backup/whole-config errors have no editable version field. Explain this
  // specific validation failure here while preserving the existing raw details.
  const validationIssues =
    presentation.kind === "validation"
      ? getApiValidationErrors(error as ApiError)
      : []
  const versionIssue = validationIssues.find(
    (entry) => entry.path === "schema_version"
  )
  const version = versionIssue
    ? getServerValidationPresentation(versionIssue)
    : undefined
  const versionSummary =
    version?.key === "serverValidation.futureSchemaVersion"
      ? t("serverValidation.futureSchemaVersion", version.values)
      : version?.key === "serverValidation.invalidSchemaVersion"
        ? t("serverValidation.invalidSchemaVersion")
        : version?.key === "serverValidation.schemaMigration"
          ? t("serverValidation.schemaMigration", version.values)
          : undefined

  // Only the finite JSON decoding codes get a whole-document explanation.
  // Other field validation and uncoded diagnostics retain their current summary.
  const jsonSummary = validationIssues
    .map(getServerValidationPresentation)
    .map(({ key }) => {
      switch (key) {
        case "serverValidation.jsonSyntax":
          return t("serverValidation.jsonSyntax")
        case "serverValidation.jsonNumberOverflow":
          return t("serverValidation.jsonNumberOverflow")
        case "serverValidation.jsonType":
          return t("serverValidation.jsonType")
        case "serverValidation.jsonMissingField":
          return t("serverValidation.jsonMissingField")
        case "serverValidation.jsonObject":
          return t("serverValidation.jsonObject")
        case "serverValidation.jsonDecode":
          return t("serverValidation.jsonDecode")
        default:
          return undefined
      }
    })
    .find((text) => text !== undefined)

  return (
    <div className="min-w-0 space-y-2 text-left font-normal">
      <div>
        {summary ??
          versionSummary ??
          jsonSummary ??
          (presentation.kind === "unknown" ? fallbackSummary : undefined) ??
          t(`operationErrors.${presentation.kind}`)}
      </div>
      {presentation.details ? (
        <details className="min-w-0 text-xs">
          <summary className="cursor-pointer rounded-sm font-medium focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring">
            {t("operationErrors.details")}
          </summary>
          <pre className="mt-2 max-h-48 overflow-auto font-mono [overflow-wrap:anywhere] whitespace-pre-wrap">
            {presentation.details}
          </pre>
        </details>
      ) : null}
    </div>
  )
}
