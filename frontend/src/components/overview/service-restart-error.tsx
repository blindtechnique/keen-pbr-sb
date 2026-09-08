import { useTranslation } from "react-i18next"

import { OperationErrorMessage } from "@/components/shared/operation-error-message"

// Only the explanation changes. Readiness, restart scheduling and timeouts
// remain owned by the existing operation; the original reason is retained.
export function ServiceRestartError({ error }: { error: unknown }) {
  const { t } = useTranslation()
  const message =
    error && typeof error === "object" && "message" in error
      ? error.message
      : undefined
  const summary =
    message === "service_process_restart_timeout"
      ? t("overview.services.processRestartUnconfirmed")
      : typeof message === "string" &&
          message.startsWith("Runtime did not become ready:")
        ? t("overview.services.readinessUnconfirmed")
        : undefined
  return (
    <OperationErrorMessage
      error={error}
      summary={summary}
      fallbackSummary={t("overview.services.restartFailed")}
    />
  )
}
