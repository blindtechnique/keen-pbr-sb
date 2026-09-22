import type { TFunction } from "i18next"
import type { RoutingTestHttpProbe } from "@/api/generated/model"

export function httpProbeReason(
  reason: RoutingTestHttpProbe["reason"],
  t: TFunction
): string {
  switch (reason) {
    case "http_response":
      return t("overview.routingDiagnostics.evidence.httpResponse")
    case "context_required":
      return t("overview.routingDiagnostics.evidence.httpContextRequired")
    case "no_route":
      return t("overview.routingDiagnostics.evidence.httpNoRoute")
    case "destination_changed":
      return t("overview.routingDiagnostics.evidence.httpDestinationChanged")
    case "blocked_route":
      return t("overview.routingDiagnostics.evidence.httpBlockedRoute")
    case "binding_failed":
      return t("overview.routingDiagnostics.evidence.httpBindingFailed")
    case "tls_error":
      return t("overview.routingDiagnostics.evidence.httpTlsError")
    case "timeout":
      return t("overview.routingDiagnostics.evidence.httpTimeout")
    case "connection_failed":
      return t("overview.routingDiagnostics.evidence.httpConnectionFailed")
    case "unsupported_target":
      return t("overview.routingDiagnostics.evidence.httpUnsupportedTarget")
    case "transport_error":
      return t("overview.routingDiagnostics.evidence.httpTransportError")
    case "budget_exhausted":
      return t("overview.routingDiagnostics.evidence.httpBudgetExhausted")
    case "response_limit":
      return t("overview.routingDiagnostics.evidence.httpResponseLimit")
    default:
      return t("overview.routingDiagnostics.evidence.httpUnavailable")
  }
}
