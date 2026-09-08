import type { TFunction } from "i18next"
import type { ApiError } from "@/api/client"

import type { CatalogSetupWarning } from "@/pages/catalog-setup-api"

export function getCatalogSetupRepairTarget(
  error: ApiError | null
): "route" | "dns" | null {
  const details = error?.details
  if (!details || typeof details !== "object" || !("code" in details))
    return null
  switch (details.code) {
    case "outbound_required":
    case "outbound_not_found":
    case "outbound_not_routable":
      return "route"
    case "dns_server_required":
    case "dns_server_not_found":
    case "dns_automatic_unavailable":
    case "dns_detour_mismatch":
      return "dns"
    default:
      return null
  }
}

export function getCatalogSetupWarningMessage(
  warning: CatalogSetupWarning,
  t: TFunction
): string {
  switch (warning.code) {
    case "broad_traffic_scope":
      return t("pages.catalog.risks.broadTrafficScope")
    case "source_detour_not_found":
      return t("pages.catalog.setup.warnings.sourceDetourNotFound")
    case "source_detour_not_routable":
      return t("pages.catalog.setup.warnings.sourceDetourNotRoutable")
    case "source_detour_not_applicable":
      return t("pages.catalog.setup.warnings.sourceDetourNotApplicable")
    case "dns_automatic_unavailable":
      return t("pages.catalog.setup.warnings.dnsAutomaticUnavailable")
    case "dns_ignored_for_block":
      return t("pages.catalog.setup.warnings.dnsIgnoredForBlock")
    case "dns_detour_missing":
      return t("pages.catalog.setup.warnings.dnsDetourMissing")
    case "dns_detour_mismatch":
      return t("pages.catalog.setup.warnings.dnsDetourMismatch")
    default:
      return warning.message
  }
}
