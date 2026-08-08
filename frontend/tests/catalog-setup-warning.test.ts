import { describe, expect, test } from "bun:test"
import type { TFunction } from "i18next"

import type { CatalogSetupWarning } from "../src/pages/catalog-setup-api"
import { getCatalogSetupWarningMessage } from "../src/pages/catalog-setup-warning"

const t = ((key: string) => key) as TFunction

function warning(code: CatalogSetupWarning["code"]): CatalogSetupWarning {
  return { code, message: `raw:${code}`, path: "route" }
}

describe("catalog setup warning localization", () => {
  test.each([
    ["broad_traffic_scope", "pages.catalog.risks.broadTrafficScope"],
    [
      "source_detour_not_found",
      "pages.catalog.setup.warnings.sourceDetourNotFound",
    ],
    [
      "source_detour_not_routable",
      "pages.catalog.setup.warnings.sourceDetourNotRoutable",
    ],
    [
      "source_detour_not_applicable",
      "pages.catalog.setup.warnings.sourceDetourNotApplicable",
    ],
    [
      "dns_automatic_unavailable",
      "pages.catalog.setup.warnings.dnsAutomaticUnavailable",
    ],
    [
      "dns_ignored_for_block",
      "pages.catalog.setup.warnings.dnsIgnoredForBlock",
    ],
    ["dns_detour_missing", "pages.catalog.setup.warnings.dnsDetourMissing"],
    ["dns_detour_mismatch", "pages.catalog.setup.warnings.dnsDetourMismatch"],
  ] as const)("maps %s to its localized key", (code, expected) => {
    expect(getCatalogSetupWarningMessage(warning(code), t)).toBe(expected)
  })
})
