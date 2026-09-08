import { useTranslation } from "react-i18next"
import { useLocation } from "wouter"
import { useHistoryState } from "wouter/use-browser-location"
import {
  catalogNavigationOptions,
  catalogReturnHref,
  catalogSelectionAfterCreate,
  readCatalogSelectionContext,
} from "@/lib/catalog-navigation"

export function useCatalogNavigation() {
  const { t } = useTranslation()
  const [, navigate] = useLocation()
  const selection = readCatalogSelectionContext(useHistoryState())
  const openCatalog = (outboundTag?: string) => {
    const restored = catalogSelectionAfterCreate(selection, outboundTag)
    navigate(catalogReturnHref(restored), catalogNavigationOptions(restored))
  }
  return {
    selection,
    navigationOptions: selection
      ? catalogNavigationOptions(selection)
      : undefined,
    openCatalog,
    successAction: (outboundTag?: string) => ({
      label: selection
        ? t("pages.catalog.continue.return")
        : t("pages.catalog.continue.open"),
      onClick: () => openCatalog(outboundTag),
    }),
  }
}
