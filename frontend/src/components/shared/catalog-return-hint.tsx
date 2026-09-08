import { useTranslation } from "react-i18next"
import { Button } from "@/components/ui/button"
import { useCatalogNavigation } from "@/hooks/use-catalog-navigation"

export function CatalogReturnHint({
  busy = false,
  needsApply = false,
}: {
  busy?: boolean
  needsApply?: boolean
}) {
  const { t } = useTranslation()
  const catalog = useCatalogNavigation()
  if (!catalog.selection) return null
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-md bg-secondary/50 px-3 py-2">
      <p className="text-sm text-muted-foreground">
        {t("pages.catalog.continue.selectionKept", {
          count: catalog.selection.selectedIds.length,
        })}
        {needsApply ? ` ${t("pages.catalog.continue.applyDnsFirst")}` : null}
        {busy ? ` ${t("pages.catalog.continue.operationPending")}` : null}
      </p>
      <Button
        disabled={busy}
        onClick={() => catalog.openCatalog()}
        variant="outline"
        size="sm"
      >
        {t("pages.catalog.continue.return")}
      </Button>
    </div>
  )
}
