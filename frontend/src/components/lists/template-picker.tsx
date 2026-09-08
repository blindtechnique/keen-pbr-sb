import { useMemo, useState } from "react"
import { SearchIcon } from "lucide-react"
import { useTranslation } from "react-i18next"

import templates from "@/data/list-templates.json"
import {
  getListTemplateDescription,
  getListTemplateName,
  matchesListTemplateSearch,
  type ListTemplate,
} from "@/components/lists/template-model"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"

export type { ListTemplate } from "@/components/lists/template-model"

const CATEGORY_ORDER = [
  "ai",
  "social",
  "media",
  "gaming",
  "developer",
  "cloud",
  "block",
  "other",
]

/**
 * Ready-made rule-set sources so a list can be created without hunting for the
 * right .srs URL. The sets come from SagerNet's published geosite rule sets,
 * except the two Russian blocklists that have no neutral equivalent.
 */
export function TemplatePicker({
  onSelect,
  onOpenCatalog,
  open,
  onOpenChange,
}: {
  onSelect: (template: ListTemplate) => void
  onOpenCatalog: (presetId: string) => boolean
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { i18n, t } = useTranslation()
  const language = i18n.resolvedLanguage ?? i18n.language
  const [query, setQuery] = useState("")

  const grouped = useMemo(() => {
    const matching = (templates as ListTemplate[]).filter((template) =>
      matchesListTemplateSearch(template, query, language)
    )

    const byCategory = new Map<string, ListTemplate[]>()
    for (const template of matching) {
      const bucket = byCategory.get(template.category) ?? []
      bucket.push(template)
      byCategory.set(template.category, bucket)
    }

    return CATEGORY_ORDER.filter((category) => byCategory.has(category)).map(
      (category) => ({ category, items: byCategory.get(category) ?? [] })
    )
  }, [query, language])

  return (
    <Dialog onOpenChange={onOpenChange} open={open}>
      <DialogContent className="max-h-[85vh] overflow-hidden sm:max-w-[640px]">
        <DialogHeader>
          <DialogTitle>{t("pages.listUpsert.templates.title")}</DialogTitle>
          <DialogDescription>
            {t("pages.listUpsert.templates.description")}
          </DialogDescription>
        </DialogHeader>

        <div className="relative">
          <SearchIcon className="absolute top-2.5 left-2.5 size-4 text-muted-foreground" />
          <Input
            className="pl-8"
            onChange={(event) => setQuery(event.target.value)}
            placeholder={t("pages.listUpsert.templates.search")}
            value={query}
          />
        </div>

        <div className="-mx-1 max-h-[50vh] overflow-y-auto px-1">
          {grouped.map((group) => (
            <div className="mb-4" key={group.category}>
              <p className="mb-1.5 text-xs font-semibold tracking-wide text-muted-foreground uppercase">
                {t(`pages.listUpsert.templates.categories.${group.category}`)}
              </p>
              <div className="divide-y rounded-md border">
                {group.items.map((template) => (
                  <button
                    className="flex w-full items-start gap-3 p-2.5 text-left hover:bg-muted/50"
                    key={template.id}
                    onClick={() => {
                      if (template.catalogPresetId) {
                        if (onOpenCatalog(template.catalogPresetId)) {
                          onOpenChange(false)
                        }
                        return
                      }
                      onSelect(template)
                      onOpenChange(false)
                    }}
                    type="button"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm font-medium">
                        {getListTemplateName(template, language)}
                      </div>
                      {getListTemplateDescription(template, language) ? (
                        <div className="text-xs text-muted-foreground">
                          {getListTemplateDescription(template, language)}
                        </div>
                      ) : null}
                      {template.catalogPresetId ? (
                        <div className="text-xs font-medium text-primary">
                          {t("pages.listUpsert.templates.catalogManaged")}
                        </div>
                      ) : null}
                      {!template.catalogPresetId ? (
                        <div className="truncate font-mono text-[11px] text-muted-foreground/80">
                          {template.url}
                        </div>
                      ) : null}
                    </div>
                    <Badge size="xs" variant="outline">
                      {t(
                        template.catalogPresetId
                          ? "pages.listUpsert.templates.openCatalog"
                          : "pages.listUpsert.templates.add"
                      )}
                    </Badge>
                  </button>
                ))}
              </div>
            </div>
          ))}

          {grouped.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              {t("pages.listUpsert.templates.empty")}
            </p>
          ) : null}
        </div>

        <DialogFooter>
          <Button onClick={() => onOpenChange(false)} variant="outline">
            {t("common.cancel")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
