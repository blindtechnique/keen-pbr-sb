import { useTranslation } from "react-i18next"

import type { ConfigObject } from "@/api/generated/model/configObject"
import { DELETE_REFERENCES } from "@/components/delete-impact/list-items"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { getListReferenceLabel } from "@/lib/list-display"

/**
 * «Что сделать со ссылками на удаляемый список» — селект в диалоге удаления.
 *
 * Общий для таблицы списков и формы редактирования: перепривязка ссылок на
 * замену — часть staged-удаления, и в обоих местах она должна выглядеть и
 * работать одинаково.
 */
export function ListDeleteReplacementPicker({
  config,
  deletedIds,
  onChange,
  replacementListId,
}: {
  readonly config: ConfigObject
  readonly deletedIds: readonly string[]
  readonly onChange: (replacementListId: string) => void
  readonly replacementListId: string
}) {
  const { t } = useTranslation()
  const deleted = new Set(deletedIds)
  const candidates = Object.keys(config.lists ?? {})
    .filter((listId) => !deleted.has(listId))
    .sort((left, right) =>
      getListReferenceLabel(left, config.lists).localeCompare(
        getListReferenceLabel(right, config.lists)
      )
    )

  return (
    <div className="space-y-2 rounded-[4px] border border-border/70 bg-secondary/30 p-3">
      <label className="text-sm font-medium" htmlFor="list-delete-replacement">
        {t("pages.lists.deleteDialog.referencesLabel")}
      </label>
      <Select
        items={[
          {
            label: t("pages.lists.deleteDialog.referencesRemoveOption"),
            value: DELETE_REFERENCES,
          },
          ...candidates.map((listId) => ({
            label: getListReferenceLabel(listId, config.lists),
            value: listId,
          })),
        ]}
        onValueChange={(value) =>
          onChange(value && value !== DELETE_REFERENCES ? value : "")
        }
        value={replacementListId || DELETE_REFERENCES}
      >
        <SelectTrigger id="list-delete-replacement">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectItem value={DELETE_REFERENCES}>
              {t("pages.lists.deleteDialog.referencesRemoveOption")}
            </SelectItem>
            {candidates.map((listId) => (
              <SelectItem key={listId} value={listId}>
                {getListReferenceLabel(listId, config.lists)}
              </SelectItem>
            ))}
          </SelectGroup>
        </SelectContent>
      </Select>
      <p className="text-xs leading-5 text-muted-foreground">
        {replacementListId
          ? t("pages.lists.deleteDialog.referencesReplaceHint", {
              name: getListReferenceLabel(replacementListId, config.lists),
            })
          : t("pages.lists.deleteDialog.referencesRemoveHint")}
      </p>
    </div>
  )
}
