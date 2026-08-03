import { SearchIcon, XIcon } from "lucide-react"
import { useTranslation } from "react-i18next"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { normalizeSearchQuery } from "@/lib/table-search"
import { cn } from "@/lib/utils"

/**
 * Поле поиска над таблицей.
 *
 * Отдельный компонент, а не поле на каждой странице: иначе плейсхолдер, кнопка
 * очистки, счётчик и поведение при пустом результате разъедутся так же, как
 * разъехались раскладки кнопок.
 */
export function TableSearch({
  value,
  onChange,
  placeholder,
  totalCount,
  matchCount,
  className,
}: {
  value: string
  onChange: (next: string) => void
  placeholder: string
  totalCount: number
  matchCount: number
  className?: string
}) {
  const { t } = useTranslation()
  const active = Boolean(normalizeSearchQuery(value))

  return (
    <div className={cn("flex flex-col gap-1", className)}>
      <div className="relative sm:max-w-md">
        <SearchIcon className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          className="pr-9 pl-9"
          onChange={(event) => onChange(event.target.value)}
          placeholder={placeholder}
          type="search"
          value={value}
        />
        {active ? (
          <Button
            aria-label={t("common.tableSearch.clear")}
            className="absolute top-1/2 right-1 size-7 -translate-y-1/2"
            onClick={() => onChange("")}
            size="icon"
            variant="ghost"
          >
            <XIcon className="size-4" />
          </Button>
        ) : null}
      </div>
      {active ? (
        <p
          aria-live="polite"
          className="text-xs text-muted-foreground"
          data-testid="table-search-summary"
        >
          {t("common.tableSearch.results", {
            count: matchCount,
            total: totalCount,
          })}
        </p>
      ) : null}
    </div>
  )
}
