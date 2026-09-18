import { ChevronRightIcon } from "lucide-react"
import type { ReactNode } from "react"
import { useTranslation } from "react-i18next"

import { DataTable } from "@/components/shared/data-table"

/** The applied stock preset stays visible without expanding every old preset. */
export function NfqwsLegacyStrategies({
  names,
  activeName,
  headers,
  columnClassNames,
  renderRow,
}: {
  names: readonly string[]
  activeName: string
  headers: string[]
  columnClassNames: Array<string | undefined>
  renderRow: (name: string) => ReactNode[]
}) {
  const { t } = useTranslation()
  const active = names.includes(activeName) ? activeName : undefined
  const inactive = names.filter((name) => name !== active)
  if (!names.length) return null

  return (
    <div className="space-y-2">
      {active ? (
        <DataTable
          columnClassNames={columnClassNames}
          headers={headers}
          narrowColumns={[1, 2]}
          rows={[renderRow(active)]}
        />
      ) : null}
      {inactive.length ? (
        <details className="group/legacy space-y-2">
          <summary className="inline-flex cursor-pointer list-none items-center gap-1.5 rounded-[4px] px-3 py-1.5 text-sm hover:bg-accent focus-visible:outline-ring [&::-webkit-details-marker]:hidden">
            <ChevronRightIcon
              aria-hidden="true"
              className="size-3.5 group-open/legacy:rotate-90"
            />
            <span className="group-open/legacy:hidden">
              {t("nfqws.legacyShow", { count: inactive.length })}
            </span>
            <span className="hidden group-open/legacy:inline">
              {t("nfqws.legacyHide")}
            </span>
          </summary>
          <p className="text-xs text-muted-foreground">
            {t("nfqws.legacyDescription")}
          </p>
          <DataTable
            columnClassNames={columnClassNames}
            headers={headers}
            narrowColumns={[1, 2]}
            rows={inactive.map(renderRow)}
          />
        </details>
      ) : null}
    </div>
  )
}
