import { useTranslation } from "react-i18next"

import { cn } from "@/lib/utils"

export type RuleCondition = {
  readonly label: string
  readonly value: string
}

/**
 * Условия правила в ячейке таблицы — тот же принцип, что «Где используется»
 * у туннелей (решение владельца): строки таблицы одной высоты, ячейка
 * показывает не больше N однострочных условий, остаток — числом «Ещё N».
 * Полный список условий всегда виден в редакторе правила и в title ячейки.
 */
export function RuleConditionsCell({
  className,
  conditions,
  maxRows = 2,
}: {
  /** min-height под maxRows строк, чтобы строка с одним условием была не ниже. */
  readonly className?: string
  readonly conditions: readonly RuleCondition[]
  readonly maxRows?: number
}) {
  const { t } = useTranslation()
  const visible = conditions.slice(0, maxRows)
  const hidden = conditions.length - visible.length
  const fullText = conditions
    .map((condition) => `${condition.label}: ${condition.value}`)
    .join("\n")

  return (
    <ul
      className={cn(
        "min-w-0 list-disc content-center space-y-1 pl-5 text-sm",
        className
      )}
      title={fullText}
    >
      {visible.map((condition, rowIndex) => (
        <li className="text-muted-foreground" key={condition.label}>
          <span className="flex min-w-0 items-baseline gap-1 overflow-hidden whitespace-nowrap">
            <span className="shrink-0 font-medium text-foreground">
              {condition.label}:
            </span>
            <span className="min-w-0 truncate">{condition.value}</span>
            {rowIndex === visible.length - 1 && hidden > 0 ? (
              <span className="shrink-0 text-xs">
                {t("common.dependencies.more", { count: hidden })}
              </span>
            ) : null}
          </span>
        </li>
      ))}
    </ul>
  )
}
