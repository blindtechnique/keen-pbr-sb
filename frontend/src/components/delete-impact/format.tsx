import type { ReactNode } from "react"

import { ChangeValue } from "@/components/delete-impact/change-value"

/**
 * Общий язык диалога «что сломается».
 *
 * Эти помощники жили по копии в каждой странице-таблице, и до формы
 * редактирования им было не дотянуться. Здесь они одни на всех: таблица и
 * форма показывают последствия удаления одним и тем же способом.
 */
export type TranslateFn = (
  key: string,
  options?: Record<string, unknown>
) => string

export function formatDetail(label: string, value: ReactNode) {
  return (
    <>
      {label}: {value}
    </>
  )
}

export function formatListValue(
  values: string[],
  t: TranslateFn,
  displayNames?: ReadonlyMap<string, string>
) {
  return values.length > 0
    ? values.map((value) => displayNames?.get(value) ?? value).join(", ")
    : t("common.noneShort")
}

export function formatTransition(
  before: string[],
  after: string[],
  t: TranslateFn,
  displayNames?: ReadonlyMap<string, string>
) {
  return (
    <ChangeValue
      after={formatListValue(after, t, displayNames)}
      before={formatListValue(before, t, displayNames)}
    />
  )
}
