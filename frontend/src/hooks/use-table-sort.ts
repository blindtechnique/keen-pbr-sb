import { useMemo, useState } from "react"

export type TableSortDirection = "asc" | "desc"

export type TableSortColumn<T> = {
  /** Индекс колонки в `headers` таблицы, без служебных колонок слева. */
  index: number
  /** Значение, по которому сравниваем. `undefined` уезжает в конец. */
  get: (item: T) => string | number | undefined
}

export type TableSortState = {
  activeColumn: number | null
  direction: TableSortDirection
  sortable: number[]
  onToggle: (columnIndex: number) => void
}

/**
 * Сортировка уже загруженной таблицы по клику на заголовок.
 *
 * Сравнение — `localeCompare` с `numeric`, поэтому «Список 2» встаёт перед
 * «Список 10», а не после: в именах списков и маршрутов числа встречаются
 * постоянно.
 *
 * Пустое значение всегда уезжает в конец независимо от направления. Иначе при
 * сортировке по убыванию первым экраном оказывались бы строки без значения, и
 * пользователь видел бы пустоту вместо «самых больших».
 */
export function compareTableValues(
  left: string | number | undefined,
  right: string | number | undefined
): number {
  const leftEmpty = left === undefined || left === ""
  const rightEmpty = right === undefined || right === ""
  if (leftEmpty || rightEmpty) {
    return leftEmpty === rightEmpty ? 0 : leftEmpty ? 1 : -1
  }
  if (typeof left === "number" && typeof right === "number") {
    return left - right
  }
  return String(left).localeCompare(String(right), undefined, {
    numeric: true,
    sensitivity: "base",
  })
}

export function sortTableItems<T>(
  items: T[],
  column: TableSortColumn<T> | undefined,
  direction: TableSortDirection
): T[] {
  if (!column) return items
  const isEmpty = (value: string | number | undefined) =>
    value === undefined || value === ""

  // Порядок равных элементов сохраняем: без этого строки с одинаковым
  // значением перескакивали бы при каждом рендере.
  return items
    .map((item, index) => ({ item, index }))
    .sort((left, right) => {
      const leftValue = column.get(left.item)
      const rightValue = column.get(right.item)

      // Пустое значение не участвует в развороте: иначе сортировка по
      // убыванию открывалась бы экраном пустых строк вместо «самых больших».
      if (isEmpty(leftValue) || isEmpty(rightValue)) {
        if (isEmpty(leftValue) === isEmpty(rightValue)) {
          return left.index - right.index
        }
        return isEmpty(leftValue) ? 1 : -1
      }

      const result = compareTableValues(leftValue, rightValue)
      if (result !== 0) return direction === "asc" ? result : -result
      return left.index - right.index
    })
    .map((entry) => entry.item)
}

export function useTableSort<T>(items: T[], columns: TableSortColumn<T>[]) {
  const [activeColumn, setActiveColumn] = useState<number | null>(null)
  const [direction, setDirection] = useState<TableSortDirection>("asc")

  const column = columns.find((entry) => entry.index === activeColumn)
  const sorted = useMemo(
    () => sortTableItems(items, column, direction),
    [items, column, direction]
  )

  const state: TableSortState = {
    activeColumn,
    direction,
    sortable: columns.map((entry) => entry.index),
    onToggle: (columnIndex) => {
      if (columnIndex === activeColumn) {
        // Третий клик снимает сортировку и возвращает исходный порядок —
        // он тоже осмысленный, в него человек и хочет вернуться.
        if (direction === "desc") {
          setActiveColumn(null)
          setDirection("asc")
          return
        }
        setDirection("desc")
        return
      }
      setActiveColumn(columnIndex)
      setDirection("asc")
    },
  }

  return { sorted, sort: state }
}
