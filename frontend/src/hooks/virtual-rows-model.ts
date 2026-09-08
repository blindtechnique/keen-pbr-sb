import { defaultRangeExtractor, type Range } from "@tanstack/react-virtual"

export const VIRTUAL_ROWS_THRESHOLD = 30

export function canVirtualizeDataTable(options: {
  requested: boolean
  count: number
  hasStableKeys: boolean
  hasReorder: boolean
  hasGroups: boolean
  hasDetails: boolean
}) {
  return (
    options.requested &&
    options.count > VIRTUAL_ROWS_THRESHOLD &&
    options.hasStableKeys &&
    !options.hasReorder &&
    !options.hasGroups &&
    !options.hasDetails
  )
}

export function getVirtualRangeWithFocus(
  range: Range,
  keys: readonly string[],
  focusedKey: string | null
) {
  const indexes = new Set(defaultRangeExtractor(range))
  const focusedIndex = focusedKey === null ? -1 : keys.indexOf(focusedKey)
  if (focusedIndex >= 0) {
    // Keep the focused row mounted, plus its neighbours so Tab can continue
    // into the next row rather than leaving a partially rendered table.
    for (let index = focusedIndex - 1; index <= focusedIndex + 1; index += 1) {
      if (index >= 0 && index < range.count) indexes.add(index)
    }
  }
  return [...indexes].sort((left, right) => left - right)
}

export type VirtualRowMeasurement = {
  index: number
  key: string
  start: number
  size: number
}

export function getVirtualRowsLayout(
  measurements: readonly VirtualRowMeasurement[],
  totalSize: number,
  scrollMargin: number
) {
  let previousEnd = 0
  const items = measurements.map((item) => {
    const start = Math.max(0, item.start - scrollMargin)
    const paddingBefore = Math.max(0, start - previousEnd)
    previousEnd = start + item.size
    return { ...item, start, paddingBefore }
  })
  return { items, paddingAfter: Math.max(0, totalSize - previousEnd) }
}
