export type DataTableMobileLayout = Readonly<{
  /** Index in `rows`/`headers` (before the actions column) used as row title. */
  titleColumn?: number
  /** Data columns rendered as controls instead of labelled values. */
  controlColumns?: readonly number[]
}>

export type DataTableMobileColumnLayout = Readonly<{
  titleIndex: number | undefined
  controlIndices: readonly number[]
  detailIndices: readonly number[]
}>

/**
 * Resolve the compact-row structure without guessing from the visible header.
 *
 * An accessible header can be non-empty even when the cell is a switch or
 * another control. Callers with that shape provide an explicit mobile layout;
 * older tables keep the previous empty-header convention as a fallback.
 */
export function getDataTableMobileColumnLayout(
  headers: readonly string[] | undefined,
  bodyCellCount: number,
  layout?: DataTableMobileLayout
): DataTableMobileColumnLayout {
  const valid = (index: number) => index >= 0 && index < bodyCellCount
  const explicitControlIndices = (layout?.controlColumns ?? []).filter(valid)
  const controlIndices =
    layout?.controlColumns !== undefined
      ? [...new Set(explicitControlIndices)]
      : headers
        ? Array.from({ length: bodyCellCount }, (_, index) => index).filter(
            (index) => !headers[index]
          )
        : []
  const controlSet = new Set(controlIndices)
  const explicitTitle = layout?.titleColumn
  const titleIndex =
    explicitTitle !== undefined && valid(explicitTitle)
      ? explicitTitle
      : headers
        ? Array.from({ length: bodyCellCount }, (_, index) => index).find(
            (index) => Boolean(headers[index]) && !controlSet.has(index)
          )
        : bodyCellCount > 0
          ? 0
          : undefined
  const detailIndices = Array.from(
    { length: bodyCellCount },
    (_, index) => index
  ).filter((index) => index !== titleIndex && !controlSet.has(index))

  return { titleIndex, controlIndices, detailIndices }
}
