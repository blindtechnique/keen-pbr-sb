import type { ReactNode } from "react"
import { ArrowDownIcon, ArrowUpIcon, ChevronsUpDownIcon, GripVerticalIcon } from "lucide-react"

import { Checkbox } from "@/components/ui/checkbox"
import { usePointerSortable } from "@/hooks/use-pointer-sortable"
import type { TableSortState } from "@/hooks/use-table-sort"
import { cn } from "@/lib/utils"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

export type DataTableSelection = {
  rowIds: string[]
  selectedIds: ReadonlySet<string>
  disabled?: boolean
  onToggle: (rowId: string) => void
  onToggleAll: (checked: boolean, rowIds?: string[]) => void
  selectAllLabel?: string
  getRowLabel: (rowId: string) => string
}

export type DataTableReorder = {
  disabled?: boolean
  onReorder: (fromIndex: number, toIndex: number) => void
  handleLabel?: string
}

function createTableRowPreview(source: HTMLElement) {
  const sourceRow = source.closest<HTMLTableRowElement>("tr") ?? source
  const sourceTable = sourceRow.closest<HTMLTableElement>("table")
  const previewTable = document.createElement("table")
  const previewBody = document.createElement("tbody")
  const previewRow = sourceRow.cloneNode(true) as HTMLElement

  if (sourceTable) {
    previewTable.className = sourceTable.className
  }
  previewTable.classList.add("table-fixed", "border-collapse", "bg-card")

  const sourceCells = sourceRow.querySelectorAll<HTMLElement>("th, td")
  const previewCells = previewRow.querySelectorAll<HTMLElement>("th, td")
  previewCells.forEach((cell, index) => {
    const sourceCell = sourceCells[index]
    if (sourceCell) {
      cell.style.width = `${sourceCell.getBoundingClientRect().width}px`
    }
  })

  previewBody.append(previewRow)
  previewTable.append(previewBody)
  return previewTable
}

export function DataTable({
  headers,
  rows,
  compact = false,
  fixedLayout = false,
  columnClassNames = [],
  narrowColumns = [],
  selection,
  reorder,
  sort,
}: {
  headers?: string[]
  rows: ReactNode[][]
  compact?: boolean
  fixedLayout?: boolean
  columnClassNames?: Array<string | undefined>
  narrowColumns?: number[]
  selection?: DataTableSelection
  reorder?: DataTableReorder
  // Сортировку считает страница: DataTable получает уже отрисованные ячейки и
  // сравнивать их не может. Здесь только заголовок-кнопка и aria-sort.
  sort?: TableSortState
}) {
  const hasSelection = Boolean(
    selection && selection.rowIds.length === rows.length
  )
  const hasReorder = Boolean(reorder)
  const {
    currentOrder,
    draggingPosition,
    getContainerProps,
    getHandleProps,
    setItemRef,
  } = usePointerSortable({
    itemCount: rows.length,
    disabled: !hasReorder || reorder?.disabled,
    itemSelector: "[data-sortable-table-row]",
    onReorder: (fromIndex, toIndex) => reorder?.onReorder(fromIndex, toIndex),
    createPreview: createTableRowPreview,
  })
  const leadingColumns = (hasReorder ? 1 : 0) + (hasSelection ? 1 : 0)
  const headersWithSelection = headers
    ? [...Array(leadingColumns).fill(""), ...headers]
    : headers
  const lastColumnIndex = headersWithSelection
    ? headersWithSelection.length - 1
    : rows.length && rows[0]?.length
      ? rows[0].length - 1
      : 0
  const narrowColumnSet = new Set(
    narrowColumns.map((index) => index + leadingColumns)
  )
  const visibleRowIds = hasSelection
    ? selection!.rowIds.filter((rowId) => rowId.length > 0)
    : []
  const allVisibleSelected =
    visibleRowIds.length > 0 &&
    visibleRowIds.every((rowId) => selection!.selectedIds.has(rowId))

  function sortableHeader(headerIndex: number) {
    return Boolean(
      sort && sort.sortable.includes(headerIndex - leadingColumns)
    )
  }

  function sortDirectionOf(headerIndex: number) {
    return sort && sort.activeColumn === headerIndex - leadingColumns
      ? sort.direction
      : null
  }

  function headClass(headerIndex: number) {
    const columnClassName =
      headerIndex >= leadingColumns
        ? columnClassNames[headerIndex - leadingColumns]
        : undefined

    if (headerIndex < leadingColumns) {
      if (fixedLayout) {
        return compact
          ? "h-8 w-8 px-0.5 font-semibold whitespace-nowrap"
          : "w-8 px-0.5 font-semibold whitespace-nowrap"
      }

      return compact
        ? "h-8 w-px px-1.5 font-semibold whitespace-nowrap"
        : "w-px px-2 font-semibold whitespace-nowrap"
    }

    return cn(
      headerIndex === lastColumnIndex
        ? compact
          ? "h-8 w-px text-right font-semibold"
          : "w-px text-right font-semibold"
        : narrowColumnSet.has(headerIndex)
          ? compact
            ? "h-8 w-px font-semibold whitespace-nowrap"
            : "w-px font-semibold whitespace-nowrap"
          : compact
            ? "h-8 font-semibold"
            : "font-semibold",
      columnClassName
    )
  }

  function cellClass(cellIndex: number) {
    const columnClassName =
      cellIndex >= leadingColumns
        ? columnClassNames[cellIndex - leadingColumns]
        : undefined

    if (cellIndex < leadingColumns) {
      if (fixedLayout) {
        return compact
          ? "w-8 px-0.5 py-1.5 align-middle whitespace-nowrap"
          : "w-8 px-0.5 py-3 align-middle whitespace-nowrap"
      }

      return compact
        ? "w-px px-1.5 py-1.5 align-middle whitespace-nowrap"
        : "w-px px-2 py-3 align-middle whitespace-nowrap"
    }

    return cn(
      cellIndex === lastColumnIndex
        ? compact
          ? "w-px px-2 py-1.5 text-right align-middle whitespace-nowrap"
          : "w-px p-3 text-right align-middle whitespace-nowrap"
        : narrowColumnSet.has(cellIndex)
          ? compact
            ? "w-px px-2 py-1.5 align-middle whitespace-nowrap"
            : "w-px p-3 align-middle whitespace-nowrap"
          : compact
            ? "px-2 py-1.5 align-middle whitespace-normal"
            : "p-3 align-middle whitespace-normal",
      columnClassName
    )
  }

  return (
    <>
      <div
        className={cn(
          "hidden max-w-full border-b md:block",
          fixedLayout
            ? "overflow-x-hidden [&_[data-slot=table-container]]:overflow-x-hidden"
            : "overflow-x-auto"
        )}
      >
        <Table className={cn("w-full text-sm", fixedLayout && "table-fixed")}>
          {/* KeeneticOS column headers: 14px bold in sentence case on the muted
              band, not small caps. --muted is #fafafa light / #2f3745 dark and
              --foreground #202020 / #c2c2c2 — the same pair the firmware uses,
              which also lifts contrast from 2.82:1 to 15.6:1 (light) and from
              4.25:1 to 6.72:1 (dark). */}
          {headersWithSelection && (
            <TableHeader className="bg-muted text-sm text-foreground">
              <TableRow>
                {headersWithSelection.map((header, headerIndex) => (
                  <TableHead
                    aria-sort={
                      sortableHeader(headerIndex)
                        ? sortDirectionOf(headerIndex) === "asc"
                          ? "ascending"
                          : sortDirectionOf(headerIndex) === "desc"
                            ? "descending"
                            : "none"
                        : undefined
                    }
                    className={headClass(headerIndex)}
                    key={`${header}-${headerIndex}`}
                  >
                    {sortableHeader(headerIndex) ? (
                      <button
                        className="-mx-1 inline-flex items-center gap-1 rounded px-1 py-0.5 text-left hover:text-primary focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                        onClick={() => sort!.onToggle(headerIndex - leadingColumns)}
                        type="button"
                      >
                        {header}
                        {sortDirectionOf(headerIndex) === "asc" ? (
                          <ArrowUpIcon className="size-3.5" />
                        ) : sortDirectionOf(headerIndex) === "desc" ? (
                          <ArrowDownIcon className="size-3.5" />
                        ) : (
                          <ChevronsUpDownIcon className="size-3.5 opacity-40" />
                        )}
                      </button>
                    ) : hasSelection && headerIndex === leadingColumns - 1 ? (
                      <div className="flex justify-center">
                        <Checkbox
                          aria-label={
                            selection!.selectAllLabel ??
                            "Select all visible rows"
                          }
                          className={
                            fixedLayout ? "after:-inset-x-2" : undefined
                          }
                          checked={allVisibleSelected}
                          disabled={
                            selection!.disabled || visibleRowIds.length === 0
                          }
                          onCheckedChange={(checked) => {
                            selection!.onToggleAll(
                              checked === true,
                              selection!.rowIds
                            )
                          }}
                        />
                      </div>
                    ) : (
                      header
                    )}
                  </TableHead>
                ))}
              </TableRow>
            </TableHeader>
          )}
          <TableBody {...getContainerProps()}>
            {currentOrder.map((rowIndex, position) => {
              const row = rows[rowIndex] ?? []
              const rowId = hasSelection
                ? (selection!.rowIds[rowIndex] ?? "")
                : ""

              return (
                <TableRow
                  className={cn(
                    "transition-[background-color,box-shadow,opacity] duration-150",
                    hasReorder &&
                      draggingPosition === position &&
                      "keen-row-dragging relative z-10"
                  )}
                  data-sortable-table-row
                  key={
                    hasSelection ? rowId || rowIndex : `${row[0]}-${rowIndex}`
                  }
                  ref={(element) => {
                    setItemRef(position, element)
                  }}
                >
                  {hasReorder ? (
                    <TableCell className={cellClass(0)}>
                      <button
                        aria-label={reorder!.handleLabel ?? "Reorder row"}
                        className="flex size-7 cursor-grab touch-none items-center justify-center text-muted-foreground transition-colors hover:text-foreground active:cursor-grabbing disabled:cursor-not-allowed disabled:opacity-40"
                        disabled={reorder!.disabled}
                        title={reorder!.handleLabel ?? "Reorder row"}
                        type="button"
                        {...getHandleProps(position)}
                      >
                        <GripVerticalIcon className="h-4 w-4" />
                      </button>
                    </TableCell>
                  ) : null}
                  {hasSelection ? (
                    <TableCell className={cellClass(leadingColumns - 1)}>
                      <div className="flex justify-center">
                        <Checkbox
                          aria-label={
                            rowId
                              ? selection!.getRowLabel(rowId)
                              : (selection!.selectAllLabel ?? "Select row")
                          }
                          className={
                            fixedLayout ? "after:-inset-x-2" : undefined
                          }
                          checked={
                            rowId ? selection!.selectedIds.has(rowId) : false
                          }
                          disabled={selection!.disabled || !rowId}
                          onCheckedChange={() => {
                            if (rowId) {
                              selection!.onToggle(rowId)
                            }
                          }}
                        />
                      </div>
                    </TableCell>
                  ) : null}
                  {row.map((cell, cellIndex) => {
                    const displayIndex = cellIndex + leadingColumns

                    return (
                      <TableCell
                        className={cellClass(displayIndex)}
                        key={cellIndex}
                      >
                        {cell}
                      </TableCell>
                    )
                  })}
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      </div>

      {/* Narrow screens get one block per row instead of a table that would have
        to be scrolled sideways to read. */}
      <div className="divide-y border-y md:hidden">
        {rows.map((row, index) => {
          const rowId = hasSelection ? (selection!.rowIds[index] ?? "") : ""
          const actionsCell = headers ? row[row.length - 1] : undefined
          const bodyCells = headers ? row.slice(0, -1) : row

          return (
            <div
              className="space-y-2 py-3"
              key={hasSelection ? rowId || index : `mobile-${index}`}
            >
              <div className="flex items-center gap-2">
                {hasReorder ? (
                  <button
                    aria-label={reorder!.handleLabel ?? "Reorder row"}
                    className="cursor-grab text-muted-foreground disabled:opacity-40"
                    disabled={reorder!.disabled}
                    type="button"
                  >
                    <GripVerticalIcon className="h-4 w-4" />
                  </button>
                ) : null}
                {hasSelection ? (
                  <Checkbox
                    aria-label={
                      rowId
                        ? selection!.getRowLabel(rowId)
                        : (selection!.selectAllLabel ?? "Select row")
                    }
                    checked={rowId ? selection!.selectedIds.has(rowId) : false}
                    disabled={selection!.disabled || !rowId}
                    onCheckedChange={() => {
                      if (rowId) selection!.onToggle(rowId)
                    }}
                  />
                ) : null}
                <div className="ml-auto">{actionsCell}</div>
              </div>

              {bodyCells.map((cell, cellIndex) => {
                const label = headers?.[cellIndex]
                if (!label) {
                  return (
                    <div className="min-w-0" key={cellIndex}>
                      {cell}
                    </div>
                  )
                }

                return (
                  <div
                    className="grid grid-cols-[minmax(0,7.5rem)_minmax(0,1fr)] items-start gap-2 text-sm"
                    key={cellIndex}
                  >
                    <span className="text-xs text-muted-foreground uppercase">
                      {label}
                    </span>
                    <div className="min-w-0 break-words">{cell}</div>
                  </div>
                )
              })}
            </div>
          )
        })}
      </div>
    </>
  )
}
