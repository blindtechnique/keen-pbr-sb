import { useState, type ReactNode } from "react"
import { GripVerticalIcon } from "lucide-react"

import { Checkbox } from "@/components/ui/checkbox"
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

export function DataTable({
  headers,
  rows,
  compact = false,
  narrowColumns = [],
  selection,
  reorder,
}: {
  headers?: string[]
  rows: ReactNode[][]
  compact?: boolean
  narrowColumns?: number[]
  selection?: DataTableSelection
  reorder?: DataTableReorder
}) {
  const [dragIndex, setDragIndex] = useState<number | null>(null)
  const [dropIndex, setDropIndex] = useState<number | null>(null)
  const hasSelection = Boolean(
    selection && selection.rowIds.length === rows.length
  )
  const hasReorder = Boolean(reorder)
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

  function headClass(headerIndex: number) {
    if (headerIndex < leadingColumns) {
      return compact
        ? "h-8 w-px px-1.5 font-semibold whitespace-nowrap"
        : "w-px px-2 font-semibold whitespace-nowrap"
    }

    return headerIndex === lastColumnIndex
      ? compact
        ? "h-8 w-px text-right font-semibold"
        : "w-px text-right font-semibold"
      : narrowColumnSet.has(headerIndex)
        ? compact
          ? "h-8 w-px font-semibold whitespace-nowrap"
          : "w-px font-semibold whitespace-nowrap"
        : compact
          ? "h-8 font-semibold"
          : "font-semibold"
  }

  function cellClass(cellIndex: number) {
    if (cellIndex < leadingColumns) {
      return compact
        ? "w-px px-1.5 py-1.5 align-middle whitespace-nowrap"
        : "w-px px-2 py-3 align-middle whitespace-nowrap"
    }

    return cellIndex === lastColumnIndex
      ? compact
        ? "w-px px-2 py-1.5 text-right align-middle whitespace-nowrap"
        : "w-px p-3 text-right align-middle whitespace-nowrap"
      : narrowColumnSet.has(cellIndex)
        ? compact
          ? "w-px px-2 py-1.5 align-middle whitespace-nowrap"
          : "w-px p-3 align-middle whitespace-nowrap"
        : compact
          ? "px-2 py-1.5 align-middle whitespace-normal"
          : "p-3 align-middle whitespace-normal"
  }

  return (
    <>
    <div className="hidden max-w-full overflow-x-auto border-b md:block">
      <Table className={compact ? "w-full text-sm" : "w-full text-sm"}>
        {headersWithSelection && (
          <TableHeader className="bg-muted/70 text-xs tracking-wide text-muted-foreground uppercase">
            <TableRow>
              {headersWithSelection.map((header, headerIndex) => (
                <TableHead
                  className={headClass(headerIndex)}
                  key={`${header}-${headerIndex}`}
                >
                  {hasSelection && headerIndex === leadingColumns - 1 ? (
                    <div className="flex justify-center">
                      <Checkbox
                        aria-label={
                          selection!.selectAllLabel ?? "Select all visible rows"
                        }
                        checked={allVisibleSelected}
                        disabled={
                          selection!.disabled || visibleRowIds.length === 0
                        }
                        onCheckedChange={(checked) => {
                          selection!.onToggleAll(checked === true, selection!.rowIds)
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
        <TableBody>
          {rows.map((row, index) => {
            const rowId = hasSelection ? (selection!.rowIds[index] ?? "") : ""

            const isDropTarget = hasReorder && dropIndex === index && dragIndex !== index

            return (
              <TableRow
                className={
                  isDropTarget
                    ? "outline outline-2 -outline-offset-2 outline-primary/60"
                    : undefined
                }
                draggable={hasReorder && dragIndex === index}
                key={hasSelection ? rowId || index : `${row[0]}-${index}`}
                onDragEnd={() => {
                  setDragIndex(null)
                  setDropIndex(null)
                }}
                onDragOver={(event) => {
                  if (!hasReorder || dragIndex === null) return
                  event.preventDefault()
                  setDropIndex(index)
                }}
                onDrop={(event) => {
                  if (!hasReorder || dragIndex === null) return
                  event.preventDefault()
                  if (dragIndex !== index) reorder!.onReorder(dragIndex, index)
                  setDragIndex(null)
                  setDropIndex(null)
                }}
              >
                {hasReorder ? (
                  <TableCell className={cellClass(0)}>
                    <button
                      aria-label={reorder!.handleLabel ?? "Reorder row"}
                      className="flex cursor-grab items-center justify-center text-muted-foreground transition-colors hover:text-foreground active:cursor-grabbing disabled:cursor-not-allowed disabled:opacity-40"
                      disabled={reorder!.disabled}
                      // Rows stay undraggable until the handle is pressed, so
                      // text selection inside cells keeps working.
                      onDragStart={() => setDragIndex(index)}
                      onPointerDown={() => setDragIndex(index)}
                      onPointerUp={() => setDragIndex(null)}
                      draggable={!reorder!.disabled}
                      title={reorder!.handleLabel ?? "Reorder row"}
                      type="button"
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
