import type { ReactNode } from "react"
import { Fragment } from "react"
import { GripVerticalIcon } from "lucide-react"

import { Checkbox } from "@/components/ui/checkbox"
import {
  getDataTableMobileColumnLayout,
  type DataTableMobileLayout,
} from "@/components/shared/data-table-mobile-layout"
import { usePointerSortable } from "@/hooks/use-pointer-sortable"
import type { TableSortDirection, TableSortState } from "@/hooks/use-table-sort"
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

/**
 * Значок сортировки KeeneticOS.
 *
 * Не стрелка, а три полосы разной длины, выровненные по левому краю: короткая,
 * средняя, длинная — «от меньшего к большему». Снято с живого конфигуратора:
 * `<use href="sprite.svg#asc">` в поле 16×16, отступ 12px слева. Обратный
 * порядок прошивка показывает переворотом того же значка
 * (`transform: scale(1,-1)`), а не вторым значком.
 *
 * Место под значок занято всегда, и скрытый он именно невидим, а не отсутствует:
 * иначе при наведении на «Состояние» заголовок сдвигался и дёргалась вся
 * таблица.
 *
 * Цвет подсказки — `--table-sort-icon-hover` из прошивки: #d6d8d9 на светлой
 * теме, #6f737b на тёмной. Выбранная колонка берёт цвет текста заголовка:
 * подсказка должна быть еле видна, выбор — читаться.
 */
function TableSortIcon({
  direction,
}: {
  direction: TableSortDirection | null
}) {
  return (
    <span
      aria-hidden="true"
      className={cn(
        "ml-3 inline-flex size-4 shrink-0 items-center justify-center",
        direction
          ? "text-foreground"
          : "invisible text-[#d6d8d9] group-hover/sort:visible group-focus-visible/sort:visible dark:text-[#6f737b]"
      )}
    >
      <svg
        className={cn(
          "size-4",
          direction === "desc" && "[transform:scale(1,-1)]"
        )}
        fill="currentColor"
        viewBox="0 0 16 16"
      >
        <rect height="1.5" width="5.5" x="0" y="2.5" />
        <rect height="1.5" width="10.75" x="0" y="7.25" />
        <rect height="1.5" width="16" x="0" y="12" />
      </svg>
    </span>
  )
}

export function DataTable({
  headers,
  rows,
  groupHeadings,
  rowDetails,
  compact = false,
  fixedLayout = false,
  columnClassNames = [],
  narrowColumns = [],
  selection,
  reorder,
  sort,
  mobileLayout,
}: {
  headers?: string[]
  rows: ReactNode[][]
  /**
   * Подзаголовки внутри одной таблицы: ключ — индекс строки, перед которой
   * встаёт заголовок группы.
   *
   * Две отдельные таблицы выглядели бы так же, но у каждой свои колонки: ширина
   * считается по содержимому, и «Название» в верхней таблице оказывалось на
   * сотню пикселей уже, чем в нижней. Одна таблица — одна сетка.
   */
  groupHeadings?: Record<number, ReactNode>
  /**
   * Раскрытые подробности строки: ключ — индекс строки, значение — то, что
   * встаёт под ней во всю ширину таблицы.
   *
   * Строка списка отвечает на «что это и работает ли», подробности — на «а
   * что там внутри». Раньше ради второго вопроса весь список рисовался
   * карточками, и первый вопрос из-за этого требовал прокрутки.
   */
  rowDetails?: Record<number, ReactNode>
  compact?: boolean
  fixedLayout?: boolean
  columnClassNames?: Array<string | undefined>
  narrowColumns?: number[]
  selection?: DataTableSelection
  reorder?: DataTableReorder
  mobileLayout?: DataTableMobileLayout
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
  // Служебные колонки — перетаскивание и выбор — тоже колонки, и до сих пор у
  // них не было имени: читалка объявляла ячейку без всякого «чего именно».
  // Подпись видна только читалке: показывать «Выбор» над галочкой значило бы
  // расширить колонку ради слова, которое и так очевидно глазом.
  const leadingHeaders = [
    ...(hasReorder ? [reorder!.handleLabel ?? "Reorder row"] : []),
    ...(hasSelection
      ? [selection!.selectAllLabel ?? "Select all visible rows"]
      : []),
  ]
  const headersWithSelection = headers
    ? [...leadingHeaders, ...headers]
    : headers
  const lastColumnIndex = headersWithSelection
    ? headersWithSelection.length - 1
    : rows.length && rows[0]?.length
      ? rows[0].length - 1
      : 0
  const totalColumns =
    leadingColumns + (headers?.length ?? rows[0]?.length ?? 1)
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
    return Boolean(sort && sort.sortable.includes(headerIndex - leadingColumns))
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
          ? "h-8 w-8 px-0.5 font-bold whitespace-nowrap"
          : "w-8 px-0.5 font-bold whitespace-nowrap"
      }

      return compact
        ? "h-8 w-px px-1.5 font-bold whitespace-nowrap"
        : "w-px px-2 font-bold whitespace-nowrap"
    }

    return cn(
      headerIndex === lastColumnIndex
        ? compact
          ? "h-8 w-px text-right font-bold"
          : "w-px text-right font-bold"
        : narrowColumnSet.has(headerIndex)
          ? compact
            ? "h-8 w-px font-bold whitespace-nowrap"
            : "w-px font-bold whitespace-nowrap"
          : compact
            ? "h-8 font-bold"
            : "font-bold",
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
                      // Значок сортировки появляется по наведению, а текст
                      // цвет не меняет — так это сделано в конфигураторе:
                      // `--sortable .hover-sort-icon { display: none }` и
                      // `--sortable:hover { cursor: pointer }`. Меняющийся цвет
                      // читался как ссылка, хотя никуда не ведёт.
                      <button
                        className="group/sort -mx-1 inline-flex cursor-pointer items-center rounded px-1 py-0.5 text-left select-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                        onClick={() =>
                          sort!.onToggle(headerIndex - leadingColumns)
                        }
                        type="button"
                      >
                        {header}
                        <TableSortIcon
                          direction={sortDirectionOf(headerIndex)}
                        />
                      </button>
                    ) : hasSelection && headerIndex === leadingColumns - 1 ? (
                      <div className="flex justify-center">
                        <span className="sr-only">{header}</span>
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
                    ) : headerIndex < leadingColumns ||
                      headerIndex === lastColumnIndex ? (
                      // Колонка действий заголовка не показывает — в
                      // конфигураторе он там пустой. Слово «Действия» ничего не
                      // добавляло: под ним и так стоят понятные значки, а
                      // колонка узкая, и подпись в ней шире содержимого.
                      // Скринридеру заголовок при этом остаётся: без него
                      // ячейка в таблице теряет имя.
                      <span className="sr-only">{header}</span>
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
              const heading = groupHeadings?.[rowIndex]
              const details = rowDetails?.[rowIndex]

              return (
                <Fragment
                  key={hasSelection ? rowId || rowIndex : `group-${rowIndex}`}
                >
                  {heading ? (
                    <TableRow className="hover:bg-transparent">
                      {/* Отступы одинаковые сверху и снизу: при 16px сверху и
                          6px снизу подпись «Работают» стояла заметно ниже
                          середины своей полосы.

                          `whitespace-normal` обязателен: ячейка таблицы по
                          умолчанию запрещает перенос, и описание группы шло
                          одной строкой — из-за неё, а не из-за колонок, в
                          маршрутах появлялась горизонтальная прокрутка. */}
                      <TableCell
                        className="bg-background px-3 py-2 whitespace-normal"
                        colSpan={totalColumns}
                      >
                        {heading}
                      </TableCell>
                    </TableRow>
                  ) : null}
                  <TableRow
                    className={cn(
                      "group/row transition-[background-color,box-shadow,opacity] duration-150",
                      // Строка и её подробности читаются как один блок, поэтому
                      // разделитель между ними убран — он остаётся снизу у
                      // подробностей.
                      details && "border-b-0",
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
                  {details ? (
                    <TableRow className="hover:bg-transparent">
                      <TableCell
                        className="bg-muted/40 px-3 py-3 whitespace-normal"
                        colSpan={totalColumns}
                      >
                        {details}
                      </TableCell>
                    </TableRow>
                  ) : null}
                </Fragment>
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
          const mobileColumns = getDataTableMobileColumnLayout(
            headers?.slice(0, -1),
            bodyCells.length,
            mobileLayout
          )
          const controlCells = mobileColumns.controlIndices.map(
            (cellIndex) => bodyCells[cellIndex]
          )
          const titleCell =
            mobileColumns.titleIndex === undefined
              ? undefined
              : bodyCells[mobileColumns.titleIndex]
          const restCells = mobileColumns.detailIndices.map((cellIndex) => ({
            cell: bodyCells[cellIndex],
            label: headers?.[cellIndex],
          }))

          return (
            <Fragment key={hasSelection ? rowId || index : `mobile-${index}`}>
              {groupHeadings?.[index] ? (
                <div className="py-2">{groupHeadings[index]}</div>
              ) : null}
              <div className="space-y-2 py-3">
                {/* Галочка, имя и действия — одной строкой, как в шапке
                    карточки. Карандаш стоял отдельной строкой под именем, и
                    чтобы понять, что он правит, приходилось возвращаться
                    глазом наверх. */}
                <div className="flex items-center gap-2">
                  {hasReorder ? (
                    <button
                      aria-label={reorder!.handleLabel ?? "Reorder row"}
                      className="shrink-0 cursor-grab text-muted-foreground disabled:opacity-40"
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
                      checked={
                        rowId ? selection!.selectedIds.has(rowId) : false
                      }
                      className="shrink-0"
                      disabled={selection!.disabled || !rowId}
                      onCheckedChange={() => {
                        if (rowId) selection!.onToggle(rowId)
                      }}
                    />
                  ) : null}
                  {titleCell ? (
                    <div className="min-w-0 flex-1 text-[15px] font-medium">
                      {titleCell}
                    </div>
                  ) : null}
                  <div className="ml-auto shrink-0">{actionsCell}</div>
                </div>
                {/* Колонка без названия — это не данные, а управление:
                    выключатель, перезапуск. Ему отдельная строка под именем:
                    в одну строку с действиями получалось шесть кнопок подряд. */}
                {controlCells.length > 0 ? (
                  <div className="flex items-center gap-2">
                    {controlCells.map((cell, cellIndex) => (
                      <div className="min-w-0" key={`control-${cellIndex}`}>
                        {cell}
                      </div>
                    ))}
                  </div>
                ) : null}

                {restCells.map(({ cell, label }, cellIndex) => {
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

                {rowDetails?.[index] ? (
                  <div className="rounded-md bg-muted/40 p-3">
                    {rowDetails[index]}
                  </div>
                ) : null}
              </div>
            </Fragment>
          )
        })}
      </div>
    </>
  )
}
