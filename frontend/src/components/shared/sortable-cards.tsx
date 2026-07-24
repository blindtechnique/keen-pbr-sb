import { GripVertical } from "lucide-react"
import type { ReactNode } from "react"

import { usePointerSortable } from "@/hooks/use-pointer-sortable"
import { cn } from "@/lib/utils"

/**
 * Список карточек с одинаковым перетаскиванием мышью, пальцем и клавиатурой.
 *
 * Общий pointer-механизм используется и настольной таблицей. Соседние строки
 * раздвигаются во время жеста, но наружу уходит только итоговый порядок после
 * отпускания. Стрелки вверх/вниз на ручке дают тот же результат с клавиатуры.
 */
export function SortableCards<T>({
  items,
  getKey,
  renderCard,
  onReorder,
  disabled = false,
  handleLabel,
}: {
  items: T[]
  getKey: (item: T, index: number) => string
  renderCard: (item: T, index: number) => ReactNode
  onReorder: (from: number, to: number) => void
  disabled?: boolean
  handleLabel: string | ((item: T, index: number) => string)
}) {
  const { currentOrder, draggingPosition, getHandleProps, setItemRef } =
    usePointerSortable({
      itemCount: items.length,
      disabled,
      itemSelector: "[data-sortable-card]",
      onReorder,
    })

  return (
    <div
      className={cn(
        "space-y-2 overscroll-contain",
        draggingPosition !== null && "select-none"
      )}
    >
      {currentOrder.map((itemIndex, position) => (
        <div
          className={cn(
            "flex items-start gap-2 rounded-xl border bg-card p-3 transition-shadow",
            draggingPosition === position && "keen-drag-lifted"
          )}
          data-sortable-card
          key={getKey(items[itemIndex], itemIndex)}
          ref={(element) => {
            setItemRef(position, element)
          }}
        >
          <button
            aria-label={
              typeof handleLabel === "function"
                ? handleLabel(items[itemIndex], itemIndex)
                : handleLabel
            }
            className="mt-0.5 shrink-0 cursor-grab touch-none p-1 text-muted-foreground active:cursor-grabbing disabled:opacity-40"
            disabled={disabled}
            title={
              typeof handleLabel === "function"
                ? handleLabel(items[itemIndex], itemIndex)
                : handleLabel
            }
            type="button"
            {...getHandleProps(position)}
          >
            <GripVertical className="size-5" />
          </button>
          <div className="min-w-0 flex-1">
            {renderCard(items[itemIndex], itemIndex)}
          </div>
        </div>
      ))}
    </div>
  )
}
