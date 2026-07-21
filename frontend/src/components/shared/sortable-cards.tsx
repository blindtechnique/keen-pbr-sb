import { GripVertical } from "lucide-react"
import type { ReactNode } from "react"
import { useRef, useState } from "react"

import { cn } from "@/lib/utils"

/**
 * Список карточек с перетаскиванием пальцем.
 *
 * На телефоне таблица разворачивается в столбик подписей и читается как каша,
 * а перетаскивать строки нельзя вовсе: HTML5-drag на сенсорных экранах не
 * работает — браузер отдаёт touch-события прокрутке. Поэтому здесь свой
 * механизм на pointer-событиях: они одинаковы для мыши и пальца, а
 * `setPointerCapture` не даёт жесту потеряться, если палец соскользнул с
 * ручки.
 *
 * Порядок меняется прямо во время перетаскивания, как только палец прошёл
 * середину соседа: так видно результат, а не только намерение. Наружу он
 * отдаётся один раз, когда палец отпущен, — промежуточные перестановки не
 * должны улетать в конфигурацию.
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
  handleLabel: string
}) {
  const [order, setOrder] = useState<number[] | null>(null)
  const [dragging, setDragging] = useState<number | null>(null)
  const rowRefs = useRef<(HTMLDivElement | null)[]>([])
  const startOrder = useRef<number[]>([])

  const current = order ?? items.map((_, index) => index)

  const beginDrag = (position: number) => (event: React.PointerEvent) => {
    if (disabled) return
    event.preventDefault()
    event.currentTarget.setPointerCapture(event.pointerId)
    startOrder.current = current
    setOrder(current)
    setDragging(position)
  }

  const moveDrag = (event: React.PointerEvent) => {
    if (dragging === null) return
    const y = event.clientY

    // Куда попал палец: ищем строку, чья середина ближе всего сверху.
    const positions = current.map((_, position) => {
      const element = rowRefs.current[position]
      if (!element) return Number.POSITIVE_INFINITY
      const box = element.getBoundingClientRect()
      return box.top + box.height / 2
    })

    let target = dragging
    if (y < positions[dragging] && dragging > 0 && y < positions[dragging - 1]) {
      target = dragging - 1
    } else if (
      y > positions[dragging] &&
      dragging < current.length - 1 &&
      y > positions[dragging + 1]
    ) {
      target = dragging + 1
    }

    if (target !== dragging) {
      const next = [...current]
      const [moved] = next.splice(dragging, 1)
      next.splice(target, 0, moved)
      setOrder(next)
      setDragging(target)
    }
  }

  const endDrag = () => {
    if (dragging === null) return
    const before = startOrder.current
    const after = current
    // Наружу отдаём один сдвиг: откуда взяли и куда положили.
    const from = before.findIndex((value, index) => value !== after[index])
    if (from !== -1) {
      const movedValue = after[from]
      const originalIndex = before.indexOf(movedValue)
      if (originalIndex !== from) {
        onReorder(originalIndex, from)
      }
    }
    setDragging(null)
    setOrder(null)
  }

  return (
    <div className="space-y-2">
      {current.map((itemIndex, position) => (
        <div
          className={cn(
            "flex items-start gap-2 rounded-xl border bg-card p-3 transition-shadow",
            dragging === position && "border-primary shadow-lg"
          )}
          key={getKey(items[itemIndex], itemIndex)}
          ref={(element) => {
            rowRefs.current[position] = element
          }}
        >
          <button
            aria-label={handleLabel}
            className="mt-0.5 shrink-0 cursor-grab touch-none p-1 text-muted-foreground active:cursor-grabbing disabled:opacity-40"
            disabled={disabled}
            onPointerCancel={endDrag}
            onPointerDown={beginDrag(position)}
            onPointerMove={moveDrag}
            onPointerUp={endDrag}
            title={handleLabel}
            type="button"
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
