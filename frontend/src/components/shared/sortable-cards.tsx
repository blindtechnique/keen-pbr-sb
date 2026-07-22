import { GripVertical } from "lucide-react"
import type { ReactNode } from "react"
import { useEffect, useRef, useState } from "react"

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
  const orderRef = useRef<number[]>([])
  const draggedItem = useRef<number | null>(null)
  const dragPreview = useRef<HTMLDivElement | null>(null)
  const dragOffsetY = useRef(0)

  const current = order ?? items.map((_, index) => index)

  const removeDragPreview = () => {
    dragPreview.current?.remove()
    dragPreview.current = null
  }

  useEffect(
    () => () => {
      dragPreview.current?.remove()
    },
    []
  )

  const beginDrag = (position: number) => (event: React.PointerEvent) => {
    if (disabled) return
    event.preventDefault()
    event.currentTarget.setPointerCapture(event.pointerId)
    orderRef.current = [...current]
    draggedItem.current = current[position]
    setOrder([...current])
    setDragging(position)

    const card = event.currentTarget.closest<HTMLDivElement>(
      "[data-sortable-card]"
    )
    if (card) {
      const box = card.getBoundingClientRect()
      const preview = card.cloneNode(true) as HTMLDivElement
      preview.setAttribute("aria-hidden", "true")
      preview
        .querySelectorAll("[id]")
        .forEach((node) => node.removeAttribute("id"))
      preview.classList.add("keen-drag-preview")
      Object.assign(preview.style, {
        height: `${box.height}px`,
        left: `${box.left}px`,
        top: `${box.top}px`,
        width: `${box.width}px`,
      })
      document.body.append(preview)
      dragPreview.current = preview
      dragOffsetY.current = event.clientY - box.top
    }
  }

  const moveDrag = (event: React.PointerEvent) => {
    if (dragging === null) return
    const y = event.clientY
    if (dragPreview.current) {
      dragPreview.current.style.top = `${y - dragOffsetY.current}px`
    }

    // Куда попал палец: ищем строку, чья середина ближе всего сверху.
    const positions = current.map((_, position) => {
      const element = rowRefs.current[position]
      if (!element) return Number.POSITIVE_INFINITY
      const box = element.getBoundingClientRect()
      return box.top + box.height / 2
    })

    let target = positions.findIndex((middle) => y < middle)
    if (target === -1) target = current.length - 1

    if (target !== dragging) {
      const next = [...current]
      const [moved] = next.splice(dragging, 1)
      next.splice(target, 0, moved)
      orderRef.current = next
      setOrder(next)
      setDragging(target)
    }
  }

  const endDrag = (commit: boolean) => {
    if (dragging === null) return
    const itemIndex = draggedItem.current
    const finalPosition =
      itemIndex === null ? -1 : orderRef.current.indexOf(itemIndex)
    // Наружу отдаём один сдвиг: откуда взяли и куда положили.
    if (commit && itemIndex !== null && finalPosition !== itemIndex) {
      onReorder(itemIndex, finalPosition)
    }
    removeDragPreview()
    draggedItem.current = null
    setDragging(null)
    setOrder(null)
  }

  return (
    <div className="space-y-2">
      {current.map((itemIndex, position) => (
        <div
          className={cn(
            "flex items-start gap-2 rounded-xl border bg-card p-3 transition-shadow",
            dragging === position && "keen-drag-lifted"
          )}
          data-sortable-card
          key={getKey(items[itemIndex], itemIndex)}
          ref={(element) => {
            rowRefs.current[position] = element
          }}
        >
          <button
            aria-label={handleLabel}
            className="mt-0.5 shrink-0 cursor-grab touch-none p-1 text-muted-foreground active:cursor-grabbing disabled:opacity-40"
            disabled={disabled}
            onPointerCancel={() => endDrag(false)}
            onPointerDown={beginDrag(position)}
            onPointerMove={moveDrag}
            onPointerUp={() => endDrag(true)}
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
