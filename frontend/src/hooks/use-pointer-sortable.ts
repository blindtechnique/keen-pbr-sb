import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type PointerEvent,
} from "react"

type PreviewFactory = (source: HTMLElement) => HTMLElement

type PointerSortableOptions = {
  itemCount: number
  disabled?: boolean
  itemSelector: string
  onReorder: (fromIndex: number, toIndex: number) => void
  createPreview?: PreviewFactory
}

function identityOrder(itemCount: number) {
  return Array.from({ length: itemCount }, (_item, index) => index)
}

function clonePreview(source: HTMLElement) {
  return source.cloneNode(true) as HTMLElement
}

export function usePointerSortable({
  itemCount,
  disabled = false,
  itemSelector,
  onReorder,
  createPreview = clonePreview,
}: PointerSortableOptions) {
  const [renderedOrder, setRenderedOrder] = useState<number[] | null>(null)
  const [draggingPosition, setDraggingPosition] = useState<number | null>(null)
  const itemRefs = useRef<(HTMLElement | null)[]>([])
  const orderRef = useRef<number[]>([])
  const draggingPositionRef = useRef<number | null>(null)
  const draggedItemRef = useRef<number | null>(null)
  const previewRef = useRef<HTMLElement | null>(null)
  const previewOffsetYRef = useRef(0)

  const currentOrder = useMemo(
    () => renderedOrder ?? identityOrder(itemCount),
    [itemCount, renderedOrder]
  )

  const removePreview = useCallback(() => {
    previewRef.current?.remove()
    previewRef.current = null
  }, [])

  const finishDrag = useCallback(
    (commit: boolean) => {
      const draggedItem = draggedItemRef.current
      const finalPosition =
        draggedItem === null ? -1 : orderRef.current.indexOf(draggedItem)

      if (
        commit &&
        draggedItem !== null &&
        finalPosition >= 0 &&
        finalPosition !== draggedItem
      ) {
        onReorder(draggedItem, finalPosition)
      }

      removePreview()
      draggingPositionRef.current = null
      draggedItemRef.current = null
      setDraggingPosition(null)
      setRenderedOrder(null)
    },
    [onReorder, removePreview]
  )

  useEffect(
    () => () => {
      previewRef.current?.remove()
    },
    []
  )

  const beginDrag =
    (position: number) => (event: PointerEvent<HTMLElement>) => {
      if (
        disabled ||
        event.button !== 0 ||
        position < 0 ||
        position >= currentOrder.length
      ) {
        return
      }

      const source = event.currentTarget.closest<HTMLElement>(itemSelector)
      if (!source) {
        return
      }

      event.preventDefault()
      event.currentTarget.setPointerCapture(event.pointerId)

      const nextOrder = [...currentOrder]
      const sourceBox = source.getBoundingClientRect()
      const preview = createPreview(source)
      preview.setAttribute("aria-hidden", "true")
      preview
        .querySelectorAll("[id]")
        .forEach((node) => node.removeAttribute("id"))
      preview.classList.add("keen-drag-preview")
      Object.assign(preview.style, {
        height: `${sourceBox.height}px`,
        left: `${sourceBox.left}px`,
        top: `${sourceBox.top}px`,
        width: `${sourceBox.width}px`,
      })
      document.body.append(preview)

      orderRef.current = nextOrder
      draggingPositionRef.current = position
      draggedItemRef.current = nextOrder[position] ?? null
      previewRef.current = preview
      previewOffsetYRef.current = event.clientY - sourceBox.top
      setRenderedOrder(nextOrder)
      setDraggingPosition(position)
    }

  const moveDrag = (event: PointerEvent<HTMLElement>) => {
    const currentPosition = draggingPositionRef.current
    if (currentPosition === null) {
      return
    }

    event.preventDefault()
    const pointerY = event.clientY
    if (previewRef.current) {
      previewRef.current.style.top = `${pointerY - previewOffsetYRef.current}px`
    }

    const hoveredItem = document
      .elementFromPoint(event.clientX, pointerY)
      ?.closest<HTMLElement>(itemSelector)
    const hoveredPosition = Number(
      hoveredItem?.dataset.sortablePosition ?? Number.NaN
    )

    let targetPosition = Number.isInteger(hoveredPosition)
      ? hoveredPosition
      : -1

    if (
      targetPosition < 0 ||
      targetPosition >= orderRef.current.length
    ) {
      const positions = orderRef.current.map((_item, position) => {
        const element = itemRefs.current[position]
        if (!element) {
          return Number.POSITIVE_INFINITY
        }
        const box = element.getBoundingClientRect()
        return box.top + box.height / 2
      })
      targetPosition = positions.findIndex((middle) => pointerY < middle)
      if (targetPosition === -1) {
        targetPosition = orderRef.current.length - 1
      }
    }
    if (targetPosition === currentPosition) {
      return
    }

    const nextOrder = [...orderRef.current]
    const [movedItem] = nextOrder.splice(currentPosition, 1)
    if (movedItem === undefined) {
      return
    }
    nextOrder.splice(targetPosition, 0, movedItem)

    orderRef.current = nextOrder
    draggingPositionRef.current = targetPosition
    setRenderedOrder(nextOrder)
    setDraggingPosition(targetPosition)
  }

  const handleKeyDown =
    (position: number) => (event: KeyboardEvent<HTMLElement>) => {
      if (disabled || (event.key !== "ArrowUp" && event.key !== "ArrowDown")) {
        return
      }

      const targetPosition =
        event.key === "ArrowUp" ? position - 1 : position + 1
      if (targetPosition < 0 || targetPosition >= itemCount) {
        return
      }

      event.preventDefault()
      onReorder(position, targetPosition)
    }

  return {
    currentOrder,
    draggingPosition,
    setItemRef: (position: number, element: HTMLElement | null) => {
      itemRefs.current[position] = element
      if (element) {
        element.dataset.sortablePosition = String(position)
      }
    },
    getHandleProps: (position: number) => ({
      onKeyDown: handleKeyDown(position),
      onLostPointerCapture: () => {
        if (draggingPositionRef.current !== null) {
          finishDrag(false)
        }
      },
      onPointerCancel: () => finishDrag(false),
      onPointerDown: beginDrag(position),
      onPointerMove: moveDrag,
      onPointerUp: () => finishDrag(true),
    }),
  }
}
