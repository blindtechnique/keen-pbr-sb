import {
  useCallback,
  useEffect,
  useLayoutEffect,
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
  const orderRef = useRef<number[]>([])
  const draggingPositionRef = useRef<number | null>(null)
  const draggedItemRef = useRef<number | null>(null)
  const dragContainerRef = useRef<HTMLElement | null>(null)
  const renderSynchronizedRef = useRef(true)
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
      dragContainerRef.current = null
      renderSynchronizedRef.current = true
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

  useLayoutEffect(() => {
    renderSynchronizedRef.current = true
  }, [renderedOrder])

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
      dragContainerRef.current = source.parentElement
      renderSynchronizedRef.current = true
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

    // React may not have committed the previous visual reorder yet. Reading
    // position attributes from the old DOM during that short window can undo
    // the previous move. Wait for the layout commit before resolving another
    // target.
    if (!renderSynchronizedRef.current) {
      return
    }

    const hoveredItem = document
      .elementFromPoint(event.clientX, pointerY)
      ?.closest<HTMLElement>(itemSelector)
    const hoveredPosition = Number(
      hoveredItem && dragContainerRef.current?.contains(hoveredItem)
        ? hoveredItem.dataset.sortablePosition
        : Number.NaN
    )

    let targetPosition = Number.isInteger(hoveredPosition)
      ? hoveredPosition
      : -1

    if (
      targetPosition < 0 ||
      targetPosition >= orderRef.current.length
    ) {
      const candidates = Array.from(
        dragContainerRef.current?.querySelectorAll<HTMLElement>(itemSelector) ??
          []
      )
        .map((element) => {
          const position = Number(element.dataset.sortablePosition)
          const box = element.getBoundingClientRect()
          return {
            middle: box.top + box.height / 2,
            position,
          }
        })
        .filter(
          ({ position }) =>
            Number.isInteger(position) &&
            position >= 0 &&
            position < orderRef.current.length
        )
        .sort((left, right) => left.middle - right.middle)

      targetPosition =
        candidates.find(({ middle }) => pointerY < middle)?.position ??
        candidates.at(-1)?.position ??
        -1
      if (targetPosition < 0) {
        return
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
    renderSynchronizedRef.current = false
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
