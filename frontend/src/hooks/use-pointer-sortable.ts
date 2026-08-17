import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type PointerEvent as ReactPointerEvent,
} from "react"

type PreviewFactory = (source: HTMLElement) => HTMLElement

type PointerSortableOptions = {
  itemCount: number
  disabled?: boolean
  itemSelector: string
  onReorder: (fromIndex: number, toIndex: number) => void
  createPreview?: PreviewFactory
}

type SortableCandidate = {
  middle: number
  position: number
}

function identityOrder(itemCount: number) {
  return Array.from({ length: itemCount }, (_item, index) => index)
}

function clonePreview(source: HTMLElement) {
  return source.cloneNode(true) as HTMLElement
}

export function resolveSortableTargetPosition(
  pointerY: number,
  currentPosition: number,
  candidates: readonly SortableCandidate[],
  itemCount: number
) {
  const orderedCandidates = [...candidates]
    .filter(
      ({ middle, position }) =>
        Number.isFinite(middle) &&
        Number.isInteger(position) &&
        position >= 0 &&
        position < itemCount
    )
    .sort((left, right) => left.middle - right.middle)

  const currentCandidate = orderedCandidates.find(
    ({ position }) => position === currentPosition
  )
  if (!currentCandidate) {
    return -1
  }

  let targetPosition = currentPosition
  if (pointerY > currentCandidate.middle) {
    for (const candidate of orderedCandidates) {
      if (
        candidate.position > currentPosition &&
        pointerY >= candidate.middle
      ) {
        targetPosition = candidate.position
      }
    }
  } else if (pointerY < currentCandidate.middle) {
    for (let index = orderedCandidates.length - 1; index >= 0; index -= 1) {
      const candidate = orderedCandidates[index]
      if (
        candidate &&
        candidate.position < currentPosition &&
        pointerY <= candidate.middle
      ) {
        targetPosition = candidate.position
      }
    }
  }

  return targetPosition
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
  const previewRef = useRef<HTMLElement | null>(null)
  const previewOffsetYRef = useRef(0)
  const activePointerIdRef = useRef<number | null>(null)

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

      activePointerIdRef.current = null
      removePreview()
      draggingPositionRef.current = null
      draggedItemRef.current = null
      dragContainerRef.current = null
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

  const moveDrag = useCallback(
    (event: ReactPointerEvent<HTMLElement>) => {
      const currentPosition = draggingPositionRef.current
      if (
        currentPosition === null ||
        event.pointerId !== activePointerIdRef.current
      ) {
        return
      }

      event.preventDefault()
      const pointerY = event.clientY
      if (previewRef.current) {
        previewRef.current.style.top = `${pointerY - previewOffsetYRef.current}px`
      }

      // Resolve the destination from the visual slots rather than from the
      // element directly below the pointer. React can still be committing the
      // previous reorder while pointer events keep arriving; slot coordinates
      // remain valid during that window, whereas a hovered row can still carry
      // the previous item and make a downward drag jump back or stop.
      const candidates = Array.from(
        dragContainerRef.current?.querySelectorAll<HTMLElement>(itemSelector) ??
          []
      ).map((element) => {
        const position = Number(element.dataset.sortablePosition)
        const box = element.getBoundingClientRect()
        return {
          middle: box.top + box.height / 2,
          position,
        }
      })

      const targetPosition = resolveSortableTargetPosition(
        pointerY,
        currentPosition,
        candidates,
        orderRef.current.length
      )
      if (targetPosition < 0 || targetPosition === currentPosition) {
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
    },
    [itemSelector]
  )

  const beginDrag =
    (position: number) => (event: ReactPointerEvent<HTMLElement>) => {
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

      const container = source.parentElement
      if (!container) {
        return
      }

      if (draggingPositionRef.current !== null) {
        finishDrag(false)
      }

      event.preventDefault()

      const pointerId = event.pointerId
      container.setPointerCapture(pointerId)

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
      dragContainerRef.current = container
      previewRef.current = preview
      previewOffsetYRef.current = event.clientY - sourceBox.top
      activePointerIdRef.current = pointerId

      setRenderedOrder(nextOrder)
      setDraggingPosition(position)
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
    getContainerProps: () => ({
      onLostPointerCapture: (event: ReactPointerEvent<HTMLElement>) => {
        if (
          event.pointerId === activePointerIdRef.current &&
          draggingPositionRef.current !== null
        ) {
          finishDrag(false)
        }
      },
      onPointerCancel: (event: ReactPointerEvent<HTMLElement>) => {
        if (event.pointerId === activePointerIdRef.current) {
          finishDrag(false)
        }
      },
      onPointerMove: moveDrag,
      onPointerUp: (event: ReactPointerEvent<HTMLElement>) => {
        if (event.pointerId === activePointerIdRef.current) {
          finishDrag(true)
        }
      },
    }),
    setItemRef: (position: number, element: HTMLElement | null) => {
      if (element) {
        element.dataset.sortablePosition = String(position)
      }
    },
    getHandleProps: (position: number) => ({
      onKeyDown: handleKeyDown(position),
      onPointerDown: beginDrag(position),
    }),
  }
}
