import { useVirtualizer } from "@tanstack/react-virtual"
import { useCallback, useLayoutEffect, useMemo, useState } from "react"

import {
  getVirtualRangeWithFocus,
  getVirtualRowsLayout,
  VIRTUAL_ROWS_THRESHOLD,
} from "@/hooks/virtual-rows-model"

const INITIAL_VIEWPORT_HEIGHT = 600

function findScrollElement(element: HTMLElement) {
  // AppShell scrolls main, not the document or the horizontal table wrapper.
  const main = element.closest<HTMLElement>("main")
  if (main) return main
  let parent = element.parentElement
  while (parent) {
    if (/(auto|scroll|overlay)/.test(getComputedStyle(parent).overflowY)) {
      return parent
    }
    parent = parent.parentElement
  }
  return null
}

/**
 * Attach containerRef to tbody/the mobile cards wrapper. Each measured row
 * needs data-index={item.index} and ref={measureElement}. Render paddingBefore
 * before EVERY item (a pinned focused row can be far outside the viewport),
 * followed by paddingAfter. Do not put vertical margins between measured rows.
 */
export function useVirtualRows({
  enabled,
  keys,
  estimateSize,
  overscan = 4,
}: {
  enabled: boolean
  keys: readonly string[]
  estimateSize: number
  overscan?: number
}) {
  const virtualized = enabled && keys.length > VIRTUAL_ROWS_THRESHOLD
  const [container, setContainer] = useState<HTMLElement | null>(null)
  const [focusedKey, setFocusedKey] = useState<string | null>(null)
  const [layout, setLayout] = useState<{
    scrollElement: HTMLElement | null
    margin: number
    visible: boolean
  }>({ scrollElement: null, margin: 0, visible: true })
  const containerRef = useCallback((element: HTMLElement | null) => {
    setContainer(element)
  }, [])

  useLayoutEffect(() => {
    if (!virtualized || !container) return
    const scrollElement = findScrollElement(container)
    if (!scrollElement) return
    const updateLayout = () => {
      const rect = container.getBoundingClientRect()
      const margin =
        rect.top -
        scrollElement.getBoundingClientRect().top +
        scrollElement.scrollTop -
        scrollElement.clientTop
      const visible = rect.width > 0 && scrollElement.clientHeight > 0
      setLayout((previous) =>
        previous.scrollElement === scrollElement &&
        previous.margin === margin &&
        previous.visible === visible
          ? previous
          : { scrollElement, margin, visible }
      )
    }
    updateLayout()
    // Ancestors above the rows can resize when a toolbar/error wraps, changing
    // the list's offset without changing the main viewport's dimensions.
    const observer =
      typeof ResizeObserver === "undefined"
        ? null
        : new ResizeObserver(updateLayout)
    let ancestor: HTMLElement | null = container
    while (ancestor) {
      observer?.observe(ancestor)
      if (ancestor === scrollElement) break
      ancestor = ancestor.parentElement
    }
    scrollElement.addEventListener("scroll", updateLayout, { passive: true })
    window.addEventListener("resize", updateLayout)
    return () => {
      observer?.disconnect()
      scrollElement.removeEventListener("scroll", updateLayout)
      window.removeEventListener("resize", updateLayout)
    }
  }, [container, virtualized])

  useLayoutEffect(() => {
    if (!virtualized || !container) return
    const readFocusedKey = (target: EventTarget | null) => {
      const row =
        target instanceof Element
          ? target.closest<HTMLElement>("[data-virtual-row-key]")
          : null
      return row && container.contains(row)
        ? (row.dataset.virtualRowKey ?? null)
        : null
    }
    const onFocus = (event: FocusEvent) => {
      setFocusedKey(readFocusedKey(event.target))
    }
    const onBlur = (event: FocusEvent) => {
      setFocusedKey(readFocusedKey(event.relatedTarget))
    }
    // Includes a row that already held focus when virtualization was enabled.
    setFocusedKey(readFocusedKey(container.ownerDocument.activeElement))
    container.addEventListener("focusin", onFocus)
    container.addEventListener("focusout", onBlur)
    return () => {
      container.removeEventListener("focusin", onFocus)
      container.removeEventListener("focusout", onBlur)
    }
  }, [container, virtualized])

  const getItemKey = useCallback((index: number) => keys[index]!, [keys])
  const rangeExtractor = useCallback(
    (range: Parameters<typeof getVirtualRangeWithFocus>[0]) =>
      getVirtualRangeWithFocus(range, keys, focusedKey),
    [keys, focusedKey]
  )
  const virtualizer = useVirtualizer<HTMLElement, HTMLElement>({
    count: keys.length,
    enabled: virtualized && layout.visible,
    getScrollElement: () => layout.scrollElement,
    getItemKey,
    estimateSize: () => estimateSize,
    overscan,
    rangeExtractor,
    scrollMargin: layout.margin,
    initialRect: { width: 0, height: INITIAL_VIEWPORT_HEIGHT },
  })
  const measureElement = useCallback(
    (element: HTMLElement | null) => {
      if (element) {
        const index = Number(element.dataset.index)
        const key = keys[index]
        if (key !== undefined) element.dataset.virtualRowKey = key
      }
      // Responsive siblings remain mounted behind display:none. A disabled
      // virtualizer clears its size cache; feeding it hidden row measurements
      // from ref callbacks would refill/clear that cache on every React commit.
      // Null still releases disconnected nodes, but only the visible, enabled
      // branch may publish a size. Client rects also cover the resize frame
      // before our container observer has updated layout.visible.
      if (
        !element ||
        (virtualized && layout.visible && element.getClientRects().length > 0)
      ) {
        virtualizer.measureElement(element)
      }
    },
    [keys, virtualized, layout.visible, virtualizer]
  )
  const plainItems = useMemo(
    () =>
      keys.map((key, index) => ({
        index,
        key,
        start: 0,
        size: 0,
        paddingBefore: 0,
      })),
    [keys]
  )
  if (!virtualized) {
    return {
      virtualized,
      containerRef,
      measureElement,
      items: plainItems,
      paddingAfter: 0,
    }
  }
  const measured = virtualizer.getVirtualItems()
  // CSS-hidden siblings and the initial render have no viewport yet. Keep a
  // bounded leading range rather than mounting every row or flashing empty.
  const initialCount = Math.min(
    keys.length,
    Math.ceil(INITIAL_VIEWPORT_HEIGHT / estimateSize) + overscan
  )
  const measurements =
    measured.length > 0
      ? measured.map((item) => ({ ...item, key: String(item.key) }))
      : keys.slice(0, initialCount).map((key, index) => ({
          key,
          index,
          start: layout.margin + index * estimateSize,
          size: estimateSize,
        }))
  const rowsLayout = getVirtualRowsLayout(
    measurements,
    measured.length > 0
      ? virtualizer.getTotalSize()
      : keys.length * estimateSize,
    layout.margin
  )
  return { virtualized, containerRef, measureElement, ...rowsLayout }
}
