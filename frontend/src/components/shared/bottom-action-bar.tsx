import {
  useLayoutEffect,
  useRef,
  useState,
  type ReactNode,
} from "react"

import { cn } from "@/lib/utils"

const FALLBACK_HEIGHT = 64

export function BottomActionBar({
  children,
  className,
  contentClassName,
}: {
  children: ReactNode
  className?: string
  contentClassName?: string
}) {
  const barRef = useRef<HTMLDivElement | null>(null)
  const [height, setHeight] = useState(FALLBACK_HEIGHT)

  useLayoutEffect(() => {
    const bar = barRef.current
    if (!bar) {
      return
    }

    const measure = () => setHeight(bar.offsetHeight)
    measure()

    if (typeof ResizeObserver === "undefined") {
      window.addEventListener("resize", measure)
      return () => window.removeEventListener("resize", measure)
    }

    const resizeObserver = new ResizeObserver(measure)
    resizeObserver.observe(bar)
    return () => resizeObserver.disconnect()
  }, [])

  return (
    <>
      <div aria-hidden="true" style={{ height }} />
      <div
        className={cn(
          "fixed inset-x-0 z-30 bg-[var(--page)] md:left-(--sidebar-offset)",
          className
        )}
        data-bottom-action-bar
        ref={barRef}
        style={{ bottom: "var(--warning-banner-height, 0px)" }}
      >
        <div
          className={cn(
            "mx-4 flex min-h-16 min-w-0 flex-wrap items-center gap-3 border-y border-border py-2 sm:mx-6 lg:mx-8",
            contentClassName
          )}
        >
          {children}
        </div>
      </div>
    </>
  )
}
