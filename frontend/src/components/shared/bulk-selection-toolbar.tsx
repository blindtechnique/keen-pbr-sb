import type { ReactNode } from "react"

export function BulkSelectionToolbar({
  countLabel,
  children,
}: {
  countLabel: string
  children: ReactNode
}) {
  // The strip floats up into the page header's description band instead of
  // occupying a row of its own. The band is mostly empty anyway, and a slot
  // reserved permanently below the header was the "much empty space at the
  // top" - while filling that slot on demand pushed the table down.
  return (
    <div
      className="absolute inset-x-0 -top-12 z-10 flex h-11 w-full items-center gap-2 overflow-x-auto rounded-md border bg-muted/20 px-3"
      data-testid="bulk-selection-toolbar"
    >
      <span
        aria-atomic="true"
        aria-live="polite"
        className="text-sm font-medium tabular-nums"
        data-testid="bulk-selection-count"
      >
        {countLabel}
      </span>
      {children}
    </div>
  )
}
