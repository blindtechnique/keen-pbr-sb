import type { ReactNode } from "react"
import { XIcon } from "lucide-react"

import { Button } from "@/components/ui/button"

export function BulkSelectionToolbar({
  countLabel,
  children,
  cancelLabel,
  onCancel,
}: {
  countLabel: string
  children: ReactNode
  cancelLabel?: string
  onCancel?: () => void
}) {
  // The strip floats up into the page header's description band instead of
  // occupying a row of its own. The band is mostly empty anyway, and a slot
  // reserved permanently below the header was the "much empty space at the
  // top" - while filling that slot on demand pushed the table down.
  return (
    <div
      className="fixed inset-x-0 bottom-[calc(var(--warning-banner-height,0px)+env(safe-area-inset-bottom,0px))] z-40 flex min-h-14 w-full items-center gap-2 overflow-x-auto border-t bg-background px-4 py-2 shadow-[0_-6px_18px_rgba(0,0,0,0.22)] md:absolute md:-top-12 md:bottom-auto md:z-10 md:h-11 md:min-h-0 md:rounded-md md:border md:bg-muted/20 md:px-3 md:py-0 md:shadow-none"
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
      {onCancel ? (
        <Button className="ml-auto" onClick={onCancel} size="sm" variant="ghost">
          <XIcon />{cancelLabel}
        </Button>
      ) : null}
    </div>
  )
}
