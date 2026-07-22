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
  return (
    <div
      className="fixed inset-x-0 bottom-[calc(var(--warning-banner-height,0px)+env(safe-area-inset-bottom,0px))] z-40 flex max-h-[50dvh] w-full flex-wrap items-center gap-2 overflow-y-auto border-t bg-background px-4 py-3 shadow-[0_-6px_18px_rgba(0,0,0,0.22)] md:absolute md:-top-12 md:bottom-auto md:z-10 md:max-h-none md:min-h-11 md:flex-nowrap md:overflow-visible md:rounded-[4px] md:border md:bg-background md:px-3 md:py-1 md:shadow-sm"
      data-testid="bulk-selection-toolbar"
    >
      <span
        aria-atomic="true"
        aria-live="polite"
        className="w-full text-sm font-medium tabular-nums md:w-auto md:shrink-0"
        data-testid="bulk-selection-count"
      >
        {countLabel}
      </span>
      <div className="flex min-w-0 flex-1 flex-wrap gap-2">{children}</div>
      {onCancel ? (
        <Button
          className="md:ml-auto"
          onClick={onCancel}
          size="sm"
          variant="ghost"
        >
          <XIcon />
          {cancelLabel}
        </Button>
      ) : null}
    </div>
  )
}
