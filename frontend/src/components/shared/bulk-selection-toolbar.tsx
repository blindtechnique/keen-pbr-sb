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
      className="fixed inset-x-0 bottom-[calc(var(--warning-banner-height,0px)+env(safe-area-inset-bottom,0px))] z-50 flex max-h-[50dvh] w-full flex-wrap items-center gap-2 overflow-x-hidden overflow-y-auto border-t bg-card px-4 py-3 shadow-[0_-5px_16px_rgba(0,0,0,0.16)] md:left-(--sidebar-width) md:max-h-none md:flex-nowrap md:px-8"
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
