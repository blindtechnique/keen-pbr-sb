import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

export function PageActionBar({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={cn(
        "sticky top-0 z-30 isolate bg-[var(--page)]",
        className
      )}
      data-page-action-bar
    >
      <div className="flex min-h-12 min-w-0 flex-1 flex-wrap items-center justify-end gap-2 border-y border-border py-2">
        {children}
      </div>
    </div>
  )
}
