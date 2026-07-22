import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

export function PageActionBar({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cn("sticky top-0 z-20 -mx-4 flex justify-end border-b border-border/70 bg-background px-4 py-2 sm:-mx-6 sm:px-6 lg:-mx-8 lg:px-8", className)}>
      <div className="flex flex-wrap justify-end gap-2">{children}</div>
    </div>
  )
}
