import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

export function PageActionBar({
  children,
  className,
  leading,
}: {
  children: ReactNode
  className?: string
  // Элементы, относящиеся ко всей таблице — сейчас это поиск. Живут в той же
  // строке, что и кнопки, слева: отдельной строкой поиск съедал вертикаль и
  // на разных страницах оказывался в разных местах.
  leading?: ReactNode
}) {
  return (
    <div
      className={cn("sticky top-0 z-30 isolate bg-[var(--page)]", className)}
      data-page-action-bar
    >
      <div className="flex min-h-12 min-w-0 flex-1 flex-wrap items-center justify-end gap-2 border-y border-border py-2">
        {leading ? (
          <div className="mr-auto min-w-0 basis-full sm:min-w-72 sm:flex-1 sm:basis-auto">
            {leading}
          </div>
        ) : null}
        {children}
      </div>
    </div>
  )
}
