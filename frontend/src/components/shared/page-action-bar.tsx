import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

export function PageActionBar({
  children,
  className,
  leading,
  primary,
}: {
  children: ReactNode
  className?: string
  // Главное действие страницы. На телефоне занимает всю ширину и стоит первым,
  // на десктопе — крайним справа, как было. Раскладка кнопок на разных
  // страницах разъезжалась: где-то столбиком, где-то 2+2, где-то две в ряд и
  // одна под ними.
  primary?: ReactNode
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
      {/* Телефон: сетка в две колонки — вторичные кнопки идут по две в ряд,
          поиск и главное действие занимают строку целиком. Десктоп: прежний
          ряд с прижатыми вправо кнопками, главное действие остаётся крайним. */}
      <div className="grid min-h-12 min-w-0 flex-1 grid-cols-2 items-center gap-2 border-y border-border py-2 *:w-full sm:flex sm:flex-wrap sm:justify-end sm:*:w-auto">
        {leading ? (
          <div className="col-span-2 min-w-0 sm:mr-auto sm:min-w-72 sm:flex-1 sm:basis-auto">
            {leading}
          </div>
        ) : null}
        {primary ? (
          <div className="col-span-2 sm:order-last sm:col-auto">{primary}</div>
        ) : null}
        {children}
      </div>
    </div>
  )
}
