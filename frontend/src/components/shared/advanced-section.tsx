import { ChevronDownIcon } from "lucide-react"
import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

/**
 * Свёрнутый блок «Дополнительно» внутри формы.
 *
 * Нужен там, где у настроек есть хорошие умолчания и обычному человеку их
 * трогать не надо: развёрнутыми они превращают короткую форму в анкету на
 * десяток полей и пугают сильнее, чем помогают. Свёрнутый блок сообщает
 * «здесь есть тонкая настройка», не заставляя её читать.
 *
 * Нативный `<details>`, а не своё состояние: раскрытие доступно с клавиатуры
 * и скринридеру без единой строки JS, и содержимое остаётся в DOM — форма
 * внутри продолжает жить (валидация, значения) в свёрнутом виде.
 *
 * `defaultOpen` передаёт вызывающий: если человек уже менял эти настройки,
 * прятать их от него при редактировании нечестно — блок открывается сам.
 */
export function AdvancedSection({
  children,
  defaultOpen = false,
  hint,
  title,
}: {
  children: ReactNode
  defaultOpen?: boolean
  /** Короткая строка под заголовком: что внутри и почему это можно не трогать. */
  hint?: string
  title: string
}) {
  return (
    <details className="group/advanced" open={defaultOpen}>
      <summary
        className={cn(
          "flex cursor-pointer list-none items-center gap-2 rounded py-1 select-none",
          "focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none",
          "[&::-webkit-details-marker]:hidden"
        )}
      >
        <ChevronDownIcon
          aria-hidden="true"
          className="size-4 shrink-0 text-muted-foreground transition-transform group-open/advanced:rotate-180"
        />
        <span className="min-w-0">
          <span className="block text-[14px] leading-[22px] font-bold text-foreground">
            {title}
          </span>
          {hint ? (
            <span className="block text-xs leading-5 text-muted-foreground">
              {hint}
            </span>
          ) : null}
        </span>
      </summary>
      <div className="mt-4 space-y-6">{children}</div>
    </details>
  )
}
