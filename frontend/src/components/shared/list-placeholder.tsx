import { Inbox, TriangleAlert } from "lucide-react"
import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"

export function ListPlaceholder({
  title,
  description,
  action,
  variant = "empty",
  className,
}: {
  title: string
  description: string
  /**
   * Что предложить сделать прямо отсюда.
   *
   * Пустой экран, который только сообщает о пустоте, оставляет человека
   * догадываться, с чего начинать. Обычно ответ есть, и это каталог.
   */
  action?: ReactNode
  variant?: "empty" | "error"
  /**
   * Только раскладка: где-то пустое место занимает всю карточку, где-то стоит
   * между другими блоками. Оформление самого состояния остаётся общим — ради
   * этого компонент и существует.
   */
  className?: string
}) {
  const Icon = variant === "error" ? TriangleAlert : Inbox

  return (
    <Empty
      className={cn("min-h-56 justify-center border sm:min-h-0", className)}
      data-testid={`list-placeholder-${variant}`}
    >
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <Icon />
        </EmptyMedia>
        <EmptyTitle>{title}</EmptyTitle>
        <EmptyDescription>{description}</EmptyDescription>
      </EmptyHeader>
      {action ? <div className="flex justify-center">{action}</div> : null}
    </Empty>
  )
}
