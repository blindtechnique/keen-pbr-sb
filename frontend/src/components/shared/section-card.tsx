import type { ReactNode } from "react"

import {
  Card,
  CardDescription,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { cn } from "@/lib/utils"

export function SectionCard({
  title,
  children,
  action,
  description,
  className,
  contentClassName,
  id,
  // Cards are reserved for the system overview; every other page renders the
  // same sections flat, the way KeeneticOS does.
  flat = false,
}: {
  title: string
  children: ReactNode
  action?: ReactNode
  description?: ReactNode
  className?: string
  contentClassName?: string
  id?: string
  flat?: boolean
}) {
  return (
    <Card
      id={id}
      className={cn(
        // `overflow-visible` здесь не косметика. У карточки в основе стоит
        // `overflow-hidden` — он обрезает скруглённые углы у картинок и таблиц
        // внутри. Плоский вариант убирает поля (`p-0`), и граница карточки
        // совпадает с границей содержимого: обрезаться начинает всё, что поле
        // рисует за своими пределами. Кольцо фокуса — это `box-shadow` в 3 px,
        // поэтому у полей внутри такого раздела оно пропадало слева, где
        // запаса не было, и оставалось справа, где место ещё было.
        flat &&
          "gap-4 overflow-visible rounded-none border-0 bg-transparent p-0 shadow-none",
        className
      )}
    >
      <CardHeader className={cn(flat && "px-0")}>
        {/* Переносится, а не подрезается: заголовок с действием рядом не
            всегда помещается в узкую карточку — «Диагностика» со «Скачать файл
            диагностики» требует 350 px при 341 доступных, и лишние девять
            съедал overflow-hidden карточки. min-w-0 нужен, чтобы длинный
            заголовок сжимался, а не распирал строку. */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="min-w-0 space-y-1">
            <CardTitle>{title}</CardTitle>
            {description ? (
              <CardDescription>{description}</CardDescription>
            ) : null}
          </div>
          {action}
        </div>
      </CardHeader>
      <CardContent
        className={cn("space-y-3", flat && "px-0", contentClassName)}
      >
        {children}
      </CardContent>
    </Card>
  )
}
