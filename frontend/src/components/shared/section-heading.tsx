import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

/**
 * Заголовок раздела внутри страницы — 20px/28px/700, как в KeeneticOS.
 *
 * Раньше таких заголовков было три вида: карточка с CardTitle, свой `<h2>` в
 * nfqws и `<h3 className="text-sm">` в маршрутах. Последний был вдвое мельче
 * первых двух, и одна и та же по смыслу подпись на разных страницах выглядела
 * как разные сущности.
 *
 * Прошивка называет каждую таблицу, потому что кладёт их по несколько на
 * страницу («Пользовательские маршруты», «Действующие маршруты IPv4»). У нас
 * таблица чаще одна и её называет заголовок страницы или вкладка — там
 * подпись была бы повтором. Этот компонент нужен ровно там, где блоков на
 * странице несколько.
 */
export function SectionHeading({
  title,
  description,
  size = "default",
  tone = "default",
  className,
}: {
  title: ReactNode
  description?: ReactNode
  /**
   * `compact` — для подзаголовка внутри таблицы.
   *
   * Заголовок раздела в 20px рассчитан на блок под собственной панелью
   * действий. Внутри таблицы, между строками в 48px, он занимал столько же
   * места, сколько две записи, и разрывал список пополам.
   */
  size?: "default" | "compact"
  /** Красный — для раздела, который сообщает о поломке. */
  tone?: "default" | "destructive"
  className?: string
}) {
  return (
    <div className={cn("min-w-0", className)}>
      <h2
        className={cn(
          size === "compact"
            ? "text-[14px] leading-[22px] font-bold"
            : "text-[20px] leading-7 font-bold",
          tone === "destructive" ? "text-destructive" : "text-foreground"
        )}
      >
        {title}
      </h2>
      {description ? (
        <p
          className={cn(
            // Потолок ширины: заголовок группы живёт в ячейке таблицы с
            // colSpan, а ячейка в авторазметке требует ширину по самой длинной
            // строке. Без ограничения описание в полтораста символов растягивало
            // таблицу и включало горизонтальную прокрутку на всей странице.
            "max-w-[48rem] text-muted-foreground",
            size === "compact"
              ? "text-[12px] leading-[18px]"
              : "mt-1 text-[14px] leading-[22px]"
          )}
        >
          {description}
        </p>
      ) : null}
    </div>
  )
}
