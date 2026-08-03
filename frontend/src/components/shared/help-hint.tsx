import { InfoIcon } from "lucide-react"
import type { ReactNode } from "react"
import { useTranslation } from "react-i18next"

import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover"
import { cn } from "@/lib/utils"

/**
 * Пояснение к заголовку — за значком, а не строкой под ним.
 *
 * Описание раздела читают один раз, а место оно занимало на каждом экране:
 * две строки и отступ, около двадцатой части высоты окна ноутбука, всегда.
 * KeeneticOS в той же ситуации оставляет у заголовка «ⓘ» — текст никуда не
 * делся, но и не мешает.
 *
 * Popover, а не Tooltip: подсказка по наведению на телефоне не открывается
 * никак, а разделы смотрят и с телефона.
 */
export function HelpHint({
  text,
  label,
  className,
}: {
  text: ReactNode
  /** Чем кнопка представляется скринридеру, если «Об этом разделе» не подходит. */
  label?: string
  className?: string
}) {
  const { t } = useTranslation()

  return (
    <Popover>
      <PopoverTrigger
        aria-label={label ?? t("common.help.about")}
        className={cn(
          "inline-flex size-9 shrink-0 items-center justify-center rounded-full text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none data-popup-open:bg-accent data-popup-open:text-foreground",
          className
        )}
        type="button"
      >
        <InfoIcon className="size-5" />
      </PopoverTrigger>
      <PopoverContent
        align="start"
        className="w-80 max-w-[calc(100vw-2rem)] text-[14px] leading-[22px] text-pretty text-foreground"
        side="bottom"
      >
        {text}
      </PopoverContent>
    </Popover>
  )
}
