import { CircleHelpIcon } from "lucide-react"
import type { ReactNode } from "react"
import { useTranslation } from "react-i18next"

import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover"
import { cn } from "@/lib/utils"

/**
 * Знак вопроса рядом с названием — пояснение к нему.
 *
 * Снято с живого конфигуратора: `.ndw-help__question` — иконка 16px цвета
 * #6e6e6e, при наведении `color: var(--primary-color)`. Ни подложки, ни тени:
 * меняется только цвет самого значка. И это именно вопрос в кружке, не «i».
 *
 * Описание раздела под этим значком не прячут: у KeeneticOS оно так и стоит
 * текстом под заголовком, а знак вопроса живёт у названий пунктов и полей.
 *
 * Popover, а не Tooltip: подсказка по наведению на телефоне не открывается.
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
          // Область нажатия крупнее самого значка: 16px — это меньше любого
          // разумного пальца, поэтому кнопка 32px, а видно только иконку.
          "inline-flex size-8 shrink-0 items-center justify-center rounded-full text-[#6e6e6e] transition-colors hover:text-primary focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none data-popup-open:text-primary dark:text-muted-foreground",
          className
        )}
        type="button"
      >
        <CircleHelpIcon className="size-4" />
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
