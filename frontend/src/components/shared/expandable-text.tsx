import { useEffect, useId, useRef, useState } from "react"
import { useTranslation } from "react-i18next"

import {
  clampClassName,
  shouldShowToggle,
  type ExpandableTextLines,
} from "@/components/shared/expandable-text-state"
import { cn } from "@/lib/utils"

/**
 * Длинное значение в компактной строке: видно начало, остальное — по кнопке.
 *
 * На телефоне одна неудачная загрузка списка занимала десять строк красного
 * текста — примерно треть экрана, — и следующая запись уезжала за границу
 * видимого. Адрес списка в той же строке, наоборот, обрезался многоточием, и
 * посмотреть его было нечем: `title` показывается по наведению мыши, которого
 * на телефоне нет. Оба случая — один и тот же дефект: значение либо занимает
 * весь экран, либо недоступно целиком.
 *
 * Кнопка появляется только когда текст действительно не поместился. Считать
 * это по длине строки нельзя: помещаемость зависит от ширины колонки, размера
 * шрифта и языка, поэтому здесь именно измерение — `scrollHeight` против
 * `clientHeight` — и повторное измерение при изменении размеров.
 */
export function ExpandableText({
  text,
  lines = 2,
  className,
  textClassName,
}: {
  text: string
  /** Сколько строк видно в свёрнутом виде. */
  lines?: ExpandableTextLines
  className?: string
  textClassName?: string
}) {
  const { t } = useTranslation()
  const [expanded, setExpanded] = useState(false)
  const [overflows, setOverflows] = useState(false)
  const textRef = useRef<HTMLSpanElement>(null)
  const textId = useId()

  useEffect(() => {
    const node = textRef.current
    if (!node || expanded) {
      return
    }

    // Округление размеров даёт разницу в доли пикселя даже когда текст
    // помещается целиком, поэтому сравнение с запасом.
    const measure = () => setOverflows(node.scrollHeight - node.clientHeight > 1)
    measure()

    if (typeof ResizeObserver === "undefined") {
      return
    }

    const observer = new ResizeObserver(measure)
    observer.observe(node)
    return () => observer.disconnect()
  }, [expanded, lines, text])

  return (
    <span className={cn("block", className)}>
      <span
        className={cn(
          "block break-words",
          expanded ? undefined : clampClassName(lines),
          textClassName
        )}
        id={textId}
        ref={textRef}
        // На широком экране полное значение по-прежнему доступно по наведению.
        title={text}
      >
        {text}
      </span>
      {shouldShowToggle(overflows, expanded) ? (
        <button
          aria-controls={textId}
          aria-expanded={expanded}
          className="-mx-1 mt-0.5 inline-flex rounded px-1 py-0.5 text-xs text-muted-foreground underline-offset-2 hover:text-foreground hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          onClick={() => setExpanded((current) => !current)}
          type="button"
        >
          {expanded ? t("common.expandable.less") : t("common.expandable.more")}
        </button>
      ) : null}
    </span>
  )
}
