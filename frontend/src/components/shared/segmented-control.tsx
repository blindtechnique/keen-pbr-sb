import { CheckCircle2Icon, CircleIcon, type LucideIcon } from "lucide-react"
import { useRef } from "react"

import { useIsMobile } from "@/hooks/use-mobile"
import { cn } from "@/lib/utils"

export type SegmentedControlOption<T extends string> = {
  value: T
  label: string
  icon?: LucideIcon
}

/**
 * Выбор одного варианта из нескольких равнозначных — ndw-picker KeeneticOS.
 *
 * Скопирован с «Анализатора трафика приложений» вместе с поведением: наведение
 * меняет только цвет рамки, нажатие не меняет ничего, а рамка выбранного
 * выглядит одинаково в любой позиции за счёт наезда кнопок друг на друга и
 * z-index. Иконки — наше дополнение: в прошивке подписи короткие и понятные
 * сами по себе, у нас «Ссылка подключения» и «Outbound JSON» иконкой читаются
 * быстрее.
 *
 * Цвета и размеры живут в .keen-picker в index.css, чтобы тем же переключателем
 * пользовались и списки, и туннели.
 */
export function SegmentedControl<T extends string>({
  value,
  onChange,
  options,
  ariaLabel,
  className,
}: {
  value: T
  onChange: (next: T) => void
  options: SegmentedControlOption<T>[]
  ariaLabel: string
  className?: string
}) {
  const containerRef = useRef<HTMLDivElement>(null)
  const isMobile = useIsMobile()

  // Стрелки переключают вариант, как того ждут от группы радиокнопок:
  // Tab заводит в группу, стрелки двигают внутри неё.
  const moveFocus = (from: number, delta: number) => {
    const next = (from + delta + options.length) % options.length
    onChange(options[next].value)
    const buttons =
      containerRef.current?.querySelectorAll<HTMLButtonElement>(
        "[data-segment]"
      )
    buttons?.[next]?.focus()
  }

  return (
    <div
      aria-label={ariaLabel}
      className={cn(
        "keen-picker",
        isMobile && "keen-picker--vertical",
        className
      )}
      ref={containerRef}
      role="radiogroup"
    >
      {options.map((option, index) => {
        const selected = option.value === value
        const Icon = option.icon

        return (
          <button
            aria-checked={selected}
            className={cn(
              "keen-picker__button",
              selected && "keen-picker__button--active"
            )}
            data-segment
            key={option.value}
            onClick={() => onChange(option.value)}
            onKeyDown={(event) => {
              if (event.key === "ArrowRight" || event.key === "ArrowDown") {
                event.preventDefault()
                moveFocus(index, 1)
              }
              if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
                event.preventDefault()
                moveFocus(index, -1)
              }
            }}
            role="radio"
            // Только выбранный сегмент участвует в обходе по Tab — иначе группа
            // из двух кнопок съедала два нажатия вместо одного.
            tabIndex={selected ? 0 : -1}
            type="button"
          >
            {isMobile ? (
              selected ? (
                <CheckCircle2Icon className="size-4 shrink-0 text-primary" />
              ) : (
                <CircleIcon className="size-4 shrink-0 text-muted-foreground" />
              )
            ) : null}
            {Icon ? <Icon className="size-4 shrink-0" /> : null}
            <span className="truncate">{option.label}</span>
          </button>
        )
      })}
    </div>
  )
}
