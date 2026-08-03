import { useRef } from "react"

import { cn } from "@/lib/utils"

export type SegmentedControlOption<T extends string> = {
  value: T
  label: string
}

/**
 * Переключатель режима из нескольких равнозначных вариантов.
 *
 * Раньше это были две обычные кнопки, из которых активная имела вид первичной —
 * синяя заливка. Читалось как «нажми синюю, чтобы отправить», а на телефоне,
 * где они складываются друг под друга, окончательно превращалось в
 * «Сохранить / Отмена». Здесь оба сегмента одного веса, а выбранный отличается
 * подложкой, а не цветом действия.
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
        "grid grid-cols-1 gap-1 rounded-[4px] border border-input bg-muted p-1 sm:grid-cols-2",
        className
      )}
      ref={containerRef}
      role="radiogroup"
    >
      {options.map((option, index) => {
        const selected = option.value === value
        return (
          <button
            aria-checked={selected}
            className={cn(
              "min-h-9 rounded-[3px] px-3 py-2 text-center text-sm leading-tight whitespace-normal transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none",
              selected
                ? "bg-card font-medium text-foreground shadow-xs"
                : "text-muted-foreground hover:text-foreground"
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
            {option.label}
          </button>
        )
      })}
    </div>
  )
}
