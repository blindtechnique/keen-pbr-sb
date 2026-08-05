import type { ReactNode } from "react"

import { IconButtonWithTooltip } from "@/components/shared/icon-button-with-tooltip"

/**
 * Действия строки таблицы — как в конфигураторе KeeneticOS.
 *
 * Снято с живого конфигуратора (`.ndw-table__cell-pencil` в таблице
 * межсетевого экрана), а не придумано:
 *
 * - в покое кнопка `visibility: hidden` и появляется при наведении на строку;
 *   переход нулевой (`transition: all 0s`) — значок просто появляется;
 * - значок 16×16, цвет `rgb(0, 134, 203)` — тот же primary, что у нас;
 * - при наведении уже на саму кнопку она заливается тем же синим, а значок
 *   становится белым;
 * - строка под курсором подсвечивается `rgb(245, 250, 252)` — это у нас было.
 *
 * Само скрытие живёт в CSS (`.keen-row-actions` в `index.css`): оно должно
 * включаться только там, где курсор есть. На телефоне наведения не бывает, и
 * спрятанное действие означало бы недоступное действие.
 */
export function ActionButtons({
  actions,
}: {
  actions: Array<{
    label: string
    icon?: ReactNode
    variant?: "ghost" | "outline"
    disabled?: boolean
    onClick?: () => void
  }>
}) {
  return (
    <div className="keen-row-actions ml-auto inline-flex justify-end gap-2">
      {actions.map((action) => (
        <IconButtonWithTooltip
          key={action.label}
          // Вид и размер прошивочные: 32×32, радиус 4px, белый фон и рамка,
          // значок 16px. Всё в `.keen-row-action` — там же и заливка под
          // курсором, чтобы карандаш, обновление и корзина не разъезжались.
          className="keen-row-action rounded-[4px]"
          disabled={action.disabled}
          label={action.label}
          onClick={action.onClick}
          size="icon"
          variant="outline"
        >
          {action.icon}
        </IconButtonWithTooltip>
      ))}
    </div>
  )
}
