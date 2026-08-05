import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

export function PageActionBar({
  children,
  className,
  leading,
  primary,
}: {
  children?: ReactNode
  className?: string
  // Главное действие страницы. На телефоне занимает всю ширину и стоит первым,
  // на десктопе — крайним справа, как было. Раскладка кнопок на разных
  // страницах разъезжалась: где-то столбиком, где-то 2+2, где-то две в ряд и
  // одна под ними.
  primary?: ReactNode
  // Элементы, относящиеся ко всей таблице — сейчас это поиск. Живут в той же
  // строке, что и кнопки, слева: отдельной строкой поиск съедал вертикаль и
  // на разных страницах оказывался в разных местах.
  leading?: ReactNode
}) {
  return (
    <div
      className={cn("sticky top-0 isolate z-30 bg-[var(--page)]", className)}
      data-page-action-bar
    >
      {/* Телефон: сетка в две колонки — вторичные кнопки идут по две в ряд,
          поиск и главное действие занимают строку целиком.

          Десктоп: ряд без рамки, кнопки слева, главная — первая. Так это
          сделано в конфигураторе: «+ Добавить» стоит под заголовком раздела,
          левым краем вровень с таблицей. У нас кнопки были прижаты вправо и
          обведены рамкой сверху и снизу — глаз искал «Добавить» слева и не
          находил. Липкость осталась: списки у нас длиннее, чем у прошивки, и
          на середине списка кнопка нужна. */}
      <div className="grid min-h-12 min-w-0 flex-1 grid-cols-2 items-center gap-2 border-b border-border py-2 *:w-full sm:flex sm:flex-wrap sm:justify-start sm:border-b-0 sm:*:w-auto">
        {leading ? (
          // Поиск уходит вправо: слева теперь действия, и меняться местами при
          // появлении поиска они не должны.
          <div className="col-span-2 min-w-0 sm:order-last sm:ml-auto sm:min-w-72 sm:flex-1 sm:basis-auto">
            {leading}
          </div>
        ) : null}
        {primary ? (
          // `*:w-full` сетки растягивает только прямых детей — то есть эту
          // обёртку, а не кнопку внутри неё. Отсюда и выходило, что «Экспорт»
          // с «Импортом» тянутся во всю колонку, а главная кнопка стоит по
          // своей ширине и выбивается из строя.
          <div className="col-span-2 *:w-full sm:order-first sm:col-auto sm:*:w-auto">
            {primary}
          </div>
        ) : null}
        {children}
      </div>
    </div>
  )
}
