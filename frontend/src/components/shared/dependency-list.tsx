import { ChevronDownIcon } from "lucide-react"
import { useState } from "react"
import { useTranslation } from "react-i18next"
import { Link } from "wouter"

import type { Dependency } from "@/lib/dependencies"
import { Badge } from "@/components/ui/badge"
import { planDependencyRows } from "@/lib/dependencies"
import { cn } from "@/lib/utils"

/**
 * Бейдж связи умеет переноситься по словам.
 *
 * Обычный бейдж — одна строка с `whitespace-nowrap` и фиксированной высотой:
 * его ширина равна длине текста, и «Meta (все сервисы) → techcorner AWG» на
 * телефоне вылезал за экран, отчего вся страница ехала вбок. Здесь имя может
 * занять две строки — это дешевле горизонтальной прокрутки.
 */
const CHIP = "h-auto max-w-full break-words whitespace-normal"

/**
 * «Что сломается, если это удалить» — рядом с записью, а не в диалоге удаления.
 *
 * Связи можно было увидеть только нажав «Удалить»: диалог честно перечислял
 * последствия, но узнавать их таким способом страшновато. Тот же расчёт
 * показывается заранее и ссылками — от связи можно перейти к тому, что за неё
 * держится.
 *
 * Строка на каждый вид связи — правила, списки, резервирование, — и не больше
 * трёх сразу. Один маршрут здесь тянет одиннадцать списков и три правила: без
 * ограничения такая строка занимает пол-экрана и роняет всю таблицу вниз.
 */
export function DependencyList({
  dependencies,
  emptyHint,
  compact = false,
}: {
  dependencies: Dependency[]
  /** Что написать, когда связей нет. Молчание тут читается как «не посчитали». */
  emptyHint?: string
  /** В колонке таблицы заголовок уже сказал «Где используется». */
  compact?: boolean
}) {
  const { t } = useTranslation()
  const [expanded, setExpanded] = useState(false)

  if (dependencies.length === 0) {
    return (
      <p className="text-xs text-muted-foreground">
        {emptyHint ?? t("common.dependencies.none")}
      </p>
    )
  }

  const { rows, hiddenCount } = planDependencyRows(dependencies, expanded)

  return (
    // Ширина ограничена нарочно. В таблице ячейка растёт по самому широкому
    // содержимому: развернув «Ещё 11», человек получал не одиннадцать строк
    // вниз, а одну колонку через полтаблицы — остальные колонки сжимались, и
    // появлялась горизонтальная прокрутка. Потолок в 26rem заставляет бейджи
    // переноситься; в карточке, которая и так уже, он ничего не меняет.
    <div className="max-w-[26rem] min-w-0 space-y-1">
      {compact ? null : (
        <p className="text-xs text-muted-foreground">
          {t("common.dependencies.title", { count: dependencies.length })}
        </p>
      )}
      {rows.map(({ kind, items }) => (
        <div className="flex min-w-0 flex-wrap items-center gap-1.5" key={kind}>
          <span className="text-xs text-muted-foreground">
            {t(`common.dependencies.kind.${kind}`)}
          </span>
          {items.map((item) =>
            item.href ? (
              <Link
                className="max-w-full min-w-0 rounded"
                href={item.href}
                key={`${kind}-${item.label}`}
              >
                <Badge
                  className={cn(CHIP, "cursor-pointer hover:bg-accent")}
                  size="xs"
                  variant="outline"
                >
                  {item.label}
                </Badge>
              </Link>
            ) : (
              <Badge
                className={CHIP}
                key={`${kind}-${item.label}`}
                size="xs"
                variant="outline"
              >
                {item.label}
              </Badge>
            )
          )}
        </div>
      ))}
      {hiddenCount > 0 || expanded ? (
        <button
          aria-expanded={expanded}
          className="-mx-1 inline-flex items-center gap-1 rounded px-1 py-0.5 text-xs text-muted-foreground hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          onClick={() => setExpanded((current) => !current)}
          type="button"
        >
          {expanded
            ? t("common.dependencies.collapse")
            : t("common.dependencies.more", { count: hiddenCount })}
          <ChevronDownIcon
            aria-hidden="true"
            className={cn(
              "size-3.5 transition-transform",
              expanded && "rotate-180"
            )}
          />
        </button>
      ) : null}
    </div>
  )
}
