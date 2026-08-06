import { ChevronDownIcon } from "lucide-react"
import { useState } from "react"
import { useTranslation } from "react-i18next"
import { Link } from "wouter"

import type { Dependency, DependencyKind } from "@/lib/dependencies"
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
  fixedKinds,
  cellRows,
  className,
}: {
  dependencies: Dependency[]
  /** Что написать, когда связей нет. Молчание тут читается как «не посчитали». */
  emptyHint?: string
  /** В колонке таблицы заголовок уже сказал «Где используется». */
  compact?: boolean
  /**
   * Всегда показывать эти виды связей в этом порядке, с честным «нет» у
   * пустых. Нужно в раскрытой строке туннеля: владелец хочет видеть ответ на
   * «кто этим пользуется» по всем четырём категориям, а не только по тем,
   * где связи нашлись. Виды сверх списка показываются после — молча прятать
   * найденную связь нельзя.
   */
  fixedKinds?: readonly DependencyKind[]
  /**
   * Ячейка таблицы: не больше стольких однострочных категорий, без переноса
   * чипов, остаток — числом «Ещё N». Решение владельца: строки таблицы
   * должны быть одной высоты, а полный ответ живёт в раскрытии строки или в
   * редакторе. Вызывающий добавляет min-height через className, чтобы строка
   * с одной категорией была не ниже строки с двумя.
   */
  cellRows?: number
  className?: string
}) {
  const { t } = useTranslation()
  const [expanded, setExpanded] = useState(false)

  if (cellRows !== undefined) {
    if (dependencies.length === 0) {
      return (
        <div
          className={cn("flex max-w-[26rem] min-w-0 items-center", className)}
        >
          <span
            className="block truncate text-xs text-muted-foreground"
            title={emptyHint ?? t("common.dependencies.none")}
          >
            {emptyHint ?? t("common.dependencies.none")}
          </span>
        </div>
      )
    }
    const byKind = new Map<string, Dependency[]>()
    for (const dependency of dependencies) {
      byKind.set(dependency.kind, [
        ...(byKind.get(dependency.kind) ?? []),
        dependency,
      ])
    }
    // Один чип на строку: два чипа делили ширину и оба сжимались до
    // нечитаемых огрызков. Один — усекается многоточием, остальное честно
    // считается в «Ещё N» (так же выглядит и прошивочная таблица).
    const CHIPS_PER_CELL_ROW = 1
    const visibleKinds = [...byKind.entries()].slice(0, cellRows)
    const shown = visibleKinds.reduce(
      (total, [, items]) => total + Math.min(items.length, CHIPS_PER_CELL_ROW),
      0
    )
    const hidden = dependencies.length - shown
    return (
      <div
        className={cn(
          "max-w-[26rem] min-w-0 content-center space-y-1",
          className
        )}
      >
        {visibleKinds.map(([kind, items], rowIndex) => (
          <div
            className="flex min-w-0 items-center gap-1.5 overflow-hidden whitespace-nowrap"
            key={kind}
          >
            <span className="shrink-0 text-xs text-muted-foreground">
              {t(`common.dependencies.kind.${kind}`)}
            </span>
            {items.slice(0, CHIPS_PER_CELL_ROW).map((item) => (
              <DependencyChip
                item={item}
                key={`${kind}-${item.label}`}
                nowrap
              />
            ))}
            {rowIndex === visibleKinds.length - 1 && hidden > 0 ? (
              <span className="shrink-0 text-xs text-muted-foreground">
                {t("common.dependencies.more", { count: hidden })}
              </span>
            ) : null}
          </div>
        ))}
      </div>
    )
  }

  if (fixedKinds) {
    const byKind = new Map<string, Dependency[]>()
    for (const dependency of dependencies) {
      byKind.set(dependency.kind, [
        ...(byKind.get(dependency.kind) ?? []),
        dependency,
      ])
    }
    const fixedRows = [
      ...fixedKinds.map((kind) => ({ kind, items: byKind.get(kind) ?? [] })),
      ...[...byKind.entries()]
        .filter(([kind]) => !fixedKinds.includes(kind as DependencyKind))
        .map(([kind, items]) => ({ kind, items })),
    ]
    return (
      <div className="max-w-[26rem] min-w-0 space-y-1">
        {fixedRows.map(({ kind, items }) => (
          <div
            className="flex min-w-0 flex-wrap items-center gap-1.5"
            key={kind}
          >
            <span className="text-xs text-muted-foreground">
              {t(`common.dependencies.kind.${kind}`)}
            </span>
            {items.length === 0 ? (
              <span className="text-xs text-muted-foreground">
                {t("common.noneShort")}
              </span>
            ) : (
              items.map((item) => (
                <DependencyChip item={item} key={`${kind}-${item.label}`} />
              ))
            )}
          </div>
        ))}
      </div>
    )
  }

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
          {items.map((item) => (
            <DependencyChip item={item} key={`${kind}-${item.label}`} />
          ))}
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

function DependencyChip({
  item,
  nowrap = false,
}: {
  readonly item: Dependency
  /** В однострочной ячейке чип не переносится, а усекается многоточием. */
  readonly nowrap?: boolean
}) {
  // Многоточие живёт на вложенном span: бейдж — flex-контейнер, а
  // text-overflow работает только на блочном тексте внутри него.
  const label = nowrap ? (
    <span className="min-w-0 truncate">{item.label}</span>
  ) : (
    item.label
  )
  // У ссылки потолок ширины стоит на самой ссылке (это и есть flex-элемент),
  // а бейдж внутри следует за ней через max-w-full: иначе ссылка сжималась,
  // бейдж — нет, и его срезало краем ячейки без многоточия.
  const chipClass = nowrap ? "max-w-full min-w-0" : CHIP
  return item.href ? (
    <Link
      className={cn(
        "min-w-0 rounded",
        nowrap ? "max-w-[11rem] shrink" : "max-w-full"
      )}
      href={item.href}
      title={nowrap ? item.label : undefined}
    >
      <Badge
        className={cn(chipClass, "cursor-pointer hover:bg-accent")}
        size="xs"
        variant="outline"
      >
        {label}
      </Badge>
    </Link>
  ) : (
    <Badge
      className={cn(nowrap ? "max-w-[11rem] min-w-0 shrink" : CHIP)}
      size="xs"
      title={nowrap ? item.label : undefined}
      variant="outline"
    >
      {label}
    </Badge>
  )
}
