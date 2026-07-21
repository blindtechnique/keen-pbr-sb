import { useTranslation } from "react-i18next"
import { Link } from "wouter"

import type { Dependency } from "@/lib/dependencies"
import { Badge } from "@/components/ui/badge"

/**
 * «Что сломается, если это удалить» — рядом с записью, а не в диалоге удаления.
 *
 * Связи можно было увидеть только нажав «Удалить»: диалог честно перечислял
 * последствия, но узнавать их таким способом страшновато. Тот же расчёт
 * показывается заранее и ссылками — от связи можно перейти к тому, что за неё
 * держится.
 */
export function DependencyList({
  dependencies,
  emptyHint,
}: {
  dependencies: Dependency[]
  /** Что написать, когда связей нет. Молчание тут читается как «не посчитали». */
  emptyHint?: string
}) {
  const { t } = useTranslation()

  if (dependencies.length === 0) {
    return (
      <p className="text-xs text-muted-foreground">
        {emptyHint ?? t("common.dependencies.none")}
      </p>
    )
  }

  const byKind = new Map<string, Dependency[]>()
  for (const dependency of dependencies) {
    byKind.set(dependency.kind, [
      ...(byKind.get(dependency.kind) ?? []),
      dependency,
    ])
  }

  return (
    <div className="space-y-1.5">
      <p className="text-xs text-muted-foreground">
        {t("common.dependencies.title", { count: dependencies.length })}
      </p>
      {[...byKind.entries()].map(([kind, items]) => (
        <div className="flex flex-wrap items-center gap-1.5" key={kind}>
          <span className="text-xs text-muted-foreground">
            {t(`common.dependencies.kind.${kind}`)}
          </span>
          {items.map((item) =>
            item.href ? (
              <Link
                className="rounded"
                href={item.href}
                key={`${kind}-${item.label}`}
              >
                <Badge
                  className="cursor-pointer hover:bg-accent"
                  size="xs"
                  variant="outline"
                >
                  {item.label}
                </Badge>
              </Link>
            ) : (
              <Badge key={`${kind}-${item.label}`} size="xs" variant="outline">
                {item.label}
              </Badge>
            )
          )}
        </div>
      ))}
    </div>
  )
}
