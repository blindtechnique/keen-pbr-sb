import type { ReactNode } from "react"
import { KeenTrashIcon } from "@/components/shared/keen-icons"

import { ArrowDown, ArrowUp } from "lucide-react"
import { useTranslation } from "react-i18next"

import { Button } from "@/components/ui/button"

export function OrderedGroupCard({
  title,
  description,
  canMoveUp = true,
  canMoveDown = true,
  canRemove = true,
  onMoveUp,
  onMoveDown,
  onRemove,
  children,
}: {
  title: ReactNode
  description?: ReactNode
  canMoveUp?: boolean
  canMoveDown?: boolean
  canRemove?: boolean
  onMoveUp?: () => void
  onMoveDown?: () => void
  onRemove?: () => void
  children: ReactNode
}) {
  const { t } = useTranslation()
  const moveUpLabel = t("common.moveUp")
  const moveDownLabel = t("common.moveDown")
  const removeLabel = t("common.delete")

  return (
    // Плоско, как весь остальной канвас: ступени разделяются линией, а не
    // рамкой-карточкой. Рамка внутри формы внутри диалога давала третий
    // уровень вложенных прямоугольников — владелец попросил убрать.
    <div className="border-t border-border pt-4 first:border-t-0 first:pt-0">
      <div className="mb-4 flex items-start justify-between gap-3">
        <div className="space-y-1">
          <div className="text-sm font-medium md:text-xs">{title}</div>
          {description ? (
            <div className="text-sm text-muted-foreground md:text-xs">
              {description}
            </div>
          ) : null}
        </div>
        <div className="flex gap-2">
          <Button
            aria-label={moveUpLabel}
            disabled={!canMoveUp}
            onClick={onMoveUp}
            size="sm"
            title={moveUpLabel}
            type="button"
            variant="outline"
          >
            <ArrowUp className="h-4 w-4" />
            <span className="hidden lg:inline">{moveUpLabel}</span>
          </Button>
          <Button
            aria-label={moveDownLabel}
            disabled={!canMoveDown}
            onClick={onMoveDown}
            size="sm"
            title={moveDownLabel}
            type="button"
            variant="outline"
          >
            <ArrowDown className="h-4 w-4" />
            <span className="hidden lg:inline">{moveDownLabel}</span>
          </Button>
          <Button
            aria-label={removeLabel}
            disabled={!canRemove}
            onClick={onRemove}
            size="sm"
            title={removeLabel}
            type="button"
            variant="outline"
          >
            <KeenTrashIcon className="h-4 w-4" />
            <span className="hidden lg:inline">{removeLabel}</span>
          </Button>
        </div>
      </div>
      {children}
    </div>
  )
}
