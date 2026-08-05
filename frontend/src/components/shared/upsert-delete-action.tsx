import { useState } from "react"
import { useTranslation } from "react-i18next"

import {
  DeleteImpactDialog,
  type DeleteImpactItem,
} from "@/components/shared/delete-impact-dialog"
import { KeenTrashIcon } from "@/components/shared/keen-icons"
import { Button } from "@/components/ui/button"

/**
 * Удаление внутри формы редактирования.
 *
 * Так это устроено в конфигураторе KeeneticOS: в строке таблицы стоит только
 * карандаш, а удаление живёт в диалоге, который он открывает. У нас удаление
 * было доступно лишь из таблицы, и человек, уже открывший запись, вынужден был
 * закрыть её и искать корзину в строке.
 *
 * Кнопка слева, потому что остальные действия формы справа: удаление не должно
 * стоять рядом с «Сохранить» — их слишком легко перепутать. По той же причине
 * оно `variant="outline"` с красным контуром, а не сплошная красная кнопка:
 * заметное, но не притягивающее нажатие.
 *
 * Показывается только при редактировании: удалять нечего, пока запись не
 * создана.
 *
 * Подтверждение — тот же диалог «что сломается», что и в таблице. Он получает
 * готовый список последствий, поэтому в формах, где ломаться нечему (правила),
 * список пуст и диалог остаётся просто подтверждением.
 */
export function UpsertDeleteAction({
  confirmLabel,
  description,
  disabled = false,
  impactItems,
  isPending = false,
  label,
  onConfirm,
  title,
}: {
  confirmLabel: string
  description: string
  disabled?: boolean
  impactItems: DeleteImpactItem[]
  isPending?: boolean
  label: string
  /** Вызывается после подтверждения. Закрытие формы — на стороне вызывающего. */
  onConfirm: () => void
  title: string
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)

  return (
    <>
      <Button
        className="mr-auto border-destructive/40 text-destructive hover:bg-destructive hover:text-destructive-foreground"
        disabled={disabled || isPending}
        onClick={() => setOpen(true)}
        size="xl"
        type="button"
        variant="outline"
      >
        <KeenTrashIcon className="mr-1 size-4" />
        {label || t("common.delete")}
      </Button>
      <DeleteImpactDialog
        confirmLabel={confirmLabel}
        description={description}
        impactItems={impactItems}
        isPending={isPending}
        onConfirm={() => {
          onConfirm()
          setOpen(false)
        }}
        onOpenChange={setOpen}
        open={open}
        title={title}
      />
    </>
  )
}
