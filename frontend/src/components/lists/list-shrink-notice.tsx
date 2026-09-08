import { LoaderCircle } from "lucide-react"
import { useTranslation } from "react-i18next"

import { Button } from "@/components/ui/button"
import type { ListShrinkRejection } from "@/lib/list-refresh-controls"

export function ListShrinkNotice({
  rejection,
  disabled,
  pending,
  onAccept,
}: {
  rejection: ListShrinkRejection
  disabled: boolean
  pending: boolean
  onAccept: () => void
}) {
  const { t } = useTranslation()
  return (
    <div className="space-y-1.5 text-xs" role="status">
      <p className="text-warning-foreground">
        {t("pages.lists.shrink.counts", {
          previous: rejection.previous_entries,
          candidate: rejection.candidate_entries,
        })}
      </p>
      <p className="text-muted-foreground">{t("pages.lists.shrink.kept")}</p>
      <Button
        disabled={disabled}
        onClick={onAccept}
        size="sm"
        type="button"
        variant="outline"
      >
        {pending ? <LoaderCircle className="size-4 animate-spin" /> : null}
        {pending
          ? t("pages.lists.shrink.pending")
          : t("pages.lists.shrink.accept")}
      </Button>
      <p className="text-muted-foreground">
        {t("pages.lists.shrink.acceptHint")}
      </p>
    </div>
  )
}
