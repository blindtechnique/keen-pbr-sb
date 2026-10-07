import { DownloadIcon, RefreshCwIcon, RotateCcwIcon } from "lucide-react"
import { useTranslation } from "react-i18next"
import { Button } from "@/components/ui/button"
import { DialogFooter } from "@/components/ui/dialog"

/** Actions stay outside the scrolling release notes, including confirmation. */
export function SoftwareUpdateActions({
  confirmation,
  busy,
  backupPending,
  updateDisabled,
  rollbackDisabled,
  rollbackReason,
  onBackup,
  onUpdate,
  onRollback,
  onCancel,
}: {
  confirmation: "update" | "rollback" | null
  busy: boolean
  backupPending: boolean
  updateDisabled: boolean
  rollbackDisabled: boolean
  rollbackReason?: string
  onBackup: () => void
  onUpdate: () => void
  onRollback: () => void
  onCancel: () => void
}) {
  const { t } = useTranslation()
  return (
    <DialogFooter className="shrink-0 flex-wrap max-sm:items-stretch max-sm:pb-[max(1rem,env(safe-area-inset-bottom))]">
      {confirmation ? (
        <Button disabled={busy} onClick={onCancel} variant="outline">
          {t("pages.settings.softwareUpdate.cancel")}
        </Button>
      ) : (
        <Button
          disabled={busy || rollbackDisabled}
          onClick={onRollback}
          title={rollbackReason}
          variant="destructive"
        >
          <RotateCcwIcon />
          {t("pages.settings.softwareUpdate.rollbackButton")}
        </Button>
      )}
      <Button
        className="sm:mr-auto"
        disabled={busy}
        onClick={onBackup}
        variant="outline"
      >
        {backupPending ? (
          <RefreshCwIcon className="animate-spin" />
        ) : (
          <DownloadIcon />
        )}
        {t("pages.settings.softwareUpdate.downloadBackup")}
      </Button>
      <Button
        disabled={
          busy ||
          (confirmation === "rollback" ? rollbackDisabled : updateDisabled)
        }
        onClick={confirmation === "rollback" ? onRollback : onUpdate}
        variant={confirmation === "rollback" ? "destructive" : "default"}
      >
        <DownloadIcon />
        {confirmation === "rollback"
          ? t("pages.settings.softwareUpdate.rollbackConfirmAction")
          : t("pages.settings.softwareUpdate.install")}
      </Button>
    </DialogFooter>
  )
}
