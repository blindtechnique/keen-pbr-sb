import { useCallback, useEffect, useRef, useState } from "react"
import { DownloadIcon, RotateCcwIcon, UploadIcon } from "lucide-react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  BACKUP_GROUPS,
  createBackup,
  createDefaultBackupSelection,
  downloadBackup,
  getRollbackAvailability,
  readBackupFile,
  restoreBackup,
  rollbackBackup,
  type BackupBundle,
  type BackupGroup,
  type BackupSelection,
} from "@/lib/backup"

// Ключ группы приходит из бэкенда и совпадает с ключом в словаре: отдельная
// карта «группа -> подпись» здесь была бы вторым списком тех же имён, который
// однажды разойдётся с первым.
const groupLabelKey = (group: BackupGroup) =>
  `pages.settings.backup.groups.${group}` as const

/**
 * Группы, которые по новой концепции ходят парой: туннель и есть маршрут,
 * а DNS-правила привязаны к спискам. Галочки остаются раздельными — состав
 * копии решает человек, — но половинчатый выбор получает честное
 * предупреждение о том, что восстановится не целое.
 */
const BACKUP_PAIR_WARNINGS = [
  {
    present: "transports",
    missing: "outbounds",
    key: "transportsWithoutOutbounds",
  },
  {
    present: "outbounds",
    missing: "transports",
    key: "outboundsWithoutTransports",
  },
  { present: "routing", missing: "dns", key: "routingWithoutDns" },
  { present: "dns", missing: "routing", key: "dnsWithoutRouting" },
] as const

function getBackupPairWarningKeys(groups: BackupSelection): string[] {
  return BACKUP_PAIR_WARNINGS.filter(
    (pair) => groups[pair.present] && !groups[pair.missing]
  ).map((pair) => `pages.settings.backup.pairWarnings.${pair.key}`)
}

type ManagedDialogProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function BackupDialog({ open, onOpenChange }: ManagedDialogProps) {
  const { t } = useTranslation()

  return (
    <Dialog onOpenChange={onOpenChange} open={open}>
      <DialogContent className="overflow-hidden max-sm:top-auto max-sm:bottom-0 max-sm:left-0 max-sm:max-h-[calc(100dvh-0.75rem)] max-sm:max-w-none max-sm:translate-x-0 max-sm:translate-y-0 max-sm:rounded-b-none max-sm:border-x-0 max-sm:border-b-0 sm:max-w-[640px]">
        <DialogHeader>
          <DialogTitle>
            {t("pages.settings.backup.dialog.backupTitle")}
          </DialogTitle>
          <DialogDescription>
            {t("pages.settings.backup.dialog.backupDescription")}
          </DialogDescription>
        </DialogHeader>
        <div className="min-h-0 overflow-y-auto">
          <BackupPanel onComplete={() => onOpenChange(false)} />
        </div>
      </DialogContent>
    </Dialog>
  )
}

export function RestoreDialog({ open, onOpenChange }: ManagedDialogProps) {
  const { t } = useTranslation()
  const [busy, setBusy] = useState(false)

  return (
    <Dialog
      onOpenChange={(nextOpen) => {
        if (!nextOpen && busy) return
        onOpenChange(nextOpen)
      }}
      open={open}
    >
      <DialogContent
        className="overflow-hidden max-sm:top-auto max-sm:bottom-0 max-sm:left-0 max-sm:max-h-[calc(100dvh-0.75rem)] max-sm:max-w-none max-sm:translate-x-0 max-sm:translate-y-0 max-sm:rounded-b-none max-sm:border-x-0 max-sm:border-b-0 sm:max-w-[640px]"
        showCloseButton={!busy}
      >
        <DialogHeader>
          <DialogTitle>
            {t("pages.settings.backup.dialog.restoreTitle")}
          </DialogTitle>
          <DialogDescription>
            {t("pages.settings.backup.dialog.restoreDescription")}
          </DialogDescription>
        </DialogHeader>
        <div className="min-h-0 overflow-y-auto">
          <RestorePanel onBusyChange={setBusy} />
        </div>
      </DialogContent>
    </Dialog>
  )
}

type BackupPanelProps = {
  onComplete?: () => void
}

export function BackupPanel({ onComplete }: BackupPanelProps) {
  const { t } = useTranslation()
  const [groups, setGroups] = useState<BackupSelection>(
    createDefaultBackupSelection
  )
  const [pending, setPending] = useState(false)

  const create = async () => {
    setPending(true)
    try {
      downloadBackup(await createBackup(groups))
      toast.success(t("pages.settings.backup.created"))
      onComplete?.()
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : t("pages.settings.backup.createFailed")
      )
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="space-y-5">
      <p className="text-sm text-muted-foreground">
        {t("pages.settings.backup.secretsWarning")}
      </p>
      <div className="grid gap-2 sm:grid-cols-2">
        {BACKUP_GROUPS.map((group) => (
          <label
            className="flex cursor-pointer items-center gap-3 rounded-md border p-3"
            key={group}
          >
            <Checkbox
              checked={groups[group]}
              onCheckedChange={(checked) =>
                setGroups((value) => ({
                  ...value,
                  [group]: checked === true,
                }))
              }
            />
            <span className="text-sm font-medium">
              {t(groupLabelKey(group))}
            </span>
          </label>
        ))}
      </div>
      {getBackupPairWarningKeys(groups).length > 0 ? (
        <div className="space-y-1">
          {getBackupPairWarningKeys(groups).map((warningKey) => (
            <p
              className="text-xs leading-5 text-amber-700 dark:text-amber-300"
              key={warningKey}
            >
              {t(warningKey)}
            </p>
          ))}
        </div>
      ) : null}
      <div className="flex justify-end">
        <Button
          disabled={pending || !Object.values(groups).some(Boolean)}
          onClick={() => void create()}
        >
          <DownloadIcon />
          {pending
            ? t("pages.settings.backup.createPending")
            : t("pages.settings.backup.createButton")}
        </Button>
      </div>
    </div>
  )
}

type RestorePanelProps = {
  onBusyChange?: (busy: boolean) => void
}

type PendingRestoreAction =
  | { kind: "restore"; bundle: BackupBundle; filename: string }
  | { kind: "rollback" }

export function RestorePanel({ onBusyChange }: RestorePanelProps) {
  const { t } = useTranslation()
  const inputRef = useRef<HTMLInputElement>(null)
  const [pending, setPending] = useState(false)
  const [rollbackAvailable, setRollbackAvailable] = useState(false)
  const [pendingAction, setPendingAction] =
    useState<PendingRestoreAction | null>(null)

  const refreshRollback = useCallback(async () => {
    try {
      setRollbackAvailable(await getRollbackAvailability())
    } catch {
      setRollbackAvailable(false)
    }
  }, [])

  useEffect(() => {
    void refreshRollback()
  }, [refreshRollback])

  useEffect(() => {
    onBusyChange?.(pending)
  }, [onBusyChange, pending])

  const chooseFile = async (file?: File) => {
    if (!file) return
    try {
      setPendingAction({
        kind: "restore",
        bundle: await readBackupFile(file),
        filename: file.name,
      })
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : t("pages.settings.backup.readFailed")
      )
    } finally {
      if (inputRef.current) inputRef.current.value = ""
    }
  }

  const confirmAction = async () => {
    if (!pendingAction) return
    setPending(true)
    try {
      if (pendingAction.kind === "restore") {
        await restoreBackup(pendingAction.bundle)
        toast.success(t("pages.settings.backup.restored"))
      } else {
        await rollbackBackup()
        toast.success(t("pages.settings.backup.rolledBack"))
      }
      setPendingAction(null)
      await refreshRollback()
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : t("pages.settings.backup.actionFailed")
      )
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        {t("pages.settings.backup.validationNote")}
      </p>
      {pendingAction ? (
        <div className="space-y-3 rounded-md border border-destructive/40 bg-destructive/5 p-4">
          <div>
            <p className="font-medium">
              {pendingAction.kind === "restore"
                ? t("pages.settings.backup.confirmRestore", {
                    filename: pendingAction.filename,
                  })
                : t("pages.settings.backup.confirmRollback")}
            </p>
            <p className="mt-1 text-sm text-muted-foreground">
              {pendingAction.kind === "restore"
                ? t("pages.settings.backup.restoreHint")
                : t("pages.settings.backup.rollbackHint")}
            </p>
          </div>
          <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
            <Button
              disabled={pending}
              onClick={() => setPendingAction(null)}
              variant="outline"
            >
              {t("pages.settings.backup.cancel")}
            </Button>
            <Button
              disabled={pending}
              onClick={() => void confirmAction()}
              variant="destructive"
            >
              {pending
                ? t("pages.settings.backup.confirmPending")
                : t("pages.settings.backup.confirm")}
            </Button>
          </div>
        </div>
      ) : (
        <DialogFooter className="mx-0 mb-0 rounded-md p-3">
          <Button
            disabled={pending || !rollbackAvailable}
            onClick={() => setPendingAction({ kind: "rollback" })}
            variant="destructive"
          >
            <RotateCcwIcon />
            {t("pages.settings.backup.rollbackButton")}
          </Button>
          <Button disabled={pending} onClick={() => inputRef.current?.click()}>
            <UploadIcon />
            {t("pages.settings.backup.chooseFile")}
          </Button>
        </DialogFooter>
      )}
      <input
        ref={inputRef}
        accept="application/json,.json"
        className="hidden"
        onChange={(event) => void chooseFile(event.target.files?.[0])}
        type="file"
      />
    </div>
  )
}
