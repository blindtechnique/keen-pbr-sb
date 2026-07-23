import { useCallback, useEffect, useRef, useState } from "react"
import { DownloadIcon, RotateCcwIcon, UploadIcon } from "lucide-react"
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

const GROUP_LABELS: Readonly<Record<BackupGroup, string>> = {
  general: "Конфигурация общих настроек",
  transports: "Транспорты",
  outbounds: "Исходящие соединения",
  dns: "Настройки DNS",
  routing: "Списки и правила маршрутизации",
  nfqws: "Конфигурация и списки nfqws2",
}

type ManagedDialogProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function BackupDialog({ open, onOpenChange }: ManagedDialogProps) {
  return (
    <Dialog onOpenChange={onOpenChange} open={open}>
      <DialogContent className="overflow-hidden max-sm:top-auto max-sm:bottom-0 max-sm:left-0 max-sm:max-h-[calc(100dvh-0.75rem)] max-sm:max-w-none max-sm:translate-x-0 max-sm:translate-y-0 max-sm:rounded-b-none max-sm:border-x-0 max-sm:border-b-0 sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Резервная копия</DialogTitle>
          <DialogDescription>
            Выберите данные и скачайте единый файл конфигурации keen-pbr-sb.
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
        className="overflow-hidden max-sm:top-auto max-sm:bottom-0 max-sm:left-0 max-sm:max-h-[calc(100dvh-0.75rem)] max-sm:max-w-none max-sm:translate-x-0 max-sm:translate-y-0 max-sm:rounded-b-none max-sm:border-x-0 max-sm:border-b-0 sm:max-w-2xl"
        showCloseButton={!busy}
      >
        <DialogHeader>
          <DialogTitle>Восстановление</DialogTitle>
          <DialogDescription>
            Восстановите выбранные группы из файла или откатите последнее
            изменение.
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
  const [groups, setGroups] = useState<BackupSelection>(
    createDefaultBackupSelection
  )
  const [pending, setPending] = useState(false)

  const create = async () => {
    setPending(true)
    try {
      downloadBackup(await createBackup(groups))
      toast.success("Резервная копия создана")
      onComplete?.()
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Не удалось создать копию"
      )
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="space-y-5">
      <p className="text-sm text-muted-foreground">
        Если выбраны транспорты, файл содержит их UUID, пароли и ключи в
        открытом виде. Храните копию в безопасном месте и не пересылайте её
        посторонним.
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
            <span className="text-sm font-medium">{GROUP_LABELS[group]}</span>
          </label>
        ))}
      </div>
      <div className="flex justify-end">
        <Button
          disabled={pending || !Object.values(groups).some(Boolean)}
          onClick={() => void create()}
        >
          <DownloadIcon />
          {pending ? "Создание…" : "Создать и скачать"}
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
        error instanceof Error ? error.message : "Не удалось прочитать копию"
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
        toast.success("Конфигурация восстановлена")
      } else {
        await rollbackBackup()
        toast.success("Откат выполнен")
      }
      setPendingAction(null)
      await refreshRollback()
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Операция не выполнена"
      )
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Конфигурация проверяется до записи и применяется только после успешной
        валидации.
      </p>
      {pendingAction ? (
        <div className="space-y-3 rounded-md border border-destructive/40 bg-destructive/5 p-4">
          <div>
            <p className="font-medium">
              {pendingAction.kind === "restore"
                ? `Восстановить «${pendingAction.filename}»?`
                : "Выполнить откат конфигурации?"}
            </p>
            <p className="mt-1 text-sm text-muted-foreground">
              {pendingAction.kind === "restore"
                ? "Перед изменением автоматически будет создана rollback-копия."
                : "Будет восстановлено состояние перед последним обновлением или восстановлением."}
            </p>
          </div>
          <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
            <Button
              disabled={pending}
              onClick={() => setPendingAction(null)}
              variant="outline"
            >
              Отмена
            </Button>
            <Button
              disabled={pending}
              onClick={() => void confirmAction()}
              variant="destructive"
            >
              {pending ? "Выполнение…" : "Подтвердить"}
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
            Откат в один клик
          </Button>
          <Button disabled={pending} onClick={() => inputRef.current?.click()}>
            <UploadIcon />
            Выбрать файл копии
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
