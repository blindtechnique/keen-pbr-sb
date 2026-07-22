import { useCallback, useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import {
  DownloadIcon,
  ExternalLinkIcon,
  RefreshCwIcon,
  RotateCcwIcon,
  UploadIcon,
} from "lucide-react"

import {
  BackupDialog,
  RestoreDialog,
} from "@/components/settings/backup-dialogs"
import { getSoftwareUpdateDialogContent } from "@/components/settings/software-update-view"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
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
  createBackup,
  createDefaultBackupSelection,
  downloadBackup,
} from "@/lib/backup"
import { formatDownloadTimestamp } from "@/lib/download"

type SoftwareUpdateStatus = {
  current: string
  latest: string
  available: boolean
  current_ahead: boolean
  release_name: string
  release_notes: string
  release_url: string
  changelog_url: string
  running: boolean
  log: string
  phase?: string
  percent?: number
  message?: string
  success?: boolean | null
}

type SoftwareUpdateProgress = Pick<
  SoftwareUpdateStatus,
  "running" | "log" | "phase" | "percent" | "message" | "success"
>

export function BackupAndRestoreCard() {
  const { t } = useTranslation()
  const [backupOpen, setBackupOpen] = useState(false)
  const [restoreOpen, setRestoreOpen] = useState(false)

  return (
    <>
      <Card size="sm">
        <CardHeader>
          <CardTitle>{t("pages.settings.backup.title")}</CardTitle>
          <CardDescription>
            {t("pages.settings.backup.description")}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Button onClick={() => setBackupOpen(true)} variant="outline">
            <DownloadIcon />
            {t("pages.settings.backup.create")}
          </Button>
          <Button onClick={() => setRestoreOpen(true)} variant="outline">
            <UploadIcon />
            {t("pages.settings.backup.restore")}
          </Button>
        </CardContent>
      </Card>
      <BackupDialog onOpenChange={setBackupOpen} open={backupOpen} />
      <RestoreDialog onOpenChange={setRestoreOpen} open={restoreOpen} />
    </>
  )
}

export function SoftwareUpdateCard() {
  const { t } = useTranslation()
  const [status, setStatus] = useState<SoftwareUpdateStatus | null>(null)
  const [error, setError] = useState("")
  const [open, setOpen] = useState(false)
  const [restoreOpen, setRestoreOpen] = useState(false)
  const [showResult, setShowResult] = useState(false)
  const [confirmInstall, setConfirmInstall] = useState(false)
  const [checking, setChecking] = useState(false)
  const [starting, setStarting] = useState(false)
  const [downloadBackupBeforeUpdate, setDownloadBackupBeforeUpdate] =
    useState(true)
  const logRef = useRef<HTMLPreElement>(null)
  const dialogContent = getSoftwareUpdateDialogContent(status, showResult)
  const showUpdateLog = dialogContent === "update-log"

  const refresh = useCallback(
    async (showFeedback = false) => {
      if (showFeedback) setChecking(true)
      try {
        const response = await fetch("/api/system/update")
        const body = (await response.json().catch(() => ({}))) as Partial<
          SoftwareUpdateStatus & { error: string }
        >
        if (!response.ok)
          throw new Error(body.error ?? `HTTP ${response.status}`)
        setStatus(body as SoftwareUpdateStatus)
        setError("")
        if (showFeedback) {
          if (body.available) {
            toast.success(
              t("pages.settings.softwareUpdate.availableToast", {
                version: body.latest,
              })
            )
          } else if (body.current_ahead) {
            toast.info(t("pages.settings.softwareUpdate.newerThanPublished"))
          } else {
            toast.success(t("pages.settings.softwareUpdate.upToDate"))
          }
        }
      } catch (refreshError) {
        const message =
          refreshError instanceof Error
            ? refreshError.message
            : t("pages.settings.softwareUpdate.checkFailed")
        setError(message)
        if (showFeedback) toast.error(message, { richColors: true })
      } finally {
        if (showFeedback) setChecking(false)
      }
    },
    [t]
  )

  const refreshProgress = useCallback(async () => {
    try {
      const response = await fetch("/api/system/update/status")
      const body = (await response.json().catch(() => ({}))) as Partial<
        SoftwareUpdateProgress & { error: string }
      >
      if (!response.ok) throw new Error(body.error ?? `HTTP ${response.status}`)
      setStatus((previous) =>
        previous
          ? { ...previous, ...(body as SoftwareUpdateProgress) }
          : previous
      )
      setError("")
    } catch (refreshError) {
      // The daemon is restarted while its package is replaced. Keep the last
      // known running state so polling resumes as soon as it is reachable.
      setError(
        refreshError instanceof Error
          ? refreshError.message
          : t("pages.settings.softwareUpdate.checkFailed")
      )
    }
  }, [t])

  useEffect(() => {
    void refresh()
  }, [refresh])

  useEffect(() => {
    if (!status?.running) return
    const timer = window.setInterval(() => void refreshProgress(), 3000)
    return () => window.clearInterval(timer)
  }, [refreshProgress, status?.running])

  useEffect(() => {
    if (!showResult || status?.phase !== "completed") return
    void refresh()
  }, [refresh, showResult, status?.phase])

  useEffect(() => {
    if (!showUpdateLog || !logRef.current) return
    logRef.current.scrollTop = logRef.current.scrollHeight
  }, [showUpdateLog, status?.log])

  const startUpdate = async () => {
    setConfirmInstall(false)
    setShowResult(true)
    setStarting(true)
    setError("")
    setStatus((previous) =>
      previous
        ? {
            ...previous,
            log: "",
            message: t("pages.settings.softwareUpdate.running"),
            percent: 0,
            phase: "preparing",
            success: null,
          }
        : previous
    )
    try {
      if (downloadBackupBeforeUpdate) {
        const backup = await createBackup(createDefaultBackupSelection())
        downloadBackup(
          backup,
          `keen-pbr-sb-before-update-${formatDownloadTimestamp()}.json`
        )
      }

      const response = await fetch("/api/system/update", { method: "POST" })
      const body = (await response.json().catch(() => ({}))) as {
        error?: string
      }
      if (!response.ok) throw new Error(body.error ?? `HTTP ${response.status}`)
      setStatus((previous) =>
        previous ? { ...previous, running: true } : previous
      )
      window.setTimeout(() => void refreshProgress(), 1200)
    } catch (updateError) {
      setStatus((previous) =>
        previous
          ? { ...previous, phase: "failed", running: false, success: false }
          : previous
      )
      setError(
        updateError instanceof Error
          ? updateError.message
          : t("pages.settings.softwareUpdate.startFailed")
      )
    } finally {
      setStarting(false)
    }
  }

  const openRollback = () => {
    setOpen(false)
    setRestoreOpen(true)
  }

  return (
    <>
      <Card
        className={
          status?.available
            ? "border-success/60 bg-success/5 shadow-[0_0_0_1px_color-mix(in_srgb,var(--success)_18%,transparent)]"
            : undefined
        }
        size="sm"
      >
        <CardHeader>
          <CardTitle>{t("pages.settings.softwareUpdate.title")}</CardTitle>
          <CardDescription>
            {t("pages.settings.softwareUpdate.description")}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <UpdateVersionSummary status={status} />
          <div className="flex flex-wrap gap-2">
            <Button
              disabled={status?.running || starting || checking}
              onClick={() => void refresh(true)}
              variant="outline"
            >
              <RefreshCwIcon
                className={
                  status?.running || starting || checking ? "animate-spin" : ""
                }
              />
              {t(
                checking
                  ? "pages.settings.softwareUpdate.checking"
                  : "pages.settings.softwareUpdate.check"
              )}
            </Button>
            <Button onClick={() => setOpen(true)}>
              <DownloadIcon />
              {status?.available
                ? t("pages.settings.softwareUpdate.install")
                : t("pages.settings.softwareUpdate.title")}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Dialog
        onOpenChange={(nextOpen) => {
          if (!nextOpen && (status?.running || starting)) return
          setOpen(nextOpen)
          if (!nextOpen) setConfirmInstall(false)
          if (nextOpen) {
            if (!status?.running) setShowResult(false)
            void refresh()
          }
        }}
        open={open}
      >
        <DialogContent
          className="overflow-hidden max-sm:top-auto max-sm:bottom-0 max-sm:left-0 max-sm:max-h-[calc(100dvh-0.75rem)] max-sm:max-w-none max-sm:translate-x-0 max-sm:translate-y-0 max-sm:rounded-b-none max-sm:border-x-0 max-sm:border-b-0 sm:max-w-3xl"
          showCloseButton={!status?.running && !starting}
        >
          <DialogHeader>
            <DialogTitle>
              {t("pages.settings.softwareUpdate.title")}
            </DialogTitle>
            <DialogDescription>
              {t("pages.settings.softwareUpdate.description")}
            </DialogDescription>
          </DialogHeader>

          <div className="min-h-0 space-y-4 overflow-y-auto pr-1">
            <UpdateVersionSummary status={status} />
            {error ? <p className="text-sm text-destructive">{error}</p> : null}
            <UpdateStateMessage status={status} />
            {status && showUpdateLog ? (
              <UpdateProgress status={status} />
            ) : null}
            {status?.available && !showUpdateLog ? (
              <ReleaseNotes status={status} />
            ) : null}
            {showUpdateLog ? (
              <div className="space-y-2 rounded-md border p-3">
                <p className="font-medium">
                  {t("pages.settings.softwareUpdate.result")}
                </p>
                <pre
                  aria-live="polite"
                  className="max-h-72 overflow-auto rounded bg-muted p-3 text-xs whitespace-pre-wrap"
                  ref={logRef}
                >
                  {status?.log ||
                    t("pages.settings.softwareUpdate.waitingForLog")}
                </pre>
              </div>
            ) : null}
            {confirmInstall ? (
              <div className="space-y-3 rounded-md border border-primary/35 bg-primary/5 p-4">
                <p className="font-medium">
                  {t("pages.settings.softwareUpdate.confirm", {
                    version: status?.latest ?? "",
                  })}
                </p>
                <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
                  <Button
                    onClick={() => setConfirmInstall(false)}
                    variant="outline"
                  >
                    Отмена
                  </Button>
                  <Button onClick={() => void startUpdate()}>
                    {t("pages.settings.softwareUpdate.install")}
                  </Button>
                </div>
              </div>
            ) : null}
          </div>

          <DialogFooter className="max-sm:items-stretch">
            <Button onClick={openRollback} variant="destructive">
              <RotateCcwIcon />
              Откат в один клик
            </Button>
            <label className="flex cursor-pointer items-center gap-3 rounded-md border bg-card px-3 py-2 text-sm sm:mr-auto">
              <Checkbox
                checked={downloadBackupBeforeUpdate}
                onCheckedChange={(checked) =>
                  setDownloadBackupBeforeUpdate(checked === true)
                }
              />
              Скачать бэкап перед установкой
            </label>
            <Button
              disabled={
                !status?.available ||
                status.running ||
                starting ||
                confirmInstall
              }
              onClick={() => setConfirmInstall(true)}
            >
              <DownloadIcon />
              {t("pages.settings.softwareUpdate.install")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <RestoreDialog onOpenChange={setRestoreOpen} open={restoreOpen} />
    </>
  )
}

function UpdateVersionSummary({
  status,
}: {
  status: SoftwareUpdateStatus | null
}) {
  const { t } = useTranslation()

  return (
    <div className="grid min-w-0 gap-x-6 gap-y-1 text-sm sm:grid-cols-2">
      <div>
        <span className="text-muted-foreground">
          {t("pages.settings.softwareUpdate.current")}:{" "}
        </span>
        <code>{status?.current ?? "—"}</code>
      </div>
      <div>
        <span className="text-muted-foreground">
          {t("pages.settings.softwareUpdate.latest")}:{" "}
        </span>
        <code>{status?.latest ?? "—"}</code>
      </div>
    </div>
  )
}

function UpdateStateMessage({
  status,
}: {
  status: SoftwareUpdateStatus | null
}) {
  const { t } = useTranslation()

  if (status?.running) {
    return (
      <p className="text-sm font-medium">
        {t("pages.settings.softwareUpdate.running")}
      </p>
    )
  }
  if (status?.current_ahead) {
    return (
      <p className="text-sm text-muted-foreground">
        {t("pages.settings.softwareUpdate.newerThanPublished")}
      </p>
    )
  }
  if (status && !status.available) {
    return (
      <p className="text-sm text-muted-foreground">
        {t("pages.settings.softwareUpdate.upToDate")}
      </p>
    )
  }
  return null
}

function UpdateProgress({ status }: { status: SoftwareUpdateStatus }) {
  const percent = Math.min(100, Math.max(0, status.percent ?? 0))

  return (
    <div className="space-y-2" aria-live="polite">
      <div className="flex items-center justify-between gap-4 text-sm">
        <span>{status.message ?? "Выполняется обновление"}</span>
        <span className="shrink-0 text-muted-foreground tabular-nums">
          {percent}%
        </span>
      </div>
      <div
        aria-label="Прогресс обновления"
        aria-valuemax={100}
        aria-valuemin={0}
        aria-valuenow={percent}
        className="h-1.5 overflow-hidden rounded-full bg-muted"
        role="progressbar"
      >
        <div
          className="h-full rounded-full bg-primary transition-[width] duration-300"
          style={{ width: `${percent}%` }}
        />
      </div>
    </div>
  )
}

function ReleaseNotes({ status }: { status: SoftwareUpdateStatus }) {
  const { t } = useTranslation()

  return (
    <div className="space-y-3 rounded-md border p-4">
      <div>
        <p className="font-medium">
          {t("pages.settings.softwareUpdate.changesTitle", {
            version: status.latest,
          })}
        </p>
        {status.release_name ? (
          <p className="mt-1 text-sm text-muted-foreground">
            {status.release_name}
          </p>
        ) : null}
      </div>
      {status.release_notes ? (
        <div className="max-h-80 overflow-auto rounded bg-muted p-3 text-sm whitespace-pre-wrap">
          {status.release_notes}
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">
          {t("pages.settings.softwareUpdate.releaseNotesMissing")}
        </p>
      )}
      <div className="flex flex-wrap gap-x-4 gap-y-2 text-sm">
        {status.release_url ? (
          <a
            className="inline-flex items-center gap-1 text-primary underline underline-offset-4"
            href={status.release_url}
            rel="noreferrer"
            target="_blank"
          >
            {t("pages.settings.softwareUpdate.releasePage")}
            <ExternalLinkIcon className="size-3.5" />
          </a>
        ) : null}
        {status.changelog_url ? (
          <a
            className="inline-flex items-center gap-1 text-primary underline underline-offset-4"
            href={status.changelog_url}
            rel="noreferrer"
            target="_blank"
          >
            {t("pages.settings.softwareUpdate.fullChangelog")}
            <ExternalLinkIcon className="size-3.5" />
          </a>
        ) : null}
      </div>
    </div>
  )
}
