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
import { KeeneticStatus } from "@/components/shared/keenetic-status"
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
import { packageRollbackReasonKey } from "@/lib/package-rollback"

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
  package_rescue_ready?: boolean
  package_rollback_available?: boolean
  package_rollback_state?: string
  check_error?: string
  cached?: boolean
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
          <CardDescription className="max-w-[480px]">
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
  const [showResult, setShowResult] = useState(false)
  const [confirmInstall, setConfirmInstall] = useState(false)
  const [confirmRollback, setConfirmRollback] = useState(false)
  const [checking, setChecking] = useState(false)
  const [starting, setStarting] = useState(false)
  const [downloadBackupBeforeUpdate, setDownloadBackupBeforeUpdate] =
    useState(true)
  const rollbackUnavailableReason = useRollbackUnavailableReason(status)
  const logRef = useRef<HTMLPreElement>(null)
  const dialogContent = getSoftwareUpdateDialogContent(status, showResult)
  const showUpdateLog = dialogContent === "update-log"

  const refresh = useCallback(
    async (showFeedback = false) => {
      if (showFeedback) setChecking(true)
      try {
        let response = await fetch(
          showFeedback ? "/api/system/update/check" : "/api/system/update",
          showFeedback ? { method: "POST" } : undefined
        )
        // Older sb.11 backends do not expose the explicit refresh endpoint.
        // Keep frontend-only previews compatible until the next IPK is
        // installed on the router.
        if (
          showFeedback &&
          (response.status === 404 || response.status === 405)
        ) {
          response = await fetch("/api/system/update")
        }
        const body = (await response.json().catch(() => ({}))) as Partial<
          SoftwareUpdateStatus & { error: string }
        >
        if (!response.ok)
          throw new Error(body.error ?? `HTTP ${response.status}`)
        setStatus(body as SoftwareUpdateStatus)
        setError(
          body.check_error ? t("pages.settings.softwareUpdate.checkFailed") : ""
        )
        if (showFeedback) {
          if (body.check_error) {
            toast.warning(t("pages.settings.softwareUpdate.cachedResult"))
          } else if (body.available) {
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
        const detail = refreshError instanceof Error ? refreshError.message : ""
        const message = t("pages.settings.softwareUpdate.checkFailed")
        setStatus((previous) => {
          if (previous) {
            return { ...previous, check_error: detail || message }
          }
          return {
            current: __APP_VERSION__,
            latest: "",
            available: false,
            current_ahead: false,
            release_name: "",
            release_notes: "",
            release_url: "",
            changelog_url: "",
            running: false,
            log: "",
            check_error: detail || message,
          }
        })
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

  const startPackageRollback = async () => {
    setConfirmRollback(false)
    setShowResult(true)
    setStarting(true)
    setError("")
    setStatus((previous) =>
      previous
        ? {
            ...previous,
            log: "",
            message: t("pages.settings.softwareUpdate.rollbackStarting"),
            percent: 0,
            phase: "rollback",
            success: null,
          }
        : previous
    )
    try {
      const response = await fetch("/api/system/update/rollback", {
        method: "POST",
      })
      const body = (await response.json().catch(() => ({}))) as {
        error?: string
      }
      if (!response.ok) throw new Error(body.error ?? `HTTP ${response.status}`)
      setStatus((previous) =>
        previous ? { ...previous, running: true } : previous
      )
      window.setTimeout(() => void refreshProgress(), 1200)
    } catch (rollbackError) {
      setStatus((previous) =>
        previous
          ? { ...previous, phase: "failed", running: false, success: false }
          : previous
      )
      setError(
        rollbackError instanceof Error
          ? rollbackError.message
          : t("pages.settings.softwareUpdate.rollbackFailed")
      )
    } finally {
      setStarting(false)
    }
  }

  return (
    <>
      <Card size="sm">
        <CardHeader>
          <CardTitle>{t("pages.settings.softwareUpdate.title")}</CardTitle>
          <CardDescription className="max-w-[480px]">
            {t("pages.settings.softwareUpdate.description")}
          </CardDescription>
        </CardHeader>
        {/* Компактная колонка, как у остальных вкладок настроек: статус и
            версии сверху, кнопки под ними, ничего не растянуто на всю
            ширину карточки. */}
        <CardContent className="flex max-w-[480px] flex-col gap-3">
          <div className="flex min-w-0 flex-col items-start gap-2">
            <KeeneticStatus tone={status?.available ? "success" : "neutral"}>
              {status?.available
                ? t("common.updateStatus.available")
                : status?.check_error
                  ? t("common.updateStatus.unavailable")
                  : status
                    ? t("common.updateStatus.current")
                    : t("common.updateStatus.checking")}
            </KeeneticStatus>
            <UpdateVersionSummary status={status} />
          </div>
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
          className="overflow-hidden max-sm:top-auto max-sm:bottom-0 max-sm:left-0 max-sm:max-h-[calc(100dvh-0.75rem)] max-sm:max-w-none max-sm:translate-x-0 max-sm:translate-y-0 max-sm:rounded-b-none max-sm:border-x-0 max-sm:border-b-0 sm:max-w-[640px]"
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
            <RollbackAvailabilityNotice status={status} />
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
                    {t("pages.settings.softwareUpdate.cancel")}
                  </Button>
                  <Button onClick={() => void startUpdate()}>
                    {t("pages.settings.softwareUpdate.install")}
                  </Button>
                </div>
              </div>
            ) : null}
            {confirmRollback ? (
              <div className="space-y-3 rounded-md border border-destructive/40 bg-destructive/5 p-4">
                <div>
                  <p className="font-medium">
                    {t("pages.settings.softwareUpdate.rollbackConfirmTitle")}
                  </p>
                  <p className="mt-1 text-sm text-muted-foreground">
                    {t("pages.settings.softwareUpdate.rollbackConfirmHint")}
                  </p>
                </div>
                <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
                  <Button
                    onClick={() => setConfirmRollback(false)}
                    variant="outline"
                  >
                    {t("pages.settings.softwareUpdate.cancel")}
                  </Button>
                  <Button
                    onClick={() => void startPackageRollback()}
                    variant="destructive"
                  >
                    {t("pages.settings.softwareUpdate.rollbackConfirmAction")}
                  </Button>
                </div>
              </div>
            ) : null}
          </div>

          <DialogFooter className="max-sm:items-stretch">
            <Button
              disabled={
                !status?.package_rollback_available ||
                status.running ||
                starting ||
                confirmRollback
              }
              onClick={() => setConfirmRollback(true)}
              title={rollbackUnavailableReason ?? undefined}
              variant="destructive"
            >
              <RotateCcwIcon />
              {t("pages.settings.softwareUpdate.rollbackButton")}
            </Button>
            <label className="flex cursor-pointer items-center gap-3 rounded-md border bg-card px-3 py-2 text-sm sm:mr-auto">
              <Checkbox
                checked={downloadBackupBeforeUpdate}
                onCheckedChange={(checked) =>
                  setDownloadBackupBeforeUpdate(checked === true)
                }
              />
              {t("pages.settings.softwareUpdate.downloadBackupBefore")}
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
    <div className="grid min-w-0 gap-y-1 text-sm">
      <div>
        <span className="text-muted-foreground">
          {t("pages.settings.softwareUpdate.current")}:{" "}
        </span>
        <code>
          {status?.current || __APP_VERSION__ || "—"}
        </code>
      </div>
      <div>
        <span className="text-muted-foreground">
          {t("pages.settings.softwareUpdate.latest")}:{" "}
        </span>
        <code>
          {status?.latest ||
            (status?.check_error
              ? t("pages.settings.softwareUpdate.unavailableValue")
              : "—")}
        </code>
      </div>
    </div>
  )
}

// Why no rollback is possible, in the operator's language.
//
// Deliberately keyed off the backend's state rather than reworded from the
// boolean: an unavailable rollback used to be explained as "appears after a
// successful managed update", which is true only when nothing was ever saved
// and misleading in every other case - a corrupted store told the operator to
// wait for something that had already happened.
//
// An unrecognised state falls back to the bare statement. A newer backend must
// never have its reason guessed at by an older page.
function useRollbackUnavailableReason(status: SoftwareUpdateStatus | null) {
  const { t } = useTranslation()

  if (!status || status.package_rollback_available) return null
  const key = packageRollbackReasonKey(status.package_rollback_state)
  const headline = t("pages.settings.softwareUpdate.rollbackUnavailable")
  if (!key) return headline
  return `${headline} — ${t(`pages.settings.softwareUpdate.${key}`)}`
}

// Shown in the dialog body, not only on the disabled button. The point of the
// slice is that the operator learns there is nothing to roll back to before
// they start an update, and a tooltip on a disabled control is not something a
// touch device can deliver.
function RollbackAvailabilityNotice({
  status,
}: {
  status: SoftwareUpdateStatus | null
}) {
  const reason = useRollbackUnavailableReason(status)

  if (!reason || status?.running) return null
  return <p className="text-sm text-muted-foreground">{reason}</p>
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
  const { t } = useTranslation()
  const percent = Math.min(100, Math.max(0, status.percent ?? 0))

  return (
    <div className="space-y-2" aria-live="polite">
      <div className="flex items-center justify-between gap-4 text-sm">
        <span>
          {status.message ?? t("pages.settings.softwareUpdate.inProgress")}
        </span>
        <span className="shrink-0 text-muted-foreground tabular-nums">
          {percent}%
        </span>
      </div>
      <div
        aria-label={t("pages.settings.softwareUpdate.progressLabel")}
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
