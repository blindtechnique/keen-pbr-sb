import { useCallback, useEffect, useRef, useState } from "react"
import type { SystemUpdateStatus } from "@/api/generated/model"
import { UpdateChannelControl } from "./update-channel-control"
import { softwareUpdateRequest } from "./software-update-channel"
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
import { OperationErrorMessage } from "@/components/shared/operation-error-message"
import {
  getSoftwareUpdateDialogContent,
  softwareUpdateResponseError,
} from "@/components/settings/software-update-view"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
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
import { fetchWithStepUp, StepUpNotAdmittedError } from "@/lib/step-up"
import {
  fetchUpdateCommand,
  startUpdatePolling,
} from "./software-update-polling"
import {
  browserUpdateStorage,
  loadUpdateAttempt,
  newUpdateAttempt,
  observeUpdateProgress,
  parseUpdateProgress,
  saveUpdateAttempt,
  updateAttemptNotice,
  updateHttpStatus,
  UPDATE_POLL_WINDOW_MS,
  type UpdateAttempt,
} from "./software-update-session"

type SoftwareUpdateStatus = Partial<
  Pick<
    SystemUpdateStatus,
    | "channel"
    | "installed_channel"
    | "release_tag"
    | "source"
    | "channel_change"
    | "installable"
    | "package_rescue_ready"
    | "package_rollback_available"
    | "check_error"
    | "cached"
  >
> &
  Pick<
    SystemUpdateStatus,
    | "current"
    | "latest"
    | "available"
    | "current_ahead"
    | "release_name"
    | "release_notes"
    | "release_url"
    | "changelog_url"
    | "running"
    | "log"
  > & {
    phase?: string
    percent?: number
    message?: string
    success?: boolean | null
    updated_at?: number
    package_rollback_state?: string
  }

const emptyUpdateStatus = (): SoftwareUpdateStatus => ({
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
})

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
  const [attempt, setAttempt] = useState(() =>
    loadUpdateAttempt(browserUpdateStorage())
  )
  const attemptRef = useRef(attempt)
  const [status, setStatus] = useState<SoftwareUpdateStatus | null>(() =>
    attempt
      ? {
          ...emptyUpdateStatus(),
          latest: attempt.target,
          phase: attempt.phase,
          percent: attempt.percent,
          running: true,
          success: null,
        }
      : null
  )
  const [error, setError] = useState<{
    cause: unknown
    fallbackSummary: string
  } | null>(null)
  const [open, setOpen] = useState(attempt !== null)
  const [showResult, setShowResult] = useState(attempt !== null)
  const [confirmInstall, setConfirmInstall] = useState(false)
  const [confirmRollback, setConfirmRollback] = useState(false)
  const [checking, setChecking] = useState(false)
  const [savingChannel, setSavingChannel] = useState(false)
  const [starting, setStarting] = useState(false)
  const [backupPending, setBackupPending] = useState(false)
  const [backupError, setBackupError] = useState<unknown>(null)
  const [notice, setNotice] = useState<
    "reconnecting" | "admissionUnknown" | "resultUnknown" | null
  >(() => (attempt ? updateAttemptNotice(attempt) : null))
  const mounted = useRef(true)
  const refreshGeneration = useRef(0)
  const activeAttempt = attempt !== null
  const rememberAttempt = useCallback((next: UpdateAttempt | null) => {
    // An old POST may settle after AuthGate remounted a fresh card. Its GET
    // poller owns the attempt now; do not resurrect or overwrite that state.
    if (!mounted.current) return
    attemptRef.current = next
    saveUpdateAttempt(browserUpdateStorage(), next)
    if (mounted.current) setAttempt(next)
  }, [])
  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
      refreshGeneration.current += 1
    }
  }, [])
  const rollbackUnavailableReason = useRollbackUnavailableReason(status)
  const logRef = useRef<HTMLPreElement>(null)
  const dialogContent = getSoftwareUpdateDialogContent(status, showResult)
  const showUpdateLog = dialogContent === "update-log"

  const refresh = useCallback(
    async (showFeedback = false, observeRunning = true) => {
      if (attemptRef.current) return
      const generation = ++refreshGeneration.current
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
          throw softwareUpdateResponseError(response.status, body)
        if (
          !mounted.current ||
          generation !== refreshGeneration.current ||
          attemptRef.current
        )
          return
        setStatus(body as SoftwareUpdateStatus)
        if (body.running && observeRunning) {
          const terminalFile =
            body.phase === "completed" ||
            body.phase === "failed" ||
            typeof body.success === "boolean"
          const existing = newUpdateAttempt(
            "update",
            body.latest ?? "",
            terminalFile ? body.updated_at : undefined
          )
          rememberAttempt({
            ...existing,
            accepted: true,
            observedRunning: !terminalFile,
            lastUpdatedAt: body.updated_at ?? null,
            phase: terminalFile ? "preparing" : (body.phase ?? "preparing"),
            percent: terminalFile ? 0 : (body.percent ?? 0),
          })
          if (terminalFile)
            setStatus((previous) =>
              previous
                ? {
                    ...previous,
                    phase: "preparing",
                    percent: 0,
                    success: null,
                    message: undefined,
                    log: "",
                  }
                : previous
            )
          setOpen(true)
          setShowResult(true)
        }
        setError(
          body.check_error
            ? {
                cause: body.check_error,
                fallbackSummary: t("pages.settings.softwareUpdate.checkFailed"),
              }
            : null
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
        if (
          !mounted.current ||
          generation !== refreshGeneration.current ||
          attemptRef.current
        )
          return
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
        setError({ cause: refreshError, fallbackSummary: message })
        if (showFeedback)
          toast.error(
            <OperationErrorMessage
              error={refreshError}
              fallbackSummary={message}
            />,
            { richColors: true }
          )
      } finally {
        if (
          showFeedback &&
          mounted.current &&
          generation === refreshGeneration.current
        )
          setChecking(false)
      }
    },
    [rememberAttempt, t]
  )

  useEffect(() => {
    void refresh()
  }, [refresh])

  useEffect(() => {
    const current = attemptRef.current
    if (!current || starting) return
    const ownsResponse = () =>
      mounted.current && attemptRef.current?.id === current.id
    return startUpdatePolling({
      deadline: current.pollUntil,
      read: async (signal) => {
        const response = await fetch("/api/system/update/status", {
          signal,
          cache: "no-store",
        })
        const body: unknown = await response.json().catch(() => null)
        if (!response.ok)
          throw softwareUpdateResponseError(
            response.status,
            body && typeof body === "object" ? body : {}
          )
        const progress = parseUpdateProgress(body)
        if (!progress)
          throw softwareUpdateResponseError(502, {
            error: "invalid update status response",
          })
        return progress
      },
      onValue: (progress) => {
        if (!ownsResponse()) return false
        const result = observeUpdateProgress(attemptRef.current!, progress)
        if (!result.apply) {
          setNotice(updateAttemptNotice(result.attempt))
          return
        }
        setStatus((previous) => ({
          ...(previous ?? emptyUpdateStatus()),
          ...progress,
        }))
        setError(null)
        setNotice(null)
        rememberAttempt(result.terminal ? null : result.attempt)
        return !result.terminal
      },
      onError: (cause) => {
        if (!ownsResponse()) return
        if (updateHttpStatus(cause) !== null) {
          setNotice(null)
          setError({
            cause,
            fallbackSummary: t(
              "pages.settings.softwareUpdate.progressUnavailable"
            ),
          })
        } else {
          setError(null)
          setNotice(updateAttemptNotice(attemptRef.current!))
        }
      },
      onExpired: () => {
        if (ownsResponse()) setNotice("resultUnknown")
      },
    })
  }, [attempt?.id, attempt?.pollUntil, rememberAttempt, starting, t])

  useEffect(() => {
    if (attempt || !showResult || status?.phase !== "completed") return
    void refresh()
  }, [attempt, refresh, showResult, status?.phase])

  useEffect(() => {
    if (!showUpdateLog || !logRef.current) return
    logRef.current.scrollTop = logRef.current.scrollHeight
  }, [showUpdateLog, status?.log])

  const startOperation = async (kind: UpdateAttempt["kind"]) => {
    if (attemptRef.current || starting || backupPending || savingChannel) return
    const selection = kind === "update" ? softwareUpdateRequest(status) : null
    if (kind === "update" && !selection) return
    setConfirmInstall(false)
    setConfirmRollback(false)
    setShowResult(true)
    setStarting(true)
    setChecking(false)
    setBackupError(null)
    setError(null)
    setNotice(null)
    refreshGeneration.current += 1
    const next = newUpdateAttempt(
      kind,
      kind === "update" ? (status?.latest ?? "") : "",
      status?.updated_at
    )
    rememberAttempt(next)
    setStatus((previous) => ({
      ...(previous ?? emptyUpdateStatus()),
      log: "",
      message:
        kind === "update"
          ? t("pages.settings.softwareUpdate.running")
          : t("pages.settings.softwareUpdate.rollbackStarting"),
      percent: 0,
      phase: next.phase,
      success: null,
      running: true,
    }))
    try {
      const response = await fetchWithStepUp(
        kind === "update"
          ? "/api/system/update"
          : "/api/system/update/rollback",
        {
          method: "POST",
          ...(selection
            ? {
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(selection),
              }
            : {}),
        },
        (input, init) => fetchUpdateCommand(input, init)
      )
      const body = (await response.json().catch(() => ({}))) as {
        error?: string
        ok?: boolean
        started?: boolean
      }
      if (!response.ok) throw softwareUpdateResponseError(response.status, body)
      // An unreadable acknowledgement is ambiguous, not proof of failure.
      // Never repeat this POST when reconnecting or after login.
      const accepted = body.ok === true && body.started === true
      rememberAttempt({ ...next, accepted })
      if (mounted.current && !accepted) setNotice("admissionUnknown")
    } catch (updateError) {
      if (
        updateHttpStatus(updateError) === null &&
        !(updateError instanceof StepUpNotAdmittedError)
      ) {
        // The router may have accepted the request before its response was lost.
        if (mounted.current) setNotice("admissionUnknown")
      } else {
        rememberAttempt(null)
        if (mounted.current) {
          setStatus((previous) =>
            previous
              ? { ...previous, phase: "failed", running: false, success: false }
              : previous
          )
          setError({
            cause: updateError,
            fallbackSummary: t("pages.settings.softwareUpdate.operationFailed"),
          })
        }
      }
    } finally {
      if (mounted.current) setStarting(false)
    }
  }

  const exportBackup = async () => {
    if (backupPending || attemptRef.current || starting) return
    setBackupPending(true)
    setBackupError(null)
    try {
      const backup = await createBackup(createDefaultBackupSelection())
      downloadBackup(
        backup,
        `keen-pbr-sb-before-update-${formatDownloadTimestamp()}.json`
      )
    } catch (cause) {
      if (mounted.current) setBackupError(cause)
    } finally {
      if (mounted.current) setBackupPending(false)
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
          <UpdateChannelControl
            channel={status?.channel}
            disabled={
              activeAttempt || !!status?.running || starting || checking
            }
            saving={savingChannel}
            onSaving={setSavingChannel}
            onSaved={(channel) => {
              refreshGeneration.current += 1
              setConfirmInstall(false)
              setStatus((previous) => ({
                ...emptyUpdateStatus(),
                current: previous?.current ?? __APP_VERSION__,
                installed_channel: previous?.installed_channel,
                channel,
              }))
              void refresh(true)
            }}
          />
          <div className="flex min-w-0 flex-col items-start gap-2">
            <KeeneticStatus tone={status?.available ? "success" : "neutral"}>
              {checking
                ? t("common.updateStatus.checking")
                : status?.installable && status.channel_change
                  ? t("pages.settings.softwareUpdate.switchAvailable")
                  : status?.available
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
              disabled={
                activeAttempt ||
                status?.running ||
                starting ||
                checking ||
                savingChannel
              }
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
              {status?.installable
                ? t("pages.settings.softwareUpdate.install")
                : t("pages.settings.softwareUpdate.title")}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Dialog
        onOpenChange={(nextOpen) => {
          // Closing the view does not cancel an admitted router operation.
          // Polling and duplicate-POST prevention belong to the saved attempt.
          setOpen(nextOpen)
          if (!nextOpen) {
            setConfirmInstall(false)
            setConfirmRollback(false)
          }
          if (nextOpen) {
            if (!activeAttempt && !status?.running) setShowResult(false)
            if (!activeAttempt) void refresh()
          }
        }}
        open={open}
      >
        <DialogContent className="overflow-hidden max-sm:top-auto max-sm:bottom-0 max-sm:left-0 max-sm:max-h-[calc(100dvh-0.75rem)] max-sm:max-w-none max-sm:translate-x-0 max-sm:translate-y-0 max-sm:rounded-b-none max-sm:border-x-0 max-sm:border-b-0 sm:max-w-[640px]">
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
            {notice ? (
              <div
                className="space-y-2 text-sm text-muted-foreground"
                role="status"
              >
                <p>
                  {notice === "reconnecting"
                    ? t("pages.settings.softwareUpdate.reconnecting")
                    : notice === "admissionUnknown"
                      ? t("pages.settings.softwareUpdate.admissionUnknown")
                      : t("pages.settings.softwareUpdate.resultUnknown")}
                </p>
                {notice === "resultUnknown" ? (
                  <Button
                    variant="outline"
                    onClick={() => {
                      const current = attemptRef.current
                      if (current) {
                        const next = {
                          ...current,
                          pollUntil: Date.now() + UPDATE_POLL_WINDOW_MS,
                        }
                        rememberAttempt(next)
                        setNotice(updateAttemptNotice(next))
                      }
                    }}
                  >
                    <RefreshCwIcon />
                    {t("pages.settings.softwareUpdate.checkProgress")}
                  </Button>
                ) : null}
                {notice === "resultUnknown" ? (
                  <div className="space-y-1">
                    <Button
                      variant="outline"
                      onClick={() => {
                        rememberAttempt(null)
                        setNotice(null)
                        setShowResult(false)
                        setOpen(false)
                        setStatus((previous) =>
                          previous
                            ? {
                                ...previous,
                                running: false,
                                phase: "unknown",
                                success: null,
                              }
                            : previous
                        )
                        // Refresh availability, but respect the explicit end
                        // of monitoring instead of reopening the same dialog.
                        void refresh(false, false)
                      }}
                    >
                      {t("pages.settings.softwareUpdate.stopMonitoring")}
                    </Button>
                    <p>
                      {t("pages.settings.softwareUpdate.stopMonitoringHint")}
                    </p>
                  </div>
                ) : null}
              </div>
            ) : null}
            {error ? (
              <div className="text-sm text-destructive">
                <OperationErrorMessage
                  error={error.cause}
                  fallbackSummary={error.fallbackSummary}
                />
              </div>
            ) : null}
            {backupError ? (
              <div className="text-sm text-destructive">
                <p className="font-medium">
                  {t("pages.settings.softwareUpdate.backupFailed")}
                </p>
                <OperationErrorMessage error={backupError} />
              </div>
            ) : null}
            <UpdateStateMessage status={status} />
            <RollbackAvailabilityNotice status={status} />
            {status && showUpdateLog ? (
              <UpdateProgress status={status} />
            ) : null}
            {status?.installable && !showUpdateLog ? (
              <ReleaseNotes status={status} />
            ) : null}
            {showUpdateLog ? (
              <details
                className="space-y-2 rounded-md border p-3"
                open={status?.success !== false || status?.running === true}
              >
                <summary className="cursor-pointer rounded-sm font-medium focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring">
                  {status?.success === false
                    ? t("operationErrors.details")
                    : t("pages.settings.softwareUpdate.result")}
                </summary>
                <pre
                  aria-live="polite"
                  className="max-h-72 overflow-auto rounded bg-muted p-3 text-xs whitespace-pre-wrap"
                  ref={logRef}
                >
                  {(status?.success === false
                    ? [status.message, status.log].filter(Boolean).join("\n\n")
                    : status?.log) ||
                    t("pages.settings.softwareUpdate.waitingForLog")}
                </pre>
              </details>
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
                  <Button
                    disabled={backupPending || starting || activeAttempt}
                    onClick={() => void startOperation("update")}
                  >
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
                    disabled={backupPending || starting || activeAttempt}
                    onClick={() => void startOperation("rollback")}
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
                activeAttempt ||
                backupPending ||
                status?.running ||
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
            <Button
              variant="outline"
              className="sm:mr-auto"
              disabled={
                backupPending || starting || activeAttempt || status?.running
              }
              onClick={() => void exportBackup()}
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
                !softwareUpdateRequest(status) ||
                savingChannel ||
                activeAttempt ||
                backupPending ||
                status?.running ||
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
      {(status?.channel === "alpha" || status?.channel === "stable") && (
        <div>
          <span className="text-muted-foreground">
            {t("pages.settings.softwareUpdate.channel")}:{" "}
          </span>
          {status.channel === "alpha" ? "Alpha" : "Stable (main)"}
        </div>
      )}
      <div>
        <span className="text-muted-foreground">
          {t("pages.settings.softwareUpdate.current")}:{" "}
        </span>
        <code>{status?.current || __APP_VERSION__ || "—"}</code>
        {status?.installed_channel && (
          <span>
            {" "}
            · {status.installed_channel === "alpha" ? "Alpha" : "Stable (main)"}
          </span>
        )}
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
      {status?.source && (
        <div className="text-muted-foreground">
          {t("pages.settings.softwareUpdate.source")}: {status.source}
        </div>
      )}
      {status?.channel_change && (
        <p className="text-sm text-warning">
          {t(
            status.current_ahead
              ? "pages.settings.softwareUpdate.downgradeBlocked"
              : "pages.settings.softwareUpdate.channelSwitchPending"
          )}
        </p>
      )}
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
  // A failed release check may still carry a cached `available: false`.
  // That is not confirmation that the installed version is current.
  if (status?.check_error) return null
  if (status?.channel_change) return null
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
          {status.success === false && !status.running
            ? t("pages.settings.softwareUpdate.operationFailed")
            : (status.message ?? t("pages.settings.softwareUpdate.inProgress"))}
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
