import { AlertTriangleIcon, RotateCcwIcon, ShieldAlertIcon } from "lucide-react"
import { useEffect, useState } from "react"
import { useTranslation } from "react-i18next"

import type { NdmsNativeMutationInventoryStatus } from "@/api/generated/model"
import {
  NativeMutationTransportError,
  postNdmsNativeDeleteRecoveryOnce,
  postNdmsNativeImportRecoveryOnce,
  type NdmsNativeDeleteResult,
} from "@/api/native-mutation"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  beginNativeMutationPending,
  clearNativeMutationPending,
  latchNativeMutationRecovery,
  latchNativeMutationUnknown,
  nativeMutationPendingIsActiveInThisProcess,
  readNativeMutationLock,
  subscribeNativeMutationLock,
  type NativeMutationLock,
  type NativeMutationOperation,
  type NativeMutationRecoveryKind,
} from "@/lib/native-mutation-lock"

type RecoveryOutcome =
  | "import_no_work"
  | "import_completed"
  | "import_blocked"
  | "delete_no_work"
  | "delete_terminal"
  | "delete_blocked"
  | "unknown"

const operationRecoveryKind = (
  operation: NativeMutationOperation
): NativeMutationRecoveryKind =>
  operation === "import" || operation === "import_recovery"
    ? "import"
    : "delete"

const lockMatches = (
  lock: NativeMutationLock | null,
  recovery: NativeMutationRecoveryKind
): boolean => {
  if (!lock) return false
  if (lock.state === "recovery_required") return lock.recovery === recovery
  return operationRecoveryKind(lock.operation) === recovery
}

export function NativeMutationRecovery({
  inventoryStatus,
  onDeleteTerminal,
  onInventoryRefresh,
}: {
  readonly inventoryStatus?: NdmsNativeMutationInventoryStatus
  readonly onDeleteTerminal: (result: NdmsNativeDeleteResult) => void
  readonly onInventoryRefresh: () => Promise<void>
}) {
  const { t } = useTranslation()
  const [lock, setLock] = useState<NativeMutationLock | null>(() =>
    readNativeMutationLock()
  )
  const [busy, setBusy] = useState<NativeMutationRecoveryKind | null>(null)
  const [outcome, setOutcome] = useState<RecoveryOutcome | null>(null)
  const [deleteReconfirmation, setDeleteReconfirmation] = useState(false)
  const [externalWriterAccepted, setExternalWriterAccepted] = useState(false)
  const [globalSaveAcknowledged, setGlobalSaveAcknowledged] = useState(false)

  useEffect(
    () => subscribeNativeMutationLock((nextLock) => setLock(nextLock)),
    []
  )

  const importState = inventoryStatus?.observed_import_journal_state
  const deleteState = inventoryStatus?.observed_delete_journal_state
  const pending = lock?.state === "pending"
  const pendingActiveHere = nativeMutationPendingIsActiveInThisProcess(lock)
  const importNeedsRecovery =
    importState === "recovery_required" || lockMatches(lock, "import")
  const deleteNeedsRecovery =
    deleteState === "recovery_required" || lockMatches(lock, "delete")
  const importJournalUnsafe =
    importState === "unsafe" || importState === "unavailable"
  const deleteJournalUnsafe =
    deleteState === "unsafe" || deleteState === "unavailable"
  const show =
    pending ||
    importNeedsRecovery ||
    deleteNeedsRecovery ||
    importJournalUnsafe ||
    deleteJournalUnsafe ||
    outcome !== null
  const outcomeCopy = outcome ? recoveryOutcomeCopy(outcome, t) : null

  const syncLock = () => setLock(readNativeMutationLock())

  const finishTrustedPending = (
    token: ReturnType<typeof beginNativeMutationPending>,
    operation: NativeMutationOperation
  ): boolean => {
    if (token && clearNativeMutationPending(token)) return true
    latchNativeMutationUnknown(operation)
    setOutcome("unknown")
    return false
  }

  const refresh = async () => {
    try {
      await onInventoryRefresh()
    } finally {
      syncLock()
    }
  }

  const recoverImport = async () => {
    if (busy || pendingActiveHere) return
    const token = beginNativeMutationPending("import_recovery")
    if (!token) {
      setOutcome("unknown")
      syncLock()
      return
    }
    setBusy("import")
    setOutcome(null)
    syncLock()
    try {
      const result = await postNdmsNativeImportRecoveryOnce()
      if (result.status === "no_work") {
        if (finishTrustedPending(token, "import_recovery")) {
          setOutcome("import_no_work")
        }
      } else if (result.status === "completed") {
        if (finishTrustedPending(token, "import_recovery")) {
          setOutcome("import_completed")
        }
      } else {
        latchNativeMutationRecovery("import")
        setOutcome("import_blocked")
      }
    } catch (error) {
      if (
        error instanceof NativeMutationTransportError &&
        error.code === "rejected"
      ) {
        latchNativeMutationRecovery("import")
        setOutcome("import_blocked")
        return
      }
      latchNativeMutationUnknown("import_recovery")
      setOutcome("unknown")
    } finally {
      setBusy(null)
      await refresh().catch(() => undefined)
    }
  }

  const recoverDelete = async (withAcknowledgements: boolean) => {
    if (busy || pendingActiveHere) return
    if (
      withAcknowledgements &&
      (!externalWriterAccepted || !globalSaveAcknowledged)
    ) {
      return
    }
    const token = beginNativeMutationPending("delete_recovery")
    if (!token) {
      setOutcome("unknown")
      syncLock()
      return
    }
    setBusy("delete")
    setOutcome(null)
    setExternalWriterAccepted(false)
    setGlobalSaveAcknowledged(false)
    syncLock()
    try {
      const result =
        await postNdmsNativeDeleteRecoveryOnce(withAcknowledgements)
      if (result.status === "save_acknowledged_unverified") {
        if (finishTrustedPending(token, "delete_recovery")) {
          setDeleteReconfirmation(false)
          setOutcome("delete_terminal")
          onDeleteTerminal(result)
        }
      } else if (
        result.status === "blocked" &&
        result.stop === "no_delete_transaction"
      ) {
        if (finishTrustedPending(token, "delete_recovery")) {
          setDeleteReconfirmation(false)
          setOutcome("delete_no_work")
        }
      } else {
        latchNativeMutationRecovery("delete")
        const reconfirm = result.stop === "save_reconfirmation_required"
        setDeleteReconfirmation(reconfirm)
        setOutcome("delete_blocked")
      }
    } catch (error) {
      if (
        error instanceof NativeMutationTransportError &&
        error.code === "rejected"
      ) {
        latchNativeMutationRecovery("delete")
        setOutcome("delete_blocked")
        return
      }
      latchNativeMutationUnknown("delete_recovery")
      setDeleteReconfirmation(false)
      setOutcome("unknown")
    } finally {
      setBusy(null)
      await refresh().catch(() => undefined)
    }
  }

  if (!show) return null

  return (
    <section
      aria-label={t("transports.nativeMutation.recovery.regionLabel")}
      className="space-y-3"
    >
      {pending ? (
        <Alert variant="warning" aria-atomic="true" aria-live="polite">
          <RotateCcwIcon className="animate-spin" />
          <AlertTitle>
            {t("transports.nativeMutation.recovery.pendingTitle")}
          </AlertTitle>
          <AlertDescription className="break-words">
            {t("transports.nativeMutation.recovery.pendingDescription")}
          </AlertDescription>
        </Alert>
      ) : null}

      {importJournalUnsafe || deleteJournalUnsafe ? (
        <Alert variant="destructive" aria-atomic="true" aria-live="polite">
          <ShieldAlertIcon />
          <AlertTitle>
            {t("transports.nativeMutation.recovery.unsafeTitle")}
          </AlertTitle>
          <AlertDescription className="break-words">
            {t("transports.nativeMutation.recovery.unsafeDescription")}
          </AlertDescription>
        </Alert>
      ) : null}

      {importNeedsRecovery && !pendingActiveHere ? (
        <Alert variant="warning" aria-atomic="true" aria-live="polite">
          <AlertTriangleIcon />
          <AlertTitle>
            {t("transports.nativeMutation.recovery.importTitle")}
          </AlertTitle>
          <AlertDescription className="space-y-3 break-words">
            <p>{t("transports.nativeMutation.recovery.importDescription")}</p>
            <Button
              className="min-h-11 max-w-full whitespace-normal"
              disabled={busy !== null}
              onClick={() => void recoverImport()}
              type="button"
              variant="outline"
            >
              <RotateCcwIcon />
              {busy === "import"
                ? t("transports.nativeMutation.recovery.checking")
                : t("transports.nativeMutation.recovery.checkImport")}
            </Button>
          </AlertDescription>
        </Alert>
      ) : null}

      {deleteNeedsRecovery && !pendingActiveHere ? (
        <Alert variant="warning" aria-atomic="true" aria-live="polite">
          <AlertTriangleIcon />
          <AlertTitle>
            {t("transports.nativeMutation.recovery.deleteTitle")}
          </AlertTitle>
          <AlertDescription className="space-y-3 break-words">
            <p>{t("transports.nativeMutation.recovery.deleteDescription")}</p>

            {deleteReconfirmation ? (
              <div className="space-y-2 rounded-md border border-warning/40 p-2">
                <p className="font-medium text-foreground">
                  {t("transports.nativeMutation.recovery.reconfirmTitle")}
                </p>
                <label className="flex min-h-11 cursor-pointer items-start gap-3 rounded-md p-1">
                  <input
                    checked={externalWriterAccepted}
                    className="mt-0.5 size-5 shrink-0 accent-primary"
                    disabled={busy !== null}
                    onChange={(event) =>
                      setExternalWriterAccepted(event.target.checked)
                    }
                    type="checkbox"
                  />
                  <span className="min-w-0 break-words">
                    {t(
                      "transports.nativeMutation.acknowledgements.externalWriter"
                    )}
                  </span>
                </label>
                <label className="flex min-h-11 cursor-pointer items-start gap-3 rounded-md p-1">
                  <input
                    checked={globalSaveAcknowledged}
                    className="mt-0.5 size-5 shrink-0 accent-primary"
                    disabled={busy !== null}
                    onChange={(event) =>
                      setGlobalSaveAcknowledged(event.target.checked)
                    }
                    type="checkbox"
                  />
                  <span className="min-w-0 break-words">
                    {t("transports.nativeMutation.acknowledgements.globalSave")}
                  </span>
                </label>
              </div>
            ) : null}

            <Button
              className="min-h-11 max-w-full whitespace-normal"
              disabled={
                busy !== null ||
                (deleteReconfirmation &&
                  (!externalWriterAccepted || !globalSaveAcknowledged))
              }
              onClick={() => void recoverDelete(deleteReconfirmation)}
              type="button"
              variant="outline"
            >
              <RotateCcwIcon />
              {busy === "delete"
                ? t("transports.nativeMutation.recovery.checking")
                : deleteReconfirmation
                  ? t("transports.nativeMutation.recovery.continueDelete")
                  : t("transports.nativeMutation.recovery.checkDelete")}
            </Button>
          </AlertDescription>
        </Alert>
      ) : null}

      <div aria-atomic="true" aria-live="polite">
        {outcomeCopy ? (
          <Alert variant={outcome === "unknown" ? "destructive" : "warning"}>
            <AlertTitle>{outcomeCopy.title}</AlertTitle>
            <AlertDescription className="break-words">
              {outcomeCopy.description}
            </AlertDescription>
          </Alert>
        ) : null}
      </div>
    </section>
  )
}

function recoveryOutcomeCopy(
  outcome: RecoveryOutcome,
  t: (key: string) => string
): Readonly<{ title: string; description: string }> {
  switch (outcome) {
    case "import_no_work":
      return {
        title: t(
          "transports.nativeMutation.recovery.outcomes.import_no_work.title"
        ),
        description: t(
          "transports.nativeMutation.recovery.outcomes.import_no_work.description"
        ),
      }
    case "import_completed":
      return {
        title: t(
          "transports.nativeMutation.recovery.outcomes.import_completed.title"
        ),
        description: t(
          "transports.nativeMutation.recovery.outcomes.import_completed.description"
        ),
      }
    case "import_blocked":
      return {
        title: t(
          "transports.nativeMutation.recovery.outcomes.import_blocked.title"
        ),
        description: t(
          "transports.nativeMutation.recovery.outcomes.import_blocked.description"
        ),
      }
    case "delete_no_work":
      return {
        title: t(
          "transports.nativeMutation.recovery.outcomes.delete_no_work.title"
        ),
        description: t(
          "transports.nativeMutation.recovery.outcomes.delete_no_work.description"
        ),
      }
    case "delete_terminal":
      return {
        title: t(
          "transports.nativeMutation.recovery.outcomes.delete_terminal.title"
        ),
        description: t(
          "transports.nativeMutation.recovery.outcomes.delete_terminal.description"
        ),
      }
    case "delete_blocked":
      return {
        title: t(
          "transports.nativeMutation.recovery.outcomes.delete_blocked.title"
        ),
        description: t(
          "transports.nativeMutation.recovery.outcomes.delete_blocked.description"
        ),
      }
    case "unknown":
      return {
        title: t("transports.nativeMutation.recovery.outcomes.unknown.title"),
        description: t(
          "transports.nativeMutation.recovery.outcomes.unknown.description"
        ),
      }
  }
}
