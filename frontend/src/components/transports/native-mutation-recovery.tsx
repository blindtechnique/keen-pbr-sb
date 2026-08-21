import { AlertTriangleIcon, RotateCcwIcon } from "lucide-react"
import { useCallback, useEffect, useRef, useState } from "react"
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
  readNativeMutationLock,
  runWithNativeMutationLease,
  subscribeNativeMutationLock,
  type NativeMutationLock,
  type NativeMutationOperation,
  type NativeMutationRecoveryKind,
} from "@/lib/native-mutation-lock"

import {
  nativeDeleteRecoveryDisposition,
  nativeImportRecoveryDisposition,
} from "./native-mutation-recovery-model"

type RecoveryOutcome =
  | "import_no_work"
  | "import_completed"
  | "import_blocked"
  | "delete_no_work"
  | "delete_terminal"
  | "delete_blocked"
  | "unknown"

type ImportRecoveryLeaseValue = Extract<
  RecoveryOutcome,
  "import_no_work" | "import_completed" | "import_blocked" | "unknown"
>

type DeleteRecoveryLeaseValue =
  | Readonly<{
      outcome: "delete_terminal"
      result: NdmsNativeDeleteResult
      reconfirm: false
    }>
  | Readonly<{
      outcome: "delete_no_work" | "delete_blocked" | "unknown"
      reconfirm: boolean
    }>

const operationRecoveryKind = (
  operation: NativeMutationOperation
): NativeMutationRecoveryKind => {
  if (operation === "import" || operation === "import_recovery") {
    return "import"
  }
  if (operation === "delete" || operation === "delete_recovery") {
    return "delete"
  }
  return "forget"
}

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
  const automaticImportRecoveryStarted = useRef(false)

  useEffect(
    () => subscribeNativeMutationLock((nextLock) => setLock(nextLock)),
    []
  )

  const importState = inventoryStatus?.observed_import_journal_state
  const deleteState = inventoryStatus?.observed_delete_journal_state
  const pending = lock?.state === "pending"
  const importNeedsRecovery =
    importState === "recovery_required" || lockMatches(lock, "import")
  const deleteNeedsRecovery =
    deleteState === "recovery_required" || lockMatches(lock, "delete")
  const forgetNeedsRecovery = lockMatches(lock, "forget")
  const show =
    pending || deleteNeedsRecovery || forgetNeedsRecovery || outcome !== null
  const outcomeCopy = outcome ? recoveryOutcomeCopy(outcome, t) : null

  const syncLock = useCallback(() => setLock(readNativeMutationLock()), [])

  const refresh = useCallback(async () => {
    try {
      await onInventoryRefresh()
    } finally {
      syncLock()
    }
  }, [onInventoryRefresh, syncLock])

  const recoverImport = useCallback(async () => {
    if (busy) return
    setBusy("import")
    setOutcome(null)
    try {
      const leaseResult =
        await runWithNativeMutationLease<ImportRecoveryLeaseValue>(
          "import_recovery",
          async () => {
            try {
              const result = await postNdmsNativeImportRecoveryOnce()
              if (result.status === "no_work") {
                return {
                  disposition: nativeImportRecoveryDisposition(result),
                  value: "import_no_work" as const,
                }
              }
              if (result.status === "completed") {
                return {
                  disposition: nativeImportRecoveryDisposition(result),
                  value: "import_completed" as const,
                }
              }
              return {
                disposition: nativeImportRecoveryDisposition(result),
                value: "import_blocked" as const,
              }
            } catch (error) {
              if (
                error instanceof NativeMutationTransportError &&
                error.code === "rejected"
              ) {
                return {
                  disposition: {
                    state: "recovery",
                    recovery: "import",
                  } as const,
                  value: "import_blocked" as const,
                }
              }
              return {
                disposition: { state: "unknown" } as const,
                value: "unknown" as const,
              }
            }
          }
        )
      const nextOutcome =
        leaseResult.status === "completed" ? leaseResult.value : "unknown"
      // A clean/no-work result is ordinary automatic reconciliation. The
      // refreshed inventory is the useful outcome; do not replace it with a
      // recovery lecture or a manual button.
      setOutcome(
        nextOutcome === "import_no_work" || nextOutcome === "import_completed"
          ? null
          : nextOutcome
      )
    } finally {
      setBusy(null)
      await refresh().catch(() => undefined)
    }
  }, [busy, refresh])

  useEffect(() => {
    if (!importNeedsRecovery) {
      automaticImportRecoveryStarted.current = false
      return
    }
    if (busy !== null || automaticImportRecoveryStarted.current) return
    automaticImportRecoveryStarted.current = true
    void recoverImport()
  }, [busy, importNeedsRecovery, recoverImport])

  const recoverDelete = async (withAcknowledgements: boolean) => {
    if (busy) return
    if (
      withAcknowledgements &&
      (!externalWriterAccepted || !globalSaveAcknowledged)
    ) {
      return
    }
    setBusy("delete")
    setOutcome(null)
    setExternalWriterAccepted(false)
    setGlobalSaveAcknowledged(false)
    try {
      const leaseResult =
        await runWithNativeMutationLease<DeleteRecoveryLeaseValue>(
          "delete_recovery",
          async () => {
            try {
              const result =
                await postNdmsNativeDeleteRecoveryOnce(withAcknowledgements)
              if (result.status === "save_acknowledged_unverified") {
                return {
                  disposition: nativeDeleteRecoveryDisposition(result),
                  value: {
                    outcome: "delete_terminal",
                    result,
                    reconfirm: false,
                  } as const,
                }
              }
              if (
                result.status === "blocked" &&
                result.stop === "no_delete_transaction"
              ) {
                return {
                  disposition: nativeDeleteRecoveryDisposition(result),
                  value: {
                    outcome: "delete_no_work",
                    reconfirm: false,
                  } as const,
                }
              }
              return {
                disposition: nativeDeleteRecoveryDisposition(result),
                value: {
                  outcome: "delete_blocked",
                  reconfirm: result.stop === "save_reconfirmation_required",
                } as const,
              }
            } catch (error) {
              if (
                error instanceof NativeMutationTransportError &&
                error.code === "rejected"
              ) {
                return {
                  disposition: {
                    state: "recovery",
                    recovery: "delete",
                  } as const,
                  value: {
                    outcome: "delete_blocked",
                    reconfirm: false,
                  } as const,
                }
              }
              return {
                disposition: { state: "unknown" } as const,
                value: {
                  outcome: "unknown",
                  reconfirm: false,
                } as const,
              }
            }
          }
        )

      if (leaseResult.status !== "completed") {
        setDeleteReconfirmation(false)
        setOutcome("unknown")
      } else {
        setDeleteReconfirmation(leaseResult.value.reconfirm)
        setOutcome(leaseResult.value.outcome)
        if (
          leaseResult.value.outcome === "delete_terminal" &&
          "result" in leaseResult.value
        ) {
          onDeleteTerminal(leaseResult.value.result)
        }
      }
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

      {deleteNeedsRecovery ? (
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

      {forgetNeedsRecovery ? (
        <Alert variant="warning" aria-atomic="true" aria-live="polite">
          <AlertTriangleIcon />
          <AlertTitle>
            {t("transports.nativeMutation.forget.recoveryTitle")}
          </AlertTitle>
          <AlertDescription className="space-y-3 break-words">
            <p>{t("transports.nativeMutation.forget.recoveryDescription")}</p>
            <Button
              className="min-h-11 max-w-full whitespace-normal"
              disabled={busy !== null}
              onClick={() => void refresh().catch(() => undefined)}
              type="button"
              variant="outline"
            >
              <RotateCcwIcon />
              {t("transports.nativeMutation.forget.refreshInventory")}
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
