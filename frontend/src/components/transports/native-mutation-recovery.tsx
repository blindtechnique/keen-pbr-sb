import { AlertTriangleIcon, RotateCcwIcon } from "lucide-react"
import { useCallback, useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"

import type { NdmsNativeMutationInventoryStatus } from "@/api/generated/model"
import {
  NativeMutationTransportError,
  postNdmsNativeDeleteRecoveryOnce,
  postNdmsNativeImportRecoveryOnce,
  type NdmsNativeDeleteResult,
  type NdmsNativeImportRecoveryResult,
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

type ImportRecoveryLeaseValue =
  | Readonly<{ outcome: "import_no_work" | "import_blocked" | "unknown" }>
  | Readonly<{
      outcome: "import_completed"
      result: NdmsNativeImportRecoveryResult
    }>

type DeleteRecoveryLeaseValue =
  | Readonly<{
      outcome: "delete_terminal"
      result: NdmsNativeDeleteResult
    }>
  | Readonly<{ outcome: "delete_no_work" | "delete_blocked" | "unknown" }>

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
  onImportCompleted,
  onInventoryRefresh,
}: {
  readonly inventoryStatus?: NdmsNativeMutationInventoryStatus
  readonly onDeleteTerminal: (result: NdmsNativeDeleteResult) => void
  readonly onImportCompleted?: (
    result: NdmsNativeImportRecoveryResult
  ) => void | Promise<void>
  readonly onInventoryRefresh: () => Promise<void>
}) {
  const { t } = useTranslation()
  const [lock, setLock] = useState<NativeMutationLock | null>(() =>
    readNativeMutationLock()
  )
  const [busy, setBusy] = useState<NativeMutationRecoveryKind | null>(null)
  const [outcome, setOutcome] = useState<RecoveryOutcome | null>(null)
  const automaticImportRecoveryAttempts = useRef(0)
  const automaticDeleteRecoveryAttempts = useRef(0)

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
                  value: { outcome: "import_no_work" } as const,
                }
              }
              if (result.status === "completed") {
                return {
                  disposition: nativeImportRecoveryDisposition(result),
                  value: { outcome: "import_completed", result } as const,
                }
              }
              return {
                disposition: nativeImportRecoveryDisposition(result),
                value: { outcome: "import_blocked" } as const,
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
                  value: { outcome: "import_blocked" } as const,
                }
              }
              return {
                disposition: { state: "unknown" } as const,
                value: { outcome: "unknown" } as const,
              }
            }
          }
        )
      const nextOutcome =
        leaseResult.status === "completed"
          ? leaseResult.value.outcome
          : "unknown"
      if (
        leaseResult.status === "completed" &&
        leaseResult.value.outcome === "import_completed"
      ) {
        await Promise.resolve(
          onImportCompleted?.(leaseResult.value.result)
        ).catch(() => undefined)
      }
      // Import recovery is automatic and bodyless. Keep the ordinary progress
      // state visible while another pass is required instead of replacing it
      // with a frightening terminal lecture or a manual recovery button.
      setOutcome(
        nextOutcome === "import_no_work" ||
          nextOutcome === "import_completed" ||
          importNeedsRecovery
          ? null
          : nextOutcome
      )
    } finally {
      setBusy(null)
      await refresh().catch(() => undefined)
    }
  }, [busy, importNeedsRecovery, onImportCompleted, refresh])

  useEffect(() => {
    if (!importNeedsRecovery) {
      automaticImportRecoveryAttempts.current = 0
      return
    }
    if (busy !== null) return
    // The fresh import publishes its browser marker immediately before
    // releasing the lease. Let that lease unwind, then keep reconciling with
    // bounded backoff. A partial first pass must not require a page reload to
    // run the next bodyless pass.
    const attempt = automaticImportRecoveryAttempts.current
    const delay =
      attempt === 0
        ? 500
        : Math.min(1_000 * 2 ** Math.min(attempt - 1, 4), 15_000)
    const timeout = window.setTimeout(() => {
      automaticImportRecoveryAttempts.current += 1
      void recoverImport()
    }, delay)
    return () => window.clearTimeout(timeout)
  }, [busy, importNeedsRecovery, recoverImport])

  const recoverDelete = useCallback(async () => {
    if (busy) return
    setBusy("delete")
    setOutcome(null)
    try {
      const leaseResult =
        await runWithNativeMutationLease<DeleteRecoveryLeaseValue>(
          "delete_recovery",
          async () => {
            try {
              const result = await postNdmsNativeDeleteRecoveryOnce(false)
              if (result.status === "save_acknowledged_unverified") {
                return {
                  disposition: nativeDeleteRecoveryDisposition(result),
                  value: {
                    outcome: "delete_terminal",
                    result,
                  } as const,
                }
              }
              if (
                result.status === "blocked" &&
                result.stop === "no_delete_transaction"
              ) {
                return {
                  disposition: nativeDeleteRecoveryDisposition(result),
                  value: { outcome: "delete_no_work" } as const,
                }
              }
              return {
                disposition: nativeDeleteRecoveryDisposition(result),
                value: { outcome: "delete_blocked" } as const,
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
                  value: { outcome: "delete_blocked" } as const,
                }
              }
              return {
                disposition: { state: "unknown" } as const,
                value: { outcome: "unknown" } as const,
              }
            }
          }
        )

      if (leaseResult.status !== "completed") {
        setOutcome(null)
      } else {
        setOutcome(
          leaseResult.value.outcome === "delete_terminal" ||
            leaseResult.value.outcome === "delete_no_work" ||
            deleteNeedsRecovery
            ? null
            : leaseResult.value.outcome
        )
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
  }, [busy, deleteNeedsRecovery, onDeleteTerminal, refresh])

  useEffect(() => {
    if (!deleteNeedsRecovery) {
      automaticDeleteRecoveryAttempts.current = 0
      return
    }
    if (busy !== null) return
    const attempt = automaticDeleteRecoveryAttempts.current
    const delay =
      attempt === 0
        ? 500
        : Math.min(1_000 * 2 ** Math.min(attempt - 1, 4), 15_000)
    const timeout = window.setTimeout(() => {
      automaticDeleteRecoveryAttempts.current += 1
      void recoverDelete()
    }, delay)
    return () => window.clearTimeout(timeout)
  }, [busy, deleteNeedsRecovery, recoverDelete])

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

      {importNeedsRecovery && !pending ? (
        <Alert aria-atomic="true" aria-live="polite">
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
        <Alert aria-atomic="true" aria-live="polite">
          <RotateCcwIcon className="animate-spin" />
          <AlertTitle>
            {t("transports.nativeMutation.recovery.deleteTitle")}
          </AlertTitle>
          <AlertDescription className="break-words">
            {t("transports.nativeMutation.recovery.deleteDescription")}
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
