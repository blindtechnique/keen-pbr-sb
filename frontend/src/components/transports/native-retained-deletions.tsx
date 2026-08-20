import { AlertTriangleIcon, ShieldAlertIcon, Trash2Icon } from "lucide-react"
import { useEffect, useState } from "react"
import { useTranslation } from "react-i18next"

import type { NdmsNativeRetainedDeletion } from "@/api/generated/model"
import {
  NativeMutationTransportError,
  postNdmsNativeTombstoneForgetOnce,
  type NdmsNativeTombstoneForgetResult,
} from "@/api/native-mutation"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { runWithNativeMutationLease } from "@/lib/native-mutation-lock"

import {
  retainedDeletionBlockerKey,
  retainedDeletionDeferredCheckKey,
  tombstoneForgetArtifactStateKey,
  tombstoneForgetDisposition,
  tombstoneForgetOutcomeKey,
  tombstoneForgetStopKey,
} from "./native-retained-deletions-model"

type ForgetSelection = Readonly<{
  interfaceName: string
  expectedOwnershipRevision: string
}>

type SubmissionState =
  | Readonly<{ status: "idle" }>
  | Readonly<{ status: "sending" }>
  | Readonly<{
      status: "result"
      result: NdmsNativeTombstoneForgetResult
    }>
  | Readonly<{ status: "rejected" }>
  | Readonly<{ status: "unknown" }>

type ForgetLeaseValue =
  | Readonly<{
      status: "result"
      result: NdmsNativeTombstoneForgetResult
    }>
  | Readonly<{ status: "rejected" | "unknown" }>

export function NativeRetainedDeletions({
  retainedDeletions,
  onInventoryRefresh,
}: {
  readonly retainedDeletions: readonly NdmsNativeRetainedDeletion[]
  readonly onInventoryRefresh: () => Promise<void>
}) {
  const { t } = useTranslation()
  const [selection, setSelection] = useState<ForgetSelection>()
  const [confirmName, setConfirmName] = useState("")
  const [rollbackAcknowledged, setRollbackAcknowledged] = useState(false)
  const [foreignAcknowledged, setForeignAcknowledged] = useState(false)
  const [submission, setSubmission] = useState<SubmissionState>({
    status: "idle",
  })
  const [lastForgotten, setLastForgotten] = useState<string>()

  const selected = selection
    ? retainedDeletions.find(
        (retained) => retained.interface_name === selection.interfaceName
      )
    : undefined
  const stale = Boolean(
    selection &&
    (!selected ||
      selected.ownership_revision !== selection.expectedOwnershipRevision ||
      !selected.forget_candidate)
  )
  const sending = submission.status === "sending"
  const canSubmit = Boolean(
    selection &&
    selected &&
    !stale &&
    confirmName === selection.interfaceName &&
    rollbackAcknowledged &&
    foreignAcknowledged &&
    submission.status === "idle"
  )

  useEffect(() => {
    if (!selection) return
    setConfirmName("")
    setRollbackAcknowledged(false)
    setForeignAcknowledged(false)
    setSubmission({ status: "idle" })
  }, [selection])

  if (retainedDeletions.length === 0 && !lastForgotten) return null

  const close = () => {
    if (sending) return
    setSelection(undefined)
  }

  const submit = async () => {
    if (!canSubmit || !selection) return
    setSubmission({ status: "sending" })
    try {
      const lease = await runWithNativeMutationLease<ForgetLeaseValue>(
        "forget",
        async () => {
          try {
            const result = await postNdmsNativeTombstoneForgetOnce({
              interface_name: selection.interfaceName,
              expected_ownership_revision: selection.expectedOwnershipRevision,
              confirm_interface_name: selection.interfaceName,
              rollback_discard_acknowledgement:
                "permanently_discard_rollback_data",
              foreign_reappearance_acknowledgement:
                "accepted_reappearance_is_foreign",
            })
            return {
              disposition: tombstoneForgetDisposition(result),
              value: { status: "result", result } as const,
            }
          } catch (error) {
            if (
              error instanceof NativeMutationTransportError &&
              error.code === "rejected"
            ) {
              return {
                disposition: { state: "clear" } as const,
                value: { status: "rejected" } as const,
              }
            }
            return {
              disposition: { state: "unknown" } as const,
              value: { status: "unknown" } as const,
            }
          }
        }
      )

      if (lease.status !== "completed") {
        setSubmission({ status: "unknown" })
      } else if (
        lease.value.status === "result" &&
        lease.value.result.status === "forgotten"
      ) {
        setLastForgotten(lease.value.result.interface_name)
        setSelection(undefined)
      } else {
        setSubmission(lease.value)
      }
    } finally {
      await onInventoryRefresh().catch(() => undefined)
    }
  }

  return (
    <section
      aria-label={t("transports.nativeMutation.forget.regionLabel")}
      className="space-y-3 rounded-xl border bg-card p-4"
    >
      <div className="space-y-1">
        <h2 className="text-base font-semibold">
          {t("transports.nativeMutation.forget.title")}
        </h2>
        <p className="text-sm break-words text-muted-foreground">
          {t("transports.nativeMutation.forget.description")}
        </p>
      </div>

      {lastForgotten ? (
        <Alert aria-atomic="true" aria-live="polite" variant="warning">
          <AlertTitle>
            {t("transports.nativeMutation.forget.outcomes.forgotten")}
          </AlertTitle>
          <AlertDescription className="break-words">
            {t("transports.nativeMutation.forget.forgottenDescription", {
              name: lastForgotten,
            })}
          </AlertDescription>
        </Alert>
      ) : null}

      <ul className="space-y-3">
        {retainedDeletions.map((retained) => (
          <li
            className="space-y-3 rounded-lg border bg-background p-3"
            key={`${retained.interface_name}:${retained.ownership_revision}`}
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-medium break-all">
                {retained.interface_name}
              </span>
              <Badge
                variant={retained.forget_candidate ? "outline" : "secondary"}
              >
                {retained.forget_candidate
                  ? t("transports.nativeMutation.forget.candidate")
                  : t("transports.nativeMutation.forget.blocked")}
              </Badge>
            </div>

            {retained.forget_blockers.length > 0 ? (
              <div className="space-y-1 text-sm">
                <p className="font-medium">
                  {t("transports.nativeMutation.forget.blockersTitle")}
                </p>
                <ul className="list-disc space-y-1 pl-5 text-muted-foreground">
                  {retained.forget_blockers.map((blocker) => (
                    <li className="break-words" key={blocker}>
                      {t(retainedDeletionBlockerKey(blocker))}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}

            <details className="text-sm">
              <summary className="cursor-pointer font-medium">
                {t("transports.nativeMutation.forget.deferredTitle")}
              </summary>
              <ul className="mt-1 list-disc space-y-1 pl-5 text-muted-foreground">
                {retained.deferred_authoritative_checks.map((check) => (
                  <li className="break-words" key={check}>
                    {t(retainedDeletionDeferredCheckKey(check))}
                  </li>
                ))}
              </ul>
            </details>

            <Button
              className="min-h-11 max-w-full whitespace-normal"
              disabled={!retained.forget_candidate}
              onClick={() => {
                setLastForgotten(undefined)
                setSelection({
                  interfaceName: retained.interface_name,
                  expectedOwnershipRevision: retained.ownership_revision,
                })
              }}
              type="button"
              variant="outline"
            >
              <Trash2Icon />
              {t("transports.nativeMutation.forget.openDialog")}
            </Button>
          </li>
        ))}
      </ul>

      <Dialog
        onOpenChange={(open) => !open && close()}
        open={Boolean(selection)}
      >
        <DialogContent className="max-sm:top-auto max-sm:bottom-0 max-sm:left-0 max-sm:max-h-[calc(100dvh-0.75rem)] max-sm:max-w-none max-sm:translate-x-0 max-sm:translate-y-0 max-sm:rounded-b-none max-sm:border-x-0 max-sm:border-b-0 sm:max-w-xl">
          <DialogHeader>
            <DialogTitle className="flex min-w-0 items-center gap-2 break-words">
              <ShieldAlertIcon className="size-5 shrink-0 text-destructive" />
              {t("transports.nativeMutation.forget.dialogTitle")}
            </DialogTitle>
            <DialogDescription className="break-words">
              {t("transports.nativeMutation.forget.dialogDescription", {
                name: selection?.interfaceName ?? "",
              })}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            {stale ? (
              <Alert variant="warning" aria-live="polite">
                <AlertTriangleIcon />
                <AlertTitle>
                  {t("transports.nativeMutation.forget.staleTitle")}
                </AlertTitle>
                <AlertDescription className="break-words">
                  {t("transports.nativeMutation.forget.staleDescription")}
                </AlertDescription>
              </Alert>
            ) : null}

            <div className="space-y-2">
              <label
                className="block text-sm font-medium break-words"
                htmlFor="native-forget-confirm-name"
              >
                {t("transports.nativeMutation.forget.typeName", {
                  name: selection?.interfaceName ?? "",
                })}
              </label>
              <Input
                autoComplete="off"
                autoFocus
                className="h-11"
                disabled={sending || stale}
                id="native-forget-confirm-name"
                onChange={(event) => setConfirmName(event.target.value)}
                spellCheck={false}
                value={confirmName}
              />
            </div>

            <label className="flex min-h-11 cursor-pointer items-start gap-3 rounded-md p-1 text-sm">
              <input
                checked={rollbackAcknowledged}
                className="mt-0.5 size-5 shrink-0 accent-primary"
                disabled={sending || stale}
                onChange={(event) =>
                  setRollbackAcknowledged(event.target.checked)
                }
                type="checkbox"
              />
              <span className="min-w-0 break-words">
                {t("transports.nativeMutation.forget.rollbackAcknowledgement")}
              </span>
            </label>

            <label className="flex min-h-11 cursor-pointer items-start gap-3 rounded-md p-1 text-sm">
              <input
                checked={foreignAcknowledged}
                className="mt-0.5 size-5 shrink-0 accent-primary"
                disabled={sending || stale}
                onChange={(event) =>
                  setForeignAcknowledged(event.target.checked)
                }
                type="checkbox"
              />
              <span className="min-w-0 break-words">
                {t("transports.nativeMutation.forget.foreignAcknowledgement")}
              </span>
            </label>

            <div aria-atomic="true" aria-live="polite">
              {submission.status === "result" ? (
                <Alert
                  variant={
                    submission.result.status === "recovery_required"
                      ? "destructive"
                      : "warning"
                  }
                >
                  <AlertTitle>
                    {t(tombstoneForgetOutcomeKey(submission.result))}
                  </AlertTitle>
                  <AlertDescription className="space-y-1 break-words">
                    <p>{t(tombstoneForgetStopKey(submission.result.stop))}</p>
                    <p>
                      {t("transports.nativeMutation.forget.artifactState", {
                        snapshot: t(
                          tombstoneForgetArtifactStateKey(
                            submission.result.snapshot_state
                          )
                        ),
                        tombstone: t(
                          tombstoneForgetArtifactStateKey(
                            submission.result.tombstone_state
                          )
                        ),
                      })}
                    </p>
                  </AlertDescription>
                </Alert>
              ) : submission.status === "rejected" ? (
                <Alert variant="warning">
                  <AlertTitle>
                    {t("transports.nativeMutation.forget.rejectedTitle")}
                  </AlertTitle>
                  <AlertDescription>
                    {t("transports.nativeMutation.forget.rejectedDescription")}
                  </AlertDescription>
                </Alert>
              ) : submission.status === "unknown" ? (
                <Alert variant="destructive">
                  <AlertTitle>
                    {t("transports.nativeMutation.forget.unknownTitle")}
                  </AlertTitle>
                  <AlertDescription>
                    {t("transports.nativeMutation.forget.unknownDescription")}
                  </AlertDescription>
                </Alert>
              ) : null}
            </div>
          </div>

          <DialogFooter className="max-sm:items-stretch">
            <Button
              className="min-h-11"
              disabled={sending}
              onClick={close}
              type="button"
              variant="outline"
            >
              {t("common.cancel")}
            </Button>
            <Button
              className="min-h-11"
              disabled={!canSubmit}
              onClick={() => void submit()}
              type="button"
              variant="destructive"
            >
              <Trash2Icon />
              {sending
                ? t("transports.nativeMutation.forget.sending")
                : t("transports.nativeMutation.forget.confirm")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </section>
  )
}
