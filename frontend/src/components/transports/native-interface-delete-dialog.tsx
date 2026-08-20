import { AlertTriangleIcon, Trash2Icon } from "lucide-react"
import { useEffect, useState } from "react"
import { useTranslation } from "react-i18next"

import {
  NativeMutationTransportError,
  postNdmsNativeDeleteOnce,
  type NdmsNativeDeleteResult,
} from "@/api/native-mutation"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
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
import type { NativeInterfaceModel } from "@/lib/native-interfaces"

type SubmissionState =
  | { readonly status: "idle" }
  | { readonly status: "sending" }
  | { readonly status: "blocked"; readonly result: NdmsNativeDeleteResult }
  | { readonly status: "rejected" }
  | { readonly status: "recovery_required" }
  | { readonly status: "unknown" }

type DeleteLeaseValue =
  | { readonly status: "terminal"; readonly result: NdmsNativeDeleteResult }
  | Extract<
      SubmissionState,
      {
        readonly status:
          | "blocked"
          | "rejected"
          | "recovery_required"
          | "unknown"
      }
    >

export function NativeInterfaceDeleteDialog({
  expectedOwnershipRevision,
  nativeInterface,
  onInventoryRefresh,
  onOpenChange,
  onTerminal,
  open,
}: {
  readonly expectedOwnershipRevision: string
  readonly nativeInterface?: NativeInterfaceModel
  readonly onInventoryRefresh: () => Promise<void>
  readonly onOpenChange: (open: boolean) => void
  readonly onTerminal: (result: NdmsNativeDeleteResult) => void
  readonly open: boolean
}) {
  const { t } = useTranslation()
  const [confirmLabel, setConfirmLabel] = useState("")
  const [externalWriterAccepted, setExternalWriterAccepted] = useState(false)
  const [globalSaveAcknowledged, setGlobalSaveAcknowledged] = useState(false)
  const [submission, setSubmission] = useState<SubmissionState>({
    status: "idle",
  })

  const interfaceName = nativeInterface?.logicalName ?? ""
  const projection = nativeInterface?.source.native_mutation
  const currentRevision = projection?.ownership_revision ?? ""
  const staleOwnership =
    !currentRevision || currentRevision !== expectedOwnershipRevision
  const exactNameConfirmed = confirmLabel === interfaceName
  const candidate = projection?.delete_candidate === true
  const sending = submission.status === "sending"
  const canSubmit =
    candidate &&
    !staleOwnership &&
    exactNameConfirmed &&
    externalWriterAccepted &&
    globalSaveAcknowledged &&
    submission.status === "idle"

  useEffect(() => {
    if (!open) return
    setConfirmLabel("")
    setExternalWriterAccepted(false)
    setGlobalSaveAcknowledged(false)
    setSubmission({ status: "idle" })
  }, [expectedOwnershipRevision, interfaceName, open])

  const close = () => {
    if (sending) return
    onOpenChange(false)
  }

  const submit = async () => {
    if (!canSubmit || !nativeInterface) return
    setSubmission({ status: "sending" })
    try {
      const leaseResult = await runWithNativeMutationLease<DeleteLeaseValue>(
        "delete",
        async () => {
          try {
            const result = await postNdmsNativeDeleteOnce({
              interface_name: interfaceName,
              expected_ownership_revision: expectedOwnershipRevision,
              confirm_label: interfaceName,
            })
            if (result.status === "save_acknowledged_unverified") {
              return {
                disposition: { state: "clear" } as const,
                value: { status: "terminal", result } as const,
              }
            }
            if (result.status === "recovery_required") {
              return {
                disposition: {
                  state: "recovery",
                  recovery: "delete",
                } as const,
                value: { status: "recovery_required" } as const,
              }
            }

            // The strict parser accepts a blocked initial delete only when
            // this invocation has no dispatch/save trace or durable claim.
            return {
              disposition: { state: "clear" } as const,
              value: { status: "blocked", result } as const,
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

      if (leaseResult.status !== "completed") {
        setSubmission({ status: "unknown" })
      } else if (leaseResult.value.status === "terminal") {
        onTerminal(leaseResult.value.result)
        onOpenChange(false)
      } else {
        setSubmission(leaseResult.value)
      }
    } finally {
      await onInventoryRefresh().catch(() => undefined)
    }
  }

  return (
    <Dialog onOpenChange={close} open={open}>
      <DialogContent className="max-sm:top-auto max-sm:bottom-0 max-sm:left-0 max-sm:max-h-[calc(100dvh-0.75rem)] max-sm:max-w-none max-sm:translate-x-0 max-sm:translate-y-0 max-sm:rounded-b-none max-sm:border-x-0 max-sm:border-b-0 sm:max-w-xl">
        <DialogHeader>
          <DialogTitle className="flex min-w-0 items-center gap-2 break-words">
            <AlertTriangleIcon className="size-5 shrink-0 text-destructive" />
            {t("transports.nativeMutation.deleteDialog.title")}
          </DialogTitle>
          <DialogDescription className="break-words">
            {t("transports.nativeMutation.deleteDialog.description", {
              name: interfaceName,
            })}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="rounded-lg border bg-muted/30 p-3 text-sm">
            <p className="font-medium break-all">{interfaceName}</p>
            <p className="mt-1 break-words text-muted-foreground">
              {t("transports.nativeMutation.deleteDialog.globalSaveWarning")}
            </p>
          </div>

          {staleOwnership || !candidate ? (
            <Alert variant="warning" aria-live="polite">
              <AlertTriangleIcon />
              <AlertTitle>
                {t("transports.nativeMutation.deleteDialog.staleTitle")}
              </AlertTitle>
              <AlertDescription className="break-words">
                {t("transports.nativeMutation.deleteDialog.staleDescription")}
              </AlertDescription>
            </Alert>
          ) : null}

          <div className="space-y-2">
            <label
              className="block text-sm font-medium break-words"
              htmlFor="native-delete-confirm-label"
            >
              {t("transports.nativeMutation.deleteDialog.typeName", {
                name: interfaceName,
              })}
            </label>
            <Input
              aria-describedby="native-delete-confirm-help"
              autoComplete="off"
              autoFocus
              className="h-11"
              disabled={sending || staleOwnership || !candidate}
              id="native-delete-confirm-label"
              onChange={(event) => setConfirmLabel(event.target.value)}
              spellCheck={false}
              value={confirmLabel}
            />
            <p
              className="text-xs break-words text-muted-foreground"
              id="native-delete-confirm-help"
            >
              {t("transports.nativeMutation.deleteDialog.exactNameHelp")}
            </p>
          </div>

          <label className="flex min-h-11 cursor-pointer items-start gap-3 rounded-md p-1 text-sm">
            <input
              checked={externalWriterAccepted}
              className="mt-0.5 size-5 shrink-0 accent-primary"
              disabled={sending || staleOwnership || !candidate}
              onChange={(event) =>
                setExternalWriterAccepted(event.target.checked)
              }
              type="checkbox"
            />
            <span className="min-w-0 break-words">
              {t("transports.nativeMutation.acknowledgements.externalWriter")}
            </span>
          </label>

          <label className="flex min-h-11 cursor-pointer items-start gap-3 rounded-md p-1 text-sm">
            <input
              checked={globalSaveAcknowledged}
              className="mt-0.5 size-5 shrink-0 accent-primary"
              disabled={sending || staleOwnership || !candidate}
              onChange={(event) =>
                setGlobalSaveAcknowledged(event.target.checked)
              }
              type="checkbox"
            />
            <span className="min-w-0 break-words">
              {t("transports.nativeMutation.acknowledgements.globalSave")}
            </span>
          </label>

          <div aria-atomic="true" aria-live="polite">
            {submission.status === "blocked" ||
            submission.status === "rejected" ? (
              <Alert variant="warning">
                <AlertTitle>
                  {t("transports.nativeMutation.deleteDialog.blockedTitle")}
                </AlertTitle>
                <AlertDescription className="break-words">
                  {t(
                    "transports.nativeMutation.deleteDialog.blockedDescription"
                  )}
                </AlertDescription>
              </Alert>
            ) : submission.status === "recovery_required" ? (
              <Alert variant="warning">
                <AlertTitle>
                  {t("transports.nativeMutation.recovery.deleteTitle")}
                </AlertTitle>
                <AlertDescription>
                  {t("transports.nativeMutation.deleteDialog.recoveryLatched")}
                </AlertDescription>
              </Alert>
            ) : submission.status === "unknown" ? (
              <Alert variant="destructive">
                <AlertTitle>
                  {t("transports.nativeMutation.recovery.unknownTitle")}
                </AlertTitle>
                <AlertDescription>
                  {t("transports.nativeMutation.recovery.unknownDescription")}
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
              ? t("transports.nativeMutation.deleteDialog.deleting")
              : t("transports.nativeMutation.deleteDialog.delete")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
