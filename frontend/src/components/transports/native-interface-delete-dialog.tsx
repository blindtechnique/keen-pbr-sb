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
import { runWithNativeMutationLease } from "@/lib/native-mutation-lock"
import type { NativeInterfaceModel } from "@/lib/native-interfaces"

type SubmissionState =
  | { readonly status: "idle" }
  | { readonly status: "sending" }
  | { readonly status: "blocked"; readonly result: NdmsNativeDeleteResult }
  | { readonly status: "preparation_failed" }
  | { readonly status: "restore_failed" }
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
          | "preparation_failed"
          | "restore_failed"
          | "rejected"
          | "recovery_required"
          | "unknown"
      }
    >

export function NativeInterfaceDeleteDialog({
  expectedOwnershipRevision,
  linkedRouteName,
  nativeInterface,
  prepareLinkedRouteRemoval,
  onInventoryRefresh,
  onOpenChange,
  onTerminal,
  open,
}: {
  readonly expectedOwnershipRevision: string
  readonly linkedRouteName?: string
  readonly nativeInterface?: NativeInterfaceModel
  readonly prepareLinkedRouteRemoval?: () => Promise<
    (() => Promise<void>) | undefined
  >
  readonly onInventoryRefresh: () => Promise<void>
  readonly onOpenChange: (open: boolean) => void
  readonly onTerminal: (result: NdmsNativeDeleteResult) => void
  readonly open: boolean
}) {
  const { t } = useTranslation()
  const [submission, setSubmission] = useState<SubmissionState>({
    status: "idle",
  })

  const interfaceName = nativeInterface?.logicalName ?? ""
  const projection = nativeInterface?.source.native_mutation
  const currentRevision = projection?.ownership_revision ?? ""
  const staleOwnership =
    !currentRevision || currentRevision !== expectedOwnershipRevision
  const candidate = projection?.delete_candidate === true
  const sending = submission.status === "sending"
  const canSubmit = candidate && !staleOwnership && submission.status === "idle"

  useEffect(() => {
    if (!open) return
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
          let restoreLinkedRoute: (() => Promise<void>) | undefined
          try {
            restoreLinkedRoute = await prepareLinkedRouteRemoval?.()
          } catch {
            return {
              disposition: { state: "clear" } as const,
              value: { status: "preparation_failed" } as const,
            }
          }

          const restoreAfterKnownRefusal = async <T extends DeleteLeaseValue>(
            value: T
          ): Promise<DeleteLeaseValue> => {
            if (!restoreLinkedRoute) return value
            try {
              await restoreLinkedRoute()
              return value
            } catch {
              return { status: "restore_failed" }
            }
          }

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
            const value = await restoreAfterKnownRefusal({
              status: "blocked",
              result,
            })
            return {
              disposition: { state: "clear" } as const,
              value,
            }
          } catch (error) {
            if (
              error instanceof NativeMutationTransportError &&
              error.code === "rejected"
            ) {
              const value = await restoreAfterKnownRefusal({
                status: "rejected",
              })
              return {
                disposition: { state: "clear" } as const,
                value,
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
            {linkedRouteName ? (
              <p className="mt-1 break-words text-muted-foreground">
                {t(
                  "transports.nativeMutation.deleteDialog.linkedRouteWarning",
                  { name: linkedRouteName }
                )}
              </p>
            ) : null}
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

          <div aria-atomic="true" aria-live="polite">
            {submission.status === "preparation_failed" ? (
              <Alert variant="destructive">
                <AlertTitle>
                  {t(
                    "transports.nativeMutation.deleteDialog.routePreparationFailedTitle"
                  )}
                </AlertTitle>
                <AlertDescription className="break-words">
                  {t(
                    "transports.nativeMutation.deleteDialog.routePreparationFailedDescription"
                  )}
                </AlertDescription>
              </Alert>
            ) : submission.status === "restore_failed" ? (
              <Alert variant="destructive">
                <AlertTitle>
                  {t(
                    "transports.nativeMutation.deleteDialog.routeRestoreFailedTitle"
                  )}
                </AlertTitle>
                <AlertDescription className="break-words">
                  {t(
                    "transports.nativeMutation.deleteDialog.routeRestoreFailedDescription"
                  )}
                </AlertDescription>
              </Alert>
            ) : submission.status === "blocked" ||
              submission.status === "rejected" ? (
              <Alert variant="warning">
                <AlertTitle>
                  {t("transports.nativeMutation.deleteDialog.blockedTitle")}
                </AlertTitle>
                <AlertDescription className="break-words">
                  {t(
                    "transports.nativeMutation.deleteDialog.blockedDescription"
                  )}
                  {submission.status === "blocked" ? (
                    <span className="mt-1 block font-mono text-xs">
                      {t(
                        "transports.nativeMutation.deleteDialog.blockedReason",
                        { reason: submission.result.stop }
                      )}
                    </span>
                  ) : null}
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
