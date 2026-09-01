import { useEffect, useRef } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import {
  NativeMutationTransportError,
  postNdmsNativeDeleteOnce,
  type NdmsNativeDeleteResult,
} from "@/api/native-mutation"
import type { ApiError } from "@/api/client"
import { getApiErrorMessage } from "@/lib/api-errors"
import type { NativeInterfaceModel } from "@/lib/native-interfaces"

/**
 * The historical name is kept so the page wiring stays small, but this is no
 * longer a dialog. Selecting the row trash action starts one deletion and the
 * result is reported with a short toast. There is no second confirmation,
 * typed-name challenge, acknowledgement form, or page-level recovery UI.
 */
export function NativeInterfaceDeleteDialog({
  expectedOwnershipRevision,
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
  const activeRequest = useRef<string | undefined>(undefined)

  const interfaceName = nativeInterface?.logicalName ?? ""
  const projection = nativeInterface?.source.native_mutation
  const currentRevision = projection?.ownership_revision ?? ""
  const candidate = projection?.delete_candidate === true

  useEffect(() => {
    if (!open || !nativeInterface || !interfaceName) return

    const requestKey = `${interfaceName}:${expectedOwnershipRevision}`
    if (activeRequest.current === requestKey) return
    activeRequest.current = requestKey

    const execute = async () => {
      const toastId = toast.loading(
        t("transports.nativeMutation.deleteDialog.deleting")
      )
      let restoreLinkedRoute: (() => Promise<void>) | undefined
      try {
        if (
          !candidate ||
          !currentRevision ||
          currentRevision !== expectedOwnershipRevision
        ) {
          toast.error(
            t("transports.nativeMutation.deleteDialog.refreshAndRetry"),
            { id: toastId, richColors: true }
          )
          return
        }

        try {
          restoreLinkedRoute = await prepareLinkedRouteRemoval?.()
        } catch (error) {
          toast.error(
            t(
              "transports.nativeMutation.deleteDialog.routePreparationFailedDescription",
              { reason: getApiErrorMessage(error as ApiError) }
            ),
            { id: toastId, richColors: true }
          )
          return
        }

        try {
          const result = await postNdmsNativeDeleteOnce({
            interface_name: interfaceName,
            expected_ownership_revision: expectedOwnershipRevision,
            confirm_label: interfaceName,
          })

          if (result.status === "save_acknowledged_unverified") {
            onTerminal(result)
            toast.success(t("transports.nativeMutation.deleteDialog.deleted"), {
              id: toastId,
            })
            return
          }

          if (result.status === "recovery_required") {
            toast.info(t("transports.nativeMutation.deleteDialog.finishing"), {
              id: toastId,
            })
            return
          }

          if (restoreLinkedRoute) await restoreLinkedRoute()
          toast.error(
            t("transports.nativeMutation.deleteDialog.deleteFailed"),
            { id: toastId, richColors: true }
          )
        } catch (error) {
          if (
            error instanceof NativeMutationTransportError &&
            error.code === "rejected"
          ) {
            if (restoreLinkedRoute) await restoreLinkedRoute()
            toast.error(
              t("transports.nativeMutation.deleteDialog.deleteFailed"),
              { id: toastId, richColors: true }
            )
            return
          }

          // The request may already have reached KeeneticOS. Do not restore a
          // route onto a possibly deleted interface; the bodyless reconciler
          // and the refreshed inventory finish the operation automatically.
          toast.info(t("transports.nativeMutation.deleteDialog.finishing"), {
            id: toastId,
          })
        }
      } catch {
        toast.error(t("transports.nativeMutation.deleteDialog.deleteFailed"), {
          id: toastId,
          richColors: true,
        })
      } finally {
        await onInventoryRefresh().catch(() => undefined)
        activeRequest.current = undefined
        onOpenChange(false)
      }
    }

    void execute()
  }, [
    candidate,
    currentRevision,
    expectedOwnershipRevision,
    interfaceName,
    nativeInterface,
    onInventoryRefresh,
    onOpenChange,
    onTerminal,
    open,
    prepareLinkedRouteRemoval,
    t,
  ])

  return null
}
