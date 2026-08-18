import { DownloadIcon, Loader2Icon } from "lucide-react"
import { useEffect, useState } from "react"
import { useMutation } from "@tanstack/react-query"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import type { ApiError } from "@/api/client"
import {
  postSingBoxInstall,
  useGetSingBoxInstallCapability,
} from "@/api/generated/keen-api"
import type { SingBoxInstallResult } from "@/api/generated/model"
import {
  subscribeSingBoxInstall,
  type SingBoxInstallState,
} from "@/api/sing-box-install-events"
import { getApiErrorMessage } from "@/lib/api-errors"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import {
  singBoxDownloadLabel,
  singBoxInstallBlockerKey,
  singBoxInstallButton,
  singBoxInstallFailureTitleKey,
  singBoxInstallLeftDown,
  singBoxInstallMayHaveApplied,
  singBoxInstallOutcomeKey,
  singBoxInstallPhaseKey,
  singBoxInstallRefusedBlockers,
  singBoxInstallResultTone,
  singBoxInstallStagedVersion,
  singBoxInstallVerdictKey,
} from "@/components/transports/sing-box-install-model"

function useSingBoxInstallState() {
  const [state, setState] = useState<SingBoxInstallState>({
    progress: null,
    lastOutcome: null,
  })
  useEffect(() => subscribeSingBoxInstall(setState), [])
  return state
}

/**
 * The single control for the sing-box binary every transport runs on.
 *
 * It is one button rather than a card or a menu entry because sing-box is not
 * something an operator manages - it is a dependency that is either there and
 * current, or not. The button knows which, says so in one short sentence, and
 * is disabled with a reason rather than hidden when there is nothing to do.
 */
export function SingBoxInstallButton({
  size,
  variant,
}: {
  size?: "sm" | "default"
  variant?: "default" | "outline" | "secondary"
}) {
  const { t } = useTranslation()
  const capabilityQuery = useGetSingBoxInstallCapability()
  const capability =
    capabilityQuery.data?.status === 200 ? capabilityQuery.data.data : undefined
  const [confirming, setConfirming] = useState(false)

  // The stream, not this component's own mutation state, is the authority for
  // "an install is running". The daemon does not stop installing because a tab
  // closed, so a second tab - or this one after a reload - has to learn it
  // from the stream.
  const { progress, lastOutcome } = useSingBoxInstallState()
  const installing = progress?.active === true

  const install = useMutation({
    mutationFn: async (stopRunningTransports: boolean) => {
      const response = await postSingBoxInstall({
        stop_running_transports: stopRunningTransports,
      })
      return response.status === 200 ? response.data : null
    },
    onSuccess: (data) => {
      void capabilityQuery.refetch()
      if (!data) return
      report(data)
    },
    onError: (error: ApiError) => {
      void capabilityQuery.refetch()
      const refused = singBoxInstallRefusedBlockers(error.details)
      const title = t(singBoxInstallFailureTitleKey(refused.length))
      const detail =
        refused.length > 0
          ? refused.map((blocker) => t(singBoxInstallBlockerKey(blocker)))
          : [getApiErrorMessage(error)]
      if (singBoxInstallMayHaveApplied(refused.length, lastOutcome)) {
        // The daemon verifies its lease AFTER the swap, so this error can
        // arrive on an install that in fact completed. Saying it never started
        // would leave the operator believing their transports still run the
        // old binary.
        detail.push(t("transports.singBoxInstall.mayHaveApplied"))
      }
      toast.error(title, { description: detail.join(" ") })
    },
  })

  const report = (result: SingBoxInstallResult) => {
    const tone = singBoxInstallResultTone(result.install_outcome)
    const message = t(singBoxInstallOutcomeKey(result.install_outcome))

    // Everything the operator needs to act on, in the order they need it.
    const lines: string[] = []
    const verdictKey = singBoxInstallVerdictKey(result)
    // Why the release was refused, when the outcome alone does not say -
    // "no checksums published" and "the digest did not match" are different
    // problems with different answers.
    if (verdictKey) lines.push(t(verdictKey))
    const staged = singBoxInstallStagedVersion(result)
    if (staged) {
      lines.push(
        t("transports.singBoxInstall.stagedVersion", { version: staged })
      )
    }
    // A tunnel that did not come back is the operator's problem to fix and
    // theirs alone, so it is said out loud rather than folded into the outcome.
    const leftDown = singBoxInstallLeftDown(result)
    if (leftDown.length > 0) {
      lines.push(
        t("transports.singBoxInstall.leftDown", { tags: leftDown.join(", ") })
      )
    }
    const description = lines.length > 0 ? lines.join(" ") : undefined
    if (tone === "success") toast.success(message, { description })
    else if (tone === "info") toast.info(message, { description })
    else if (tone === "warning") toast.warning(message, { description })
    else toast.error(message, { description })
  }

  const state = singBoxInstallButton(capability, installing, install.isPending)
  const phaseKey = progress ? singBoxInstallPhaseKey(progress.phase) : null

  // Nothing measured and nothing to say. Not an error message: an operator who
  // never asked about sing-box should not be told the capability read failed.
  // isLoadingError, not isError: react-query reports an error on a background
  // refetch while keeping the data it already has. Unmounting on that would
  // make the whole control vanish mid-install - the refetch fires on window
  // focus, and a daemon busy installing is exactly the one that answers 503.
  // The operator would tab back to no button, no phase, and nothing saying an
  // install is running.
  if (capabilityQuery.isLoadingError) return null

  const start = () => {
    if (state.needsConsent) {
      setConfirming(true)
      return
    }
    install.mutate(false)
  }

  // The phase, plus how far the download has got when there is a download and
  // the daemon has seen bytes. Percentage only when the server said how big
  // the body is; otherwise how much has arrived, because a chunked response
  // has no denominator and inventing one would show every such download as
  // finished.
  const download = progress
    ? singBoxDownloadLabel(progress.receivedBytes, progress.totalBytes)
    : null
  const phaseLabel = installing
    ? phaseKey
      ? t(phaseKey)
      : t("transports.singBoxInstall.runningPlain")
    : t(state.labelKey)
  const label =
    installing && download
      ? download.kind === "percent"
        ? `${phaseLabel} ${download.percent}%`
        : t("transports.singBoxInstall.received", {
            megabytes: download.megabytes,
          })
      : phaseLabel

  return (
    <>
      <Tooltip>
        <TooltipTrigger
          render={
            <span className="inline-flex">
              {/* Wrapped, because a disabled button fires no pointer events -
                  and the tooltip on a disabled control is the one an operator
                  needs most: it says why they cannot press it. */}
              <Button
                disabled={!state.enabled}
                onClick={start}
                size={size}
                type="button"
                variant={variant}
              >
                {installing || install.isPending ? (
                  <Loader2Icon className="animate-spin" />
                ) : (
                  <DownloadIcon />
                )}
                {label}
              </Button>
            </span>
          }
        />
        <TooltipContent>{t(state.tooltipKey)}</TooltipContent>
      </Tooltip>

      <Dialog onOpenChange={setConfirming} open={confirming}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>
              {t("transports.singBoxInstall.consentTitle")}
            </DialogTitle>
            <DialogDescription>
              {t("transports.singBoxInstall.consentBody", {
                count: capability?.running_transports ?? 0,
              })}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button onClick={() => setConfirming(false)} variant="outline">
              {t("common.cancel")}
            </Button>
            <Button
              onClick={() => {
                setConfirming(false)
                install.mutate(true)
              }}
            >
              {t("transports.singBoxInstall.consentConfirm")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
