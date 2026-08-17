import { DownloadIcon, Loader2Icon } from "lucide-react"
import { useEffect, useState } from "react"
import { useMutation } from "@tanstack/react-query"
import { useTranslation } from "react-i18next"

import type { ApiError } from "@/api/client"
import {
  postSingBoxInstall,
  useGetSingBoxInstallCapability,
} from "@/api/generated/keen-api"
import type {
  SingBoxInstallCapabilityBlockersItem,
  SingBoxInstallResult,
} from "@/api/generated/model"
import {
  subscribeSingBoxInstall,
  type SingBoxInstallState,
} from "@/api/sing-box-install-events"
import { getApiErrorMessage } from "@/lib/api-errors"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  singBoxInstallBlockerKey,
  singBoxInstallDisplayableBlockers,
  singBoxInstallFailureTitleKey,
  singBoxInstallMayHaveApplied,
  singBoxInstallRefusedBlockers,
  singBoxInstallButtonState,
  singBoxInstallOperationKey,
  singBoxInstallOutcomeKey,
  singBoxInstallPhaseKey,
  singBoxInstallResultTone,
  singBoxInstallStagedVersion,
  singBoxInstallUnmetPromiseKeys,
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

export function SingBoxInstallCard() {
  const { t } = useTranslation()
  const capabilityQuery = useGetSingBoxInstallCapability()
  // Narrowed by status, as everywhere else in this client: the generated
  // response type is a union with the error body, and only 200 carries a
  // capability.
  const capability =
    capabilityQuery.data?.status === 200 ? capabilityQuery.data.data : undefined
  const [result, setResult] = useState<SingBoxInstallResult | null>(null)
  const [failure, setFailure] = useState<ApiError | null>(null)

  // The stream, not this component's own mutation state, is the authority for
  // "an install is running". The daemon does not stop installing because a tab
  // closed, so a second tab - or this one after a reload - has to learn it
  // from the stream or it would offer a button to start another.
  const { progress, lastOutcome } = useSingBoxInstallState()
  const running = progress?.active === true

  const install = useMutation({
    mutationFn: async () => {
      const response = await postSingBoxInstall()
      // Anything but 200 was thrown by apiFetch before reaching here; this
      // narrows the generated union rather than asserting past it.
      return response.status === 200 ? response.data : null
    },
    onMutate: () => {
      setResult(null)
      setFailure(null)
      // `lastOutcome` needs no clearing here: the daemon's first phase frame
      // for this attempt clears it, so a previous install's ending cannot be
      // read as this one's.
    },
    onSuccess: (data) => {
      setResult(data)
      // The capability is what the button reads, and the install just changed
      // the thing it measures: the installed version, and possibly whether a
      // marker exists at all.
      void capabilityQuery.refetch()
    },
    onError: (error: ApiError) => {
      setFailure(error)
      // The refusal measured the router more recently than the capability
      // query did, so what it says is now the truth about this router.
      void capabilityQuery.refetch()
    },
  })

  const button = singBoxInstallButtonState(
    capability,
    running,
    install.isPending
  )
  // An unknown phase renders the plain running text rather than its raw name:
  // a step this build has never heard of is not an explanation to show an
  // operator.
  const phaseKey = progress ? singBoxInstallPhaseKey(progress.phase) : null
  const refusedBlockers = failure
    ? singBoxInstallRefusedBlockers(failure.details)
    : []
  const capabilityBlockers = capability
    ? singBoxInstallDisplayableBlockers(capability.blockers)
    : []
  const verdictKey = result ? singBoxInstallVerdictKey(result) : null
  const stagedVersion = result ? singBoxInstallStagedVersion(result) : null
  const failureTitleKey = singBoxInstallFailureTitleKey(refusedBlockers.length)
  const mayHaveApplied = singBoxInstallMayHaveApplied(
    refusedBlockers.length,
    lastOutcome
  )

  // Nothing measurable to show and nothing to report: stay out of the way.
  // Not when there IS something to report - the install refetches the
  // capability when it finishes, and a refetch that fails must not take the
  // result of the install with it off the screen.
  if (capabilityQuery.isError && !result && !failure) return null

  return (
    <div className="rounded-lg border p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="font-medium">{t("transports.singBoxInstall.title")}</h3>
          <p className="text-muted-foreground text-sm">
            {capability
              ? t("transports.singBoxInstall.pinned", {
                  version: capability.pinned_version,
                })
              : t("transports.singBoxInstall.measuring")}
          </p>
          {capability?.installed_version ? (
            <p className="text-muted-foreground text-sm">
              {t("transports.singBoxInstall.installed", {
                version: capability.installed_version,
              })}
            </p>
          ) : null}
          {capability ? (
            <p className="text-muted-foreground text-sm">
              {t(singBoxInstallOperationKey(capability.operation))}
            </p>
          ) : null}
        </div>
        <div className="flex flex-col items-end gap-1">
          <Button
            disabled={!button.enabled}
            onClick={() => install.mutate()}
            type="button"
          >
            {running || install.isPending ? (
              <Loader2Icon className="animate-spin" />
            ) : (
              <DownloadIcon />
            )}
            {t("transports.singBoxInstall.action")}
          </Button>
          {button.disabledReasonKey ? (
            <span className="text-muted-foreground text-xs">
              {t(button.disabledReasonKey)}
            </span>
          ) : null}
        </div>
      </div>

      {running ? (
        <p className="mt-3 text-sm" role="status">
          {phaseKey ? t(phaseKey) : t("transports.singBoxInstall.runningPlain")}
        </p>
      ) : null}

      {capability && !capability.available && capabilityBlockers.length > 0 ? (
        <Alert className="mt-3" variant="default">
          <AlertTitle>{t("transports.singBoxInstall.blockedTitle")}</AlertTitle>
          <AlertDescription>
            {/* Every blocker, never just the first: an operator who fixes the
                one reason they were shown, only to be handed the next, learns
                to distrust the report. */}
            <ul className="list-disc pl-4">
              {/* Filtered like the refusal's list: a daemon newer than this
                  build can name a blocker here too, and an unnamable one would
                  print its own i18n key at the operator. */}
              {capabilityBlockers.map((blocker) => (
                <li key={blocker}>
                  {t(
                    singBoxInstallBlockerKey(
                      blocker as SingBoxInstallCapabilityBlockersItem
                    )
                  )}
                </li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      ) : null}

      {result ? (
        <Alert
          className="mt-3"
          variant={
            singBoxInstallResultTone(result.install_outcome) === "failure"
              ? "destructive"
              : "default"
          }
        >
          <AlertTitle>
            {t(singBoxInstallOutcomeKey(result.install_outcome))}
          </AlertTitle>
          <AlertDescription>
            {verdictKey ? <p>{t(verdictKey)}</p> : null}
            {stagedVersion ? (
              <p>
                {t("transports.singBoxInstall.stagedVersion", {
                  version: stagedVersion,
                })}
              </p>
            ) : null}
          </AlertDescription>
        </Alert>
      ) : null}

      {failure ? (
        <Alert className="mt-3" variant="destructive">
          <AlertTitle>{t(failureTitleKey)}</AlertTitle>
          <AlertDescription>
            {mayHaveApplied ? (
              // The daemon re-checks its maintenance lease AFTER the binary is
              // swapped, so this error can arrive on an install that in fact
              // completed. Saying it never started would leave the operator
              // believing their transports still run the old binary.
              <p>{t("transports.singBoxInstall.mayHaveApplied")}</p>
            ) : null}
            {refusedBlockers.length > 0 ? (
              // The install re-measured the router and refused. These reasons
              // are newer than the ones above, so they are the ones to act on.
              <ul className="list-disc pl-4">
                {refusedBlockers.map((blocker) => (
                  <li key={blocker}>
                    {t(
                      singBoxInstallBlockerKey(
                        blocker as SingBoxInstallCapabilityBlockersItem
                      )
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              getApiErrorMessage(failure)
            )}
          </AlertDescription>
        </Alert>
      ) : null}

      {capability ? (
        <ul className="text-muted-foreground mt-3 list-disc pl-4 text-xs">
          {/* What this build does not promise, stated where the button is
              rather than left for an operator to assume. */}
          {singBoxInstallUnmetPromiseKeys(capability).map((key) => (
            <li key={key}>{t(key)}</li>
          ))}
        </ul>
      ) : null}
    </div>
  )
}
