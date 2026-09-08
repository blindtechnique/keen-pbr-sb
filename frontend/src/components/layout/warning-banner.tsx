import { useEffect, useLayoutEffect, useMemo, useRef } from "react"
import { RotateCcwIcon, SaveIcon } from "lucide-react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import { Link, useLocation } from "wouter"

import {
  useApplyConfigMutation,
  useDiscardConfigMutation,
  usePostServiceActionMutation,
} from "@/api/mutations"
import { useGetConfig } from "@/api/queries"
import { selectConfig } from "@/api/selectors"
import {
  compareConfigEffects,
  configFailureDestination,
  confirmedConfigApply,
  summarizeConfigEffects,
} from "@/lib/config-apply-guidance"
import { PostApplyDescription } from "@/components/layout/post-apply-feedback"
import { OperationErrorMessage } from "@/components/shared/operation-error-message"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import type {
  WarningBannerMode,
  WarningBannerState,
} from "@/components/layout/warning-banner-state"
import { getWarningBannerDraftActions } from "@/components/layout/warning-banner-state"

export function WarningBanner({
  className,
  state,
}: {
  className?: string
  state: WarningBannerState
}) {
  const { t } = useTranslation()
  const [, navigate] = useLocation()
  const configQuery = useGetConfig()
  const visibleConfig = selectConfig(configQuery.data)
  const visibleEffects = useMemo(
    () =>
      visibleConfig && !configQuery.isError
        ? summarizeConfigEffects(visibleConfig)
        : undefined,
    [visibleConfig, configQuery.isError]
  )
  const activeEffects = useRef<
    ReturnType<typeof summarizeConfigEffects> | undefined
  >(undefined)
  useEffect(() => {
    if (
      configQuery.data?.status === 200 &&
      !configQuery.data.data.is_draft &&
      visibleEffects
    ) {
      activeEffects.current = visibleEffects
    }
  }, [configQuery.data, visibleEffects])

  const applyConfigMutation = useApplyConfigMutation({
    mutation: {
      onError: (error) => {
        const destination = configFailureDestination(error)
        toast.error(<OperationErrorMessage error={error} />, {
          richColors: true,
          ...(destination
            ? {
                action: {
                  label: t("postApply.openDiagnostics"),
                  onClick: () => navigate(`/?section=${destination}`),
                },
              }
            : {}),
        })
      },
    },
  })
  const discardConfigMutation = useDiscardConfigMutation({
    mutation: {
      onError: (error) => {
        toast.error(<OperationErrorMessage error={error} />, {
          richColors: true,
        })
      },
    },
  })
  const restartServiceMutation = usePostServiceActionMutation("restart")
  const containerRef = useRef<HTMLDivElement>(null)

  useLayoutEffect(() => {
    const rootStyle = document.documentElement.style

    if (!state.isVisible) {
      rootStyle.setProperty("--warning-banner-height", "0px")
      return
    }

    const element = containerRef.current

    if (!element) {
      return
    }

    const updateHeight = () => {
      rootStyle.setProperty(
        "--warning-banner-height",
        `${element.getBoundingClientRect().height}px`
      )
    }

    updateHeight()

    const resizeObserver = new ResizeObserver(updateHeight)
    resizeObserver.observe(element)

    return () => {
      resizeObserver.disconnect()
      rootStyle.setProperty("--warning-banner-height", "0px")
    }
  }, [state.isVisible])

  if (!state.isVisible) {
    return null
  }

  const isConverging = state.mode === "dnsmasq-converging"
  const isLifecycle = state.mode.startsWith("lifecycle-")
  const isError =
    state.mode === "dnsmasq-error" || state.mode === "lifecycle-error"
  const { canResolveDraft, canApplyOrRestart } = getWarningBannerDraftActions(
    state.mode,
    state.hasDraftConfig
  )
  const handleApplyAndReload = () => {
    if (state.hasDraftConfig) {
      // Capture only the effect category at the click: invalidation may replace
      // the cached candidate before the callback. Never retain the config body.
      const impact = compareConfigEffects(activeEffects.current, visibleEffects)
      applyConfigMutation.mutate(undefined, {
        onSuccess: (response) => {
          if (!confirmedConfigApply(response)) return
          const checkRelevant = impact !== "none" && impact !== "unknown"
          toast.success(t("postApply.applied"), {
            richColors: true,
            ...(checkRelevant
              ? {
                  description: <PostApplyDescription impact={impact} />,
                  duration: 10_000,
                  action: {
                    label: t("postApply.checkSite"),
                    onClick: () => navigate("/?check=1"),
                  },
                }
              : {}),
          })
        },
      })
      return
    }

    restartServiceMutation.mutate()
  }

  return (
    // NDMS pins this to the bottom of the window, not the top:
    // .ndw-save-pattern--page-container { position: fixed; bottom: 0 }
    // with min-height 64px and a plain --background fill. Fixed at the bottom
    // it cannot push the page, cannot scroll away, and cannot move the menu.
    <div
      ref={containerRef}
      className={cn(
        "fixed inset-x-0 bottom-0 z-20 min-h-16 border-t md:left-(--sidebar-offset)",
        "bg-card",
        isError
          ? "border-destructive/40"
          : isConverging
            ? "border-primary/30"
            : "border-warning/50",
        className
      )}
    >
      <div className="flex min-h-16 flex-col justify-center gap-2 px-4 py-3 sm:px-6 lg:px-8">
        <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
          <div className="min-w-0">
            <p className="text-[13px] leading-5 font-medium text-foreground">
              {t(getWarningBannerTitleKey(state.mode))}
            </p>
            <p className="text-[12px] leading-4 text-muted-foreground">
              {t(getWarningBannerDescriptionKey(state.mode))}
            </p>
            {state.mode === "lifecycle-error" && state.operationError ? (
              <div className="mt-1 text-[12px] leading-4 text-destructive">
                <OperationErrorMessage error={state.operationError} />
              </div>
            ) : null}
          </div>

          <div className="flex shrink-0 flex-wrap gap-2">
            {canResolveDraft ? (
              <Button
                disabled={state.isActionDisabled}
                onClick={() => discardConfigMutation.mutate()}
                size="sm"
                variant="outline"
                className="shrink-0"
              >
                <RotateCcwIcon className="mr-1 h-4 w-4" />
                {discardConfigMutation.isPending
                  ? t("warning.actions.discarding")
                  : t("warning.actions.discard")}
              </Button>
            ) : null}
            {canApplyOrRestart ? (
              <Button
                disabled={state.isActionDisabled}
                onClick={handleApplyAndReload}
                size="sm"
                className="shrink-0"
              >
                <SaveIcon className="mr-1 h-4 w-4" />
                {state.actionPending
                  ? t("warning.actions.applyingAndRestarting")
                  : t("warning.actions.applyAndRestart")}
              </Button>
            ) : null}
            {isError ? (
              <Button
                render={
                  <Link
                    href={
                      state.mode === "dnsmasq-error"
                        ? "/?section=dns"
                        : "/?section=routing"
                    }
                  />
                }
                size="sm"
                variant="outline"
              >
                {t("postApply.openDiagnostics")}
              </Button>
            ) : null}
            {state.mode === "lifecycle-error" ? (
              <Button
                onClick={state.dismissFailure}
                size="sm"
                variant="outline"
                className="shrink-0"
              >
                {t("lifecycle.dismiss")}
              </Button>
            ) : null}
          </div>
        </div>

        {isLifecycle && state.operationSteps.length > 0 ? (
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-[12px] leading-4">
            {state.operationSteps.map((step) => (
              <span
                key={step.id}
                className={cn(
                  "inline-flex items-center gap-1.5",
                  step.status === "failed"
                    ? "text-destructive"
                    : step.status === "succeeded"
                      ? "text-success"
                      : step.status === "running"
                        ? "text-primary"
                        : "text-muted-foreground"
                )}
              >
                <span
                  className={cn(
                    "h-1.5 w-1.5 rounded-full bg-current",
                    step.status === "running" && "animate-pulse"
                  )}
                />
                {step.title}
              </span>
            ))}
          </div>
        ) : null}

        {isConverging ? (
          <div className="h-1.5 rounded bg-muted">
            <div
              className="h-1.5 rounded bg-primary transition-[width] duration-700"
              style={{ width: `${state.progressPercent}%` }}
            />
          </div>
        ) : null}
      </div>
    </div>
  )
}

function getWarningBannerTitleKey(mode: WarningBannerMode) {
  switch (mode) {
    case "draft":
      return "warning.compact.keenRestartRequired"
    case "draft-and-dnsmasq":
      return "warning.compact.keenAndDnsmasqRestartRequired"
    case "dnsmasq-stale":
      return "warning.compact.dnsmasqRestartRequired"
    case "dnsmasq-converging":
      return "warning.compact.dnsmasqRestarting"
    case "dnsmasq-error":
      return "warning.compact.dnsmasqUnavailable"
    case "lifecycle-running":
      return "lifecycle.running"
    case "lifecycle-success":
      return "lifecycle.success"
    case "lifecycle-error":
      return "lifecycle.error"
    case "hidden":
      return "warning.compact.keenRestartRequired"
  }
}

function getWarningBannerDescriptionKey(mode: WarningBannerMode) {
  switch (mode) {
    case "draft":
      return "warning.compact.keenRestartRequiredDescription"
    case "draft-and-dnsmasq":
      return "warning.compact.keenAndDnsmasqRestartRequiredDescription"
    case "dnsmasq-stale":
      return "warning.compact.dnsmasqRestartRequiredDescription"
    case "dnsmasq-converging":
      return "warning.compact.dnsmasqRestartingDescription"
    case "dnsmasq-error":
      return "warning.compact.dnsmasqUnavailableDescription"
    case "lifecycle-running":
      return "lifecycle.runningDescription"
    case "lifecycle-success":
      return "lifecycle.successDescription"
    case "lifecycle-error":
      return "lifecycle.errorDescription"
    case "hidden":
      return "warning.compact.keenRestartRequiredDescription"
  }
}
