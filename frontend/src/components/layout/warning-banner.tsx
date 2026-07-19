import { useLayoutEffect, useRef } from "react"
import { SaveIcon } from "lucide-react"
import { useTranslation } from "react-i18next"

import {
  useApplyConfigMutation,
  usePostServiceActionMutation,
} from "@/api/mutations"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import type {
  WarningBannerMode,
  WarningBannerState,
} from "@/components/layout/warning-banner-state"

export function WarningBanner({
  className,
  state,
}: {
  className?: string
  state: WarningBannerState
}) {
  const { t } = useTranslation()
  const applyConfigMutation = useApplyConfigMutation()
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
  const isError = state.mode === "dnsmasq-error"
  const handleApplyAndReload = () => {
    if (state.hasDraftConfig) {
      applyConfigMutation.mutate()
      return
    }

    restartServiceMutation.mutate()
  }

  return (
    // Sits under the system bar instead of floating above the page: the old
    // fixed footer covered action buttons at the bottom of long forms.
    <div
      ref={containerRef}
      className={cn(
        "sticky top-0 z-30 border-b md:top-16",
        "bg-card/95 backdrop-blur-md",
        isError
          ? "border-destructive/40"
          : isConverging
            ? "border-primary/30"
            : "border-warning/50",
        className
      )}
    >
      <div className="mx-auto flex max-w-[92rem] flex-col gap-2 px-4 py-2 sm:px-6 lg:px-8">
        <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
          <div className="min-w-0">
            <p className="text-[13px] leading-5 font-medium text-foreground">
              {t(getWarningBannerTitleKey(state.mode))}
            </p>
            <p className="text-[12px] leading-4 text-muted-foreground">
              {t(getWarningBannerDescriptionKey(state.mode))}
            </p>
          </div>

          {!isConverging ? (
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
        </div>

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
    case "hidden":
      return "warning.compact.keenRestartRequiredDescription"
  }
}
