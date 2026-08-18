import { useState } from "react"
import { useTranslation } from "react-i18next"
import { Loader2Icon, RadioIcon } from "lucide-react"

import { usePostTransportExitCheck } from "@/api/generated/keen-api"
import type { TransportExitCheckResponse } from "@/api/generated/model"
import { Button } from "@/components/ui/button"
import { KeeneticStatus } from "@/components/shared/keenetic-status"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { exitCheckSummary } from "@/components/transports/exit-check-model"

/**
 * "Проверить" for one transport: does traffic really leave through it, and
 * does the world see a different address?
 *
 * The result is deliberately not a tick or a cross. There are four things this
 * can honestly say, and the two middle ones - "answered, but we could not
 * attribute it to this transport" and "answered, but your address did not
 * change" - are the ones an operator most needs and a boolean cannot express.
 */
export function TransportExitCheckButton({
  outbound,
  device,
}: {
  outbound?: string
  // A native firmware tunnel usually has no keen-pbr outbound, and therefore
  // no routing mark. It is still measurable, because binding to its device is
  // what makes the answer attributable - so such a row names the device and
  // the check works there too.
  device?: string
}) {
  const { t } = useTranslation()
  const [result, setResult] = useState<TransportExitCheckResponse | undefined>()
  const check = usePostTransportExitCheck()

  const target = outbound
    ? { outbound }
    : device
      ? { interface: device }
      : undefined

  const run = () => {
    if (!target) return
    setResult(undefined)
    check.mutate(
      { data: target },
      {
        onSuccess: (response) => {
          if (response.status === 200) setResult(response.data)
        },
      }
    )
  }

  const summary = exitCheckSummary(result)
  const tooltipKey = target
    ? "transports.exitCheck.tip"
    : "transports.exitCheck.tipNoOutbound"

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Tooltip>
        <TooltipTrigger
          render={
            <span className="inline-flex">
              {/* Wrapped so the disabled state still explains itself. */}
              <Button
                disabled={!target || check.isPending}
                onClick={run}
                size="sm"
                type="button"
                variant="outline"
              >
                {check.isPending ? (
                  <Loader2Icon className="animate-spin" />
                ) : (
                  <RadioIcon />
                )}
                {t("transports.exitCheck.action")}
              </Button>
            </span>
          }
        />
        <TooltipContent>{t(tooltipKey)}</TooltipContent>
      </Tooltip>

      {check.isError ? (
        <KeeneticStatus tone="neutral">
          {t("transports.exitCheck.requestFailed")}
        </KeeneticStatus>
      ) : null}

      {/* Only the one unambiguous answer is green. The chip has two tones and
          this check has four outcomes, so the sentence carries the meaning -
          which is the right way round: an operator reads the words, and a
          colour that implied "fine" for an unattributable result would be the
          same lie in a different medium. */}
      {summary ? (
        <KeeneticStatus tone={summary.tone === "success" ? "success" : "neutral"}>
          {t(summary.titleKey, {
            through: summary.through ?? "",
            direct: summary.direct ?? "",
          })}
        </KeeneticStatus>
      ) : null}
    </div>
  )
}
