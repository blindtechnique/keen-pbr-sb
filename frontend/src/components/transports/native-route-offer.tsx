import { WorkflowIcon } from "lucide-react"
import { useTranslation } from "react-i18next"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import type { NativeRouteOfferCandidate } from "@/lib/native-route-offers"

/**
 * Вопрос «использовать новый туннель как VPN?» — по одному на каждый
 * клиентский туннель KeeneticOS без маршрута. «Создать маршрут» сразу
 * создаёт привязку в черновике конфигурации; «Не предлагать» убирает
 * вопрос для этого интерфейса, сам туннель остаётся в таблице.
 */
export function NativeRouteOffer({
  candidates,
  disabled = false,
  onCreate,
  onDismiss,
}: {
  readonly candidates: readonly NativeRouteOfferCandidate[]
  readonly disabled?: boolean
  readonly onCreate: (candidate: NativeRouteOfferCandidate) => void
  readonly onDismiss: (candidate: NativeRouteOfferCandidate) => void
}) {
  const { t } = useTranslation()

  if (candidates.length === 0) {
    return null
  }

  return (
    <Alert>
      <WorkflowIcon className="size-4" />
      <AlertTitle>{t("transports.routeOffer.title")}</AlertTitle>
      <AlertDescription className="space-y-3">
        {candidates.map((candidate) => (
          <div className="space-y-2" key={candidate.id}>
            <p>
              {t("transports.routeOffer.question", {
                name: candidate.label,
              })}
            </p>
            <div className="flex flex-wrap gap-2">
              <Button
                disabled={disabled}
                onClick={() => onCreate(candidate)}
                size="sm"
              >
                {t("transports.routeOffer.create")}
              </Button>
              <Button
                disabled={disabled}
                onClick={() => onDismiss(candidate)}
                size="sm"
                variant="outline"
              >
                {t("transports.routeOffer.dismiss")}
              </Button>
            </div>
          </div>
        ))}
      </AlertDescription>
    </Alert>
  )
}
