import type { Outbound } from "@/api/generated/model/outbound"
import { MultiSelectList } from "@/components/shared/multi-select-list"
import { OutboundSelect } from "@/components/shared/outbound-select"
import {
  Field,
  FieldContent,
  FieldHint,
  FieldLabel,
} from "@/components/shared/field"
import {
  getListRefreshCapableOutbounds,
  type ListRefreshRouteChain,
} from "@/lib/list-refresh-route"
import {
  getOutboundDisplayName,
  getOutboundReferenceLabel,
} from "@/lib/outbound-display"
import { useMemo, type ReactNode } from "react"
import { useTranslation } from "react-i18next"

export function ListRefreshRouteFields({
  chain,
  detourError,
  detourFieldName,
  fallbackError,
  fallbackFieldName,
  fieldWidth = "full",
  addControlSize = "sm",
  onChange,
  outbounds,
  primaryEmptyLabel,
}: {
  /** «Настройки» показывают эти поля компактными, редактор списка — во всю ширину. */
  fieldWidth?: "full" | "short"
  addControlSize?: "sm" | "default"
  chain: ListRefreshRouteChain
  detourError?: ReactNode
  detourFieldName?: string
  fallbackError?: ReactNode
  fallbackFieldName?: string
  onChange: (chain: ListRefreshRouteChain) => void
  outbounds: readonly Outbound[]
  primaryEmptyLabel?: string
}) {
  const { t } = useTranslation()
  const refreshOutbounds = useMemo(
    () => getListRefreshCapableOutbounds(outbounds),
    [outbounds]
  )
  const outboundByTag = useMemo(
    () => new Map(refreshOutbounds.map((outbound) => [outbound.tag, outbound])),
    [refreshOutbounds]
  )

  return (
    <>
      <Field invalid={Boolean(detourError)} width={fieldWidth}>
        <FieldLabel>{t("common.listRefreshRoute.primary")}</FieldLabel>
        <FieldContent data-field-name={detourFieldName}>
          <OutboundSelect
            allowEmpty
            ariaInvalid={Boolean(detourError)}
            emptyLabel={
              primaryEmptyLabel ?? t("common.listRefreshRoute.primaryEmpty")
            }
            onValueChange={(detour) =>
              onChange({
                detour,
                fallbackDetours: detour
                  ? chain.fallbackDetours.filter(
                      (fallback) => fallback !== detour
                    )
                  : [],
              })
            }
            outbounds={refreshOutbounds}
            placeholder={t("common.listRefreshRoute.primaryPlaceholder")}
            value={chain.detour}
          />
          <FieldHint
            description={t("common.listRefreshRoute.primaryHint")}
            error={detourError}
          />
        </FieldContent>
      </Field>

      {chain.detour ? (
        <Field invalid={Boolean(fallbackError)} width={fieldWidth}>
          <FieldLabel>{t("common.listRefreshRoute.fallbacks")}</FieldLabel>
          <FieldContent>
            <MultiSelectList
              addControlSize={addControlSize}
              addLabel={t("common.listRefreshRoute.addFallback")}
              allowReorder
              emptyMessage={t("common.listRefreshRoute.noFallbacks")}
              fullWidthAdd={fieldWidth === "short"}
              getSearchText={(tag) => {
                const outbound = outboundByTag.get(tag)
                return outbound ? getOutboundReferenceLabel(outbound) : tag
              }}
              limitMessage={t("common.listRefreshRoute.fallbackLimit")}
              maxItems={3}
              name={fallbackFieldName}
              onChange={(fallbackDetours) =>
                onChange({ ...chain, fallbackDetours })
              }
              options={refreshOutbounds.map((outbound) => outbound.tag)}
              placeholderDescription={t(
                "common.listRefreshRoute.fallbackPlaceholderDescription"
              )}
              placeholderTitle={t(
                "common.listRefreshRoute.fallbackPlaceholder"
              )}
              renderItem={(tag) => {
                const outbound = outboundByTag.get(tag)
                return outbound ? getOutboundDisplayName(outbound) : tag
              }}
              unavailable={[chain.detour]}
              value={chain.fallbackDetours}
            />
            <FieldHint
              description={t("common.listRefreshRoute.fallbackHint")}
              error={fallbackError}
            />
          </FieldContent>
        </Field>
      ) : null}
    </>
  )
}
