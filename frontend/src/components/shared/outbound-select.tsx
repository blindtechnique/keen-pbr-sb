import { useMemo } from "react"
import { useTranslation } from "react-i18next"

import type { Outbound } from "@/api/generated/model/outbound"
import type { RuntimeOutboundState } from "@/api/generated/model/runtimeOutboundState"
import { useGetRuntimeOutbounds } from "@/api/queries"
import { RuntimeOutboundStatusLabel } from "@/components/shared/runtime-outbound-state"
import { Badge } from "@/components/ui/badge"
import {
  getOutboundSelectDisplayName,
  getOutboundSelectReferenceLabel,
  sortOutboundsByDisplayName,
} from "@/lib/outbound-display"
import { useInterfaceDisplayNames } from "@/hooks/use-interface-display-names"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"

type OutboundSelectProps = {
  value: string
  onValueChange: (value: string) => void
  outbounds: Outbound[]
  allowEmpty?: boolean
  emptyLabel?: string
  placeholder?: string
  groupLabel?: string
  ariaInvalid?: boolean
  disabled?: boolean
}

export function OutboundSelect({
  value,
  onValueChange,
  outbounds,
  allowEmpty = false,
  emptyLabel,
  placeholder,
  groupLabel,
  ariaInvalid,
  disabled,
}: OutboundSelectProps) {
  const { t } = useTranslation()
  const { labelFor: interfaceLabelFor } = useInterfaceDisplayNames()
  const runtimeOutboundsQuery = useGetRuntimeOutbounds()

  const runtimeOutboundsByTag = useMemo(
    () =>
      new Map(
        (runtimeOutboundsQuery.data?.status === 200
          ? runtimeOutboundsQuery.data.data.outbounds
          : []
        ).map((runtimeOutbound) => [runtimeOutbound.tag, runtimeOutbound])
      ),
    [runtimeOutboundsQuery.data]
  )

  const selectedValue = value || null
  const resolvedEmptyLabel =
    emptyLabel ?? t("pages.dnsServerUpsert.fields.detourEmpty")
  const resolvedPlaceholder =
    placeholder ?? t("pages.routingRuleUpsert.fields.selectOutbound")
  const resolvedGroupLabel =
    groupLabel ?? t("pages.routingRuleUpsert.fields.configuredOutbounds")
  const outboundByTag = useMemo(
    () => new Map(outbounds.map((outbound) => [outbound.tag, outbound])),
    [outbounds]
  )
  const sortedOutbounds = useMemo(
    () => sortOutboundsByDisplayName(outbounds),
    [outbounds]
  )

  return (
    <Select
      disabled={disabled}
      onValueChange={(nextValue) => onValueChange(nextValue ?? "")}
      value={selectedValue}
    >
      <SelectTrigger aria-invalid={ariaInvalid}>
        <SelectValue placeholder={resolvedPlaceholder}>
          {(selected) => {
            if (!selected) {
              return allowEmpty ? resolvedEmptyLabel : resolvedPlaceholder
            }

            const selectedOutbound = outboundByTag.get(selected) ?? {
              tag: selected,
              type: "interface" as const,
            }

            return (
              <span
                className="min-w-0"
                title={getOutboundSelectReferenceLabel(
                  selectedOutbound,
                  interfaceLabelFor
                )}
              >
                <RuntimeOutboundStatusLabel
                  runtimeState={runtimeOutboundsByTag.get(selected)}
                  t={t}
                  title={getOutboundSelectDisplayName(
                    selectedOutbound,
                    interfaceLabelFor
                  )}
                />
              </span>
            )
          }}
        </SelectValue>
      </SelectTrigger>
      <SelectContent>
        <SelectGroup>
          <SelectLabel>{resolvedGroupLabel}</SelectLabel>
          {allowEmpty ? (
            <SelectItem value={null}>
              <span className="text-muted-foreground">
                {resolvedEmptyLabel}
              </span>
            </SelectItem>
          ) : null}
          {sortedOutbounds.map((outbound) => (
            <SelectItem key={outbound.tag} value={outbound.tag}>
              <OutboundSelectOption
                outbound={outbound}
                interfaceLabelFor={interfaceLabelFor}
                runtimeState={runtimeOutboundsByTag.get(outbound.tag)}
                t={t}
              />
            </SelectItem>
          ))}
        </SelectGroup>
      </SelectContent>
    </Select>
  )
}

function OutboundSelectOption({
  outbound,
  interfaceLabelFor,
  runtimeState,
  t,
}: {
  outbound: Outbound
  interfaceLabelFor: (interfaceName: string) => string
  runtimeState?: RuntimeOutboundState
  t: (key: string, options?: Record<string, unknown>) => string
}) {
  const displayName = getOutboundSelectDisplayName(outbound, interfaceLabelFor)

  return (
    <div
      className="flex min-w-0 items-center justify-between gap-3"
      title={getOutboundSelectReferenceLabel(outbound, interfaceLabelFor)}
    >
      <RuntimeOutboundStatusLabel
        runtimeState={runtimeState}
        t={t}
        title={displayName}
      />
      {displayName !== outbound.tag ? (
        <span className="truncate font-mono text-xs text-muted-foreground">
          {outbound.tag}
        </span>
      ) : null}
      <span className="flex shrink-0 items-center gap-2">
        <Badge size="xs" variant="outline">
          {outbound.type}
        </Badge>
      </span>
    </div>
  )
}
