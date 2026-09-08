import { useEffect, useRef, type ReactNode } from "react"
import { useTranslation } from "react-i18next"

import type { Outbound } from "@/api/generated/model/outbound"
import {
  Field,
  FieldContent,
  FieldHint,
  FieldLabel,
} from "@/components/shared/field"
import { OutboundSelect } from "@/components/shared/outbound-select"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  getRouteFailureFallbackOutbounds,
  supportsRouteFailurePolicy,
  type RouteFailurePolicy,
} from "@/lib/route-failure-policy"

export function RouteFailurePolicyFields({
  policy,
  fallbackOutbound,
  primaryOutbound,
  outbounds,
  onPolicyChange,
  onFallbackChange,
  policyError,
  fallbackError,
}: {
  policy: RouteFailurePolicy
  fallbackOutbound: string
  primaryOutbound: string
  outbounds: Outbound[]
  onPolicyChange: (policy: RouteFailurePolicy) => void
  onFallbackChange: (outbound: string) => void
  policyError?: ReactNode
  fallbackError?: ReactNode
}) {
  const { t } = useTranslation()
  const fallbackRef = useRef<HTMLDivElement>(null)
  const policyRef = useRef<HTMLDivElement>(null)
  const supported = supportsRouteFailurePolicy(outbounds, primaryOutbound)
  const hasPolicyError = Boolean(policyError)
  const hasFallbackError = Boolean(fallbackError)
  const items = [
    { value: "inherit", label: t("routeFailurePolicy.inherit") },
    { value: "block", label: t("routeFailurePolicy.block") },
    { value: "fallback", label: t("routeFailurePolicy.fallback") },
  ] satisfies { value: RouteFailurePolicy; label: string }[]
  useEffect(() => {
    if (hasPolicyError) {
      policyRef.current?.querySelector("button")?.focus()
    } else if (supported && policy === "fallback" && hasFallbackError) {
      fallbackRef.current?.querySelector("button")?.focus()
    }
  }, [hasFallbackError, hasPolicyError, policy, supported])

  return (
    <>
      <Field invalid={Boolean(policyError)} ref={policyRef}>
        <FieldLabel>{t("routeFailurePolicy.label")}</FieldLabel>
        <FieldContent>
          <Select
            disabled={!supported && policy === "inherit"}
            items={items}
            onValueChange={(value) => {
              if (
                value === "inherit" ||
                value === "block" ||
                value === "fallback"
              ) {
                onPolicyChange(value)
              }
            }}
            value={policy}
          >
            <SelectTrigger aria-invalid={Boolean(policyError)}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {items.map((item) => (
                <SelectItem
                  disabled={!supported && item.value !== "inherit"}
                  key={item.value}
                  value={item.value}
                >
                  {item.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <FieldHint
            description={
              !supported
                ? t("routeFailurePolicy.supportedPrimaryHint")
                : policy === "inherit"
                  ? t("routeFailurePolicy.inheritHint")
                  : policy === "block"
                    ? t("routeFailurePolicy.blockHint")
                    : t("routeFailurePolicy.fallbackHint")
            }
            error={policyError}
          />
        </FieldContent>
      </Field>
      {supported && policy === "fallback" ? (
        <Field invalid={Boolean(fallbackError)} ref={fallbackRef}>
          <FieldLabel>{t("routeFailurePolicy.fallbackLabel")}</FieldLabel>
          <FieldContent>
            <OutboundSelect
              ariaInvalid={Boolean(fallbackError)}
              onValueChange={onFallbackChange}
              outbounds={getRouteFailureFallbackOutbounds(
                outbounds,
                primaryOutbound
              )}
              placeholder={t("routeFailurePolicy.fallbackPlaceholder")}
              value={fallbackOutbound}
            />
            <FieldHint
              description={t("routeFailurePolicy.fallbackBothDownHint")}
              error={fallbackError}
            />
          </FieldContent>
        </Field>
      ) : null}
    </>
  )
}
