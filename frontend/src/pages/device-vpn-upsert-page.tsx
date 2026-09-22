import { useEffect, useState } from "react"
import { useTranslation } from "react-i18next"
import { useLocation } from "wouter"
import { toast } from "sonner"
import type { ConfigObject, RouteRule } from "@/api/generated/model"
import { useGetSystemDevices } from "@/api/generated/keen-api"
import { useGetConfig } from "@/api/queries"
import {
  useConfigMutationPending,
  usePostConfigMutation,
} from "@/api/mutations"
import { selectConfig } from "@/api/selectors"
import { useRuleEditTarget } from "@/hooks/use-rule-edit-target"
import {
  UpsertPage,
  type UpsertPagePresentation,
} from "@/components/shared/upsert-page"
import {
  useUpsertPageClose,
  useUpsertPageComplete,
} from "@/components/shared/upsert-page-context"
import { UpsertDeleteAction } from "@/components/shared/upsert-delete-action"
import { ConfigSaveErrorAlert } from "@/components/shared/config-save-error-alert"
import {
  Field,
  FieldContent,
  FieldGroup,
  FieldHint,
  FieldLabel,
} from "@/components/shared/field"
import { OutboundSelect } from "@/components/shared/outbound-select"
import { RouteFailurePolicyFields } from "@/components/shared/route-failure-policy-fields"
import { TableSkeleton } from "@/components/shared/table-skeleton"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Alert, AlertDescription } from "@/components/ui/alert"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  deviceRuleAddress,
  deviceVpnError,
  deviceVpnOutbounds,
  emptyDeviceVpnDraft,
  normalizeDeviceVpnDraft,
  removeDeviceVpnRule,
  saveDeviceVpnRule,
  toDeviceVpnDraft,
  type DeviceVpnDraft,
  type DeviceVpnError,
} from "@/lib/device-vpn"
import { areRouteRulesSemanticallyEqual } from "@/pages/routing-rules-utils"
import { semanticJsonEqual } from "@/lib/semantic-json"

export function DeviceVpnUpsertPage({
  mode,
  ruleId,
  presentation = "dialog",
}: {
  mode: "create" | "edit"
  ruleId?: string
  presentation?: UpsertPagePresentation
}) {
  const { t } = useTranslation()
  const [, navigate] = useLocation()
  const [dirty, setDirty] = useState(false)
  const query = useGetConfig()
  const config = selectConfig(query.data)
  const target = useRuleEditTarget(
    config?.route?.rules ?? [],
    mode === "edit" ? ruleId : undefined,
    Boolean(config),
    (a, b) => areRouteRulesSemanticallyEqual([a], [b])
  )
  const invalidTarget = mode === "edit" && !target.rule
  const title = t(mode === "create" ? "deviceVpn.add" : "deviceVpn.edit")
  return (
    <UpsertPage
      title={title}
      cardTitle={title}
      description={t("deviceVpn.formDescription")}
      cardDescription={t("deviceVpn.formDescription")}
      dirty={dirty}
      onClose={() => navigate("/device-vpn")}
      presentation={presentation}
      showAdvancedEditor={false}
    >
      {!config ? (
        query.isError ? (
          <Alert variant="destructive">
            <AlertDescription>
              {t("common.loadErrorDescription")}
            </AlertDescription>
          </Alert>
        ) : (
          <TableSkeleton />
        )
      ) : invalidTarget ? (
        <Alert variant="warning">
          <AlertDescription>{t("deviceVpn.errors.changed")}</AlertDescription>
        </Alert>
      ) : (
        <DeviceVpnForm
          key={mode + ":" + (ruleId ?? "new")}
          config={config}
          original={mode === "edit" ? target.rule : undefined}
          onDirtyChange={setDirty}
        />
      )}
    </UpsertPage>
  )
}

export function DeviceVpnForm({
  config,
  original,
  onDirtyChange,
}: {
  config: ConfigObject
  original?: RouteRule
  onDirtyChange: (dirty: boolean) => void
}) {
  const { t } = useTranslation()
  const close = useUpsertPageClose()
  const errors = {
    address: t("deviceVpn.errors.address"),
    name: t("deviceVpn.errors.name"),
    outbound: t("deviceVpn.errors.outbound"),
    duplicate: t("deviceVpn.errors.duplicate"),
    changed: t("deviceVpn.errors.changed"),
    fallback: t("deviceVpn.errors.fallback"),
  }
  const complete = useUpsertPageComplete()
  // Capture the edit target once, but always merge into the latest config.
  const [baselineRule] = useState(original)
  const [baseline] = useState(() =>
    baselineRule ? toDeviceVpnDraft(baselineRule) : emptyDeviceVpnDraft
  )
  const [draft, setDraft] = useState<DeviceVpnDraft>(baseline)
  const [error, setValidationCode] = useState<DeviceVpnError>()
  const [selectedDevice, setSelectedDevice] = useState<string | null>(null)
  const mutation = usePostConfigMutation()
  const pending = useConfigMutationPending()
  const inventory = useGetSystemDevices({
    query: {
      staleTime: 60_000,
      retry: false,
      refetchOnWindowFocus: false,
      refetchOnReconnect: false,
    },
  })
  const snapshot =
    inventory.data?.status === 200 ? inventory.data.data : undefined
  const devices = snapshot?.devices ?? []
  const rules = config.route?.rules ?? []
  const outbounds = deviceVpnOutbounds(config.outbounds ?? [])
  const dirty = !semanticJsonEqual(
    normalizeDeviceVpnDraft(draft),
    normalizeDeviceVpnDraft(baseline)
  )
  useEffect(() => onDirtyChange(dirty), [dirty, onDirtyChange])
  const change = <K extends keyof DeviceVpnDraft>(
    key: K,
    value: DeviceVpnDraft[K]
  ) => {
    if (pending) return
    setDraft((current) => ({ ...current, [key]: value }))
    setValidationCode(undefined)
  }
  const persist = async (nextRules: RouteRule[]) => {
    try {
      await mutation.mutateAsync({
        data: { ...config, route: { ...config.route, rules: nextRules } },
      })
      toast.success(t("deviceVpn.saved"))
      complete()
    } catch {
      /* The common operation error preserves the draft and recovery guidance. */
    }
  }
  const targetChanged =
    baselineRule &&
    deviceVpnError(draft, rules, config.outbounds ?? [], baselineRule) ===
      "changed"
  // Reject an advanced rule opened directly, but keep an already-open simple
  // editor mounted if another tab adds conditions. Its draft must not vanish.
  if (baselineRule && !deviceRuleAddress(baselineRule)) {
    return (
      <Alert variant="warning">
        <AlertDescription>{errors.changed}</AlertDescription>
      </Alert>
    )
  }
  return (
    <form
      className="space-y-6"
      onSubmit={(event) => {
        event.preventDefault()
        if (pending || !dirty) return
        const result = saveDeviceVpnRule(
          rules,
          config.outbounds ?? [],
          draft,
          baselineRule
        )
        if (result.error) {
          setValidationCode(result.error)
          return
        }
        void persist(result.rules!)
      }}
    >
      <fieldset disabled={pending} className="min-w-0 space-y-6">
        <FieldGroup>
          <Field>
            <FieldLabel htmlFor="device-vpn-choice">
              {t("deviceVpn.device")}
            </FieldLabel>
            <FieldContent>
              <Select
                disabled={pending}
                value={selectedDevice}
                onValueChange={(value) => {
                  if (pending) return
                  setSelectedDevice(value)
                  const device = devices.find((entry) => entry.ipv4 === value)
                  if (!snapshot?.available || !device || device.conflict) return
                  setDraft((current) => ({
                    ...current,
                    address: device.ipv4,
                    name: [...(device.name?.trim() ?? "")]
                      .slice(0, 80)
                      .join(""),
                  }))
                  setValidationCode(undefined)
                }}
              >
                <SelectTrigger
                  id="device-vpn-choice"
                  disabled={!snapshot?.available || !devices.length}
                >
                  <SelectValue
                    placeholder={
                      inventory.isLoading
                        ? t("common.loading")
                        : t("deviceVpn.chooseDevice")
                    }
                  >
                    {selectedDevice
                      ? devices.find((entry) => entry.ipv4 === selectedDevice)
                          ?.name || selectedDevice
                      : undefined}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent>
                  {devices.map((device) => (
                    <SelectItem
                      key={device.ipv4}
                      value={device.ipv4}
                      disabled={device.conflict}
                    >
                      <span className="flex min-w-0 flex-col">
                        <span>{device.name || device.ipv4}</span>
                        <span className="text-xs text-muted-foreground">
                          {device.ipv4}
                          {device.mac ? " · " + device.mac : ""}
                          {device.conflict
                            ? " · " + t("deviceVpn.conflict")
                            : ""}
                        </span>
                      </span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <FieldHint
                description={
                  snapshot?.available
                    ? devices.length
                      ? t("deviceVpn.inventoryHint")
                      : t("deviceVpn.inventoryEmpty")
                    : t("deviceVpn.inventoryUnavailable")
                }
              />
              {snapshot?.truncated ? (
                <p className="text-sm text-muted-foreground">
                  {t("deviceVpn.inventoryTruncated")}
                </p>
              ) : null}
              <Button
                variant="outline"
                type="button"
                className="self-start"
                disabled={inventory.isFetching}
                onClick={() => void inventory.refetch()}
              >
                {t("deviceVpn.refreshDevices")}
              </Button>
            </FieldContent>
          </Field>
          <Field invalid={error === "address"}>
            <FieldLabel htmlFor="device-vpn-address">
              {t("deviceVpn.address")}
            </FieldLabel>
            <FieldContent>
              <Input
                id="device-vpn-address"
                inputMode="decimal"
                autoComplete="off"
                spellCheck={false}
                value={draft.address}
                aria-invalid={error === "address"}
                placeholder="192.168.1.50"
                onChange={(event) => {
                  setSelectedDevice(null)
                  change("address", event.target.value)
                }}
              />
              <FieldHint description={t("deviceVpn.addressHint")} />
            </FieldContent>
          </Field>
          <Field>
            <FieldLabel htmlFor="device-vpn-name">
              {t("deviceVpn.name")}
            </FieldLabel>
            <FieldContent>
              <Input
                id="device-vpn-name"
                value={draft.name}
                maxLength={80}
                onChange={(event) => change("name", event.target.value)}
              />
            </FieldContent>
          </Field>
          <Field>
            <FieldLabel id="device-vpn-outbound-label">
              {t("deviceVpn.outbound")}
            </FieldLabel>
            <FieldContent>
              <OutboundSelect
                value={draft.outbound}
                outbounds={outbounds}
                ariaLabelledBy="device-vpn-outbound-label"
                onValueChange={(value) => change("outbound", value)}
                disabled={!outbounds.length}
              />
              {!outbounds.length ? (
                <FieldHint description={t("deviceVpn.noOutbounds")} />
              ) : null}
            </FieldContent>
          </Field>
          <Field orientation="horizontal">
            <FieldLabel htmlFor="device-vpn-enabled">
              {t("deviceVpn.enabled")}
            </FieldLabel>
            <Switch
              id="device-vpn-enabled"
              checked={draft.enabled}
              onCheckedChange={(value) => change("enabled", value)}
            />
          </Field>
        </FieldGroup>
        <Alert variant="warning">
          <AlertDescription>{t("deviceVpn.ipv6Warning")}</AlertDescription>
        </Alert>
        <p className="text-sm text-muted-foreground">
          {t("deviceVpn.priorityHint")}
        </p>
        <details className="space-y-4">
          <summary className="cursor-pointer">
            {t("deviceVpn.advanced")}
          </summary>
          <RouteFailurePolicyFields
            outbounds={outbounds}
            primaryOutbound={draft.outbound}
            policy={draft.failurePolicy}
            fallbackOutbound={draft.fallbackOutbound}
            onPolicyChange={(value) => change("failurePolicy", value)}
            onFallbackChange={(value) => change("fallbackOutbound", value)}
          />
          {draft.failurePolicy !== "inherit" ? (
            <Alert variant="warning">
              <AlertDescription>
                {t("deviceVpn.blockScopeWarning")}
              </AlertDescription>
            </Alert>
          ) : null}
          {(config.route?.inbound_interfaces?.length ?? 0) > 0 ? (
            <p className="text-sm text-warning-foreground">
              {t("deviceVpn.ingressRestriction")}
            </p>
          ) : null}
          <p className="text-sm text-muted-foreground">
            {t("deviceVpn.scopeHint")}
          </p>
        </details>
      </fieldset>
      {error || targetChanged ? (
        <Alert variant="destructive">
          <AlertDescription>{errors[error ?? "changed"]}</AlertDescription>
        </Alert>
      ) : null}
      <ConfigSaveErrorAlert error={mutation.error} />
      <div className="flex flex-wrap justify-end gap-3" data-upsert-actions>
        {baselineRule ? (
          <UpsertDeleteAction
            label={t("deviceVpn.remove")}
            title={t("deviceVpn.removeTitle")}
            description={t("deviceVpn.removeDescription")}
            confirmLabel={t("deviceVpn.remove")}
            impactItems={[]}
            isPending={pending}
            disabled={Boolean(targetChanged)}
            onConfirm={() => {
              const next = removeDeviceVpnRule(rules, baselineRule)
              if (!next) {
                setValidationCode("changed")
                return
              }
              void persist(next)
            }}
          />
        ) : null}
        <Button
          variant="outline"
          type="button"
          onClick={close}
          disabled={pending}
        >
          {t("common.cancel")}
        </Button>
        <Button
          type="submit"
          disabled={pending || !dirty || Boolean(targetChanged)}
        >
          {pending ? t("common.saving") : t("deviceVpn.save")}
        </Button>
      </div>
    </form>
  )
}
