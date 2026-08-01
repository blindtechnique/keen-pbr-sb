import {
  useEffect,
  useMemo,
  useState,
  type FormEvent,
  type ReactNode,
} from "react"
import { useTranslation } from "react-i18next"

import { TransportSpecType, type TransportSpec } from "@/api/generated/model"
import { Button } from "@/components/ui/button"
import type { UpsertPagePresentation } from "@/components/shared/upsert-page"
import { useUpsertPageClose } from "@/components/shared/upsert-page-context"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { countryOptions } from "@/data/countries"
import { validateDisplayName } from "@/lib/display-name-validation"
import {
  formatNativeTransportCandidate,
  type NativeTransportCandidate,
} from "@/lib/hidden-native-interfaces"
import { isSemanticallyDirty } from "@/lib/semantic-dirty"
import { semanticJsonEqual } from "@/lib/semantic-json"
import {
  generateTransportIdentity,
  inferTransportProtocol,
} from "@/lib/technical-id"

type Props = {
  existingInterfaces?: readonly string[]
  existingTags?: readonly string[]
  initial?: TransportSpec
  isPending: boolean
  nativeCandidates?: readonly NativeTransportCandidate[]
  onDirtyChange: (dirty: boolean) => void
  onSubmit: (spec: TransportSpec, options: { createOutbound: boolean }) => void
  presentation: UpsertPagePresentation
  singBoxAvailable?: boolean
}

type SourceMode = "link" | "json"

const emptySpec = (): TransportSpec => ({
  tag: "",
  type: TransportSpecType["sing-box"],
  interface: "",
  auto_start: false,
  geo_mode: "disabled",
})

export type TransportFormValue = {
  spec: TransportSpec
  sourceMode: SourceMode
  createOutbound: boolean
}

export type TransportFormSubmission = {
  spec: TransportSpec
  options: { createOutbound: boolean }
}

// Exported for focused form tests. Suggestions never mutate the form by
// themselves: the user must explicitly accept one in the dialog.
// eslint-disable-next-line react-refresh/only-export-components
export function inferTransportAliasSuggestion(
  sourceMode: SourceMode,
  spec: Pick<TransportSpec, "link" | "outbound_json">
): string | undefined {
  if (sourceMode === "json") {
    try {
      const parsed = JSON.parse(spec.outbound_json?.trim() ?? "") as unknown
      if (
        typeof parsed === "object" &&
        parsed !== null &&
        "server" in parsed &&
        typeof parsed.server === "string"
      ) {
        return normalizeEndpointSuggestion(parsed.server)
      }
    } catch {
      return undefined
    }
    return undefined
  }

  const link = spec.link?.trim()
  if (!link) {
    return undefined
  }

  try {
    return normalizeEndpointSuggestion(new URL(link).hostname)
  } catch {
    return undefined
  }
}

// Exported for focused semantic-form tests; it has no module-level state.
// eslint-disable-next-line react-refresh/only-export-components
export function createTransportFormValue(
  initial?: TransportSpec,
  identity?: { interfaceName: string; tag: string }
): TransportFormValue {
  const spec = initial
    ? structuredClone(initial)
    : {
        ...emptySpec(),
        interface: identity?.interfaceName ?? "",
        tag: identity?.tag ?? "",
      }

  return {
    spec,
    sourceMode:
      spec.outbound_json && !spec.link
        ? ("json" satisfies SourceMode)
        : ("link" satisfies SourceMode),
    createOutbound: !initial,
  }
}

/**
 * Produces exactly the value sent to the transport API. Dirty-state checks use
 * the same projection, so representation-only changes (omitted defaults,
 * whitespace in bootstrap resolvers and inactive source fields) stay clean.
 */
// Exported for focused semantic-form tests; it has no module-level state.
// eslint-disable-next-line react-refresh/only-export-components
export function normalizeTransportFormValue(
  value: TransportFormValue,
  editing: boolean
): TransportFormSubmission {
  const { spec, sourceMode } = value
  const bootstrapDns = spec.bootstrap_dns
    ?.map((resolver) => resolver.trim())
    .filter(Boolean)
  const normalizedSpec: TransportSpec = {
    ...spec,
    display_name: spec.display_name?.trim() || undefined,
    auto_start: spec.auto_start ?? false,
    geo_mode: spec.geo_mode ?? "disabled",
    country_code:
      spec.geo_mode === "manual"
        ? spec.country_code?.trim().toUpperCase()
        : undefined,
    country: spec.geo_mode === "manual" ? spec.country?.trim() : undefined,
  }

  if (spec.type === TransportSpecType.native) {
    return {
      spec: {
        ...normalizedSpec,
        link: undefined,
        outbound_json: undefined,
        mtu: undefined,
        bootstrap_dns: undefined,
        tun_address: undefined,
        vless: undefined,
      },
      options: { createOutbound: value.createOutbound && !editing },
    }
  }

  return {
    spec: {
      ...normalizedSpec,
      link: sourceMode === "link" && spec.link?.trim() ? spec.link : undefined,
      outbound_json:
        sourceMode === "json" && spec.outbound_json?.trim()
          ? spec.outbound_json
          : undefined,
      mtu: spec.mtu ?? 1420,
      bootstrap_dns: bootstrapDns?.length ? bootstrapDns : undefined,
      vless: undefined,
    },
    options: { createOutbound: value.createOutbound && !editing },
  }
}

// Exported for focused semantic-form tests; it has no module-level state.
// eslint-disable-next-line react-refresh/only-export-components
export function normalizeTransportFormComparable(
  value: TransportFormValue,
  baseline: TransportFormValue,
  editing: boolean
): TransportFormSubmission {
  const comparable = normalizeTransportFormValue(value, editing)
  if (
    !editing ||
    comparable.spec.link !== undefined ||
    comparable.spec.outbound_json !== undefined
  ) {
    return comparable
  }

  // Empty secret fields mean "keep the stored connection" on update. Compare
  // that state with the original source instead of reporting a false change.
  const original = normalizeTransportFormValue(baseline, editing)
  return {
    ...comparable,
    spec: {
      ...comparable.spec,
      link: original.spec.link,
      outbound_json: original.spec.outbound_json,
    },
  }
}

export function TransportConfigForm({
  existingInterfaces = [],
  existingTags = [],
  initial,
  isPending,
  nativeCandidates = [],
  onDirtyChange,
  onSubmit,
  presentation,
  singBoxAvailable = true,
}: Props) {
  const { t, i18n } = useTranslation()
  const close = useUpsertPageClose()
  const [baseline] = useState<TransportFormValue>(() =>
    createTransportFormValue(
      initial,
      initial
        ? undefined
        : generateTransportIdentity({
            existingInterfaces,
            existingTags,
          })
    )
  )
  const [spec, setSpec] = useState<TransportSpec>(() =>
    structuredClone(baseline.spec)
  )
  const [sourceMode, setSourceMode] = useState<SourceMode>(baseline.sourceMode)
  const showAdvanced = presentation === "page"
  const [technicalIdentityAutomatic, setTechnicalIdentityAutomatic] =
    useState(!initial)
  // A transport only becomes a route once an interface outbound points at it,
  // so offer that step right here instead of sending people to another page.
  const [createOutbound, setCreateOutbound] = useState(baseline.createOutbound)
  const countries = useMemo(
    () => countryOptions(i18n.resolvedLanguage ?? i18n.language ?? "ru"),
    [i18n.language, i18n.resolvedLanguage]
  )

  const isSingBox = spec.type !== TransportSpecType.native
  const aliasSuggestion = inferTransportAliasSuggestion(sourceMode, spec)
  const displayNameError = validateDisplayName(spec.display_name ?? "")
  const selectedNativeCandidate =
    spec.type === TransportSpecType.native
      ? nativeCandidates.find(
          (candidate) => candidate.interfaceName === spec.interface
        )
      : undefined
  const nativeSelectionInvalid =
    spec.type === TransportSpecType.native &&
    !initial &&
    (!selectedNativeCandidate || !selectedNativeCandidate.selectable)
  const formValue: TransportFormValue = {
    spec,
    sourceMode,
    createOutbound,
  }
  const isDirty = isSemanticallyDirty(formValue, baseline, {
    equals: semanticJsonEqual,
    normalize: (value) =>
      normalizeTransportFormComparable(value, baseline, Boolean(initial)),
  })

  const withAutomaticTechnicalIdentity = (
    nextSpec: TransportSpec,
    nextSourceMode = sourceMode
  ) => {
    if (
      !technicalIdentityAutomatic ||
      nextSpec.type === TransportSpecType.native
    ) {
      return nextSpec
    }

    const protocol =
      nextSourceMode === "link"
        ? inferTransportProtocol(nextSpec.link, undefined)
        : inferTransportProtocol(undefined, nextSpec.outbound_json)
    const identity = generateTransportIdentity({
      existingInterfaces,
      existingTags,
      protocol,
    })
    return {
      ...nextSpec,
      interface: identity.interfaceName,
      tag: identity.tag,
    }
  }

  const selectSourceMode = (nextSourceMode: SourceMode) => {
    setSourceMode(nextSourceMode)
    setSpec((current) =>
      withAutomaticTechnicalIdentity(current, nextSourceMode)
    )
  }

  useEffect(() => {
    onDirtyChange(isDirty)
  }, [isDirty, onDirtyChange])

  const submit = (event: FormEvent) => {
    event.preventDefault()
    const submission = normalizeTransportFormValue(formValue, Boolean(initial))
    onSubmit(submission.spec, submission.options)
  }

  return (
    <form className="space-y-6" onSubmit={submit}>
      <div className="grid content-start gap-4">
        <Field label={t("transports.form.displayName")}>
          <Input
            aria-invalid={Boolean(displayNameError)}
            onChange={(event) =>
              setSpec({
                ...spec,
                display_name: event.target.value || undefined,
              })
            }
            placeholder={t("transports.form.displayNamePlaceholder")}
            required
            value={spec.display_name ?? ""}
          />
          <p className="text-xs text-muted-foreground">
            {t("transports.form.displayNameHint")}
          </p>
          {displayNameError ? (
            <p className="text-xs text-destructive">
              {t("transports.form.displayNameInvalid")}
            </p>
          ) : null}
          {aliasSuggestion && aliasSuggestion !== spec.display_name?.trim() ? (
            <Button
              className="w-fit px-0"
              onClick={() =>
                setSpec({ ...spec, display_name: aliasSuggestion })
              }
              size="sm"
              type="button"
              variant="link"
            >
              {t("transports.form.useAliasSuggestion", {
                name: aliasSuggestion,
              })}
            </Button>
          ) : null}
        </Field>
        <Field label={t("transports.form.type")}>
          <select
            className="h-9 rounded-md border bg-background px-3"
            disabled={Boolean(initial)}
            onChange={(event) => {
              const nextType = event.target.value as TransportSpec["type"]
              const firstNative = nativeCandidates.find(
                (candidate) => candidate.selectable
              )
              setSpec((current) =>
                withAutomaticTechnicalIdentity({
                  ...current,
                  type: nextType,
                  interface:
                    nextType === TransportSpecType.native
                      ? (firstNative?.interfaceName ?? "")
                      : baseline.spec.interface,
                })
              )
            }}
            value={spec.type}
          >
            {initial?.type === TransportSpecType.native ||
            nativeCandidates.length > 0 ? (
              <option value={TransportSpecType.native}>
                {t("transports.form.native")}
              </option>
            ) : null}
            <option value={TransportSpecType["sing-box"]}>
              {t("transports.form.singBox")}
            </option>
            {spec.type === TransportSpecType["sing-box-vless-reality"] ? (
              <option value={TransportSpecType["sing-box-vless-reality"]}>
                {t("transports.form.singBoxLegacy")}
              </option>
            ) : null}
          </select>
        </Field>
        {spec.type === TransportSpecType.native ? (
          <Field label={t("transports.form.nativeInterface")}>
            <select
              className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
              disabled={Boolean(initial)}
              onChange={(event) =>
                setSpec({ ...spec, interface: event.target.value })
              }
              required
              value={spec.interface}
            >
              <option disabled value="">
                {t("transports.form.nativeInterfacePlaceholder")}
              </option>
              {initial?.type === TransportSpecType.native &&
              !selectedNativeCandidate ? (
                <option value={spec.interface}>{spec.interface}</option>
              ) : null}
              {nativeCandidates.map((candidate) => (
                <option
                  disabled={!candidate.selectable}
                  key={candidate.id}
                  value={
                    candidate.interfaceName ?? `unresolved:${candidate.id}`
                  }
                >
                  {formatNativeTransportCandidate(candidate, {
                    hidden: t("transports.form.nativeInterfaceHidden"),
                    unavailable: t(
                      "transports.form.nativeInterfaceUnavailable"
                    ),
                  })}
                </option>
              ))}
            </select>
            <p className="text-xs text-muted-foreground">
              {t("transports.form.nativeInterfaceHint")}
            </p>
          </Field>
        ) : null}
        {showAdvanced ? (
          <div className="grid gap-4 rounded-md border px-3 py-3">
            <p className="text-sm font-medium">
              {t("transports.form.technicalSettings")}
            </p>
            <Field label={t("transports.form.tag")}>
              <Input
                aria-describedby="transport-tag-hint"
                disabled={Boolean(initial)}
                maxLength={24}
                onChange={(event) => {
                  setTechnicalIdentityAutomatic(false)
                  setSpec({ ...spec, tag: event.target.value })
                }}
                pattern="[a-z][a-z0-9_]{0,23}"
                placeholder="my_tunnel"
                required
                title={t("transports.form.tagHint")}
                value={spec.tag}
              />
              <p
                className="text-xs text-muted-foreground"
                id="transport-tag-hint"
              >
                {t("transports.form.tagHint")}
              </p>
            </Field>
            <Field label={t("transports.form.interface")}>
              <Input
                maxLength={15}
                onChange={(event) => {
                  setTechnicalIdentityAutomatic(false)
                  setSpec({ ...spec, interface: event.target.value })
                }}
                pattern="[A-Za-z0-9_.-]{1,15}"
                placeholder="vless1"
                readOnly={
                  Boolean(initial) || spec.type === TransportSpecType.native
                }
                required
                value={spec.interface}
              />
              {initial ? (
                <p className="text-xs text-muted-foreground">
                  {t("transports.form.technicalIdentityImmutable")}
                </p>
              ) : null}
            </Field>
          </div>
        ) : null}
        <div className="flex items-center justify-between rounded-md border p-3">
          <Label htmlFor="transport-auto-start">
            {t("transports.form.autoStart")}
          </Label>
          <Switch
            checked={spec.auto_start ?? false}
            id="transport-auto-start"
            onCheckedChange={(checked) =>
              setSpec({ ...spec, auto_start: checked })
            }
          />
        </div>
        {showAdvanced ? (
          <Field label={t("transports.form.countryDisplay")}>
            <div className="grid gap-2 rounded-md border p-3">
              {(["disabled", "manual", "auto"] as const).map((mode) => (
                <label
                  className="flex cursor-pointer items-start gap-3 rounded-md border border-transparent p-2 has-[:checked]:border-primary has-[:checked]:bg-primary/10"
                  key={mode}
                >
                  <input
                    checked={(spec.geo_mode ?? "disabled") === mode}
                    className="mt-1 accent-primary"
                    name="transport-geo-mode"
                    onChange={() => setSpec({ ...spec, geo_mode: mode })}
                    type="radio"
                  />
                  <span className="grid gap-0.5">
                    <span className="text-sm font-medium">
                      {t(`transports.form.geo.${mode}`)}
                    </span>
                    {mode === "auto" ? (
                      <span className="text-xs text-amber-700 dark:text-amber-300">
                        {t("transports.form.geo.autoWarning")}
                      </span>
                    ) : null}
                  </span>
                </label>
              ))}
              {spec.geo_mode === "manual" ? (
                <select
                  className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
                  onChange={(event) => {
                    const selected = countries.find(
                      (country) => country.code === event.target.value
                    )
                    setSpec({
                      ...spec,
                      country_code: selected?.code,
                      country: selected?.name,
                    })
                  }}
                  required
                  value={spec.country_code?.toUpperCase() ?? ""}
                >
                  <option disabled value="">
                    {t("transports.form.geo.countryPlaceholder")}
                  </option>
                  {countries.map((country) => (
                    <option key={country.code} value={country.code}>
                      {country.flag} {country.name} ({country.code})
                    </option>
                  ))}
                </select>
              ) : null}
            </div>
          </Field>
        ) : null}
        {!initial ? (
          <div className="flex items-center justify-between rounded-md border p-3">
            <div className="min-w-0 pr-3">
              <Label htmlFor="transport-create-outbound">
                {t("transports.form.createOutbound")}
              </Label>
              <p className="mt-1 text-xs text-muted-foreground">
                {t("transports.form.createOutboundHint")}
              </p>
            </div>
            <Switch
              checked={createOutbound}
              id="transport-create-outbound"
              onCheckedChange={setCreateOutbound}
            />
          </div>
        ) : null}

        {isSingBox ? (
          <div className="grid gap-4 rounded-lg border p-4">
            {!singBoxAvailable ? (
              <Alert variant="destructive">
                <AlertTitle>{t("transports.singBoxMissing.title")}</AlertTitle>
                <AlertDescription className="space-y-2">
                  <p>{t("transports.singBoxMissing.description")}</p>
                  <code className="block overflow-x-auto rounded bg-muted p-2 text-xs text-foreground">
                    sh -c &quot;$(curl -fsSL
                    https://raw.githubusercontent.com/blindtechnique/keen-pbr-sb/main/install.sh)&quot;
                  </code>
                </AlertDescription>
              </Alert>
            ) : null}
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              <Button
                className="h-auto min-h-9 py-2 text-center leading-tight whitespace-normal"
                type="button"
                variant={sourceMode === "link" ? "default" : "outline"}
                onClick={() => selectSourceMode("link")}
              >
                {t("transports.form.shareLink")}
              </Button>
              <Button
                className="h-auto min-h-9 py-2 text-center leading-tight whitespace-normal"
                type="button"
                variant={sourceMode === "json" ? "default" : "outline"}
                onClick={() => selectSourceMode("json")}
              >
                {t("transports.form.outboundJson")}
              </Button>
            </div>
            {sourceMode === "link" ? (
              <Field label={t("transports.form.shareLink")}>
                <Textarea
                  className="min-h-28 font-mono text-xs"
                  onChange={(event) =>
                    setSpec((current) =>
                      withAutomaticTechnicalIdentity({
                        ...current,
                        link: event.target.value,
                      })
                    )
                  }
                  placeholder={
                    initial
                      ? t("transports.form.keepConnection")
                      : "vless://…  vmess://…  trojan://…  ss://…  hy2://…  tuic://…"
                  }
                  required={!initial}
                  value={spec.link ?? ""}
                />
                <p className="text-xs text-muted-foreground">
                  {t("transports.form.shareLinkHint")}
                </p>
              </Field>
            ) : (
              <Field label={t("transports.form.outboundJson")}>
                <Textarea
                  className="min-h-48 font-mono text-xs"
                  onChange={(event) =>
                    setSpec((current) =>
                      withAutomaticTechnicalIdentity({
                        ...current,
                        outbound_json: event.target.value,
                      })
                    )
                  }
                  placeholder={
                    initial
                      ? t("transports.form.keepConnection")
                      : '{\n  "type": "ssh",\n  "server": "example.com",\n  "server_port": 22\n}'
                  }
                  required={!initial}
                  value={spec.outbound_json ?? ""}
                />
                <p className="text-xs text-muted-foreground">
                  {t("transports.form.outboundJsonHint")}
                </p>
              </Field>
            )}
            {showAdvanced ? (
              <>
                <Field label={t("transports.form.mtu")}>
                  <Input
                    min={576}
                    max={9000}
                    onChange={(event) =>
                      setSpec({
                        ...spec,
                        mtu: Number(event.target.value),
                      })
                    }
                    type="number"
                    value={spec.mtu ?? 1420}
                  />
                </Field>
                <Field label={t("transports.form.tunAddress")}>
                  <Input
                    onChange={(event) =>
                      setSpec({
                        ...spec,
                        tun_address: event.target.value.trim() || undefined,
                      })
                    }
                    pattern="(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/30"
                    placeholder={t("transports.form.tunAddressPlaceholder")}
                    title={t("transports.form.tunAddressHint")}
                    value={spec.tun_address ?? ""}
                  />
                  <p className="text-xs text-muted-foreground">
                    {t("transports.form.tunAddressHint")}
                  </p>
                </Field>
                <Field label={t("transports.form.bootstrapDns")}>
                  <Textarea
                    className="min-h-20 font-mono text-xs"
                    onChange={(event) =>
                      setSpec({
                        ...spec,
                        bootstrap_dns: event.target.value
                          .split(/[\n,]/)
                          .map((value) => value.trim())
                          .filter(Boolean),
                      })
                    }
                    placeholder={"1.1.1.1\n9.9.9.9"}
                    value={(spec.bootstrap_dns ?? []).join("\n")}
                  />
                  <p className="text-xs text-muted-foreground">
                    {t("transports.form.bootstrapDnsHint")}
                  </p>
                </Field>
              </>
            ) : null}
          </div>
        ) : null}
      </div>
      <div className="flex justify-end gap-3" data-upsert-actions>
        <Button
          disabled={isPending}
          onClick={close}
          size="xl"
          type="button"
          variant="outline"
        >
          {t("common.cancel")}
        </Button>
        <Button
          disabled={
            isPending ||
            !isDirty ||
            Boolean(displayNameError) ||
            nativeSelectionInvalid
          }
          size="xl"
          type="submit"
        >
          {isPending ? t("transports.form.saving") : t("transports.form.save")}
        </Button>
      </div>
    </form>
  )
}

function Field({ children, label }: { children: ReactNode; label: string }) {
  return (
    <div className="grid gap-1.5">
      <Label>{label}</Label>
      {children}
    </div>
  )
}

function normalizeEndpointSuggestion(value: string) {
  const normalized = value.trim().replace(/^\[|\]$/g, "")
  if (validateDisplayName(normalized)) {
    return undefined
  }
  return normalized
}
