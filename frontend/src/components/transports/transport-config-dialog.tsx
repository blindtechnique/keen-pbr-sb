import { BracesIcon, FileUpIcon, LinkIcon } from "lucide-react"
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import {
  TransportSpecType,
  type NdmsInterfaceInventoryResponseRequiredGuardsItem,
  type NdmsNativeImportReadiness,
  type NdmsTunnelInterface,
  type TransportSpec,
} from "@/api/generated/model"
import { HelpHint } from "@/components/shared/help-hint"
import { SegmentedControl } from "@/components/shared/segmented-control"
import { Button } from "@/components/ui/button"
import type { UpsertPagePresentation } from "@/components/shared/upsert-page"
import {
  useUpsertPageClose,
  useUpsertPageComplete,
} from "@/components/shared/upsert-page-context"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
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
import { NativeWireGuardImportFields } from "@/components/transports/native-wireguard-import-card"
import {
  NATIVE_WIREGUARD_IMPORT_PROGRESS_TOAST_ID,
  stageNativeWireGuardImportCompletion,
  type NativeWireGuardImportedIdentity,
} from "@/lib/native-wireguard-import-completion"
import { SubscriptionImportDialog } from "@/components/transports/subscription-import-dialog"
import { classifyPastedLink } from "@/components/transports/subscription-import-model"
import {
  generateTransportIdentity,
  inferTransportProtocol,
} from "@/lib/technical-id"

type Props = {
  /** Native interface selected by the pencil before a panel tracker exists. */
  createSeed?: TransportSpec
  existingInterfaces?: readonly string[]
  existingTags?: readonly string[]
  initial?: TransportSpec
  initialCreateOutbound?: boolean
  /**
   * Начальное положение переопределения kill-switch связанного маршрута.
   * Туннель и есть маршрут (решение владельца), поэтому настройка маршрута
   * редактируется здесь же, а не в отдельном месте.
   */
  initialKillSwitch?: TransportKillSwitchOption
  isPending: boolean
  /** Есть ли маршрут, которому можно записать kill-switch. Без него поле — обман. */
  killSwitchAvailable?: boolean
  linkedOutboundExists?: boolean
  nativeCandidates?: readonly NativeTransportCandidate[]
  nativeImportInterfaces?: readonly NdmsTunnelInterface[]
  nativeImportReadiness?: NdmsNativeImportReadiness
  nativeImportRequiredGuards?: readonly NdmsInterfaceInventoryResponseRequiredGuardsItem[]
  onDirtyChange: (dirty: boolean) => void
  onSubmit: (
    spec: TransportSpec,
    options: { createOutbound: boolean; killSwitch: TransportKillSwitchOption }
  ) => void
  presentation: UpsertPagePresentation
  singBoxAvailable?: boolean
}

export type SourceMode = "link" | "file" | "json"

// eslint-disable-next-line react-refresh/only-export-components
export const TRANSPORT_SOURCE_MODE_ORDER: readonly SourceMode[] = [
  "link",
  "file",
  "json",
]

// eslint-disable-next-line react-refresh/only-export-components
export function isNativeImportPreviewOnlyMode(
  sourceMode: SourceMode,
  nativeUriActive: boolean
): boolean {
  return sourceMode === "file" || nativeUriActive
}

/**
 * File reads and pasted native URIs have their own short-lived state. React
 * must remount that state when the user changes source mode so a completed or
 * still-running file preview cannot appear beside the ordinary link form.
 */
// eslint-disable-next-line react-refresh/only-export-components
export function nativeImportFieldsStateBoundaryKey(
  sourceMode: Extract<SourceMode, "link" | "file">
): string {
  return `native-import-${sourceMode}`
}

// eslint-disable-next-line react-refresh/only-export-components
export function selectImportedNativeInterface(
  current: TransportSpec,
  identity: NativeWireGuardImportedIdentity
): TransportSpec {
  return {
    ...current,
    type: TransportSpecType.native,
    interface: identity.kernelInterface,
    link: undefined,
    outbound_json: undefined,
  }
}

// eslint-disable-next-line react-refresh/only-export-components
export function importedNativeInterfaceSelectionIsValid({
  inventoryCandidateSelectable,
  importedProofMatches,
}: {
  readonly inventoryCandidateSelectable: boolean | undefined
  readonly importedProofMatches: boolean
}): boolean {
  // The one-shot proof bridges only the short inventory-refresh gap. Once a
  // fresh candidate exists, its current selectable verdict is authoritative.
  return inventoryCandidateSelectable ?? importedProofMatches
}

/** Та же трёхпозиционная шкала, что у маршрута в расширенном редакторе. */
export type TransportKillSwitchOption = "default" | "enabled" | "disabled"

const KILL_SWITCH_OPTIONS: TransportKillSwitchOption[] = [
  "default",
  "enabled",
  "disabled",
]

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
  killSwitch: TransportKillSwitchOption
}

export type TransportFormSubmission = {
  spec: TransportSpec
  options: { createOutbound: boolean; killSwitch: TransportKillSwitchOption }
}

/**
 * Ручной режим геолокации без выбранной страны — сохранять нельзя.
 *
 * Раньше это держалось на `required` нативного `<select>` и всплывающей
 * подсказке браузера. У своего поля такой проверки нет, поэтому условие
 * переехало на кнопку сохранения: заодно видно заранее, а не по нажатию.
 */
// eslint-disable-next-line react-refresh/only-export-components
export function isTransportGeoSelectionInvalid(
  spec: Pick<TransportSpec, "geo_mode" | "country_code">
): boolean {
  return spec.geo_mode === "manual" && !spec.country_code?.trim()
}

// Exported for focused form tests. Suggestions never mutate the form by
// themselves: the user must explicitly accept one in the dialog.
// eslint-disable-next-line react-refresh/only-export-components
export function inferTransportAliasSuggestion(
  sourceMode: SourceMode,
  spec: Pick<TransportSpec, "link" | "outbound_json">
): string | undefined {
  if (sourceMode === "file") return undefined
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
  identity?: { interfaceName: string; tag: string },
  killSwitch: TransportKillSwitchOption = "default",
  create?: {
    readonly seed?: TransportSpec
    readonly createOutbound?: boolean
  }
): TransportFormValue {
  const spec = initial ?? create?.seed
  const formSpec = spec
    ? structuredClone(spec)
    : {
        ...emptySpec(),
        interface: identity?.interfaceName ?? "",
        tag: identity?.tag ?? "",
      }

  return {
    spec: formSpec,
    sourceMode:
      formSpec.outbound_json && !formSpec.link
        ? ("json" satisfies SourceMode)
        : ("link" satisfies SourceMode),
    createOutbound: create?.createOutbound ?? !initial,
    killSwitch,
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
  // Kept in the public helper signature because comparable edit semantics use
  // the same normalizer; linked-route creation is now valid in both modes.
  void editing
  const { spec, sourceMode } = value
  const bootstrapDns = spec.bootstrap_dns
    ?.map((resolver) => resolver.trim())
    .filter(Boolean)
  const keepsCountrySnapshot =
    spec.geo_mode === "manual" || spec.geo_mode === "auto"
  const normalizedSpec: TransportSpec = {
    ...spec,
    display_name: spec.display_name?.trim() || undefined,
    auto_start: spec.auto_start ?? false,
    geo_mode: spec.geo_mode ?? "disabled",
    country_code: keepsCountrySnapshot
      ? spec.country_code?.trim().toUpperCase()
      : undefined,
    country: keepsCountrySnapshot ? spec.country?.trim() : undefined,
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
      options: {
        createOutbound: value.createOutbound,
        killSwitch: value.killSwitch,
      },
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
    options: {
      createOutbound: value.createOutbound,
      killSwitch: value.killSwitch,
    },
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
  createSeed,
  existingInterfaces = [],
  existingTags = [],
  initial,
  initialCreateOutbound,
  initialKillSwitch = "default",
  isPending,
  killSwitchAvailable = false,
  linkedOutboundExists = false,
  nativeCandidates = [],
  nativeImportInterfaces = [],
  nativeImportReadiness,
  nativeImportRequiredGuards = [],
  onDirtyChange,
  onSubmit,
  presentation,
  singBoxAvailable = true,
}: Props) {
  const { t, i18n } = useTranslation()
  const close = useUpsertPageClose()
  const complete = useUpsertPageComplete()
  const [baseline] = useState<TransportFormValue>(() =>
    createTransportFormValue(
      initial,
      initial
        ? undefined
        : generateTransportIdentity({
            existingInterfaces,
            existingTags,
          }),
      initialKillSwitch,
      {
        seed: createSeed,
        createOutbound: initialCreateOutbound,
      }
    )
  )
  const [spec, setSpec] = useState<TransportSpec>(() =>
    structuredClone(baseline.spec)
  )
  const [sourceMode, setSourceMode] = useState<SourceMode>(baseline.sourceMode)
  const [displayNameTouched, setDisplayNameTouched] = useState(false)
  const [nativeUriActive, setNativeUriActive] = useState(false)
  const [nativeImportAliasSuggestion, setNativeImportAliasSuggestion] =
    useState<string>()
  const [importedNativeIdentity, setImportedNativeIdentity] =
    useState<NativeWireGuardImportedIdentity | null>(null)
  const [nativeImportSubmitted, setNativeImportSubmitted] = useState(false)
  const importedNativeFocusPendingRef = useRef(false)
  const nativeImportHandoffCloseTimerRef = useRef<number | null>(null)
  const nativeInterfaceTriggerRef = useRef<HTMLButtonElement>(null)
  // What the operator handed over that turned out to be a subscription rather
  // than one connection. Null until then, so the import UI does not exist for
  // the ordinary case.
  const [subscriptionSeed, setSubscriptionSeed] = useState<
    { readonly url: string } | { readonly document: string } | null
  >(null)
  const showAdvanced = presentation === "page"
  const [technicalIdentityAutomatic, setTechnicalIdentityAutomatic] =
    useState(!initial)
  // A transport only becomes a route once an interface outbound points at it,
  // so offer that step right here instead of sending people to another page.
  const [createOutbound, setCreateOutbound] = useState(baseline.createOutbound)
  const [killSwitch, setKillSwitch] = useState(baseline.killSwitch)
  const countries = useMemo(
    () => countryOptions(i18n.resolvedLanguage ?? i18n.language ?? "ru"),
    [i18n.language, i18n.resolvedLanguage]
  )

  const isSingBox = spec.type !== TransportSpecType.native
  const nativeSelectionLocked =
    Boolean(initial) || createSeed?.type === TransportSpecType.native
  const inferredAliasSuggestion = inferTransportAliasSuggestion(
    sourceMode,
    spec
  )
  const aliasSuggestion =
    (nativeUriActive || sourceMode === "file") &&
    nativeImportAliasSuggestion &&
    !validateDisplayName(nativeImportAliasSuggestion)
      ? nativeImportAliasSuggestion
      : inferredAliasSuggestion
  const displayNameError = validateDisplayName(spec.display_name ?? "")
  const selectedNativeCandidate =
    spec.type === TransportSpecType.native
      ? nativeCandidates.find(
          (candidate) => candidate.interfaceName === spec.interface
        )
      : undefined
  const selectedImportedNativeIdentity =
    spec.type === TransportSpecType.native &&
    importedNativeIdentity?.kernelInterface === spec.interface
      ? importedNativeIdentity
      : undefined
  const nativeSelectionInvalid =
    spec.type === TransportSpecType.native &&
    !initial &&
    !importedNativeInterfaceSelectionIsValid({
      inventoryCandidateSelectable: selectedNativeCandidate?.selectable,
      importedProofMatches: Boolean(selectedImportedNativeIdentity),
    })
  const nativeImportPreviewOnly =
    isSingBox && isNativeImportPreviewOnlyMode(sourceMode, nativeUriActive)
  // Списки для выпадающих полей считаем здесь: `Select` показывает выбранное
  // значение по этому же списку, поэтому он должен быть один и тот же для
  // кнопки и для меню.
  const typeOptions = [
    ...(initial?.type === TransportSpecType.native ||
    nativeCandidates.length > 0 ||
    importedNativeIdentity
      ? [
          {
            value: TransportSpecType.native as TransportSpec["type"],
            label: t("transports.form.native"),
          },
        ]
      : []),
    {
      value: TransportSpecType["sing-box"] as TransportSpec["type"],
      label: t("transports.form.singBox"),
    },
    ...(spec.type === TransportSpecType["sing-box-vless-reality"]
      ? [
          {
            value: TransportSpecType[
              "sing-box-vless-reality"
            ] as TransportSpec["type"],
            label: t("transports.form.singBoxLegacy"),
          },
        ]
      : []),
  ]
  const nativeInterfaceOptions = [
    // Интерфейс сохранённого транспорта мог исчезнуть из системы: без этой
    // строки поле показало бы пустоту вместо того, что там записано.
    ...(initial?.type === TransportSpecType.native && !selectedNativeCandidate
      ? [{ value: spec.interface, label: spec.interface, disabled: false }]
      : []),
    ...(selectedImportedNativeIdentity &&
    !nativeCandidates.some(
      (candidate) =>
        candidate.interfaceName ===
        selectedImportedNativeIdentity.kernelInterface
    )
      ? [
          {
            value: selectedImportedNativeIdentity.kernelInterface,
            label: t("transports.nativeImport.results.panelCandidate", {
              firmware: selectedImportedNativeIdentity.firmwareInterface,
              kernel: selectedImportedNativeIdentity.kernelInterface,
            }),
            disabled: false,
          },
        ]
      : []),
    ...nativeCandidates.map((candidate) => ({
      value: candidate.interfaceName ?? `unresolved:${candidate.id}`,
      label: formatNativeTransportCandidate(candidate, {
        hidden: t("transports.form.nativeInterfaceHidden"),
        unavailable: t("transports.form.nativeInterfaceUnavailable"),
        unavailableReasons: {
          server: t("transports.form.nativeInterfaceUnavailableServer"),
          unresolved: t("transports.form.nativeInterfaceUnavailableDisabled"),
        },
      }),
      disabled: !candidate.selectable,
    })),
  ]
  const countryItems = countries.map((country) => ({
    value: country.code,
    label: `${country.flag} ${country.name} (${country.code})`,
  }))
  const geoSelectionInvalid = isTransportGeoSelectionInvalid(spec)
  const formValue: TransportFormValue = {
    spec,
    sourceMode,
    createOutbound,
    killSwitch,
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
        : nextSourceMode === "json"
          ? inferTransportProtocol(undefined, nextSpec.outbound_json)
          : undefined
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

  const useImportedNativeIdentity = useCallback(
    (identity: NativeWireGuardImportedIdentity | null) => {
      setImportedNativeIdentity(identity)
      if (!identity) return

      const selected = selectImportedNativeInterface(spec, identity)
      importedNativeFocusPendingRef.current = true
      setTechnicalIdentityAutomatic(false)
      setNativeUriActive(false)
      setSourceMode("link")
      setSpec(selected)

      // The native import itself is already complete at this point.  Persist
      // the panel transport and its linked route immediately when the owner
      // supplied a valid name; requiring a second hidden Save click was what
      // discarded that name and let the inventory fallback create
      // "WireguardN" instead.  A missing/invalid name returns to the ordinary
      // form so the operator can explicitly accept the domain/IP suggestion.
      if (!validateDisplayName(selected.display_name ?? "")) {
        const submission = normalizeTransportFormValue(
          {
            spec: selected,
            sourceMode: "link",
            createOutbound,
            killSwitch,
          },
          false
        )
        onSubmit(submission.spec, submission.options)
      }
    },
    [
      createOutbound,
      killSwitch,
      onSubmit,
      spec,
      setImportedNativeIdentity,
      setNativeUriActive,
      setSourceMode,
      setSpec,
      setTechnicalIdentityAutomatic,
    ]
  )

  const stageCurrentNativeImportCompletion = useCallback(
    (endpointHost?: string) => {
      const displayName = spec.display_name?.trim()
      if (!displayName) return
      // The secret has already been handed to Keenetic at this boundary and
      // the non-secret completion plan is durable for this tab. Closing the
      // modal no longer discards a draft, so the ordinary unsaved-form prompt
      // would be false and used to trap the operator in a completed import.
      setNativeImportSubmitted(true)
      stageNativeWireGuardImportCompletion({
        tag: spec.tag,
        displayName,
        createOutbound,
        strictEnforcement:
          killSwitch === "default" ? undefined : killSwitch === "enabled",
        autoStart: false,
        geoMode: spec.geo_mode ?? "disabled",
        countryCode: spec.country_code?.trim().toUpperCase() || undefined,
        country: spec.country?.trim() || undefined,
        endpointHost,
      })
    },
    [createOutbound, killSwitch, spec]
  )

  const finishHandedOffNativeImport = useCallback(() => {
    // Let the existing progress state paint once, then move completion to the
    // page. The request and its non-secret plan are already durable here, so a
    // discard-draft question would be false and would delay route binding.
    setNativeImportSubmitted(true)
    if (nativeImportHandoffCloseTimerRef.current !== null) return
    toast.loading(t("transports.nativeImport.importingToast"), {
      id: NATIVE_WIREGUARD_IMPORT_PROGRESS_TOAST_ID,
    })
    nativeImportHandoffCloseTimerRef.current = window.setTimeout(() => {
      nativeImportHandoffCloseTimerRef.current = null
      complete()
    }, 900)
  }, [complete, t])

  useEffect(
    () => () => {
      if (nativeImportHandoffCloseTimerRef.current !== null) {
        window.clearTimeout(nativeImportHandoffCloseTimerRef.current)
      }
    },
    []
  )

  useEffect(() => {
    if (
      !importedNativeFocusPendingRef.current ||
      spec.type !== TransportSpecType.native
    ) {
      return
    }
    importedNativeFocusPendingRef.current = false
    queueMicrotask(() => nativeInterfaceTriggerRef.current?.focus())
  }, [spec.interface, spec.type])

  const selectSourceMode = (nextSourceMode: SourceMode) => {
    setNativeUriActive(false)
    setSourceMode(nextSourceMode)
    setSpec((current) =>
      withAutomaticTechnicalIdentity(current, nextSourceMode)
    )
  }

  // Ошибка имени не показывается на открытии: окно встречало пользователя
  // красным полем и строкой о том, что он уже ошибся, — до того как он
  // что-либо напечатал. Показываем, когда поле тронули либо когда в форме уже
  // есть изменения: в этот момент «Сохранить» заблокирована именно из-за
  // имени, и это надо объяснить.
  const showDisplayNameError =
    Boolean(displayNameError) && (displayNameTouched || isDirty)

  useEffect(() => {
    onDirtyChange(isDirty && !nativeImportSubmitted)
  }, [isDirty, nativeImportSubmitted, onDirtyChange])

  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (nativeImportPreviewOnly) return
    const submission = normalizeTransportFormValue(formValue, Boolean(initial))
    onSubmit(submission.spec, submission.options)
  }

  return (
    <form className="space-y-6" onSubmit={submit}>
      <div className="grid content-start gap-4">
        <Field label={t("transports.form.displayName")}>
          <Input
            aria-invalid={showDisplayNameError}
            onBlur={() => setDisplayNameTouched(true)}
            onChange={(event) => {
              setDisplayNameTouched(true)
              setSpec({
                ...spec,
                display_name: event.target.value || undefined,
              })
            }}
            placeholder={t("transports.form.displayNamePlaceholder")}
            required
            value={spec.display_name ?? ""}
          />
          <p className="text-xs text-muted-foreground">
            {t("transports.form.displayNameHint")}
          </p>
          {showDisplayNameError ? (
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
          <Select
            disabled={nativeSelectionLocked}
            items={typeOptions}
            onValueChange={(value) => {
              const nextType = (value ?? spec.type) as TransportSpec["type"]
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
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                {typeOptions.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
        </Field>
        {spec.type === TransportSpecType.native ? (
          <Field label={t("transports.form.nativeInterface")}>
            <Select
              disabled={nativeSelectionLocked}
              items={nativeInterfaceOptions}
              onValueChange={(value) =>
                setSpec({ ...spec, interface: String(value ?? "") })
              }
              value={spec.interface}
            >
              <SelectTrigger ref={nativeInterfaceTriggerRef}>
                <SelectValue
                  placeholder={t("transports.form.nativeInterfacePlaceholder")}
                />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  {nativeInterfaceOptions.map((option) => (
                    <SelectItem
                      disabled={option.disabled}
                      key={option.value}
                      value={option.value}
                    >
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectGroup>
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              {t("transports.form.nativeInterfaceHint")}
            </p>
          </Field>
        ) : null}
        {/* Плоский раздел, а не карточка: рамка внутри формы внутри диалога
            давала лишний уровень вложенных прямоугольников (замечание
            владельца). Разделы отделяются линией сверху. */}
        {showAdvanced ? (
          <div className="grid gap-4 border-t border-border pt-4">
            <p className="text-sm font-bold">
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
        {isSingBox ? (
          <div className="flex items-center justify-between gap-3 py-1">
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
        ) : null}
        {/* Выбор страны доступен и в диалоге (просьба владельца): флаг у
            туннеля помогает различать серверы, это не тонкая настройка. */}
        <Field label={t("transports.form.countryDisplay")}>
          <div className="grid gap-2">
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
              <Select
                items={countryItems}
                onValueChange={(value) => {
                  const selected = countries.find(
                    (country) => country.code === value
                  )
                  setSpec({
                    ...spec,
                    country_code: selected?.code,
                    country: selected?.name,
                  })
                }}
                value={spec.country_code?.toUpperCase() ?? ""}
              >
                <SelectTrigger>
                  <SelectValue
                    placeholder={t("transports.form.geo.countryPlaceholder")}
                  />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    {countryItems.map((item) => (
                      <SelectItem key={item.value} value={item.value}>
                        {item.label}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            ) : null}
          </div>
        </Field>
        {/* «Сразу создать маршрут» — только в расширенном редакторе: по
            умолчанию туннель и есть маршрут (решение владельца), и в простом
            диалоге этот выбор лишний — маршрут создаётся всегда. */}
        {showAdvanced && !linkedOutboundExists ? (
          <div className="flex items-center justify-between gap-3 py-1">
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

        {/* Настройка маршрута прямо в форме туннеля: туннель и есть маршрут
            (решение владельца), и посылать человека в расширенный редактор за
            одним переключателем нечестно. Поле показывается только когда
            маршрут будет: при создании — вместе с туннелем, при
            редактировании — когда он уже есть. Формулировки — те же, что в
            расширенном редакторе маршрута. */}
        {killSwitchAvailable &&
        (initial || linkedOutboundExists || createOutbound) ? (
          <Field
            hint={
              <HelpHint
                label={t("pages.outboundUpsert.strictEnforcement.label")}
                text={t("pages.settings.general.strictEnforcementHelp")}
              />
            }
            label={t("pages.outboundUpsert.strictEnforcement.label")}
          >
            <Select
              items={KILL_SWITCH_OPTIONS.map((option) => ({
                value: option,
                label: killSwitchOptionLabel(option, t),
              }))}
              onValueChange={(value) =>
                setKillSwitch(
                  (value as TransportKillSwitchOption) ?? killSwitch
                )
              }
              value={killSwitch}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  {KILL_SWITCH_OPTIONS.map((option) => (
                    <SelectItem key={option} value={option}>
                      {killSwitchOptionLabel(option, t)}
                    </SelectItem>
                  ))}
                </SelectGroup>
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              {t(
                `pages.outboundUpsert.strictEnforcement.explanations.${killSwitch}`
              )}
            </p>
          </Field>
        ) : null}

        {/* Раньше здесь была рамка вокруг переключателя «ссылка / JSON» и
            поля ввода — карточка внутри карточки диалога. Границу она не
            обозначала: переключатель и так виден, а лишний контур делал форму
            многослойной. Ссылка подключения — обычное поле формы, а не
            отдельный блок. */}
        {isSingBox ? (
          <div className="grid gap-4">
            {!singBoxAvailable && sourceMode !== "file" && !nativeUriActive ? (
              <Alert variant="destructive">
                <AlertTitle>{t("transports.singBoxMissing.title")}</AlertTitle>
                <AlertDescription className="space-y-2">
                  <p>{t("transports.singBoxMissing.description")}</p>
                  <code className="block rounded bg-muted p-2 text-xs break-all text-foreground">
                    sh -c &quot;$(curl -fsSL
                    https://raw.githubusercontent.com/blindtechnique/keen-pbr-sb/main/install.sh)&quot;
                  </code>
                </AlertDescription>
              </Alert>
            ) : null}
            <SegmentedControl
              ariaLabel={t("transports.form.sourceMode")}
              onChange={selectSourceMode}
              options={TRANSPORT_SOURCE_MODE_ORDER.filter(
                (mode) => !initial || mode !== "file"
              ).map((mode) => {
                if (mode === "link") {
                  return {
                    value: mode,
                    label: t("transports.form.shareLink"),
                    icon: LinkIcon,
                  }
                }
                if (mode === "file") {
                  return {
                    value: mode,
                    label: t("transports.form.importFile"),
                    icon: FileUpIcon,
                  }
                }
                return {
                  value: mode,
                  label: t("transports.form.outboundJson"),
                  icon: BracesIcon,
                }
              })}
              value={sourceMode}
            />
            {sourceMode === "link" ? (
              <>
                <NativeWireGuardImportFields
                  displayName={
                    displayNameError ? undefined : spec.display_name?.trim()
                  }
                  existingInterfaces={nativeImportInterfaces}
                  key={nativeImportFieldsStateBoundaryKey("link")}
                  linkRequired={!initial}
                  linkValue={spec.link ?? ""}
                  mode="link"
                  onAliasSuggestionChange={setNativeImportAliasSuggestion}
                  onImportHandedOff={finishHandedOffNativeImport}
                  onImportPending={stageCurrentNativeImportCompletion}
                  onLinkChange={(value) =>
                    setSpec((current) =>
                      withAutomaticTechnicalIdentity({
                        ...current,
                        link: value,
                      })
                    )
                  }
                  onNativeUriActiveChange={setNativeUriActive}
                  onImportedIdentityChange={useImportedNativeIdentity}
                  readiness={nativeImportReadiness}
                  requiredGuards={nativeImportRequiredGuards}
                />
                {/* A share link carries its protocol in the scheme; a
                  subscription is an ordinary web address. That is the whole
                  difference, so the field takes either and this offer appears
                  when the operator has pasted the second kind. */}
                {classifyPastedLink(spec.link ?? "") === "subscription" ? (
                  <div className="flex flex-wrap items-center gap-2 rounded-md border border-dashed p-3">
                    <p className="text-sm text-muted-foreground">
                      {t("transports.form.subscriptionDetected")}
                    </p>
                    <Button
                      onClick={() =>
                        setSubscriptionSeed({ url: (spec.link ?? "").trim() })
                      }
                      size="sm"
                      type="button"
                      variant="outline"
                    >
                      {t("transports.subscriptionImport.open")}
                    </Button>
                  </div>
                ) : null}
              </>
            ) : sourceMode === "file" ? (
              <NativeWireGuardImportFields
                displayName={
                  displayNameError ? undefined : spec.display_name?.trim()
                }
                existingInterfaces={nativeImportInterfaces}
                key={nativeImportFieldsStateBoundaryKey("file")}
                mode="file"
                onAliasSuggestionChange={setNativeImportAliasSuggestion}
                onImportHandedOff={finishHandedOffNativeImport}
                onImportPending={stageCurrentNativeImportCompletion}
                onSubscriptionDocument={(text) =>
                  setSubscriptionSeed({ document: text })
                }
                onImportedIdentityChange={useImportedNativeIdentity}
                readiness={nativeImportReadiness}
                requiredGuards={nativeImportRequiredGuards}
              />
            ) : (
              <Field label={t("transports.form.outboundJson")}>
                {/* Та же высота, что у ссылки подключения: разные высоты
                    читались как разные по важности поля (замечание
                    владельца). Textarea растягивается вручную при нужде. */}
                <Textarea
                  className="min-h-28 font-mono text-xs"
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
          {t(nativeImportPreviewOnly ? "common.close" : "common.cancel")}
        </Button>
        {!nativeImportPreviewOnly ? (
          <Button
            disabled={
              isPending ||
              !isDirty ||
              Boolean(displayNameError) ||
              nativeSelectionInvalid ||
              geoSelectionInvalid
            }
            size="xl"
            type="submit"
          >
            {isPending
              ? t("transports.form.saving")
              : t("transports.form.save")}
          </Button>
        ) : null}
      </div>
      {/* Seeded, so the operator is not asked for the subscription a second
          time: the modal already has what they gave it. */}
      <SubscriptionImportDialog
        onOpenChange={(next) => {
          if (!next) setSubscriptionSeed(null)
        }}
        open={subscriptionSeed !== null}
        {...(subscriptionSeed ? { seed: subscriptionSeed } : {})}
      />
    </form>
  )
}

function Field({
  children,
  hint,
  label,
}: {
  children: ReactNode
  /** Знак вопроса рядом с подписью — например, «что такое kill-switch». */
  hint?: ReactNode
  label: string
}) {
  return (
    <div className="grid gap-1.5">
      {hint ? (
        <div className="flex items-center gap-1">
          <Label>{label}</Label>
          {hint}
        </div>
      ) : (
        <Label>{label}</Label>
      )}
      {children}
    </div>
  )
}

function killSwitchOptionLabel(
  option: TransportKillSwitchOption,
  t: (key: string) => string
): string {
  if (option === "default") {
    return t("pages.outboundUpsert.strictEnforcement.default")
  }
  return option === "enabled" ? t("common.enabled") : t("common.disabled")
}

function normalizeEndpointSuggestion(value: string) {
  const normalized = value.trim().replace(/^\[|\]$/g, "")
  if (validateDisplayName(normalized)) {
    return undefined
  }
  return normalized
}
