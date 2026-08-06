import { Plus } from "lucide-react"
import { useEffect, useId, useState } from "react"
import { useTranslation } from "react-i18next"

import { revalidateLogic, useForm } from "@tanstack/react-form"
import { useQueryClient } from "@tanstack/react-query"
import { useStore } from "@tanstack/react-store"
import { useLocation } from "wouter"

import type { ApiError } from "@/api/client"
import type { ConfigObject } from "@/api/generated/model/configObject"
import type { Outbound } from "@/api/generated/model/outbound"
import type { RuntimeInterfaceInventoryEntry } from "@/api/generated/model/runtimeInterfaceInventoryEntry"
import { usePostConfigMutation } from "@/api/mutations"
import { getOutboundDeleteImpactItems } from "@/components/delete-impact/outbound-items"
import { UpsertDeleteAction } from "@/components/shared/upsert-delete-action"
import {
  buildUpdatedConfigForOutboundsDelete,
  getOutboundDeleteImpact,
  isSystemOutboundType,
} from "@/pages/outbounds-utils"
import { queryKeys } from "@/api/query-keys"
import {
  useGetConfig,
  useGetNdmsInterfaceInventory,
  useGetRuntimeInterfaces,
} from "@/api/queries"
import {
  findOutboundByTag,
  selectConfig,
  selectOutbounds,
} from "@/api/selectors"
import {
  Field,
  FieldContent,
  FieldGroup,
  FieldHint,
  FieldLabel,
} from "@/components/shared/field"
import {
  InterfacePicker,
  OutboundInterfaceLabel,
} from "@/components/shared/interface-picker"
import { MultiSelectList } from "@/components/shared/multi-select-list"
import { OrderedGroupCard } from "@/components/shared/ordered-group-card"
import { AdvancedSection } from "@/components/shared/advanced-section"
import { SectionCard } from "@/components/shared/section-card"
import { ServerValidationAlert } from "@/components/shared/server-validation-alert"
import {
  UpsertPage,
  type UpsertPagePresentation,
} from "@/components/shared/upsert-page"
import { useUpsertPageClose } from "@/components/shared/upsert-page-context"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  clearFormServerErrors,
  setFormServerErrors,
  splitFormApiErrors,
} from "@/lib/form-api-errors"
import { getTagNameValidationError } from "@/lib/tag-name-validation"
import { getInterfaceSearchText } from "@/lib/runtime-interfaces"
import {
  getOutboundDisplayName,
  getOutboundSelectDisplayName,
  sortOutboundsByDisplayName,
} from "@/lib/outbound-display"
import { useInterfaceDisplayNames } from "@/hooks/use-interface-display-names"
import { semanticJsonEqual } from "@/lib/semantic-json"
import { makeTechnicalId } from "@/lib/technical-id"
import { useInterfaceProtocols } from "@/hooks/use-interface-protocols"
import { excludeIngressServerInterfaces } from "@/lib/native-interfaces"
import {
  createDefaultOutboundDraft,
  mapOutboundToDraft,
  normalizeOutboundDraftForPersistence,
  normalizeOutboundGroups,
  type ConntrackOnSwitchMode,
  type OutboundDraft,
  type OutboundGroupDraft,
  type StrictEnforcementOption,
  type UrltestSelectionMode,
} from "@/pages/outbound-upsert-utils"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"

const OUTBOUND_FIELD_NAMES = {
  displayName: "displayName",
  tag: "tag",
  type: "type",
  interfaceName: "interfaceName",
  gateway: "gateway",
  gateway6: "gateway6",
  table: "table",
  outboundGroups: "outboundGroups",
  probeUrl: "probeUrl",
  interval: "interval",
  probeTimeout: "probeTimeout",
  tolerance: "tolerance",
  selectionMode: "selectionMode",
  conntrackOnSwitch: "conntrackOnSwitch",
  retryAttempts: "retryAttempts",
  retryInterval: "retryInterval",
  circuitBreakerFailures: "circuitBreakerFailures",
  circuitBreakerSuccesses: "circuitBreakerSuccesses",
  circuitBreakerTimeout: "circuitBreakerTimeout",
  circuitBreakerHalfOpen: "circuitBreakerHalfOpen",
  strictEnforcement: "strictEnforcement",
} as const

type OutboundFieldName =
  (typeof OUTBOUND_FIELD_NAMES)[keyof typeof OUTBOUND_FIELD_NAMES]

const sampleNewOutbound = createDefaultOutboundDraft()

const strictOptions = [
  "default",
  "enabled",
  "disabled",
] as const satisfies readonly StrictEnforcementOption[]

const urltestSelectionModes = [
  "latency",
  "priority",
] as const satisfies readonly UrltestSelectionMode[]

const conntrackOnSwitchModes = [
  "preserve",
  "delete_on_failure",
  "delete",
] as const satisfies readonly ConntrackOnSwitchMode[]

const outboundTypeOptions: Outbound["type"][] = [
  "interface",
  "table",
  "blackhole",
  "ignore",
  "urltest",
]

export function OutboundUpsertPage({
  mode,
  outboundId,
  presentation = "page",
}: {
  mode: "create" | "edit"
  outboundId?: string
  presentation?: UpsertPagePresentation
}) {
  const { t } = useTranslation()
  const [, navigate] = useLocation()
  const [dirty, setDirty] = useState(false)
  const configQuery = useGetConfig()
  const loadedConfig = selectConfig(configQuery.data)

  if (!loadedConfig) {
    return (
      <UpsertPage
        cardDescription={t("pages.outboundUpsert.cardDescription")}
        cardTitle={
          mode === "create"
            ? t("pages.outboundUpsert.createTitle")
            : t("pages.outboundUpsert.editTitle")
        }
        description={t("pages.outboundUpsert.description")}
        onClose={() => navigate("/outbounds")}
        presentation={presentation}
        title={
          mode === "create"
            ? t("pages.outboundUpsert.createTitle")
            : t("pages.outboundUpsert.editTitle")
        }
      >
        <div className="space-y-3">
          <div className="h-8 rounded-lg bg-muted" />
          <div className="h-24 rounded-lg bg-muted" />
          <div className="h-8 rounded-lg bg-muted" />
          <div className="h-8 rounded-lg bg-muted" />
        </div>
      </UpsertPage>
    )
  }

  const draft =
    getOutboundDraft(loadedConfig, mode === "edit" ? outboundId : undefined) ??
    getCreateDraftFromLocation()

  if (
    mode === "edit" &&
    outboundId &&
    !findOutboundByTag(loadedConfig, outboundId)
  ) {
    return (
      <UpsertPage
        cardDescription={t("pages.outboundUpsert.missing.cardDescription")}
        cardTitle={t("pages.outboundUpsert.missing.cardTitle")}
        description={t("pages.outboundUpsert.missing.description")}
        onClose={() => navigate("/outbounds")}
        presentation={presentation}
        title={t("pages.outboundUpsert.editTitle")}
      >
        <div className="flex justify-end">
          <Button onClick={() => navigate("/outbounds")} variant="outline">
            {t("pages.outboundUpsert.missing.back")}
          </Button>
        </div>
      </UpsertPage>
    )
  }

  return (
    <UpsertPage
      cardDescription={t(
        draft.type === "urltest"
          ? "pages.outboundUpsert.groupCardDescription"
          : "pages.outboundUpsert.cardDescription"
      )}
      cardTitle={
        mode === "create"
          ? t(
              draft.type === "urltest"
                ? "pages.outboundUpsert.createGroupTitle"
                : "pages.outboundUpsert.createTitle"
            )
          : t("pages.outboundUpsert.editCardTitle", {
              tag: getOutboundDisplayName(
                findOutboundByTag(loadedConfig, draft.tag) ?? {
                  type: draft.type,
                  tag: draft.tag,
                  display_name: draft.displayName,
                }
              ),
            })
      }
      description={t("pages.outboundUpsert.description")}
      dirty={dirty}
      onClose={() => navigate(outboundReturnHref(draft.type))}
      presentation={presentation}
      title={
        mode === "create"
          ? t(
              draft.type === "urltest"
                ? "pages.outboundUpsert.createGroupTitle"
                : "pages.outboundUpsert.createTitle"
            )
          : t(
              draft.type === "urltest"
                ? "pages.outboundUpsert.editGroupTitle"
                : "pages.outboundUpsert.editTitle"
            )
      }
    >
      <OutboundForm
        key={`${mode}:${outboundId ?? "new"}`}
        draft={draft}
        loadedConfig={loadedConfig}
        mode={mode}
        onDirtyChange={setDirty}
        outboundId={outboundId}
        presentation={presentation}
      />
    </UpsertPage>
  )
}

/**
 * Куда возвращаться после закрытия формы: группа живёт на вкладке «Группы»,
 * системные направления — на «Системных». Раньше любое закрытие вело на
 * вкладку туннелей, и человек, добавлявший группу, оказывался не там, где был.
 */
function outboundReturnHref(type: Outbound["type"]): string {
  if (type === "urltest") {
    return "/outbounds#failover"
  }
  if (type !== "interface") {
    return "/outbounds#system"
  }
  return "/outbounds"
}

function getCreateDraftFromLocation(): OutboundDraft {
  if (typeof window === "undefined") {
    return sampleNewOutbound
  }
  const params = new URLSearchParams(window.location.search)
  const requestedType = params.get("type")
  const type = outboundTypeOptions.includes(requestedType as Outbound["type"])
    ? (requestedType as Outbound["type"])
    : sampleNewOutbound.type
  return {
    ...sampleNewOutbound,
    type,
    interfaceName:
      type === "interface"
        ? (params.get("interface") ?? sampleNewOutbound.interfaceName)
        : sampleNewOutbound.interfaceName,
  }
}

function OutboundForm({
  mode,
  draft,
  loadedConfig,
  onCancel,
  onDirtyChange,
  onSaved,
  outboundId,
  presentation = "page",
}: {
  mode: "create" | "edit"
  draft: OutboundDraft
  loadedConfig: ConfigObject
  onCancel?: () => void
  onDirtyChange?: (dirty: boolean) => void
  onSaved?: () => void
  outboundId?: string
  presentation?: UpsertPagePresentation
}) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [, navigate] = useLocation()
  const close = useUpsertPageClose()
  const existingOutbounds = selectOutbounds(loadedConfig)
  const [initialDraft] = useState<OutboundDraft>(() => draft)
  const [technicalIdManuallyEdited, setTechnicalIdManuallyEdited] =
    useState(false)
  const runtimeInterfacesQuery = useGetRuntimeInterfaces()
  const ndmsInventoryQuery = useGetNdmsInterfaceInventory()
  // Входящие VPN-серверы прошивки из выбора убраны: направить исходящий
  // трафик в интерфейс, который принимает чужие подключения, нельзя.
  const runtimeInterfaces = excludeIngressServerInterfaces(
    runtimeInterfacesQuery.data?.status === 200
      ? runtimeInterfacesQuery.data.data.interfaces
      : [],
    ndmsInventoryQuery.data?.status === 200 &&
      ndmsInventoryQuery.data.data.available
      ? ndmsInventoryQuery.data.data.interfaces
      : []
  )
  const { protocolOf } = useInterfaceProtocols()
  const runtimeInterfaceByName = new Map(
    runtimeInterfaces.map((runtimeInterface) => [
      runtimeInterface.name,
      runtimeInterface,
    ])
  )
  // A failover group may contain plain interfaces as well as other failover
  // groups; routing resolves nested selections down to a leaf interface.
  // Сортировка по имени: раз туннель=маршрут, участников группы ищут по
  // имени туннеля, и список должен идти в том же порядке, что и таблица.
  const groupMemberCandidates = sortOutboundsByDisplayName(
    existingOutbounds.filter(
      (item) =>
        (item.type === "interface" || item.type === "urltest") &&
        item.tag !== initialDraft.tag
    )
  )
  const interfaceOutboundByTag = new Map(
    groupMemberCandidates.map((item) => [item.tag, item])
  )
  const interfaceOutboundOptions = groupMemberCandidates.map((item) => item.tag)
  const { labelFor: interfaceLabelFor } = useInterfaceDisplayNames()
  // Имя туннеля для участника группы: имя маршрута, затем имя туннеля по
  // интерфейсу (управляемого или KeeneticOS), тег — последний запасной.
  const groupMemberLabel = (tag: string) => {
    const outbound = interfaceOutboundByTag.get(tag)
    return outbound
      ? getOutboundSelectDisplayName(outbound, interfaceLabelFor)
      : tag
  }
  const strictSelectItems = strictOptions.map((option) => ({
    value: option,
    label: getStrictOptionLabel(option, t),
  }))
  const [baselinePayload] = useState(() =>
    normalizeOutboundDraftForPersistence(initialDraft)
  )

  const form = useForm({
    defaultValues: initialDraft,
    validationLogic: revalidateLogic({
      mode: "submit",
      modeAfterSubmission: "change",
    }),
    validators: {
      onSubmitAsync: async ({ value }) => {
        clearFormServerErrors(form)
        const displayNameError = getDisplayNameError(value.displayName, t)
        if (displayNameError) {
          setFormServerErrors(form, {
            fields: {
              [OUTBOUND_FIELD_NAMES.displayName]: displayNameError,
            },
          })
          return {
            fields: {
              [OUTBOUND_FIELD_NAMES.displayName]: displayNameError,
            },
          }
        }

        const valueToPersist =
          mode === "create" && !value.tag.trim()
            ? {
                ...value,
                tag: makeTechnicalId(
                  value.displayName,
                  existingOutbounds.map((outbound) => outbound.tag),
                  { prefix: "outbound" }
                ),
              }
            : value
        const tagError = getOutboundTagError(
          valueToPersist.tag,
          existingOutbounds,
          mode === "edit" ? outboundId : undefined,
          t
        )
        if (tagError) {
          setFormServerErrors(form, {
            fields: {
              [OUTBOUND_FIELD_NAMES.tag]: tagError,
            },
          })
          return {
            fields: {
              [OUTBOUND_FIELD_NAMES.tag]: tagError,
            },
          }
        }

        const payload = normalizeOutboundDraftForPersistence(valueToPersist)
        const nextOutbounds =
          mode === "create"
            ? [...existingOutbounds, payload]
            : existingOutbounds.map((outbound) =>
                outbound.tag === outboundId ? payload : outbound
              )

        const urltestReferencesError = validateUrltestGroupReferences(
          nextOutbounds,
          t
        )
        if (urltestReferencesError) {
          setFormServerErrors(form, {
            form: urltestReferencesError,
            fields: {},
          })
          return {
            form: urltestReferencesError,
            fields: {},
          }
        }

        try {
          await postConfigMutation.mutateAsync({
            data: {
              ...loadedConfig,
              outbounds: nextOutbounds,
            } satisfies ConfigObject,
          })
          clearFormServerErrors(form)
          await Promise.all([
            queryClient.invalidateQueries({ queryKey: queryKeys.config() }),
            queryClient.invalidateQueries({
              queryKey: queryKeys.healthService(),
            }),
            queryClient.invalidateQueries({
              queryKey: queryKeys.healthRouting(),
            }),
          ])
          if (onSaved) onSaved()
          else navigate(outboundReturnHref(valueToPersist?.type ?? draft.type))
          return undefined
        } catch (error) {
          const result = splitFormApiErrors({
            error: error as ApiError,
            fieldNames: Object.values(OUTBOUND_FIELD_NAMES),
            resolvePath: (path) =>
              resolveOutboundFieldPath(path, payload.tag || initialDraft.tag),
          })

          setFormServerErrors(form, {
            form: result.formError ?? undefined,
            fields: result.fieldErrors,
            unmapped: result.unmappedErrors,
          })

          return {
            form: result.formError ?? undefined,
            fields: result.fieldErrors,
          }
        }
      },
    },
  })

  const postConfigMutation = usePostConfigMutation()

  // Удаление из формы. Системные wan и block удалить нельзя — как и в таблице,
  // где их отфильтровывает filterDeletableOutboundTags; для них кнопки нет.
  const existingOutbound =
    mode === "edit" && outboundId
      ? loadedConfig.outbounds?.find((outbound) => outbound.tag === outboundId)
      : undefined
  const deletableFromForm = Boolean(
    existingOutbound && !isSystemOutboundType(existingOutbound.type)
  )
  const handleDelete = () => {
    if (!loadedConfig || !outboundId || !deletableFromForm) {
      return
    }

    postConfigMutation.mutate(
      {
        data: buildUpdatedConfigForOutboundsDelete(loadedConfig, [outboundId]),
      },
      {
        onSuccess: () => {
          navigate(outboundReturnHref(existingOutbound?.type ?? draft.type))
        },
      }
    )
  }

  const outboundType = useStore(form.store, (state) => state.values.type)
  const apiErrorMessage = useStore(
    form.store,
    (state) =>
      (state.errorMap.onServer as { form?: string } | undefined)?.form ?? null
  )
  const unmappedServerErrors = useStore(
    form.store,
    (state) =>
      (
        state.errorMap.onServer as
          | { unmapped?: { path: string; message: string }[] }
          | undefined
      )?.unmapped ?? []
  )
  const isDirty = useStore(
    form.store,
    (state) =>
      !semanticJsonEqual(
        normalizeOutboundDraftForPersistence(state.values),
        baselinePayload
      )
  )
  const canSubmit = useStore(form.store, (state) => state.canSubmit)

  useEffect(() => {
    onDirtyChange?.(isDirty)
  }, [isDirty, onDirtyChange])

  const isInterface = outboundType === "interface"
  const isTable = outboundType === "table"
  const isBlackhole = outboundType === "blackhole"
  const isIgnore = outboundType === "ignore"
  const isUrltest = outboundType === "urltest"
  const displayNameId = useId()
  const tagId = useId()
  const interfaceId = useId()
  const gatewayId = useId()
  const gateway6Id = useId()
  const tableId = useId()
  const probeUrlId = useId()
  const intervalId = useId()
  const probeTimeoutId = useId()
  const toleranceId = useId()
  const groupWeightId = useId()
  const retryAttemptsId = useId()
  const retryIntervalId = useId()
  const circuitBreakerFailuresId = useId()
  const circuitBreakerSuccessesId = useId()
  const circuitBreakerTimeoutId = useId()
  const circuitBreakerHalfOpenId = useId()

  return (
    <form
      className="space-y-6"
      onSubmit={(event) => {
        event.preventDefault()
        void form.handleSubmit()
      }}
    >
      {apiErrorMessage ? (
        <Alert className="border-destructive/30 bg-destructive/5 text-destructive">
          <AlertDescription className="whitespace-pre-wrap">
            {apiErrorMessage}
          </AlertDescription>
        </Alert>
      ) : null}

      {/* Название, технический ID и тип — на всю ширину формы (решение
          владельца): это главные поля, узкая колонка им не по чину. */}
      <FieldGroup>
        <form.Field
          name={OUTBOUND_FIELD_NAMES.displayName}
          validators={{
            onChange: ({ value }) => getDisplayNameError(value, t) ?? undefined,
          }}
        >
          {(field) => {
            const error = getFirstFieldError(field.state.meta.errors)
            return (
              <Field invalid={Boolean(error)}>
                <FieldLabel htmlFor={displayNameId}>
                  {t("pages.outboundUpsert.fields.displayName")}
                </FieldLabel>
                <FieldContent>
                  <Input
                    aria-invalid={Boolean(error)}
                    id={displayNameId}
                    onBlur={field.handleBlur}
                    onChange={(event) => {
                      const nextDisplayName = event.target.value
                      field.handleChange(nextDisplayName)
                      if (
                        mode === "create" &&
                        (presentation === "dialog" ||
                          !technicalIdManuallyEdited)
                      ) {
                        form.setFieldValue(
                          OUTBOUND_FIELD_NAMES.tag,
                          makeTechnicalId(
                            nextDisplayName,
                            existingOutbounds.map((outbound) => outbound.tag),
                            { prefix: "outbound" }
                          )
                        )
                      }
                    }}
                    value={field.state.value}
                  />
                  <FieldHint
                    description={t(
                      "pages.outboundUpsert.fields.displayNameHint"
                    )}
                    error={error ?? null}
                  />
                </FieldContent>
              </Field>
            )
          }}
        </form.Field>

        {presentation === "page" ? (
          <form.Field
            name={OUTBOUND_FIELD_NAMES.tag}
            validators={{
              onChange: ({ value }) =>
                getOutboundTagError(
                  value,
                  existingOutbounds,
                  mode === "edit" ? outboundId : undefined,
                  t
                ) ?? undefined,
            }}
          >
            {(field) => {
              const error = getFirstFieldError(field.state.meta.errors)
              return (
                <Field invalid={Boolean(error)}>
                  <FieldLabel htmlFor={tagId}>
                    {t("pages.outboundUpsert.fields.technicalId")}
                  </FieldLabel>
                  <FieldContent>
                    <Input
                      aria-invalid={Boolean(error)}
                      id={tagId}
                      onBlur={field.handleBlur}
                      onChange={(event) => {
                        setTechnicalIdManuallyEdited(true)
                        field.handleChange(event.target.value)
                      }}
                      readOnly={mode === "edit"}
                      value={field.state.value}
                    />
                    <FieldHint
                      description={t(
                        "pages.outboundUpsert.fields.technicalIdHint"
                      )}
                      error={error ?? null}
                    />
                  </FieldContent>
                </Field>
              )
            }}
          </form.Field>
        ) : null}

        {/*
         * Выбор типа живёт только в расширенном редакторе: в упрощённом
         * диалоге тип задан кнопкой, которой человек его открыл («Добавить
         * туннель» / «Добавить группу»), и лишний селект здесь только путает.
         */}
        {presentation === "page" ? (
          <form.Field name={OUTBOUND_FIELD_NAMES.type}>
            {(field) => {
              const error = getFirstFieldError(field.state.meta.errors)
              return (
                <Field invalid={Boolean(error)}>
                  <FieldLabel>
                    {t("pages.outboundUpsert.fields.type")}
                  </FieldLabel>
                  <FieldContent>
                    <Select
                      items={outboundTypeOptions.map((type) => ({
                        value: type,
                        label: t(
                          `pages.outboundUpsert.fields.typeOptions.${type}`
                        ),
                      }))}
                      onValueChange={(value) =>
                        field.handleChange(
                          (value as Outbound["type"]) ?? initialDraft.type
                        )
                      }
                      value={field.state.value}
                    >
                      <SelectTrigger aria-invalid={Boolean(error)}>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          <SelectLabel>
                            {t("pages.outboundUpsert.fields.outboundTypes")}
                          </SelectLabel>
                          {outboundTypeOptions.map((option) => (
                            <SelectItem key={option} value={option}>
                              {t(
                                `pages.outboundUpsert.fields.typeOptions.${option}`
                              )}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                    <FieldHint error={error ?? null} />
                  </FieldContent>
                </Field>
              )
            }}
          </form.Field>
        ) : null}
      </FieldGroup>

      {isInterface ? (
        <SectionCard
          flat
          description={t("pages.outboundUpsert.interface.description")}
          title={t("pages.outboundUpsert.interface.title")}
        >
          <FieldGroup className="gap-4" width="short">
            <form.Field name={OUTBOUND_FIELD_NAMES.interfaceName}>
              {(field) => {
                const error = getFirstFieldError(field.state.meta.errors)
                return (
                  <Field invalid={Boolean(error)}>
                    <FieldLabel htmlFor={interfaceId}>
                      {t("pages.outboundUpsert.interface.interface")}
                    </FieldLabel>
                    <FieldContent>
                      <InterfacePicker
                        allowCustomOption
                        id={interfaceId}
                        interfaces={runtimeInterfaces}
                        invalid={Boolean(error)}
                        onChange={field.handleChange}
                        onSelect={field.handleChange}
                        placeholder={t(
                          "pages.outboundUpsert.interface.interfacePlaceholder"
                        )}
                        protocolOf={protocolOf}
                        renderSelectedInline
                        showDetails={false}
                        value={field.state.value}
                      />
                      <FieldHint
                        description={t(
                          "pages.outboundUpsert.interface.interfaceHint"
                        )}
                        error={error ?? null}
                      />
                    </FieldContent>
                  </Field>
                )
              }}
            </form.Field>

            <form.Field name={OUTBOUND_FIELD_NAMES.gateway}>
              {(field) => {
                const error = getFirstFieldError(field.state.meta.errors)
                return (
                  <Field invalid={Boolean(error)}>
                    <FieldLabel htmlFor={gatewayId}>
                      {t("pages.outboundUpsert.interface.gateway")}
                    </FieldLabel>
                    <FieldContent>
                      <Input
                        aria-invalid={Boolean(error)}
                        id={gatewayId}
                        onBlur={field.handleBlur}
                        onChange={(event) =>
                          field.handleChange(event.target.value)
                        }
                        value={field.state.value}
                      />
                      <FieldHint
                        description={t(
                          "pages.outboundUpsert.interface.gatewayHint"
                        )}
                        error={error ?? null}
                      />
                    </FieldContent>
                  </Field>
                )
              }}
            </form.Field>

            <form.Field name={OUTBOUND_FIELD_NAMES.gateway6}>
              {(field) => {
                const error = getFirstFieldError(field.state.meta.errors)
                return (
                  <Field invalid={Boolean(error)}>
                    <FieldLabel htmlFor={gateway6Id}>
                      {t("pages.outboundUpsert.interface.gateway6")}
                    </FieldLabel>
                    <FieldContent>
                      <Input
                        aria-invalid={Boolean(error)}
                        id={gateway6Id}
                        onBlur={field.handleBlur}
                        onChange={(event) =>
                          field.handleChange(event.target.value)
                        }
                        value={field.state.value}
                      />
                      <FieldHint
                        description={t(
                          "pages.outboundUpsert.interface.gateway6Hint"
                        )}
                        error={error ?? null}
                      />
                    </FieldContent>
                  </Field>
                )
              }}
            </form.Field>
          </FieldGroup>
        </SectionCard>
      ) : null}

      {isTable ? (
        <SectionCard
          flat
          description={t("pages.outboundUpsert.table.description")}
          title={t("pages.outboundUpsert.table.title")}
        >
          <FieldGroup width="short">
            <form.Field name={OUTBOUND_FIELD_NAMES.table}>
              {(field) => {
                const error = getFirstFieldError(field.state.meta.errors)
                return (
                  <Field invalid={Boolean(error)}>
                    <FieldLabel htmlFor={tableId}>
                      {t("pages.outboundUpsert.table.field")}
                    </FieldLabel>
                    <FieldContent>
                      <Input
                        aria-invalid={Boolean(error)}
                        id={tableId}
                        onBlur={field.handleBlur}
                        onChange={(event) =>
                          field.handleChange(event.target.value)
                        }
                        value={field.state.value}
                      />
                      <FieldHint
                        description={t("pages.outboundUpsert.table.hint")}
                        error={error ?? null}
                      />
                    </FieldContent>
                  </Field>
                )
              }}
            </form.Field>
          </FieldGroup>
        </SectionCard>
      ) : null}

      {isBlackhole ? (
        <SectionCard
          flat
          description={t("pages.outboundUpsert.blackhole.description")}
          title={t("pages.outboundUpsert.blackhole.title")}
        >
          <p className="text-sm text-muted-foreground md:text-xs">
            {t("pages.outboundUpsert.common.noExtraFields")}
          </p>
        </SectionCard>
      ) : null}

      {isIgnore ? (
        <SectionCard
          flat
          description={t("pages.outboundUpsert.ignore.description")}
          title={t("pages.outboundUpsert.ignore.title")}
        >
          <p className="text-sm text-muted-foreground md:text-xs">
            {t("pages.outboundUpsert.common.noExtraFields")}
          </p>
        </SectionCard>
      ) : null}

      {isUrltest ? (
        <form.Field name={OUTBOUND_FIELD_NAMES.outboundGroups}>
          {(field) => {
            const error = getFirstFieldError(field.state.meta.errors)
            const groups = normalizeOutboundGroups(field.state.value)
            return (
              <SectionCard
                flat
                description={t(
                  "pages.outboundUpsert.urltest.groupsDescription"
                )}
                title={t("pages.outboundUpsert.urltest.groupsTitle")}
              >
                <div className="space-y-4">
                  {groups.map((group, index) => (
                    <OrderedGroupCard
                      canMoveDown={index !== groups.length - 1}
                      canMoveUp={index !== 0}
                      canRemove={groups.length !== 1}
                      description={t(
                        "pages.outboundUpsert.urltest.groupDescription",
                        { index: index + 1 }
                      )}
                      key={`${index}-${group.outbounds.join(",")}`}
                      onMoveDown={() =>
                        field.handleChange(moveGroup(groups, index, index + 1))
                      }
                      onMoveUp={() =>
                        field.handleChange(moveGroup(groups, index, index - 1))
                      }
                      onRemove={() =>
                        field.handleChange(
                          groups.length === 1
                            ? groups
                            : normalizeOutboundGroups(
                                groups.filter(
                                  (_, currentIndex) => currentIndex !== index
                                )
                              )
                        )
                      }
                      title={t("pages.outboundUpsert.urltest.groupTitle", {
                        index: index + 1,
                      })}
                    >
                      <div className="grid gap-4 md:grid-cols-[minmax(0,1fr)_10rem]">
                        <Field invalid={Boolean(error)}>
                          <FieldLabel>
                            {t(
                              "pages.outboundUpsert.urltest.interfaceOutbounds"
                            )}
                          </FieldLabel>
                          <FieldContent>
                            {interfaceOutboundOptions.length ? (
                              <MultiSelectList
                                error={error}
                                name={OUTBOUND_FIELD_NAMES.outboundGroups}
                                addLabel={t(
                                  "pages.outboundUpsert.urltest.addOutbound"
                                )}
                                emptyMessage={t(
                                  "pages.outboundUpsert.urltest.noInterfaceOutbounds"
                                )}
                                groupLabel={t(
                                  "pages.outboundUpsert.urltest.interfaceOutbounds"
                                )}
                                onChange={(nextOutbounds) =>
                                  field.handleChange(
                                    groups.map((item, itemIndex) =>
                                      itemIndex === index
                                        ? {
                                            ...item,
                                            outbounds: nextOutbounds,
                                          }
                                        : item
                                    )
                                  )
                                }
                                options={interfaceOutboundOptions}
                                getSearchText={(tag) =>
                                  getInterfaceOutboundSearchText(
                                    tag,
                                    interfaceOutboundByTag.get(tag)?.interface,
                                    runtimeInterfaceByName,
                                    groupMemberLabel(tag)
                                  )
                                }
                                renderItem={(tag) => (
                                  <OutboundInterfaceLabel
                                    interfaceName={
                                      interfaceOutboundByTag.get(tag)?.interface
                                    }
                                    label={groupMemberLabel(tag)}
                                    runtimeInterface={runtimeInterfaceByName.get(
                                      interfaceOutboundByTag.get(tag)
                                        ?.interface ?? ""
                                    )}
                                    t={t}
                                    tag={tag}
                                  />
                                )}
                                unavailable={getUnavailableOutbounds(
                                  groups,
                                  index
                                )}
                                value={group.outbounds}
                              />
                            ) : (
                              <div className="text-sm text-muted-foreground md:text-xs">
                                {t(
                                  "pages.outboundUpsert.urltest.addInterfaceOutboundsFirst"
                                )}
                              </div>
                            )}
                            {interfaceOutboundOptions.length ? (
                              <FieldHint error={error ?? null} />
                            ) : null}
                          </FieldContent>
                        </Field>

                        <Field>
                          <FieldLabel htmlFor={`${groupWeightId}-${index}`}>
                            {t("pages.outboundUpsert.urltest.groupWeight")}
                          </FieldLabel>
                          <FieldContent>
                            <Input
                              id={`${groupWeightId}-${index}`}
                              inputMode="numeric"
                              onChange={(event) =>
                                field.handleChange(
                                  groups.map((item, itemIndex) =>
                                    itemIndex === index
                                      ? {
                                          ...item,
                                          weight: event.target.value,
                                        }
                                      : item
                                  )
                                )
                              }
                              placeholder="1"
                              step="1"
                              type="number"
                              value={group.weight}
                            />
                            <FieldHint
                              description={t(
                                "pages.outboundUpsert.urltest.groupWeightHint"
                              )}
                            />
                          </FieldContent>
                        </Field>
                      </div>
                    </OrderedGroupCard>
                  ))}
                  <div className="flex justify-start">
                    <Button
                      onClick={() =>
                        field.handleChange([
                          ...groups,
                          {
                            outbounds: getNextAvailableOutbounds(
                              interfaceOutboundOptions,
                              groups
                            ),
                            weight: "",
                          },
                        ])
                      }
                      type="button"
                      variant="outline"
                    >
                      <Plus className="h-4 w-4" />
                      {t("pages.outboundUpsert.urltest.addGroup")}
                    </Button>
                  </div>
                </div>
              </SectionCard>
            )
          }}
        </form.Field>
      ) : null}

      {isUrltest ? (
        // Режим выбора и судьба активных соединений — не тонкая настройка, а
        // само поведение группы: владелец вернул их наверх из «Дополнительно».
        <div className="grid gap-4 md:grid-cols-2">
          <form.Field name={OUTBOUND_FIELD_NAMES.selectionMode}>
            {(field) => (
              <Field>
                <FieldLabel>
                  {t("pages.outboundUpsert.urltest.selectionMode")}
                </FieldLabel>
                <FieldContent>
                  <Select
                    items={urltestSelectionModes.map((mode) => ({
                      value: mode,
                      label: t(
                        `pages.outboundUpsert.urltest.selectionModeOptions.${mode}`
                      ),
                    }))}
                    onValueChange={(value) => {
                      const nextMode =
                        (value as UrltestSelectionMode | null) ?? "latency"
                      field.handleChange(nextMode)
                      if (
                        nextMode !== "priority" &&
                        form.state.values.conntrackOnSwitch ===
                          "delete_on_failure"
                      ) {
                        form.setFieldValue(
                          OUTBOUND_FIELD_NAMES.conntrackOnSwitch,
                          "preserve"
                        )
                      }
                    }}
                    value={field.state.value}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        {urltestSelectionModes.map((mode) => (
                          <SelectItem key={mode} value={mode}>
                            {t(
                              `pages.outboundUpsert.urltest.selectionModeOptions.${mode}`
                            )}
                          </SelectItem>
                        ))}
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                  <FieldHint
                    description={t(
                      `pages.outboundUpsert.urltest.selectionModeHints.${field.state.value}`
                    )}
                  />
                </FieldContent>
              </Field>
            )}
          </form.Field>

          <form.Field name={OUTBOUND_FIELD_NAMES.conntrackOnSwitch}>
            {(field) => (
              <Field>
                <FieldLabel>
                  {t("pages.outboundUpsert.urltest.conntrackOnSwitch")}
                </FieldLabel>
                <FieldContent>
                  <Select
                    items={conntrackOnSwitchModes.map((mode) => ({
                      value: mode,
                      label: t(
                        `pages.outboundUpsert.urltest.conntrackOnSwitchOptions.${mode}`
                      ),
                    }))}
                    onValueChange={(value) => {
                      const nextMode =
                        (value as ConntrackOnSwitchMode | null) ?? "preserve"
                      field.handleChange(nextMode)
                      if (nextMode === "delete_on_failure") {
                        form.setFieldValue(
                          OUTBOUND_FIELD_NAMES.selectionMode,
                          "priority"
                        )
                      }
                    }}
                    value={field.state.value}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        {conntrackOnSwitchModes.map((mode) => (
                          <SelectItem key={mode} value={mode}>
                            {t(
                              `pages.outboundUpsert.urltest.conntrackOnSwitchOptions.${mode}`
                            )}
                          </SelectItem>
                        ))}
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                  <FieldHint
                    description={t(
                      `pages.outboundUpsert.urltest.conntrackOnSwitchHints.${field.state.value}`
                    )}
                  />
                </FieldContent>
              </Field>
            )}
          </form.Field>
        </div>
      ) : null}

      {isUrltest && presentation === "page" ? (
        // Тонкая настройка живёт только в расширенном редакторе и сразу
        // раскрыта (решение владельца): в диалоге группы её нет вообще —
        // умолчания хороши, а кто пришёл в расширенный редактор, пришёл
        // именно за этими полями, и прятать их от него нечестно.
        <AdvancedSection
          defaultOpen
          hint={t("pages.outboundUpsert.urltest.advancedHint")}
          title={t("pages.outboundUpsert.urltest.advancedTitle")}
        >
          <SectionCard
            flat
            description={t("pages.outboundUpsert.urltest.probingDescription")}
            title={t("pages.outboundUpsert.urltest.probingTitle")}
          >
            <div className="grid gap-4 md:grid-cols-2">
              <form.Field name={OUTBOUND_FIELD_NAMES.probeUrl}>
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)
                  return (
                    <Field invalid={Boolean(error)}>
                      <FieldLabel htmlFor={probeUrlId}>
                        {t("pages.outboundUpsert.urltest.probeUrl")}
                      </FieldLabel>
                      <FieldContent>
                        <Input
                          aria-invalid={Boolean(error)}
                          id={probeUrlId}
                          onBlur={field.handleBlur}
                          onChange={(event) =>
                            field.handleChange(event.target.value)
                          }
                          value={field.state.value}
                        />
                        <FieldHint
                          description={t(
                            "pages.outboundUpsert.urltest.probeUrlHint"
                          )}
                          error={error ?? null}
                        />
                      </FieldContent>
                    </Field>
                  )
                }}
              </form.Field>

              <form.Field name={OUTBOUND_FIELD_NAMES.interval}>
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)
                  return (
                    <Field invalid={Boolean(error)}>
                      <FieldLabel htmlFor={intervalId}>
                        {t("pages.outboundUpsert.urltest.interval")}
                      </FieldLabel>
                      <FieldContent>
                        <Input
                          aria-invalid={Boolean(error)}
                          id={intervalId}
                          onBlur={field.handleBlur}
                          onChange={(event) =>
                            field.handleChange(event.target.value)
                          }
                          value={field.state.value}
                        />
                        <FieldHint
                          description={t(
                            "pages.outboundUpsert.urltest.intervalHint"
                          )}
                          error={error ?? null}
                        />
                      </FieldContent>
                    </Field>
                  )
                }}
              </form.Field>

              <form.Field name={OUTBOUND_FIELD_NAMES.probeTimeout}>
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)
                  return (
                    <Field invalid={Boolean(error)}>
                      <FieldLabel htmlFor={probeTimeoutId}>
                        {t("pages.outboundUpsert.urltest.probeTimeout")}
                      </FieldLabel>
                      <FieldContent>
                        <Input
                          aria-invalid={Boolean(error)}
                          id={probeTimeoutId}
                          inputMode="numeric"
                          onBlur={field.handleBlur}
                          onChange={(event) =>
                            field.handleChange(event.target.value)
                          }
                          step="1"
                          type="number"
                          value={field.state.value}
                        />
                        <FieldHint
                          description={t(
                            "pages.outboundUpsert.urltest.probeTimeoutHint"
                          )}
                          error={error ?? null}
                        />
                      </FieldContent>
                    </Field>
                  )
                }}
              </form.Field>

              <form.Field name={OUTBOUND_FIELD_NAMES.tolerance}>
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)
                  return (
                    <Field invalid={Boolean(error)}>
                      <FieldLabel htmlFor={toleranceId}>
                        {t("pages.outboundUpsert.urltest.tolerance")}
                      </FieldLabel>
                      <FieldContent>
                        <Input
                          aria-invalid={Boolean(error)}
                          id={toleranceId}
                          onBlur={field.handleBlur}
                          onChange={(event) =>
                            field.handleChange(event.target.value)
                          }
                          value={field.state.value}
                        />
                        <FieldHint
                          description={t(
                            "pages.outboundUpsert.urltest.toleranceHint"
                          )}
                          error={error ?? null}
                        />
                      </FieldContent>
                    </Field>
                  )
                }}
              </form.Field>

              <form.Field name={OUTBOUND_FIELD_NAMES.retryAttempts}>
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)
                  return (
                    <Field invalid={Boolean(error)}>
                      <FieldLabel htmlFor={retryAttemptsId}>
                        {t("pages.outboundUpsert.urltest.retryAttempts")}
                      </FieldLabel>
                      <FieldContent>
                        <Input
                          aria-invalid={Boolean(error)}
                          id={retryAttemptsId}
                          onBlur={field.handleBlur}
                          onChange={(event) =>
                            field.handleChange(event.target.value)
                          }
                          value={field.state.value}
                        />
                        <FieldHint
                          description={t(
                            "pages.outboundUpsert.urltest.retryAttemptsHint"
                          )}
                          error={error ?? null}
                        />
                      </FieldContent>
                    </Field>
                  )
                }}
              </form.Field>

              <form.Field name={OUTBOUND_FIELD_NAMES.retryInterval}>
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)
                  return (
                    <Field invalid={Boolean(error)}>
                      <FieldLabel htmlFor={retryIntervalId}>
                        {t("pages.outboundUpsert.urltest.retryInterval")}
                      </FieldLabel>
                      <FieldContent>
                        <Input
                          aria-invalid={Boolean(error)}
                          id={retryIntervalId}
                          onBlur={field.handleBlur}
                          onChange={(event) =>
                            field.handleChange(event.target.value)
                          }
                          value={field.state.value}
                        />
                        <FieldHint
                          description={t(
                            "pages.outboundUpsert.urltest.retryIntervalHint"
                          )}
                          error={error ?? null}
                        />
                      </FieldContent>
                    </Field>
                  )
                }}
              </form.Field>
            </div>
          </SectionCard>

          <SectionCard
            flat
            description={t("pages.outboundUpsert.circuitBreaker.description")}
            title={t("pages.outboundUpsert.circuitBreaker.title")}
          >
            <div className="grid gap-4 md:grid-cols-2">
              <form.Field name={OUTBOUND_FIELD_NAMES.circuitBreakerFailures}>
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)
                  return (
                    <Field invalid={Boolean(error)}>
                      <FieldLabel htmlFor={circuitBreakerFailuresId}>
                        {t("pages.outboundUpsert.circuitBreaker.failures")}
                      </FieldLabel>
                      <FieldContent>
                        <Input
                          aria-invalid={Boolean(error)}
                          id={circuitBreakerFailuresId}
                          onBlur={field.handleBlur}
                          onChange={(event) =>
                            field.handleChange(event.target.value)
                          }
                          value={field.state.value}
                        />
                        <FieldHint
                          description={t(
                            "pages.outboundUpsert.circuitBreaker.failuresHint"
                          )}
                          error={error ?? null}
                        />
                      </FieldContent>
                    </Field>
                  )
                }}
              </form.Field>

              <form.Field name={OUTBOUND_FIELD_NAMES.circuitBreakerSuccesses}>
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)
                  return (
                    <Field invalid={Boolean(error)}>
                      <FieldLabel htmlFor={circuitBreakerSuccessesId}>
                        {t("pages.outboundUpsert.circuitBreaker.successes")}
                      </FieldLabel>
                      <FieldContent>
                        <Input
                          aria-invalid={Boolean(error)}
                          id={circuitBreakerSuccessesId}
                          onBlur={field.handleBlur}
                          onChange={(event) =>
                            field.handleChange(event.target.value)
                          }
                          value={field.state.value}
                        />
                        <FieldHint
                          description={t(
                            "pages.outboundUpsert.circuitBreaker.successesHint"
                          )}
                          error={error ?? null}
                        />
                      </FieldContent>
                    </Field>
                  )
                }}
              </form.Field>

              <form.Field name={OUTBOUND_FIELD_NAMES.circuitBreakerTimeout}>
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)
                  return (
                    <Field invalid={Boolean(error)}>
                      <FieldLabel htmlFor={circuitBreakerTimeoutId}>
                        {t("pages.outboundUpsert.circuitBreaker.timeout")}
                      </FieldLabel>
                      <FieldContent>
                        <Input
                          aria-invalid={Boolean(error)}
                          id={circuitBreakerTimeoutId}
                          onBlur={field.handleBlur}
                          onChange={(event) =>
                            field.handleChange(event.target.value)
                          }
                          value={field.state.value}
                        />
                        <FieldHint
                          description={t(
                            "pages.outboundUpsert.circuitBreaker.timeoutHint"
                          )}
                          error={error ?? null}
                        />
                      </FieldContent>
                    </Field>
                  )
                }}
              </form.Field>

              <form.Field name={OUTBOUND_FIELD_NAMES.circuitBreakerHalfOpen}>
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)
                  return (
                    <Field invalid={Boolean(error)}>
                      <FieldLabel htmlFor={circuitBreakerHalfOpenId}>
                        {t("pages.outboundUpsert.circuitBreaker.halfOpen")}
                      </FieldLabel>
                      <FieldContent>
                        <Input
                          aria-invalid={Boolean(error)}
                          id={circuitBreakerHalfOpenId}
                          onBlur={field.handleBlur}
                          onChange={(event) =>
                            field.handleChange(event.target.value)
                          }
                          value={field.state.value}
                        />
                        <FieldHint
                          description={t(
                            "pages.outboundUpsert.circuitBreaker.halfOpenHint"
                          )}
                          error={error ?? null}
                        />
                      </FieldContent>
                    </Field>
                  )
                }}
              </form.Field>
            </div>
          </SectionCard>
        </AdvancedSection>
      ) : null}

      {isInterface ? (
        <FieldGroup width="short">
          <form.Field name={OUTBOUND_FIELD_NAMES.strictEnforcement}>
            {(field) => {
              const error = getFirstFieldError(field.state.meta.errors)
              return (
                <Field invalid={Boolean(error)}>
                  <FieldLabel>
                    {t("pages.outboundUpsert.strictEnforcement.label")}
                  </FieldLabel>
                  <FieldContent>
                    <Select
                      items={strictSelectItems}
                      onValueChange={(value) =>
                        field.handleChange(value ?? draft.strictEnforcement)
                      }
                      value={field.state.value}
                    >
                      <SelectTrigger aria-invalid={Boolean(error)}>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          <SelectLabel>
                            {t("pages.outboundUpsert.strictEnforcement.label")}
                          </SelectLabel>
                          {strictOptions.map((option) => (
                            <SelectItem key={option} value={option}>
                              {getStrictOptionLabel(option, t)}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                    <FieldHint
                      description={t(
                        "pages.outboundUpsert.strictEnforcement.hint"
                      )}
                      error={error ?? null}
                    />
                    <p className="rounded-md border border-border bg-muted/30 px-3 py-2 text-sm text-muted-foreground">
                      {t(
                        `pages.outboundUpsert.strictEnforcement.explanations.${field.state.value}`
                      )}
                    </p>
                  </FieldContent>
                </Field>
              )
            }}
          </form.Field>
        </FieldGroup>
      ) : null}

      <ServerValidationAlert errors={unmappedServerErrors} />

      <div className="flex justify-end gap-3" data-upsert-actions>
        {deletableFromForm && outboundId ? (
          <UpsertDeleteAction
            confirmLabel={t("pages.outbounds.deleteDialog.confirm")}
            description={t("pages.outbounds.deleteDialog.description", {
              tags: outboundId,
            })}
            impactItems={getOutboundDeleteImpactItems(
              loadedConfig,
              [outboundId],
              getOutboundDeleteImpact(loadedConfig, [outboundId]),
              t
            )}
            isPending={postConfigMutation.isPending}
            label={t("common.delete")}
            onConfirm={handleDelete}
            title={t("pages.outbounds.deleteDialog.title")}
          />
        ) : null}
        <Button
          onClick={onCancel ?? close}
          size="xl"
          type="button"
          variant="outline"
        >
          {t("common.cancel")}
        </Button>
        <Button
          disabled={postConfigMutation.isPending || !isDirty || !canSubmit}
          size="xl"
          type="submit"
        >
          {mode === "create"
            ? t("pages.outboundUpsert.actions.create")
            : t("pages.outboundUpsert.actions.save")}
        </Button>
      </div>
    </form>
  )
}

function getFirstFieldError(errors: unknown[]) {
  const firstError = errors[0]
  return typeof firstError === "string" ? firstError : null
}

function getOutboundTagError(
  value: string,
  outbounds: Outbound[],
  existingTag: string | undefined,
  t: (key: string, options?: Record<string, unknown>) => string
) {
  return getTagNameValidationError(value, {
    requiredError: t("pages.outboundUpsert.validation.tagRequired"),
    invalidError: t("common.validation.tagNamePattern"),
    duplicateError: validateTagUniqueness(
      outbounds,
      value.trim(),
      existingTag,
      t
    ),
  })
}

function getOutboundDraft(
  config: ConfigObject | undefined,
  outboundId?: string
) {
  if (!outboundId || !config) {
    return null
  }

  const outbound = findOutboundByTag(config, outboundId)
  return outbound ? mapOutboundToDraft(outbound) : null
}

function moveGroup(
  groups: OutboundGroupDraft[],
  fromIndex: number,
  toIndex: number
) {
  const next = [...groups]
  const [moved] = next.splice(fromIndex, 1)
  next.splice(toIndex, 0, moved)
  return next
}

function getUnavailableOutbounds(
  groups: OutboundGroupDraft[],
  currentIndex: number
) {
  return groups
    .filter((_, index) => index !== currentIndex)
    .flatMap((group) => group.outbounds)
}

function getNextAvailableOutbounds(
  options: string[],
  groups: OutboundGroupDraft[]
) {
  const used = new Set(groups.flatMap((group) => group.outbounds))
  const next = options.find((option) => !used.has(option))
  return next ? [next] : []
}

function getInterfaceOutboundSearchText(
  tag: string,
  interfaceName: string | undefined,
  runtimeInterfaceByName: Map<string, RuntimeInterfaceInventoryEntry>,
  label?: string
) {
  const runtimeInterface = interfaceName
    ? runtimeInterfaceByName.get(interfaceName)
    : undefined

  return [label, tag, interfaceName, getInterfaceSearchText(runtimeInterface)]
    .filter(Boolean)
    .join(" ")
}

function getStrictOptionLabel(
  value: (typeof strictOptions)[number],
  t: (key: string) => string
) {
  if (value === "default") {
    return t("pages.outboundUpsert.strictEnforcement.default")
  }

  if (value === "enabled") {
    return t("common.enabled")
  }

  return t("common.disabled")
}

function validateTagUniqueness(
  outbounds: Outbound[],
  tag: string,
  existingTag: string | undefined,
  t: (key: string, options?: Record<string, unknown>) => string
): string | null {
  const isDuplicate = outbounds.some(
    (outbound) => outbound.tag === tag && outbound.tag !== existingTag
  )
  return isDuplicate
    ? t("pages.outboundUpsert.validation.duplicateTag", { tag })
    : null
}

function getDisplayNameError(
  value: string,
  t: (key: string) => string
): string | null {
  const trimmed = value.trim()
  if (!trimmed) {
    return t("pages.outboundUpsert.validation.displayNameRequired")
  }

  return [...trimmed].length > 80
    ? t("pages.outboundUpsert.validation.displayNameTooLong")
    : null
}

function validateUrltestGroupReferences(
  outbounds: Outbound[],
  t: (key: string, options?: Record<string, unknown>) => string
): string | null {
  const tags = new Set(outbounds.map((outbound) => outbound.tag))

  for (const outbound of outbounds) {
    if (outbound.type !== "urltest") {
      continue
    }

    for (const group of outbound.outbound_groups ?? []) {
      for (const referencedTag of group.outbounds) {
        if (!tags.has(referencedTag)) {
          return t("pages.outboundUpsert.validation.missingReference", {
            outbound: outbound.tag,
            referenced: referencedTag,
          })
        }
      }
    }
  }

  return null
}

function resolveOutboundFieldPath(
  path: string,
  tag: string
): OutboundFieldName | undefined {
  const normalizedTag = tag.trim()
  if (path === "outbounds") {
    return OUTBOUND_FIELD_NAMES.tag
  }

  if (!normalizedTag) {
    return undefined
  }

  const prefix = `outbounds.${normalizedTag}`
  if (path === prefix || path === `${prefix}.tag`) {
    return OUTBOUND_FIELD_NAMES.tag
  }

  if (path === `${prefix}.display_name`) {
    return OUTBOUND_FIELD_NAMES.displayName
  }

  if (path === `${prefix}.type`) {
    return OUTBOUND_FIELD_NAMES.type
  }

  if (path === `${prefix}.interface`) {
    return OUTBOUND_FIELD_NAMES.interfaceName
  }

  if (path === `${prefix}.gateway`) {
    return OUTBOUND_FIELD_NAMES.gateway
  }

  if (path === `${prefix}.table`) {
    return OUTBOUND_FIELD_NAMES.table
  }

  if (path === `${prefix}.gateway6`) {
    return OUTBOUND_FIELD_NAMES.gateway6
  }

  if (
    path === `${prefix}.outbound_groups` ||
    new RegExp(
      `^${prefix.replaceAll(".", "\\.")}\\.outbound_groups(?:\\[\\d+\\])?(?:\\.(?:outbounds|weight))?$`
    ).test(path)
  ) {
    return OUTBOUND_FIELD_NAMES.outboundGroups
  }

  if (path === `${prefix}.url`) {
    return OUTBOUND_FIELD_NAMES.probeUrl
  }

  if (path === `${prefix}.interval_ms`) {
    return OUTBOUND_FIELD_NAMES.interval
  }

  if (path === `${prefix}.probe_timeout_ms`) {
    return OUTBOUND_FIELD_NAMES.probeTimeout
  }

  if (path === `${prefix}.tolerance_ms`) {
    return OUTBOUND_FIELD_NAMES.tolerance
  }

  if (path === `${prefix}.retry.attempts`) {
    return OUTBOUND_FIELD_NAMES.retryAttempts
  }

  if (path === `${prefix}.retry.interval_ms`) {
    return OUTBOUND_FIELD_NAMES.retryInterval
  }

  if (path === `${prefix}.circuit_breaker.failure_threshold`) {
    return OUTBOUND_FIELD_NAMES.circuitBreakerFailures
  }

  if (path === `${prefix}.circuit_breaker.success_threshold`) {
    return OUTBOUND_FIELD_NAMES.circuitBreakerSuccesses
  }

  if (path === `${prefix}.circuit_breaker.timeout_ms`) {
    return OUTBOUND_FIELD_NAMES.circuitBreakerTimeout
  }

  if (path === `${prefix}.circuit_breaker.half_open_max_requests`) {
    return OUTBOUND_FIELD_NAMES.circuitBreakerHalfOpen
  }

  if (path === `${prefix}.strict_enforcement`) {
    return OUTBOUND_FIELD_NAMES.strictEnforcement
  }

  return undefined
}
