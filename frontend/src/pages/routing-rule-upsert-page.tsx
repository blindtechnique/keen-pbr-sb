import { useTranslation } from "react-i18next"
import { useLocation } from "wouter"
import { useEffect, useState } from "react"

import { revalidateLogic, useForm } from "@tanstack/react-form"
import { useStore } from "@tanstack/react-store"

import type { ApiError } from "@/api/client"
import type { ConfigObject } from "@/api/generated/model/configObject"
import type { Outbound } from "@/api/generated/model/outbound"
import type { RouteRule } from "@/api/generated/model/routeRule"
import { usePostConfigMutation } from "@/api/mutations"
import { useGetConfig } from "@/api/queries"
import { selectConfig } from "@/api/selectors"
import {
  Field,
  FieldContent,
  FieldGroup,
  FieldHint,
  FieldLabel,
} from "@/components/shared/field"
import { ListIdentityLabel } from "@/components/shared/list-identity-label"
import { MultiSelectList } from "@/components/shared/multi-select-list"
import { OutboundSelect } from "@/components/shared/outbound-select"
import { ServerValidationAlert } from "@/components/shared/server-validation-alert"
import {
  UpsertPage,
  type UpsertPagePresentation,
} from "@/components/shared/upsert-page"
import { useUpsertPageClose } from "@/components/shared/upsert-page-context"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { useListUsageSubtitle } from "@/hooks/use-list-usage-subtitle"
import {
  clearFormServerErrors,
  setFormServerErrors,
  splitFormApiErrors,
} from "@/lib/form-api-errors"
import { getListSearchText, sortListIdsByDisplayName } from "@/lib/list-display"
import { sortOutboundsByDisplayName } from "@/lib/outbound-display"
import { makeTechnicalId } from "@/lib/technical-id"
import { resolveRuleRouteIndex } from "@/lib/rule-route"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  createRouteRuleDraft,
  getFirstFieldError,
  getRouteRuleDisplayName,
  normalizeRouteRuleDraft,
  protoOptions,
  toRouteRuleDraft,
} from "@/pages/routing-rules-utils"
import { isSemanticallyDirty } from "@/lib/semantic-dirty"
import { semanticJsonEqual } from "@/lib/semantic-json"
import { getTagNameValidationError } from "@/lib/tag-name-validation"

const ROUTING_RULE_FIELD_NAMES = {
  id: "id",
  displayName: "displayName",
  enabled: "enabled",
  list: "list",
  proto: "proto",
  dscp: "dscp",
  srcPort: "src_port",
  destPort: "dest_port",
  srcAddr: "src_addr",
  destAddr: "dest_addr",
  outbound: "outbound",
} as const

type RoutingRuleFieldName =
  (typeof ROUTING_RULE_FIELD_NAMES)[keyof typeof ROUTING_RULE_FIELD_NAMES]

export function RoutingRuleUpsertPage({
  mode,
  ruleId,
  presentation = "page",
}: {
  mode: "create" | "edit"
  ruleId?: string
  presentation?: UpsertPagePresentation
}) {
  const { t } = useTranslation()
  const [, navigate] = useLocation()
  const [dirty, setDirty] = useState(false)
  const configQuery = useGetConfig()
  const loadedConfig = selectConfig(configQuery.data)
  const rules = loadedConfig?.route?.rules ?? []
  const parsedRuleIndex =
    mode === "edit" ? resolveRuleRouteIndex(rules, ruleId) : -1
  const existingRule =
    mode === "edit" && parsedRuleIndex >= 0
      ? rules[parsedRuleIndex]
      : undefined

  if (mode === "edit" && loadedConfig && !existingRule) {
    return (
      <UpsertPage
        cardDescription={t("pages.routingRuleUpsert.missing.cardDescription")}
        cardTitle={t("pages.routingRuleUpsert.missing.cardTitle")}
        description={t("pages.routingRuleUpsert.missing.description")}
        onClose={() => navigate("/routing-rules")}
        presentation={presentation}
        title={t("pages.routingRuleUpsert.editTitle")}
      >
        <div className="flex justify-end">
          <Button onClick={() => navigate("/routing-rules")} variant="outline">
            {t("pages.routingRuleUpsert.missing.back")}
          </Button>
        </div>
      </UpsertPage>
    )
  }

  if (!loadedConfig) {
    return (
      <UpsertPage
        cardDescription={t(
          presentation === "dialog"
            ? "pages.routingRuleUpsert.simpleCardDescription"
            : "pages.routingRuleUpsert.cardDescription"
        )}
        cardTitle={
          mode === "create"
            ? t("pages.routingRuleUpsert.createTitle")
            : t("pages.routingRuleUpsert.editTitle")
        }
        description={t("pages.routingRuleUpsert.description")}
        onClose={() => navigate("/routing-rules")}
        presentation={presentation}
        title={
          mode === "create"
            ? t("pages.routingRuleUpsert.createTitle")
            : t("pages.routingRuleUpsert.editTitle")
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

  return (
    <UpsertPage
      cardDescription={t(
        presentation === "dialog"
          ? "pages.routingRuleUpsert.simpleCardDescription"
          : "pages.routingRuleUpsert.cardDescription"
      )}
      cardTitle={
        mode === "create"
          ? t("pages.routingRuleUpsert.createTitle")
          : t("pages.routingRuleUpsert.editCardTitle", {
              name: existingRule
                ? getRouteRuleDisplayName(existingRule, parsedRuleIndex)
                : "",
            })
      }
      description={t("pages.routingRuleUpsert.description")}
      dirty={dirty}
      onClose={() => navigate("/routing-rules")}
      presentation={presentation}
      title={
        mode === "create"
          ? t("pages.routingRuleUpsert.createTitle")
          : t("pages.routingRuleUpsert.editTitle")
      }
    >
      <RoutingRuleForm
        key={`${mode}:${ruleId ?? "new"}`}
        existingRule={existingRule}
        loadedConfig={loadedConfig}
        mode={mode}
        onDirtyChange={setDirty}
        parsedRuleIndex={parsedRuleIndex}
        presentation={presentation}
        rules={rules}
      />
    </UpsertPage>
  )
}

function RoutingRuleForm({
  existingRule,
  loadedConfig,
  mode,
  onDirtyChange,
  parsedRuleIndex,
  presentation,
  rules,
}: {
  existingRule?: RouteRule
  loadedConfig: ConfigObject
  mode: "create" | "edit"
  onDirtyChange: (dirty: boolean) => void
  parsedRuleIndex: number
  presentation: UpsertPagePresentation
  rules: RouteRule[]
}) {
  const { t } = useTranslation()
  const [, navigate] = useLocation()
  const close = useUpsertPageClose()
  const listOptions = sortListIdsByDisplayName(
    Object.keys(loadedConfig.lists ?? {}),
    loadedConfig.lists
  )
  const outbounds = sortOutboundsByDisplayName(
    (loadedConfig.outbounds ?? []).filter(
      (outbound: Outbound): outbound is Outbound & { tag: string } =>
        Boolean(outbound.tag)
    )
  )
  const listUsageSubtitle = useListUsageSubtitle(
    rules,
    "routing",
    mode === "edit" ? parsedRuleIndex : undefined,
    {
      rule: (index) =>
        rules[index]
          ? getRouteRuleDisplayName(rules[index], index)
          : `#${index + 1}`,
      target: (tag) =>
        loadedConfig.outbounds?.find((outbound) => outbound.tag === tag)
          ?.display_name?.trim() || tag,
    }
  )
  const protoSelectItems = protoOptions.map((option) => ({
    value: option,
    label: option || t("pages.routingRuleUpsert.fields.anyLower"),
  }))

  const postConfigMutation = usePostConfigMutation()
  const existingRuleIds = rules
    .map((rule) => rule.id?.trim())
    .filter((id): id is string => Boolean(id))
  const [initialDraft] = useState(() => {
    if (mode === "edit" && existingRule) {
      const draft = toRouteRuleDraft(existingRule)
      return draft.id
        ? draft
        : {
            ...draft,
            id: makeTechnicalId(
              draft.displayName || `rule_${parsedRuleIndex + 1}`,
              existingRuleIds,
              { prefix: "rule" }
            ),
          }
    }

    return createRouteRuleDraft("", existingRuleIds)
  })
  const [technicalIdManuallyEdited, setTechnicalIdManuallyEdited] =
    useState(false)
  const hasAdvancedConditions =
    Boolean(initialDraft.proto) ||
    Boolean(initialDraft.dscp) ||
    Boolean(initialDraft.src_port) ||
    Boolean(initialDraft.dest_port) ||
    Boolean(initialDraft.src_addr) ||
    Boolean(initialDraft.dest_addr)

  const form = useForm({
    defaultValues: initialDraft,
    validationLogic: revalidateLogic({
      mode: "submit",
      modeAfterSubmission: "change",
    }),
    validators: {
      onSubmitAsync: async ({ value }) => {
        clearFormServerErrors(form)
        const displayNameError = validateDisplayName(value.displayName, t)
        if (displayNameError) {
          setFormServerErrors(form, {
            fields: {
              [ROUTING_RULE_FIELD_NAMES.displayName]: displayNameError,
            },
          })
          return {
            fields: {
              [ROUTING_RULE_FIELD_NAMES.displayName]: displayNameError,
            },
          }
        }

        const valueToPersist =
          !value.id.trim()
            ? {
                ...value,
                id: makeTechnicalId(value.displayName, existingRuleIds, {
                  prefix: "rule",
                }),
              }
            : value
        const idError = validateRuleId(
          valueToPersist.id,
          existingRuleIds,
          existingRule?.id,
          t
        )
        if (idError) {
          setFormServerErrors(form, {
            fields: {
              [ROUTING_RULE_FIELD_NAMES.id]: idError,
            },
          })
          return {
            fields: {
              [ROUTING_RULE_FIELD_NAMES.id]: idError,
            },
          }
        }

        const nextRule = normalizeRouteRuleDraft(valueToPersist)
        const hasRuleCondition =
          (nextRule.list ?? []).length > 0 ||
          nextRule.dscp !== undefined ||
          Boolean(nextRule.src_port) ||
          Boolean(nextRule.dest_port) ||
          Boolean(nextRule.src_addr) ||
          Boolean(nextRule.dest_addr)

        if (!hasRuleCondition) {
          return {
            form: t("pages.routingRuleUpsert.validation.atLeastOneCondition"),
            fields: {},
          }
        }

        const nextRules =
          mode === "edit"
            ? rules.map((rule: RouteRule, index: number) =>
                index === parsedRuleIndex ? nextRule : rule
              )
            : [...rules, nextRule]

        try {
          await postConfigMutation.mutateAsync({
            data: {
              ...loadedConfig,
              route: {
                ...loadedConfig.route,
                rules: nextRules,
              },
            },
          })
          toast.success(t("pages.routingRuleUpsert.messages.saved"))
          clearFormServerErrors(form)
          navigate("/routing-rules")
          return undefined
        } catch (error) {
          const result = splitFormApiErrors({
            error: error as ApiError,
            fieldNames: Object.values(ROUTING_RULE_FIELD_NAMES),
            resolvePath: resolveRoutingRuleFieldPath,
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
  const submitErrorMessage = useStore(form.store, (state) => {
    const onSubmitError = state.errorMap.onSubmit
    if (typeof onSubmitError === "string") {
      return onSubmitError
    }

    const firstError = state.errors[0]
    return typeof firstError === "string" ? firstError : null
  })
  const unmappedServerErrors = useStore(
    form.store,
    (state) =>
      (
        state.errorMap.onServer as
          | {
              unmapped?: { path: string; message: string }[]
            }
          | undefined
      )?.unmapped ?? []
  )
  const isDirty = useStore(form.store, (state) =>
    isSemanticallyDirty(state.values, initialDraft, {
      equals: semanticJsonEqual,
      normalize: normalizeRouteRuleDraft,
    })
  )

  useEffect(() => {
    onDirtyChange(isDirty)
  }, [isDirty, onDirtyChange])

  return (
    <form
      className="space-y-6"
      onSubmit={(event) => {
        event.preventDefault()
        void form.handleSubmit()
      }}
    >
      <FieldGroup width="short">
        {presentation === "dialog" && hasAdvancedConditions ? (
          <Alert>
            <AlertDescription>
              {t("pages.routingRuleUpsert.advancedConditionsPresent")}
            </AlertDescription>
          </Alert>
        ) : null}

        <form.Field
          name={ROUTING_RULE_FIELD_NAMES.displayName}
          validators={{
            onChange: ({ value }) => validateDisplayName(value, t),
          }}
        >
          {(field) => {
            const error = getFirstFieldError(field.state.meta.errors)

            return (
              <Field invalid={Boolean(error)}>
                <FieldLabel htmlFor="routing-rule-display-name">
                  {t("pages.routingRuleUpsert.fields.displayName")}
                </FieldLabel>
                <FieldContent>
                  <Input
                    aria-invalid={Boolean(error)}
                    id="routing-rule-display-name"
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
                          ROUTING_RULE_FIELD_NAMES.id,
                          makeTechnicalId(nextDisplayName, existingRuleIds, {
                            prefix: "rule",
                          })
                        )
                      }
                    }}
                    value={field.state.value}
                  />
                  <FieldHint
                    description={t(
                      "pages.routingRuleUpsert.fields.displayNameHint"
                    )}
                    error={error}
                  />
                </FieldContent>
              </Field>
            )
          }}
        </form.Field>

        {presentation === "page" ? (
          <form.Field
            name={ROUTING_RULE_FIELD_NAMES.id}
            validators={{
              onChange: ({ value }) =>
                validateRuleId(
                  value,
                  existingRuleIds,
                  existingRule?.id,
                  t
                ),
            }}
          >
            {(field) => {
              const error = getFirstFieldError(field.state.meta.errors)

              return (
                <Field invalid={Boolean(error)}>
                  <FieldLabel htmlFor="routing-rule-id">
                    {t("pages.routingRuleUpsert.fields.technicalId")}
                  </FieldLabel>
                  <FieldContent>
                    <Input
                      aria-invalid={Boolean(error)}
                      id="routing-rule-id"
                      onBlur={field.handleBlur}
                      onChange={(event) => {
                        setTechnicalIdManuallyEdited(true)
                        field.handleChange(event.target.value)
                      }}
                      readOnly={mode === "edit" && Boolean(existingRule?.id)}
                      value={field.state.value}
                    />
                    <FieldHint
                      description={t(
                        "pages.routingRuleUpsert.fields.technicalIdHint"
                      )}
                      error={error}
                    />
                  </FieldContent>
                </Field>
              )
            }}
          </form.Field>
        ) : null}

        <form.Field name={ROUTING_RULE_FIELD_NAMES.enabled}>
          {(field) => (
            <Field>
              <FieldContent>
                <div className="flex items-center space-x-3">
                  <Checkbox
                    checked={field.state.value}
                    id="routing-rule-enabled"
                    onCheckedChange={(checked) =>
                      field.handleChange(checked === true)
                    }
                  />
                  <FieldLabel
                    className="cursor-pointer flex-col items-start gap-0"
                    htmlFor="routing-rule-enabled"
                  >
                    {t("common.enabled")}
                  </FieldLabel>
                </div>
              </FieldContent>
            </Field>
          )}
        </form.Field>

        <form.Field name={ROUTING_RULE_FIELD_NAMES.list}>
          {(field) => {
            const error = getFirstFieldError(field.state.meta.errors)

            return (
              <Field invalid={Boolean(error)}>
                <FieldLabel>
                  {t("pages.routingRuleUpsert.fields.lists")}
                </FieldLabel>
                <FieldContent>
                  <MultiSelectList
                    error={error}
                    name={ROUTING_RULE_FIELD_NAMES.list}
                    onChange={field.handleChange}
                    options={listOptions}
                    placeholderDescription={t(
                      "pages.routingRuleUpsert.fields.listsPlaceholderDescription"
                    )}
                    placeholderTitle={t(
                      "pages.routingRuleUpsert.fields.noListsSelected"
                    )}
                    getSearchText={(technicalId) =>
                      getListSearchText(technicalId, loadedConfig.lists)
                    }
                    renderItem={(technicalId) => (
                      <ListIdentityLabel
                        lists={loadedConfig.lists}
                        technicalId={technicalId}
                      />
                    )}
                    usageSubtitle={listUsageSubtitle}
                    value={field.state.value}
                  />
                  <FieldHint
                    description={t("pages.routingRuleUpsert.fields.listsHint")}
                  />
                </FieldContent>
              </Field>
            )
          }}
        </form.Field>

        {presentation === "page" ? (
          <>
            <form.Field name={ROUTING_RULE_FIELD_NAMES.proto}>
              {(field) => (
                <Field>
                  <FieldLabel>
                    {t("pages.routingRuleUpsert.fields.proto")}
                  </FieldLabel>
                  <FieldContent>
                    <Select
                      items={protoSelectItems}
                      onValueChange={(value) => field.handleChange(value ?? "")}
                      value={field.state.value}
                    >
                      <SelectTrigger>
                        <SelectValue
                          placeholder={t("pages.routingRuleUpsert.fields.any")}
                        />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          <SelectLabel>
                            {t("pages.routingRuleUpsert.fields.protocol")}
                          </SelectLabel>
                          {protoOptions.map((option) => (
                            <SelectItem key={option || "any"} value={option}>
                              {option ||
                                t("pages.routingRuleUpsert.fields.anyLower")}
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                    <FieldHint
                      description={t(
                        "pages.routingRuleUpsert.fields.protoHint"
                      )}
                    />
                  </FieldContent>
                </Field>
              )}
            </form.Field>

            <form.Field
              name={ROUTING_RULE_FIELD_NAMES.dscp}
              validators={{
                onChange: ({ value }) => validateDscp(value, t),
              }}
            >
              {(field) => {
                const error = getFirstFieldError(field.state.meta.errors)

                return (
                  <Field invalid={Boolean(error)}>
                    <FieldLabel htmlFor="routing-dscp">
                      {t("pages.routingRuleUpsert.fields.dscp")}
                    </FieldLabel>
                    <FieldContent>
                      <Input
                        aria-invalid={Boolean(error)}
                        id="routing-dscp"
                        inputMode="numeric"
                        max={63}
                        min={1}
                        onBlur={field.handleBlur}
                        onChange={(event) =>
                          field.handleChange(event.target.value)
                        }
                        placeholder={t(
                          "pages.routingRuleUpsert.placeholders.dscp"
                        )}
                        type="number"
                        value={field.state.value}
                      />
                      <FieldHint
                        description={t(
                          "pages.routingRuleUpsert.fields.dscpHint"
                        )}
                        error={error}
                      />
                    </FieldContent>
                  </Field>
                )
              }}
            </form.Field>

            <form.Field name={ROUTING_RULE_FIELD_NAMES.srcPort}>
              {(field) => {
                const error = getFirstFieldError(field.state.meta.errors)

                return (
                  <Field invalid={Boolean(error)}>
                    <FieldLabel htmlFor="routing-src-port">
                      {t("pages.routingRuleUpsert.fields.sourcePort")}
                    </FieldLabel>
                    <FieldContent>
                      <Input
                        aria-invalid={Boolean(error)}
                        id="routing-src-port"
                        onBlur={field.handleBlur}
                        onChange={(event) =>
                          field.handleChange(event.target.value)
                        }
                        placeholder={t(
                          "pages.routingRuleUpsert.placeholders.sourcePort"
                        )}
                        value={field.state.value}
                      />
                      <FieldHint
                        description={t(
                          "pages.routingRuleUpsert.fields.sourcePortHint"
                        )}
                        error={error}
                      />
                    </FieldContent>
                  </Field>
                )
              }}
            </form.Field>

            <form.Field name={ROUTING_RULE_FIELD_NAMES.destPort}>
              {(field) => {
                const error = getFirstFieldError(field.state.meta.errors)

                return (
                  <Field invalid={Boolean(error)}>
                    <FieldLabel htmlFor="routing-dest-port">
                      {t("pages.routingRuleUpsert.fields.destinationPort")}
                    </FieldLabel>
                    <FieldContent>
                      <Input
                        aria-invalid={Boolean(error)}
                        id="routing-dest-port"
                        onBlur={field.handleBlur}
                        onChange={(event) =>
                          field.handleChange(event.target.value)
                        }
                        placeholder={t(
                          "pages.routingRuleUpsert.placeholders.destinationPort"
                        )}
                        value={field.state.value}
                      />
                      <FieldHint
                        description={t(
                          "pages.routingRuleUpsert.fields.destinationPortHint"
                        )}
                        error={error}
                      />
                    </FieldContent>
                  </Field>
                )
              }}
            </form.Field>

            <form.Field name={ROUTING_RULE_FIELD_NAMES.srcAddr}>
              {(field) => {
                const error = getFirstFieldError(field.state.meta.errors)

                return (
                  <Field invalid={Boolean(error)}>
                    <FieldLabel htmlFor="routing-src-addr">
                      {t("pages.routingRuleUpsert.fields.sourceAddresses")}
                    </FieldLabel>
                    <FieldContent>
                      <Input
                        aria-invalid={Boolean(error)}
                        id="routing-src-addr"
                        onBlur={field.handleBlur}
                        onChange={(event) =>
                          field.handleChange(event.target.value)
                        }
                        placeholder={t(
                          "pages.routingRuleUpsert.placeholders.sourceAddresses"
                        )}
                        value={field.state.value}
                      />
                      <FieldHint
                        description={t(
                          "pages.routingRuleUpsert.fields.sourceAddressHint"
                        )}
                        error={error}
                      />
                    </FieldContent>
                  </Field>
                )
              }}
            </form.Field>

            <form.Field name={ROUTING_RULE_FIELD_NAMES.destAddr}>
              {(field) => {
                const error = getFirstFieldError(field.state.meta.errors)

                return (
                  <Field invalid={Boolean(error)}>
                    <FieldLabel htmlFor="routing-dest-addr">
                      {t("pages.routingRuleUpsert.fields.destinationAddresses")}
                    </FieldLabel>
                    <FieldContent>
                      <Input
                        aria-invalid={Boolean(error)}
                        id="routing-dest-addr"
                        onBlur={field.handleBlur}
                        onChange={(event) =>
                          field.handleChange(event.target.value)
                        }
                        placeholder={t(
                          "pages.routingRuleUpsert.placeholders.destinationAddresses"
                        )}
                        value={field.state.value}
                      />
                      <FieldHint
                        description={t(
                          "pages.routingRuleUpsert.fields.destinationAddressHint"
                        )}
                        error={error}
                      />
                    </FieldContent>
                  </Field>
                )
              }}
            </form.Field>
          </>
        ) : null}

        <form.Field
          name={ROUTING_RULE_FIELD_NAMES.outbound}
          validators={{
            onChange: ({ value }) =>
              value.trim().length > 0
                ? undefined
                : t("pages.routingRuleUpsert.validation.outboundRequired"),
          }}
        >
          {(field) => {
            const error = getFirstFieldError(field.state.meta.errors)

            return (
              <Field invalid={Boolean(error)}>
                <FieldLabel>
                  {t("pages.routingRuleUpsert.fields.outbound")}
                </FieldLabel>
                <FieldContent>
                  <OutboundSelect
                    ariaInvalid={Boolean(error)}
                    onValueChange={field.handleChange}
                    outbounds={outbounds}
                    value={field.state.value}
                  />
                  <FieldHint
                    description={t(
                      "pages.routingRuleUpsert.fields.outboundHint"
                    )}
                    error={error}
                  />
                </FieldContent>
              </Field>
            )
          }}
        </form.Field>
      </FieldGroup>
      <ServerValidationAlert
        errors={unmappedServerErrors}
        message={submitErrorMessage}
      />

      <div className="flex justify-end gap-3" data-upsert-actions>
        <Button onClick={close} size="xl" type="button" variant="outline">
          {t("common.cancel")}
        </Button>
        <form.Subscribe selector={(state) => state.canSubmit}>
          {(canSubmit) => (
            <Button
              disabled={postConfigMutation.isPending || !isDirty || !canSubmit}
              size="xl"
              type="submit"
            >
              {mode === "create"
                ? t("pages.routingRuleUpsert.actions.create")
                : t("pages.routingRuleUpsert.actions.save")}
            </Button>
          )}
        </form.Subscribe>
      </div>
    </form>
  )
}

function resolveRoutingRuleFieldPath(
  path: string
): RoutingRuleFieldName | undefined {
  if (path === "route.rules") {
    return ROUTING_RULE_FIELD_NAMES.outbound
  }

  if (/^route\.rules(?:\[\d+\]|\.\d+)?$/.test(path)) {
    return ROUTING_RULE_FIELD_NAMES.outbound
  }

  if (/^route\.rules(?:\[\d+\]|\.\d+)?\.id$/.test(path)) {
    return ROUTING_RULE_FIELD_NAMES.id
  }

  if (/^route\.rules(?:\[\d+\]|\.\d+)?\.display_name$/.test(path)) {
    return ROUTING_RULE_FIELD_NAMES.displayName
  }

  if (/^route\.rules(?:\[\d+\]|\.\d+)?\.(list|lists)$/.test(path)) {
    return ROUTING_RULE_FIELD_NAMES.list
  }

  if (/^route\.rules(?:\[\d+\]|\.\d+)?\.outbound$/.test(path)) {
    return ROUTING_RULE_FIELD_NAMES.outbound
  }

  if (/^route\.rules(?:\[\d+\]|\.\d+)?\.proto$/.test(path)) {
    return ROUTING_RULE_FIELD_NAMES.proto
  }

  if (/^route\.rules(?:\[\d+\]|\.\d+)?\.dscp$/.test(path)) {
    return ROUTING_RULE_FIELD_NAMES.dscp
  }

  if (/^route\.rules(?:\[\d+\]|\.\d+)?\.src_port$/.test(path)) {
    return ROUTING_RULE_FIELD_NAMES.srcPort
  }

  if (/^route\.rules(?:\[\d+\]|\.\d+)?\.dest_port$/.test(path)) {
    return ROUTING_RULE_FIELD_NAMES.destPort
  }

  if (/^route\.rules(?:\[\d+\]|\.\d+)?\.src_addr$/.test(path)) {
    return ROUTING_RULE_FIELD_NAMES.srcAddr
  }

  if (/^route\.rules(?:\[\d+\]|\.\d+)?\.dest_addr$/.test(path)) {
    return ROUTING_RULE_FIELD_NAMES.destAddr
  }

  return undefined
}

function validateDisplayName(value: string, t: (key: string) => string) {
  const trimmed = value.trim()
  if (!trimmed) {
    return t("pages.routingRuleUpsert.validation.displayNameRequired")
  }

  return [...trimmed].length > 80
    ? t("pages.routingRuleUpsert.validation.displayNameTooLong")
    : undefined
}

function validateRuleId(
  value: string,
  existingIds: readonly string[],
  currentId: string | undefined,
  t: (key: string, options?: Record<string, unknown>) => string
) {
  const trimmed = value.trim()
  return getTagNameValidationError(value, {
    requiredError: t("pages.routingRuleUpsert.validation.technicalIdRequired"),
    invalidError: t("common.validation.tagNamePattern"),
    duplicateError:
      existingIds.includes(trimmed) && trimmed !== currentId
        ? t("pages.routingRuleUpsert.validation.duplicateTechnicalId", {
            id: trimmed,
          })
        : null,
  })
}

function validateDscp(value: string, t: (key: string) => string) {
  const trimmed = value.trim()
  if (trimmed.length === 0) {
    return undefined
  }

  if (!/^\d+$/.test(trimmed)) {
    return t("pages.routingRuleUpsert.validation.dscpRange")
  }

  const parsed = Number(trimmed)
  return parsed >= 1 && parsed <= 63
    ? undefined
    : t("pages.routingRuleUpsert.validation.dscpRange")
}
