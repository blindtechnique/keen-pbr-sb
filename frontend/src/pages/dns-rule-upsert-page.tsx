import { toast } from "sonner"
import { useEffect, useState } from "react"
import { useTranslation } from "react-i18next"
import { useLocation } from "wouter"

import { useForm } from "@tanstack/react-form"
import { useQueryClient } from "@tanstack/react-query"
import { useStore } from "@tanstack/react-store"

import type { ApiError } from "@/api/client"
import type { ConfigObject } from "@/api/generated/model/configObject"
import type { DnsRule } from "@/api/generated/model/dnsRule"
import { usePostConfigMutation } from "@/api/mutations"
import { queryKeys } from "@/api/query-keys"
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
import { ServerValidationAlert } from "@/components/shared/server-validation-alert"
import {
  UpsertPage,
  type UpsertPagePresentation,
} from "@/components/shared/upsert-page"
import { useUpsertPageClose } from "@/components/shared/upsert-page-context"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { useListUsageSubtitle } from "@/hooks/use-list-usage-subtitle"
import {
  createDnsServerDisplayNameMap,
  getDnsRuleDisplayName,
  getDnsServerDisplayName,
} from "@/lib/dns-display"
import {
  clearFormServerErrors,
  setFormServerErrors,
  splitFormApiErrors,
} from "@/lib/form-api-errors"
import { getListSearchText, sortListIdsByDisplayName } from "@/lib/list-display"
import { isSemanticallyDirty } from "@/lib/semantic-dirty"
import { semanticJsonEqual } from "@/lib/semantic-json"
import { getTagNameValidationError } from "@/lib/tag-name-validation"
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
  buildUpdatedConfigWithRules,
  createDnsRuleDraft,
  type DnsRuleDraft,
  getRuleDraft,
  normalizeDnsRuleDraft,
  validateRules,
} from "@/pages/dns-rules-utils"

const DNS_RULE_FIELD_NAMES = {
  id: "rule.id",
  displayName: "rule.displayName",
  enabled: "rule.enabled",
  server: "rule.server",
  lists: "rule.lists",
  allowDomainRebinding: "rule.allowDomainRebinding",
} as const

type DnsRuleFieldName =
  (typeof DNS_RULE_FIELD_NAMES)[keyof typeof DNS_RULE_FIELD_NAMES]

export function DnsRuleUpsertPage({
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
  const rules = loadedConfig?.dns?.rules ?? []
  const parsedRuleIndex =
    mode === "edit" ? resolveRuleRouteIndex(rules, ruleId) : -1
  const existingRule =
    mode === "edit" && parsedRuleIndex >= 0
      ? rules[parsedRuleIndex]
      : undefined

  if (mode === "edit" && loadedConfig && !existingRule) {
    return (
      <UpsertPage
        cardDescription={t("pages.dnsRuleUpsert.missing.cardDescription")}
        cardTitle={t("pages.dnsRuleUpsert.missing.cardTitle")}
        description={t("pages.dnsRuleUpsert.missing.description")}
        onClose={() => navigate("/dns-rules")}
        presentation={presentation}
        title={t("pages.dnsRuleUpsert.editTitle")}
      >
        <div className="flex justify-end">
          <Button onClick={() => navigate("/dns-rules")} variant="outline">
            {t("pages.dnsRuleUpsert.missing.back")}
          </Button>
        </div>
      </UpsertPage>
    )
  }

  if (!loadedConfig) {
    return (
      <UpsertPage
        cardDescription={t("pages.dnsRuleUpsert.cardDescription")}
        cardTitle={
          mode === "create"
            ? t("pages.dnsRuleUpsert.createTitle")
            : t("pages.dnsRuleUpsert.editTitle")
        }
        description={t("pages.dnsRuleUpsert.description")}
        onClose={() => navigate("/dns-rules")}
        presentation={presentation}
        title={
          mode === "create"
            ? t("pages.dnsRuleUpsert.createTitle")
            : t("pages.dnsRuleUpsert.editTitle")
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
      cardDescription={t("pages.dnsRuleUpsert.cardDescription")}
      cardTitle={
        mode === "create"
          ? t("pages.dnsRuleUpsert.createTitle")
          : t("pages.dnsRuleUpsert.editCardTitle", {
              name: getDnsRuleDisplayName(existingRule, parsedRuleIndex),
            })
      }
      description={t("pages.dnsRuleUpsert.description")}
      dirty={dirty}
      onClose={() => navigate("/dns-rules")}
      presentation={presentation}
      title={
        mode === "create"
          ? t("pages.dnsRuleUpsert.createTitle")
          : t("pages.dnsRuleUpsert.editTitle")
      }
    >
      <DnsRuleForm
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

function DnsRuleForm({
  existingRule,
  loadedConfig,
  mode,
  onDirtyChange,
  parsedRuleIndex,
  presentation,
  rules,
}: {
  existingRule?: DnsRule
  loadedConfig: ConfigObject
  mode: "create" | "edit"
  onDirtyChange: (dirty: boolean) => void
  parsedRuleIndex: number
  presentation: UpsertPagePresentation
  rules: DnsRule[]
}) {
  const { t, i18n } = useTranslation()
  const queryClient = useQueryClient()
  const [, navigate] = useLocation()
  const close = useUpsertPageClose()
  const dnsServers = loadedConfig.dns?.servers ?? []
  const serverTags = dnsServers
    .map((server) => server.tag)
    .filter(Boolean)
  const serverNames = createDnsServerDisplayNameMap(dnsServers)
  const serverSelectItems = dnsServers.map((server) => ({
    value: server.tag,
    label: getDnsServerDisplayName(server),
  }))
  const listOptions = sortListIdsByDisplayName(
    Object.keys(loadedConfig.lists ?? {}),
    loadedConfig.lists
  )
  const listUsageSubtitle = useListUsageSubtitle(
    rules,
    "dns",
    mode === "edit" ? parsedRuleIndex : undefined,
    {
      rule: (index) => getDnsRuleDisplayName(rules[index], index),
      target: (tag) => serverNames.get(tag) ?? tag,
    }
  )
  const postConfigMutation = usePostConfigMutation()
  const existingRuleIds = rules
    .map((rule) => rule.id?.trim())
    .filter((id): id is string => Boolean(id))
  const [baselineDraft] = useState<DnsRuleDraft>(() => {
    if (mode === "edit" && existingRule) {
      const draft = getRuleDraft(existingRule)
      const displayName =
        draft.displayName || getDnsRuleDisplayName(existingRule, parsedRuleIndex)
      return {
        ...draft,
        displayName,
        id:
          draft.id ||
          makeTechnicalId(displayName, existingRuleIds, {
            prefix: "dns_rule",
          }),
      }
    }

    return {
      ...createDnsRuleDraft("", existingRuleIds),
      server: serverTags[0] ?? "",
    }
  })
  const [technicalIdManuallyEdited, setTechnicalIdManuallyEdited] =
    useState(false)
  const form = useForm({
    defaultValues: {
      rule: baselineDraft,
    },
    validators: {
      onSubmitAsync: async ({ value }) => {
        clearFormServerErrors(form)
        const displayNameError = validateDisplayName(value.rule.displayName, t)
        if (displayNameError) {
          setFormServerErrors(form, {
            fields: {
              [DNS_RULE_FIELD_NAMES.displayName]: displayNameError,
            },
          })
          return {
            fields: {
              [DNS_RULE_FIELD_NAMES.displayName]: displayNameError,
            },
          }
        }

        const valueToPersist = !value.rule.id.trim()
          ? {
              ...value.rule,
              id: makeTechnicalId(
                value.rule.displayName,
                existingRuleIds,
                { prefix: "dns_rule" }
              ),
            }
          : value.rule
        const idError = validateRuleId(
          valueToPersist.id,
          existingRuleIds,
          existingRule?.id,
          t
        )
        if (idError) {
          setFormServerErrors(form, {
            fields: { [DNS_RULE_FIELD_NAMES.id]: idError },
          })
          return {
            fields: { [DNS_RULE_FIELD_NAMES.id]: idError },
          }
        }

        const nextRules = rules.map((rule) => getRuleDraft(rule))

        if (mode === "edit") {
          if (!existingRule || Number.isNaN(parsedRuleIndex)) {
            toast.error(t("pages.dnsRuleUpsert.validation.notFound"), {
              richColors: true,
            })
            return undefined
          }

          nextRules[parsedRuleIndex] = valueToPersist
        } else {
          nextRules.push(valueToPersist)
        }

        const validation = validateRules(nextRules, serverTags, listOptions)
        if (Object.keys(validation).length > 0) {
          const currentIndex =
            mode === "edit" ? parsedRuleIndex : nextRules.length - 1
          const currentError = validation[currentIndex]
          if (!currentError) {
            return undefined
          }

          const fieldErrors: Record<string, string> = {}
          if (currentError.id) {
            fieldErrors[DNS_RULE_FIELD_NAMES.id] = currentError.id
          }
          if (currentError.server) {
            fieldErrors[DNS_RULE_FIELD_NAMES.server] = currentError.server
          }
          if (currentError.lists) {
            fieldErrors[DNS_RULE_FIELD_NAMES.lists] = currentError.lists
          }

          setFormServerErrors(form, {
            form: currentError.duplicate,
            fields: fieldErrors,
          })
          return {
            form: currentError.duplicate,
            fields: fieldErrors,
          }
        }

        try {
          await postConfigMutation.mutateAsync({
            data: buildUpdatedConfigWithRules(
              loadedConfig,
              loadedConfig.dns?.fallback ?? [],
              nextRules
            ),
          })
          await queryClient.invalidateQueries({ queryKey: queryKeys.dnsTest() })
          toast.success(t("pages.dnsRuleUpsert.messages.saved"))
          clearFormServerErrors(form)
          navigate("/dns-rules")
          return undefined
        } catch (error) {
          const result = splitFormApiErrors({
            error: error as ApiError,
            fieldNames: Object.values(DNS_RULE_FIELD_NAMES),
            resolvePath: resolveDnsRuleFieldPath,
          })

          setFormServerErrors(form, {
            form: result.formError ?? undefined,
            fields: result.fieldErrors,
            unmapped: result.unmappedErrors,
          })
          if (result.formError) {
            toast.error(result.formError, { richColors: true })
          }

          return {
            form: result.formError ?? undefined,
            fields: result.fieldErrors,
          }
        }
      },
    },
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
    isSemanticallyDirty(state.values.rule, baselineDraft, {
      equals: semanticJsonEqual,
      normalize: normalizeDnsRuleDraft,
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
        event.stopPropagation()
        void form.handleSubmit()
      }}
    >
      <FieldGroup>
        <form.Field
          name={DNS_RULE_FIELD_NAMES.displayName}
          validators={{
            onChange: ({ value }) => validateDisplayName(value, t),
          }}
        >
          {(field) => {
            const error = getFirstFieldError(field.state.meta.errors)
            return (
              <Field invalid={Boolean(error)}>
                <FieldLabel htmlFor="dns-rule-display-name">
                  {t("pages.dnsRuleUpsert.fields.displayName")}
                </FieldLabel>
                <FieldContent>
                  <Input
                    aria-invalid={Boolean(error)}
                    id="dns-rule-display-name"
                    maxLength={80}
                    onBlur={field.handleBlur}
                    onChange={(event) => {
                      const displayName = event.target.value
                      field.handleChange(displayName)
                      if (
                        mode === "create" &&
                        (presentation === "dialog" ||
                          !technicalIdManuallyEdited)
                      ) {
                        form.setFieldValue(
                          DNS_RULE_FIELD_NAMES.id,
                          makeTechnicalId(displayName, existingRuleIds, {
                            prefix: "dns_rule",
                          })
                        )
                      }
                    }}
                    value={field.state.value}
                  />
                  <FieldHint
                    description={t(
                      "pages.dnsRuleUpsert.fields.displayNameHint"
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
            name={DNS_RULE_FIELD_NAMES.id}
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
                  <FieldLabel htmlFor="dns-rule-id">
                    {t("pages.dnsRuleUpsert.fields.technicalId")}
                  </FieldLabel>
                  <FieldContent>
                    <Input
                      aria-invalid={Boolean(error)}
                      id="dns-rule-id"
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
                        "pages.dnsRuleUpsert.fields.technicalIdHint"
                      )}
                      error={error}
                    />
                  </FieldContent>
                </Field>
              )
            }}
          </form.Field>
        ) : null}

        <form.Field name={DNS_RULE_FIELD_NAMES.enabled}>
          {(field) => (
            <Field>
              <FieldContent>
                <div className="flex items-center space-x-3">
                  <Checkbox
                    checked={field.state.value}
                    id="dns-rule-enabled"
                    onCheckedChange={(checked) =>
                      field.handleChange(checked === true)
                    }
                  />
                  <FieldLabel
                    className="cursor-pointer flex-col items-start gap-0"
                    htmlFor="dns-rule-enabled"
                  >
                    {t("common.enabled")}
                  </FieldLabel>
                </div>
              </FieldContent>
            </Field>
          )}
        </form.Field>

        <form.Field name={DNS_RULE_FIELD_NAMES.server}>
          {(field) => {
            const error = getFirstFieldError(field.state.meta.errors)
            return (
              <Field invalid={Boolean(error)}>
                <FieldLabel>
                  {t("pages.dnsRuleUpsert.fields.serverTag")}
                </FieldLabel>
                <FieldContent>
                  <Select
                    items={serverSelectItems}
                    onValueChange={(server) => field.handleChange(server ?? "")}
                    value={field.state.value}
                  >
                    <SelectTrigger aria-invalid={Boolean(error)}>
                      <SelectValue
                        placeholder={t(
                          "pages.dnsRuleUpsert.fields.selectServer"
                        )}
                      />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        <SelectLabel>
                          {t("pages.dnsRuleUpsert.fields.dnsServers")}
                        </SelectLabel>
                        {dnsServers
                          .slice()
                          .sort((left, right) =>
                            getDnsServerDisplayName(left).localeCompare(
                              getDnsServerDisplayName(right),
                              i18n.language
                            )
                          )
                          .map((server) => (
                          <SelectItem
                            key={server.tag}
                            value={server.tag}
                          >
                            <span title={server.tag}>
                              {serverNames.get(server.tag) ?? server.tag}
                            </span>
                          </SelectItem>
                          ))}
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                  <FieldHint
                    description={
                      serverTags.length === 0
                        ? t("pages.dnsRuleUpsert.fields.noServers")
                        : undefined
                    }
                    error={error}
                  />
                </FieldContent>
              </Field>
            )
          }}
        </form.Field>

        <form.Field name={DNS_RULE_FIELD_NAMES.lists}>
          {(field) => {
            const error = getFirstFieldError(field.state.meta.errors)
            return (
              <Field invalid={Boolean(error)}>
                <FieldLabel>
                  {t("pages.dnsRuleUpsert.fields.listNames")}
                </FieldLabel>
                <FieldContent>
                  <MultiSelectList
                    name={DNS_RULE_FIELD_NAMES.lists}
                    onChange={field.handleChange}
                    options={listOptions}
                    error={error}
                    placeholderDescription={t(
                      "pages.dnsRuleUpsert.fields.listPlaceholderDescription"
                    )}
                    placeholderTitle={t(
                      "pages.dnsRuleUpsert.fields.noListsSelected"
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
                    description={
                      listOptions.length === 0
                        ? t("pages.dnsRuleUpsert.fields.noLists")
                        : undefined
                    }
                  />
                </FieldContent>
              </Field>
            )
          }}
        </form.Field>

        {presentation === "page" ? (
          <form.Field name={DNS_RULE_FIELD_NAMES.allowDomainRebinding}>
            {(field) => (
              <Field>
                <FieldContent>
                  <div className="flex items-center space-x-3">
                    <Checkbox
                      checked={field.state.value}
                      id="allow-domain-rebinding"
                      onCheckedChange={(checked) =>
                        field.handleChange(checked === true)
                      }
                    />
                    <FieldLabel
                      className="cursor-pointer flex-col items-start gap-0"
                      htmlFor="allow-domain-rebinding"
                    >
                      {t("pages.dnsRuleUpsert.fields.allowDomainRebinding")}
                    </FieldLabel>
                  </div>
                  <FieldHint
                    description={t(
                      "pages.dnsRuleUpsert.fields.allowDomainRebindingHint"
                    )}
                  />
                </FieldContent>
              </Field>
            )}
          </form.Field>
        ) : null}
      </FieldGroup>

      <ServerValidationAlert errors={unmappedServerErrors} />

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
                ? t("pages.dnsRuleUpsert.actions.create")
                : t("pages.dnsRuleUpsert.actions.save")}
            </Button>
          )}
        </form.Subscribe>
      </div>
    </form>
  )
}

function getFirstFieldError(errors: unknown[]) {
  const firstError = errors[0]
  return typeof firstError === "string" ? firstError : undefined
}

function resolveDnsRuleFieldPath(path: string): DnsRuleFieldName | undefined {
  if (path === "dns.rules") {
    return DNS_RULE_FIELD_NAMES.server
  }

  if (/^dns\.rules(?:\[\d+\]|\.\d+)?$/.test(path)) {
    return DNS_RULE_FIELD_NAMES.server
  }

  if (/^dns\.rules(?:\[\d+\]|\.\d+)?\.server$/.test(path)) {
    return DNS_RULE_FIELD_NAMES.server
  }

  if (/^dns\.rules(?:\[\d+\]|\.\d+)?\.id$/.test(path)) {
    return DNS_RULE_FIELD_NAMES.id
  }

  if (/^dns\.rules(?:\[\d+\]|\.\d+)?\.display_name$/.test(path)) {
    return DNS_RULE_FIELD_NAMES.displayName
  }

  if (/^dns\.rules(?:\[\d+\]|\.\d+)?\.(list|lists)$/.test(path)) {
    return DNS_RULE_FIELD_NAMES.lists
  }

  if (/^dns\.rules(?:\[\d+\]|\.\d+)?\.allow_domain_rebinding$/.test(path)) {
    return DNS_RULE_FIELD_NAMES.allowDomainRebinding
  }

  return undefined
}

function validateDisplayName(value: string, t: (key: string) => string) {
  const trimmed = value.trim()
  if (!trimmed) {
    return t("pages.dnsRuleUpsert.validation.displayNameRequired")
  }

  return [...trimmed].length > 80
    ? t("pages.dnsRuleUpsert.validation.displayNameTooLong")
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
    requiredError: t("pages.dnsRuleUpsert.validation.technicalIdRequired"),
    invalidError: t("common.validation.tagNamePattern"),
    duplicateError:
      existingIds.includes(trimmed) && trimmed !== currentId
        ? t("pages.dnsRuleUpsert.validation.duplicateTechnicalId", {
            id: trimmed,
          })
        : null,
  })
}
