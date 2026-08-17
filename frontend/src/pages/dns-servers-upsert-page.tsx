import { useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { useLocation } from "wouter"

import type { ApiError } from "@/api/client"
import type { ConfigObject } from "@/api/generated/model/configObject"
import type { DnsServer } from "@/api/generated/model/dnsServer"
import { DnsServerType } from "@/api/generated/model/dnsServerType"
import { usePostConfigMutation } from "@/api/mutations"
import {
  buildUpdatedConfigForDnsServersDelete,
  getDnsServerDeleteImpact,
} from "@/pages/dns-servers-utils"
import {
  formatDnsServerNames,
  getDnsServerDeleteImpactItems,
} from "@/components/delete-impact/dns-server-items"
import { UpsertDeleteAction } from "@/components/shared/upsert-delete-action"
import { useGetConfig } from "@/api/queries"
import { selectConfig } from "@/api/selectors"
import {
  Field,
  FieldContent,
  FieldGroup,
  FieldHint,
  FieldLabel,
} from "@/components/shared/field"
import { OutboundSelect } from "@/components/shared/outbound-select"
import {
  UpsertPage,
  type UpsertPagePresentation,
} from "@/components/shared/upsert-page"
import { useUpsertPageClose } from "@/components/shared/upsert-page-context"
import { ServerValidationAlert } from "@/components/shared/server-validation-alert"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Checkbox } from "@/components/ui/checkbox"
import { DnsPresetPicker } from "@/components/dns/dns-preset-picker"
import {
  resolveDnsTemplateSelection,
  type DnsPresetSelection,
} from "@/components/dns/dns-preset-selection"
import { findDnsPresetByAddress } from "@/data/dns-presets"
import i18n from "@/i18n"
import {
  applyFormApiErrors,
  clearFormServerErrors,
} from "@/lib/form-api-errors"
import { getTagNameValidationError } from "@/lib/tag-name-validation"
import { isSemanticallyDirty } from "@/lib/semantic-dirty"
import { semanticJsonEqual } from "@/lib/semantic-json"
import { makeTechnicalId } from "@/lib/technical-id"
import {
  buildUpdatedConfigForDnsServerUpsert,
  getDnsServerDraft,
  getDnsServerPresetTransition,
  normalizeDnsAddress,
  normalizePlainDnsTemplateAddress,
  normalizeDnsServerDraftForComparison,
  withSavedPlainDnsTemplate,
  type DnsServerDraft,
} from "@/pages/dns-server-upsert-utils"
import { useForm } from "@tanstack/react-form"
import { useStore } from "@tanstack/react-store"

const DNS_SERVER_FIELD_NAMES = {
  displayName: "displayName",
  tag: "tag",
  type: "type",
  address: "address",
  detour: "detour",
} as const

type DnsServerFieldName =
  (typeof DNS_SERVER_FIELD_NAMES)[keyof typeof DNS_SERVER_FIELD_NAMES]

export function DnsServerUpsertPage({
  mode,
  serverTag,
  presentation = "page",
}: {
  mode: "create" | "edit"
  serverTag?: string
  presentation?: UpsertPagePresentation
}) {
  const { t } = useTranslation()
  const [, navigate] = useLocation()
  const [dirty, setDirty] = useState(false)
  const configQuery = useGetConfig()
  const config = selectConfig(configQuery.data)
  const dnsServers = config?.dns?.servers ?? []

  const existingServer =
    mode === "edit"
      ? dnsServers.find((server) => server.tag === serverTag)
      : undefined
  const existingDisplayName =
    existingServer?.display_name ??
    findDnsPresetByAddress(existingServer?.address)?.name ??
    existingServer?.tag
  const initialDraft = getDnsServerDraft(existingServer)

  if (mode === "edit" && !existingServer && !configQuery.isLoading) {
    return (
      <UpsertPage
        cardDescription={t("pages.dnsServerUpsert.missingCardDescription")}
        cardTitle={t("pages.dnsServerUpsert.missingCardTitle")}
        description={t("pages.dnsServerUpsert.missingDescription")}
        onClose={() => navigate("/dns-servers")}
        presentation={presentation}
        showAdvancedEditor={false}
        title={t("pages.dnsServerUpsert.editTitle")}
      >
        <div className="flex justify-end">
          <Button onClick={() => navigate("/dns-servers")} variant="outline">
            {t("pages.dnsServerUpsert.back")}
          </Button>
        </div>
      </UpsertPage>
    )
  }

  return (
    <UpsertPage
      cardDescription={t("pages.dnsServerUpsert.cardDescription")}
      cardTitle={
        mode === "create"
          ? t("pages.dnsServerUpsert.createTitle")
          : t("pages.dnsServerUpsert.editCardTitle", {
              tag: existingDisplayName ?? t("pages.dnsServerUpsert.editTitle"),
            })
      }
      description={t("pages.dnsServerUpsert.description")}
      dirty={dirty}
      onClose={() => navigate("/dns-servers")}
      presentation={presentation}
      title={
        mode === "create"
          ? t("pages.dnsServerUpsert.createTitle")
          : t("pages.dnsServerUpsert.editTitle")
      }
    >
      <DnsServerForm
        config={config}
        initialDraft={initialDraft}
        key={`${mode}:${serverTag ?? "new"}:${existingServer ? "loaded" : "empty"}`}
        mode={mode}
        onDirtyChange={setDirty}
        onSaved={() => navigate("/dns-servers")}
        presentation={presentation}
        serverTag={serverTag}
      />
    </UpsertPage>
  )
}

function DnsServerForm({
  mode,
  serverTag,
  config,
  initialDraft,
  onDirtyChange,
  onSaved,
  presentation,
}: {
  mode: "create" | "edit"
  serverTag?: string
  config: ConfigObject | undefined
  initialDraft: DnsServerDraft
  onDirtyChange: (dirty: boolean) => void
  onSaved: () => void
  presentation: UpsertPagePresentation
}) {
  const { t } = useTranslation()
  const close = useUpsertPageClose()
  const [apiErrorMessage, setApiErrorMessage] = useState<string | null>(null)
  const [baselineDraft] = useState(initialDraft)
  const initialPreset = findDnsPresetByAddress(initialDraft.address)
  const [presetSelection, setPresetSelection] = useState<DnsPresetSelection>(
    initialPreset?.id ?? "custom"
  )
  const [includeBackup, setIncludeBackup] = useState(
    mode === "create" && Boolean(initialPreset)
  )
  const [customSecondaryAddress, setCustomSecondaryAddress] = useState("")
  const [saveCustomTemplate, setSaveCustomTemplate] = useState(false)
  const customPresetStateRef = useRef({
    draft: baselineDraft,
    includeBackup: false,
    secondaryAddress: "",
    saveCustomTemplate: false,
  })
  const configServers = config?.dns?.servers ?? []
  const savedTemplates = config?.ui_preferences?.plain_dns_templates ?? []
  const normalizedCustomSecondaryAddress = normalizePlainDnsTemplateAddress(
    customSecondaryAddress
  )
  const customSecondaryInvalid =
    customSecondaryAddress.trim().length > 0 &&
    !normalizedCustomSecondaryAddress
  const form = useForm({
    defaultValues: baselineDraft,
    onSubmit: ({ value }) => {
      if (!config) {
        return
      }
      if (presetSelection === "custom" && customSecondaryInvalid) {
        setApiErrorMessage(
          t("pages.dnsServerUpsert.validation.templateAddressInvalid")
        )
        return
      }

      const selectedPreset = resolveDnsTemplateSelection(
        presetSelection,
        savedTemplates
      )
      const backupAddress =
        presetSelection === "custom"
          ? normalizedCustomSecondaryAddress
          : selectedPreset?.secondaryAddress
      const backupDraft =
        mode === "create" && includeBackup && backupAddress
          ? {
              displayName: t(
                "pages.dnsServerUpsert.presets.backupDisplayName",
                { name: value.displayName.trim() }
              ),
              tag: makeTechnicalId(
                `${value.tag}_backup`,
                configServers.map((server) => server.tag),
                { prefix: "dns" }
              ),
              address: backupAddress,
            }
          : undefined
      let updatedConfig = buildUpdatedConfigForDnsServerUpsert(
        config,
        mode,
        value,
        serverTag,
        backupDraft
      )
      if (!updatedConfig) {
        return
      }
      if (
        mode === "create" &&
        presetSelection === "custom" &&
        saveCustomTemplate
      ) {
        updatedConfig = withSavedPlainDnsTemplate(updatedConfig, {
          name: value.displayName,
          primary_ipv4: value.address,
          ...(backupAddress ? { secondary_ipv4: backupAddress } : {}),
        })
        if (!updatedConfig) {
          setApiErrorMessage(
            t("pages.dnsServerUpsert.validation.templateInvalid")
          )
          return
        }
      }

      setApiErrorMessage(null)
      clearFormServerErrors(form)
      postConfigMutation.mutate({ data: updatedConfig })
    },
  })
  const unmappedServerErrors = useStore(
    form.store,
    (state) =>
      (
        state.errorMap.onServer as
          | { unmapped?: { path: string; message: string }[] }
          | undefined
      )?.unmapped ?? []
  )
  const formIsDirty = useStore(form.store, (state) =>
    isSemanticallyDirty(state.values, baselineDraft, {
      equals: semanticJsonEqual,
      normalize: normalizeDnsServerDraftForComparison,
    })
  )
  const isDirty =
    formIsDirty ||
    customSecondaryAddress.trim().length > 0 ||
    saveCustomTemplate

  const postConfigMutation = usePostConfigMutation({
    mutation: {
      onSuccess: () => {
        clearFormServerErrors(form)
        setApiErrorMessage(null)
        onSaved()
      },
      onError: (error) => {
        setApiErrorMessage(
          applyFormApiErrors({
            error: error as ApiError,
            fieldNames: Object.values(DNS_SERVER_FIELD_NAMES),
            form,
            resolvePath: (path) =>
              resolveDnsServerFieldPath(
                path,
                form.state.values.tag || serverTag || initialDraft.tag
              ),
          }) ?? null
        )
      },
    },
  })

  // Удаление из формы — как в конфигураторе, где корзина живёт в диалоге
  // редактирования. Тот же диалог «что сломается», что и в таблице: удаление
  // сервера меняет DNS-правила и fallback, и человек видит это до подтверждения.
  const handleDelete = () => {
    if (!config || !serverTag) {
      return
    }

    postConfigMutation.mutate({
      data: buildUpdatedConfigForDnsServersDelete(config, [serverTag], true),
    })
  }

  useEffect(() => {
    onDirtyChange(isDirty)
  }, [isDirty, onDirtyChange])

  const selectPreset = (selection: DnsPresetSelection) => {
    if (presetSelection === "custom" && selection !== "custom") {
      customPresetStateRef.current = {
        draft: { ...form.state.values },
        includeBackup,
        secondaryAddress: customSecondaryAddress,
        saveCustomTemplate,
      }
    }

    const transition = getDnsServerPresetTransition(
      selection,
      selection === "custom"
        ? customPresetStateRef.current.draft
        : form.state.values,
      savedTemplates,
      configServers.map((server) => server.tag)
    )
    if (!transition) {
      return
    }

    setPresetSelection(selection)
    setIncludeBackup(
      selection === "custom"
        ? customPresetStateRef.current.includeBackup
        : transition.includeBackup
    )
    setCustomSecondaryAddress(
      selection === "custom"
        ? customPresetStateRef.current.secondaryAddress
        : transition.secondaryAddress
    )
    setSaveCustomTemplate(
      selection === "custom"
        ? customPresetStateRef.current.saveCustomTemplate
        : false
    )
    form.setFieldValue(
      DNS_SERVER_FIELD_NAMES.displayName,
      transition.fields.displayName
    )
    form.setFieldValue(DNS_SERVER_FIELD_NAMES.tag, transition.fields.tag)
    form.setFieldValue(DNS_SERVER_FIELD_NAMES.type, transition.fields.type)
    form.setFieldValue(
      DNS_SERVER_FIELD_NAMES.address,
      transition.fields.address
    )
    form.setFieldValue(DNS_SERVER_FIELD_NAMES.detour, transition.fields.detour)
  }

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
          name={DNS_SERVER_FIELD_NAMES.displayName}
          validators={{
            onChange: ({ value }) => getDisplayNameError(value),
          }}
        >
          {(field) => {
            const error = getFirstFieldError(field.state.meta.errors)
            return (
              <Field invalid={Boolean(error)}>
                <FieldLabel htmlFor="dns-server-display-name">
                  {t("pages.dnsServerUpsert.fields.displayName")}
                </FieldLabel>
                <FieldContent>
                  <Input
                    aria-invalid={Boolean(error)}
                    id="dns-server-display-name"
                    maxLength={80}
                    onBlur={field.handleBlur}
                    onChange={(event) => {
                      field.handleChange(event.target.value)
                      if (mode === "create") {
                        form.setFieldValue(
                          DNS_SERVER_FIELD_NAMES.tag,
                          makeTechnicalId(
                            event.target.value,
                            configServers.map((server) => server.tag),
                            { prefix: "dns" }
                          )
                        )
                      }
                    }}
                    placeholder={t(
                      "pages.dnsServerUpsert.fields.displayNamePlaceholder"
                    )}
                    value={field.state.value}
                  />
                  <FieldHint
                    description={t(
                      "pages.dnsServerUpsert.fields.displayNameHint"
                    )}
                    error={error}
                  />
                </FieldContent>
              </Field>
            )
          }}
        </form.Field>

        <form.Field
          name={DNS_SERVER_FIELD_NAMES.tag}
          validators={{
            onChange: ({ value }) =>
              getTagError(
                value,
                configServers,
                mode === "edit" ? serverTag : undefined
              ),
          }}
        >
          {(field) =>
            presentation === "page" ? (
              <Field
                invalid={Boolean(getFirstFieldError(field.state.meta.errors))}
              >
                <FieldLabel htmlFor="dns-server-technical-id">
                  {t("pages.dnsServerUpsert.fields.technicalId")}
                </FieldLabel>
                <FieldContent>
                  <Input
                    aria-invalid={Boolean(
                      getFirstFieldError(field.state.meta.errors)
                    )}
                    id="dns-server-technical-id"
                    onBlur={field.handleBlur}
                    onChange={(event) => field.handleChange(event.target.value)}
                    readOnly={mode === "edit"}
                    value={field.state.value}
                  />
                  <FieldHint
                    description={t(
                      mode === "edit"
                        ? "pages.dnsServerUpsert.fields.technicalIdEditHint"
                        : "pages.dnsServerUpsert.fields.technicalIdCreateHint"
                    )}
                    error={getFirstFieldError(field.state.meta.errors)}
                  />
                </FieldContent>
              </Field>
            ) : (
              <input
                name={field.name}
                readOnly
                type="hidden"
                value={field.state.value}
              />
            )
          }
        </form.Field>

        {mode === "create" ? (
          <DnsPresetPicker
            customLabel={t("pages.dnsServerUpsert.presets.custom")}
            label={t("pages.dnsServerUpsert.presets.label")}
            onValueChange={selectPreset}
            savedTemplates={savedTemplates}
            value={presetSelection}
          />
        ) : null}

        <form.Subscribe selector={(state) => state.values.type}>
          {(type) => {
            const isKeeneticDns = type === DnsServerType.keenetic

            return (
              <>
                {isKeeneticDns ? (
                  <Field>
                    <FieldContent>
                      <Alert>
                        <AlertDescription>
                          {t(
                            "pages.dnsServerUpsert.fields.keeneticNotice.legacy"
                          )}
                        </AlertDescription>
                      </Alert>
                    </FieldContent>
                  </Field>
                ) : null}

                <form.Field
                  name={DNS_SERVER_FIELD_NAMES.address}
                  validators={{
                    onChange: ({ value, fieldApi }) =>
                      fieldApi.form.getFieldValue("type") ===
                      DnsServerType.keenetic
                        ? undefined
                        : (getAddressError(value) ?? undefined),
                  }}
                >
                  {(field) => {
                    const error = getFirstFieldError(field.state.meta.errors)

                    if (isKeeneticDns) {
                      return null
                    }

                    return (
                      <Field invalid={Boolean(error)}>
                        <FieldLabel htmlFor="dns-server-address">
                          {t("pages.dnsServerUpsert.fields.address")}
                        </FieldLabel>
                        <FieldContent>
                          <Input
                            aria-invalid={Boolean(error)}
                            id="dns-server-address"
                            onBlur={field.handleBlur}
                            onChange={(event) => {
                              field.handleChange(event.target.value)
                              if (
                                mode === "create" &&
                                presetSelection === "custom"
                              ) {
                                form.setFieldValue(
                                  DNS_SERVER_FIELD_NAMES.tag,
                                  makeTechnicalId(
                                    `dns_${event.target.value}`,
                                    configServers.map((server) => server.tag),
                                    { prefix: "dns" }
                                  )
                                )
                              }
                            }}
                            placeholder={t(
                              "pages.dnsServerUpsert.fields.addressPlaceholder"
                            )}
                            value={field.state.value}
                          />
                          <FieldHint
                            description={t(
                              "pages.dnsServerUpsert.fields.addressHint"
                            )}
                            error={error}
                          />
                        </FieldContent>
                      </Field>
                    )
                  }}
                </form.Field>

                {presentation === "page" &&
                mode === "create" &&
                presetSelection === "custom" ? (
                  <>
                    <Field invalid={customSecondaryInvalid}>
                      <FieldLabel htmlFor="dns-server-secondary-address">
                        {t("pages.dnsServerUpsert.fields.secondaryAddress")}
                      </FieldLabel>
                      <FieldContent>
                        <Input
                          aria-invalid={customSecondaryInvalid}
                          id="dns-server-secondary-address"
                          onChange={(event) => {
                            setCustomSecondaryAddress(event.target.value)
                            if (!event.target.value.trim()) {
                              setIncludeBackup(false)
                            }
                          }}
                          placeholder={t(
                            "pages.dnsServerUpsert.fields.secondaryAddressPlaceholder"
                          )}
                          value={customSecondaryAddress}
                        />
                        <FieldHint
                          description={t(
                            "pages.dnsServerUpsert.fields.secondaryAddressHint"
                          )}
                          error={
                            customSecondaryInvalid
                              ? t(
                                  "pages.dnsServerUpsert.validation.templateAddressInvalid"
                                )
                              : null
                          }
                        />
                      </FieldContent>
                    </Field>
                    <label
                      className="flex cursor-pointer items-start gap-3"
                      htmlFor="dns-server-save-template"
                    >
                      <Checkbox
                        checked={saveCustomTemplate}
                        id="dns-server-save-template"
                        onCheckedChange={(checked) =>
                          setSaveCustomTemplate(checked === true)
                        }
                      />
                      <span className="space-y-0.5">
                        <span className="block text-sm font-medium">
                          {t("pages.dnsServerUpsert.presets.saveCustom")}
                        </span>
                        <span className="block text-xs text-muted-foreground">
                          {t("pages.dnsServerUpsert.presets.saveCustomHint")}
                        </span>
                      </span>
                    </label>
                  </>
                ) : null}

                <form.Field name={DNS_SERVER_FIELD_NAMES.detour}>
                  {(field) => {
                    if (isKeeneticDns) {
                      return null
                    }

                    return (
                      <Field>
                        <FieldLabel>
                          {t("pages.dnsServerUpsert.fields.detour")}
                        </FieldLabel>
                        <FieldContent>
                          <OutboundSelect
                            allowEmpty
                            emptyLabel={t(
                              "pages.dnsServerUpsert.fields.detourEmpty"
                            )}
                            onValueChange={field.handleChange}
                            outbounds={config?.outbounds ?? []}
                            placeholder={t(
                              "pages.routingRuleUpsert.fields.selectOutbound"
                            )}
                            value={field.state.value}
                          />
                          <FieldHint
                            description={t(
                              "pages.dnsServerUpsert.fields.detourHint"
                            )}
                          />
                        </FieldContent>
                      </Field>
                    )
                  }}
                </form.Field>
              </>
            )
          }}
        </form.Subscribe>

        {mode === "create" &&
        (presetSelection !== "custom" ||
          customSecondaryAddress.trim().length > 0) ? (
          <label
            className="flex cursor-pointer items-start gap-3"
            htmlFor="dns-server-include-backup"
          >
            <Checkbox
              checked={includeBackup}
              disabled={presetSelection === "custom" && customSecondaryInvalid}
              id="dns-server-include-backup"
              onCheckedChange={(checked) => setIncludeBackup(checked === true)}
            />
            <span className="space-y-0.5">
              <span className="block text-sm font-medium">
                {t("pages.dnsServerUpsert.presets.includeBackup")}
              </span>
              <span className="block text-xs text-muted-foreground">
                {t("pages.dnsServerUpsert.presets.includeBackupHint", {
                  address:
                    presetSelection === "custom"
                      ? customSecondaryAddress
                      : resolveDnsTemplateSelection(
                          presetSelection,
                          savedTemplates
                        )?.secondaryAddress,
                })}
              </span>
            </span>
          </label>
        ) : null}
      </FieldGroup>

      {apiErrorMessage ? (
        <Alert className="border-destructive/30 bg-destructive/5 text-destructive">
          <AlertDescription className="whitespace-pre-wrap">
            {apiErrorMessage}
          </AlertDescription>
        </Alert>
      ) : null}

      <ServerValidationAlert errors={unmappedServerErrors} />

      <div className="flex justify-end gap-3" data-upsert-actions>
        {mode === "edit" && serverTag && config ? (
          <UpsertDeleteAction
            confirmLabel={t("pages.dnsServers.deleteDialog.confirm")}
            description={t("pages.dnsServers.deleteDialog.description", {
              tags: formatDnsServerNames(config, [serverTag]),
            })}
            impactItems={getDnsServerDeleteImpactItems(
              config,
              [serverTag],
              getDnsServerDeleteImpact(config, [serverTag]),
              t
            )}
            isPending={postConfigMutation.isPending}
            label={t("common.delete")}
            onConfirm={handleDelete}
            title={t("pages.dnsServers.deleteDialog.title")}
          />
        ) : null}
        <Button onClick={close} size="xl" type="button" variant="outline">
          {t("common.cancel")}
        </Button>
        <form.Subscribe selector={(state) => state.canSubmit}>
          {(canSubmit) => (
            <Button
              disabled={
                postConfigMutation.isPending ||
                !config ||
                !isDirty ||
                !canSubmit ||
                customSecondaryInvalid
              }
              size="xl"
              type="submit"
            >
              {mode === "create"
                ? t("pages.dnsServerUpsert.actions.create")
                : t("pages.dnsServerUpsert.actions.save")}
            </Button>
          )}
        </form.Subscribe>
      </div>
    </form>
  )
}

function getFirstFieldError(errors: unknown[]) {
  const error = errors.find((item) => typeof item === "string")
  return typeof error === "string" ? error : null
}

function getTagError(value: string, servers: DnsServer[], editingTag?: string) {
  const t = i18n.t.bind(i18n)
  const normalizedTag = value.trim()
  const duplicate = servers.some(
    (server) => server.tag === normalizedTag && server.tag !== editingTag
  )

  return (
    getTagNameValidationError(value, {
      requiredError: t("pages.dnsServerUpsert.validation.tagRequired"),
      invalidError: t("common.validation.tagNamePattern"),
      duplicateError: duplicate
        ? t("pages.dnsServerUpsert.validation.tagUnique")
        : null,
    }) ?? undefined
  )
}

function getAddressError(value: string) {
  const t = i18n.t.bind(i18n)
  if (!value.trim()) {
    return t("pages.dnsServerUpsert.validation.addressRequired")
  }

  if (!normalizeDnsAddress(value)) {
    return t("pages.dnsServerUpsert.validation.addressInvalid")
  }

  return undefined
}

function getDisplayNameError(value: string) {
  const t = i18n.t.bind(i18n)
  const normalized = value.trim()
  if (!normalized) {
    return t("pages.dnsServerUpsert.validation.displayNameRequired")
  }
  if (normalized.length > 80) {
    return t("pages.dnsServerUpsert.validation.displayNameTooLong")
  }
  return undefined
}

function resolveDnsServerFieldPath(
  path: string,
  tag: string
): DnsServerFieldName | undefined {
  const normalizedTag = tag.trim()

  if (path === "dns.servers") {
    return DNS_SERVER_FIELD_NAMES.tag
  }

  if (path === `dns.servers.${normalizedTag}`) {
    return DNS_SERVER_FIELD_NAMES.tag
  }

  if (path === `dns.servers.${normalizedTag}.tag`) {
    return DNS_SERVER_FIELD_NAMES.tag
  }

  if (path === `dns.servers.${normalizedTag}.display_name`) {
    return DNS_SERVER_FIELD_NAMES.displayName
  }

  if (path === `dns.servers.${normalizedTag}.type`) {
    return DNS_SERVER_FIELD_NAMES.type
  }

  if (path === `dns.servers.${normalizedTag}.address`) {
    return DNS_SERVER_FIELD_NAMES.address
  }

  if (path === `dns.servers.${normalizedTag}.detour`) {
    return DNS_SERVER_FIELD_NAMES.detour
  }

  return undefined
}
