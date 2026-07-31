import { useTranslation } from "react-i18next"
import { useMemo, useRef, useState } from "react"

import { useForm } from "@tanstack/react-form"
import { useQueryClient } from "@tanstack/react-query"
import { useStore } from "@tanstack/react-store"

import type { ApiError } from "@/api/client"
import type { ConfigObject } from "@/api/generated/model/configObject"
import type { InternalVpnServer } from "@/api/generated/model/internalVpnServer"
import type { InternalVpnService } from "@/api/generated/model/internalVpnService"
import { usePostConfigMutation } from "@/api/mutations"
import { queryKeys } from "@/api/query-keys"
import {
  useGetConfig,
  useGetNdmsInterfaceInventory,
  useGetNdmsVpnServerServices,
  useGetRuntimeInterfaces,
} from "@/api/queries"
import { selectConfig } from "@/api/selectors"
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldGroup,
  FieldHint,
  FieldLabel,
  FieldSeparator,
} from "@/components/shared/field"
import { BottomActionBar } from "@/components/shared/bottom-action-bar"
import { InterfaceMultiSelectList } from "@/components/shared/interface-picker"
import { ListPlaceholder } from "@/components/shared/list-placeholder"
import { PageHeader } from "@/components/shared/page-header"
import { SchedulePicker } from "@/components/shared/schedule-picker"
import { SectionTabs, type SectionTab } from "@/components/shared/section-tabs"
import { AuthSettingsCard } from "@/components/settings/auth-settings-card"
import {
  InternalVpnServersField,
  type InternalVpnServerInventoryState,
} from "@/components/settings/internal-vpn-servers-field"
import { InternalVpnServicesField } from "@/components/settings/internal-vpn-services-field"
import { LoggingSettingsCard } from "@/components/settings/logging-settings-card"
import {
  BackupAndRestoreCard,
  SoftwareUpdateCard,
} from "@/components/settings/maintenance-cards"
import { RemoteAccessCard } from "@/components/settings/remote-access-card"
import {
  CLEAN_SETTINGS_SECTION_STATE,
  type SettingsSectionController,
  type SettingsSectionState,
} from "@/components/settings/settings-section-control"
import { ServerValidationAlert } from "@/components/shared/server-validation-alert"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import {
  clearFormServerErrors,
  setFormServerErrors,
  splitFormApiErrors,
} from "@/lib/form-api-errors"
import {
  normalizeInternalVpnServerInterfaceNames,
  reconcileInternalVpnServerOverrides,
  type InternalVpnServerRuntimeState,
} from "@/lib/internal-vpn-server-policy"
import { reconcileInternalVpnServiceOverrides } from "@/lib/internal-vpn-service-policy"
import { mapNativeInterfaces } from "@/lib/native-interfaces"
import { getGeneralConfigActionState } from "@/pages/general-config-form-state"
import { useSectionTab } from "@/hooks/use-section-tab"
import { toast } from "sonner"

type StrictEnforcementOption = "automatic" | "enabled" | "disabled"

type SettingsDraft = {
  strictEnforcement: StrictEnforcementOption
  skipMarkedPackets: boolean
  clearDynamicSetsOnApply: boolean
  reconnectUnmarkedFlowsOnRoutingChange: boolean
  ipv6Enabled: boolean
  clientDnsEnforcement: boolean
  inboundInterfaces: string[]
  internalVpnServers?: InternalVpnServer[]
  internalVpnServices?: InternalVpnService[]
  listsAutoupdateEnabled: boolean
  cron: string
  fwmarkStart: string
  fwmarkMask: string
  tableStart: string
}

const fallbackDraft: SettingsDraft = {
  strictEnforcement: "automatic",
  skipMarkedPackets: true,
  clearDynamicSetsOnApply: true,
  reconnectUnmarkedFlowsOnRoutingChange: true,
  ipv6Enabled: true,
  clientDnsEnforcement: false,
  inboundInterfaces: [],
  listsAutoupdateEnabled: false,
  cron: "0 4 * * 0",
  fwmarkStart: "0x00010000",
  fwmarkMask: "0xffff0000",
  tableStart: "150",
}

const SETTINGS_FIELD_NAMES = {
  strictEnforcement: "strictEnforcement",
  skipMarkedPackets: "skipMarkedPackets",
  clearDynamicSetsOnApply: "clearDynamicSetsOnApply",
  reconnectUnmarkedFlowsOnRoutingChange:
    "reconnectUnmarkedFlowsOnRoutingChange",
  ipv6Enabled: "ipv6Enabled",
  clientDnsEnforcement: "clientDnsEnforcement",
  inboundInterfaces: "inboundInterfaces",
  internalVpnServers: "internalVpnServers",
  internalVpnServices: "internalVpnServices",
  listsAutoupdateEnabled: "listsAutoupdateEnabled",
  cron: "cron",
  fwmarkStart: "fwmarkStart",
  fwmarkMask: "fwmarkMask",
  tableStart: "tableStart",
} as const

type SettingsFieldName =
  (typeof SETTINGS_FIELD_NAMES)[keyof typeof SETTINGS_FIELD_NAMES]

const SETTINGS_TAB_VALUES = [
  "general",
  "incoming",
  "access",
  "logging",
  "advanced",
  "maintenance",
] as const

type SettingsTab = (typeof SETTINGS_TAB_VALUES)[number]
type DeferredSettingsKey = "auth" | "remoteAccess" | "logging"

const INITIAL_DEFERRED_SETTINGS_STATE: Record<
  DeferredSettingsKey,
  SettingsSectionState
> = {
  auth: CLEAN_SETTINGS_SECTION_STATE,
  remoteAccess: CLEAN_SETTINGS_SECTION_STATE,
  logging: CLEAN_SETTINGS_SECTION_STATE,
}

export function GeneralConfigPage() {
  const { t } = useTranslation()
  const configQuery = useGetConfig()
  const loadedConfig = selectConfig(configQuery.data)

  return (
    <div>
      <PageHeader
        description={t("pages.settings.description")}
        title={t("pages.settings.title")}
      />

      <div className="mt-3">
        {configQuery.isLoading ? (
          <GeneralConfigPageSkeleton />
        ) : configQuery.isError || !loadedConfig ? (
          <ListPlaceholder
            description="We can't load settings right now. Try refreshing the page."
            title="Unable to load data"
            variant="error"
          />
        ) : (
          <LoadedGeneralConfigPage loadedConfig={loadedConfig} />
        )}
      </div>
    </div>
  )
}

type LoadedGeneralConfigPageProps = {
  loadedConfig: ConfigObject
}

function LoadedGeneralConfigPage({
  loadedConfig,
}: LoadedGeneralConfigPageProps) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const ndmsInventoryQuery = useGetNdmsInterfaceInventory()
  const ndmsVpnServicesQuery = useGetNdmsVpnServerServices()
  const runtimeInterfacesQuery = useGetRuntimeInterfaces()
  const authSettingsRef = useRef<SettingsSectionController>(null)
  const remoteAccessRef = useRef<SettingsSectionController>(null)
  const loggingSettingsRef = useRef<SettingsSectionController>(null)
  // Role-less WG/AWG confirmation is an explicit user action in this edit
  // session. Keep it independently of live inventory flags: stale snapshots
  // intentionally mask candidate authority and must not erase the draft.
  const rolelessConfirmationNdmsIdsRef = useRef(new Set<string>())
  const [deferredState, setDeferredState] = useState(
    INITIAL_DEFERRED_SETTINGS_STATE
  )
  const [deferredSavePending, setDeferredSavePending] = useState(false)

  const postConfigMutation = usePostConfigMutation()
  const [activeTab, setActiveTab] = useSectionTab<SettingsTab>(
    SETTINGS_TAB_VALUES,
    "general"
  )
  const settingsTabs: SectionTab<SettingsTab>[] = [
    {
      value: "general",
      label: t("pages.settings.tabs.general"),
    },
    {
      value: "incoming",
      label: t("pages.settings.tabs.incoming"),
    },
    {
      value: "access",
      label: t("pages.settings.tabs.access"),
    },
    {
      value: "logging",
      label: t("pages.settings.tabs.logging"),
    },
    {
      value: "advanced",
      label: t("pages.settings.tabs.advanced"),
    },
    {
      value: "maintenance",
      label: t("pages.settings.tabs.maintenance"),
    },
  ]

  const form = useForm({
    defaultValues: getDraftFromConfig(loadedConfig),
    validators: {
      onSubmitAsync: async ({ value }) => {
        const updatedConfig = buildUpdatedConfig(loadedConfig, value)
        clearFormServerErrors(form)

        try {
          await postConfigMutation.mutateAsync({ data: updatedConfig })
          toast.success(t("pages.settings.saved"))
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

          form.reset(getDraftFromConfig(updatedConfig))
          return undefined
        } catch (error) {
          const result = splitFormApiErrors({
            error: error as ApiError,
            fieldNames: Object.values(SETTINGS_FIELD_NAMES),
            resolvePath: resolveSettingsFieldPath,
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
          | { unmapped?: { path: string; message: string }[] }
          | undefined
      )?.unmapped ?? []
  )

  const isPending = postConfigMutation.isPending || deferredSavePending
  const internalVpnServerInventoryState: InternalVpnServerInventoryState =
    ndmsInventoryQuery.isLoading
      ? "loading"
      : ndmsInventoryQuery.isError || ndmsInventoryQuery.data?.status !== 200
        ? "error"
        : ndmsInventoryQuery.data.data.catalog_status === "stale"
          ? "stale"
          : ndmsInventoryQuery.data.data.catalog_status === "fresh" &&
              ndmsInventoryQuery.data.data.available
            ? "ready"
            : "unavailable"
  const internalVpnServerRuntimeState: InternalVpnServerRuntimeState =
    runtimeInterfacesQuery.isLoading
      ? "loading"
      : runtimeInterfacesQuery.isError ||
          runtimeInterfacesQuery.data?.status !== 200
        ? "error"
        : "ready"
  const internalVpnServiceInventoryState: InternalVpnServerInventoryState =
    ndmsVpnServicesQuery.isLoading
      ? "loading"
      : ndmsVpnServicesQuery.isError ||
          ndmsVpnServicesQuery.data?.status !== 200
        ? "error"
        : ndmsVpnServicesQuery.data.data.catalog_status === "stale"
          ? "stale"
          : ndmsVpnServicesQuery.data.data.catalog_status === "fresh" &&
              ndmsVpnServicesQuery.data.data.available
            ? "ready"
            : "unavailable"
  const runtimeInterfaces = useMemo(
    () =>
      runtimeInterfacesQuery.data?.status === 200
        ? runtimeInterfacesQuery.data.data.interfaces
        : [],
    [runtimeInterfacesQuery.data]
  )
  const nativeInterfaces = useMemo(
    () =>
      mapNativeInterfaces(
        ndmsInventoryQuery.data?.status === 200
          ? ndmsInventoryQuery.data.data.interfaces
          : [],
        runtimeInterfaces
      ),
    [ndmsInventoryQuery.data, runtimeInterfaces]
  )
  const nativeVpnServices = useMemo(
    () =>
      ndmsVpnServicesQuery.data?.status === 200
        ? ndmsVpnServicesQuery.data.data.services
        : [],
    [ndmsVpnServicesQuery.data]
  )

  const handleCancel = () => {
    rolelessConfirmationNdmsIdsRef.current.clear()
    form.reset(getDraftFromConfig(loadedConfig))
    clearFormServerErrors(form)
    authSettingsRef.current?.reset()
    remoteAccessRef.current?.reset()
    loggingSettingsRef.current?.reset()
    setDeferredState(INITIAL_DEFERRED_SETTINGS_STATE)
  }

  const updateDeferredState = (
    key: DeferredSettingsKey,
    state: SettingsSectionState
  ) => {
    setDeferredState((current) =>
      current[key].dirty === state.dirty && current[key].valid === state.valid
        ? current
        : { ...current, [key]: state }
    )
  }

  const deferredDirty = Object.values(deferredState).some(
    (state) => state.dirty
  )
  const deferredValid = Object.values(deferredState).every(
    (state) => state.valid
  )

  const handleSaveAll = async (formIsDefaultValue: boolean) => {
    setDeferredSavePending(true)
    try {
      if (!formIsDefaultValue) {
        await form.handleSubmit()
      }
      await loggingSettingsRef.current?.save()
      await remoteAccessRef.current?.save()
      await authSettingsRef.current?.save()
    } catch {
      // Existing section mutations report their own localized errors and keep
      // the failed section dirty so the user can correct it and retry.
    } finally {
      setDeferredSavePending(false)
    }
  }

  return (
    <>
      <SectionTabs
        ariaLabel={t("pages.settings.tabs.ariaLabel")}
        onValueChange={setActiveTab}
        tabs={settingsTabs}
        value={activeTab}
      />

      <div
        aria-hidden={activeTab !== "general" && activeTab !== "incoming"}
        className="settings-sections"
        hidden={activeTab !== "general" && activeTab !== "incoming"}
        role="tabpanel"
      >
        <Card size="sm">
          <CardHeader>
            <CardTitle>
              {t(
                activeTab === "incoming"
                  ? "pages.settings.incoming.title"
                  : "pages.settings.general.title"
              )}
            </CardTitle>
            <CardDescription>
              {t(
                activeTab === "incoming"
                  ? "pages.settings.incoming.description"
                  : "pages.settings.general.description"
              )}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <FieldGroup>
              <form.Field name={SETTINGS_FIELD_NAMES.strictEnforcement}>
                {(field) => (
                  <Field
                    className={activeTab === "general" ? undefined : "hidden"}
                  >
                    <FieldLabel>
                      {t("pages.settings.general.strictEnforcementLabel")}
                    </FieldLabel>
                    <FieldContent>
                      <Select
                        items={[
                          {
                            value: "automatic",
                            label: t(
                              "pages.settings.general.strictEnforcementOptions.automatic"
                            ),
                          },
                          {
                            value: "enabled",
                            label: t(
                              "pages.settings.general.strictEnforcementOptions.enabled"
                            ),
                          },
                          {
                            value: "disabled",
                            label: t(
                              "pages.settings.general.strictEnforcementOptions.disabled"
                            ),
                          },
                        ]}
                        onValueChange={(value) =>
                          field.handleChange(
                            (value ??
                              fallbackDraft.strictEnforcement) as StrictEnforcementOption
                          )
                        }
                        value={field.state.value}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            {(
                              ["automatic", "enabled", "disabled"] as const
                            ).map((option) => (
                              <SelectItem key={option} value={option}>
                                {t(
                                  `pages.settings.general.strictEnforcementOptions.${option}`
                                )}
                              </SelectItem>
                            ))}
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                      <FieldHint
                        description={t(
                          `pages.settings.general.strictEnforcementHints.${field.state.value}`
                        )}
                      />
                    </FieldContent>
                  </Field>
                )}
              </form.Field>

              <FieldSeparator
                className={activeTab === "general" ? undefined : "hidden"}
              />

              <form.Field name={SETTINGS_FIELD_NAMES.skipMarkedPackets}>
                {(field) => (
                  <Field
                    className={activeTab === "general" ? undefined : "hidden"}
                  >
                    <FieldContent>
                      <div className="flex items-center space-x-3">
                        <Checkbox
                          checked={field.state.value}
                          id="skip-marked-packets"
                          onCheckedChange={(checked) =>
                            field.handleChange(checked === true)
                          }
                        />
                        <FieldLabel
                          className="cursor-pointer flex-col items-start gap-0"
                          htmlFor="skip-marked-packets"
                        >
                          {t("pages.settings.general.skipMarkedPacketsLabel")}
                        </FieldLabel>
                      </div>
                      <FieldHint
                        description={t(
                          "pages.settings.general.skipMarkedPacketsHint"
                        )}
                      />
                    </FieldContent>
                  </Field>
                )}
              </form.Field>

              <FieldSeparator
                className={activeTab === "general" ? undefined : "hidden"}
              />

              <form.Field name={SETTINGS_FIELD_NAMES.clearDynamicSetsOnApply}>
                {(field) => (
                  <Field
                    className={activeTab === "general" ? undefined : "hidden"}
                  >
                    <FieldContent>
                      <div className="flex items-center space-x-3">
                        <Checkbox
                          checked={field.state.value}
                          id="clear-dynamic-sets-on-apply"
                          onCheckedChange={(checked) =>
                            field.handleChange(checked === true)
                          }
                        />
                        <FieldLabel
                          className="cursor-pointer flex-col items-start gap-0"
                          htmlFor="clear-dynamic-sets-on-apply"
                        >
                          {t(
                            "pages.settings.general.clearDynamicSetsOnApplyLabel"
                          )}
                        </FieldLabel>
                      </div>
                      <FieldHint
                        description={t(
                          "pages.settings.general.clearDynamicSetsOnApplyHint"
                        )}
                      />
                    </FieldContent>
                  </Field>
                )}
              </form.Field>

              <FieldSeparator
                className={activeTab === "general" ? undefined : "hidden"}
              />

              <form.Field name={SETTINGS_FIELD_NAMES.ipv6Enabled}>
                {(field) => (
                  <Field
                    className={activeTab === "general" ? undefined : "hidden"}
                  >
                    <FieldContent>
                      <div className="flex items-center space-x-3">
                        <Checkbox
                          checked={field.state.value}
                          id="ipv6-enabled"
                          onCheckedChange={(checked) =>
                            field.handleChange(checked === true)
                          }
                        />
                        <FieldLabel
                          className="cursor-pointer flex-col items-start gap-0"
                          htmlFor="ipv6-enabled"
                        >
                          {t("pages.settings.general.ipv6EnabledLabel")}
                        </FieldLabel>
                      </div>
                      <FieldHint
                        description={t(
                          "pages.settings.general.ipv6EnabledHint"
                        )}
                      />
                    </FieldContent>
                  </Field>
                )}
              </form.Field>

              <FieldSeparator
                className={activeTab === "general" ? undefined : "hidden"}
              />

              <form.Field name={SETTINGS_FIELD_NAMES.clientDnsEnforcement}>
                {(field) => (
                  <Field
                    className={activeTab === "general" ? undefined : "hidden"}
                  >
                    <FieldContent>
                      <div className="flex items-center space-x-3">
                        <Checkbox
                          checked={field.state.value}
                          id="client-dns-enforcement"
                          onCheckedChange={(checked) =>
                            field.handleChange(checked === true)
                          }
                        />
                        <FieldLabel
                          className="cursor-pointer flex-col items-start gap-0"
                          htmlFor="client-dns-enforcement"
                        >
                          {t(
                            "pages.settings.general.clientDnsEnforcementLabel"
                          )}
                        </FieldLabel>
                      </div>
                      <FieldHint
                        description={t(
                          "pages.settings.general.clientDnsEnforcementHint"
                        )}
                      />
                    </FieldContent>
                  </Field>
                )}
              </form.Field>

              <form.Field name={SETTINGS_FIELD_NAMES.inboundInterfaces}>
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)
                  return (
                    <Field
                      className={
                        activeTab === "incoming" ? undefined : "hidden"
                      }
                      invalid={Boolean(error)}
                    >
                      <FieldLabel htmlFor="inbound-interfaces">
                        {t("pages.settings.general.inboundInterfacesLabel")}
                      </FieldLabel>
                      <FieldContent>
                        <div id="inbound-interfaces">
                          <InterfaceMultiSelectList
                            flat
                            name={SETTINGS_FIELD_NAMES.inboundInterfaces}
                            interfaces={runtimeInterfaces}
                            value={field.state.value}
                            onChange={(nextInterfaces) => {
                              const normalizedInterfaces =
                                normalizeInternalVpnServerInterfaceNames(
                                  nextInterfaces
                                )
                              const reconciledOverrides =
                                reconcileInternalVpnServerOverrides({
                                  overrides: form.getFieldValue(
                                    SETTINGS_FIELD_NAMES.internalVpnServers
                                  ),
                                  baselineOverrides:
                                    loadedConfig.route?.internal_vpn_servers,
                                  legacyInboundInterfaces: normalizedInterfaces,
                                  baselineLegacyInboundInterfaces:
                                    loadedConfig.route?.inbound_interfaces,
                                  rolelessConfirmationNdmsIds: [
                                    ...new Set([
                                      ...nativeInterfaces
                                        .filter(
                                          (nativeInterface) =>
                                            nativeInterface.source
                                              .internal_vpn_server_role_confirmation_required
                                        )
                                        .map(
                                          (nativeInterface) =>
                                            nativeInterface.source.id
                                        ),
                                      ...rolelessConfirmationNdmsIdsRef.current,
                                    ]),
                                  ],
                                })
                              const reconciledServiceOverrides =
                                reconcileInternalVpnServiceOverrides({
                                  overrides: form.getFieldValue(
                                    SETTINGS_FIELD_NAMES.internalVpnServices
                                  ),
                                  baselineOverrides:
                                    loadedConfig.route?.internal_vpn_services,
                                  legacyInboundInterfaces: normalizedInterfaces,
                                  baselineLegacyInboundInterfaces:
                                    loadedConfig.route?.inbound_interfaces,
                                })

                              field.handleChange(normalizedInterfaces)
                              form.setFieldValue(
                                SETTINGS_FIELD_NAMES.internalVpnServers,
                                reconciledOverrides
                              )
                              form.setFieldValue(
                                SETTINGS_FIELD_NAMES.internalVpnServices,
                                reconciledServiceOverrides
                              )
                            }}
                            addLabel={t(
                              "pages.settings.general.inboundInterfacesAddAction"
                            )}
                            emptyMessage={t(
                              "pages.settings.general.inboundInterfacesNoAvailable"
                            )}
                            placeholderTitle={t(
                              "pages.settings.general.inboundInterfacesEmptyTitle"
                            )}
                            placeholderDescription={t(
                              "pages.settings.general.inboundInterfacesEmptyDescription"
                            )}
                            error={error}
                          />
                        </div>
                        <FieldDescription>
                          {t("pages.settings.general.inboundInterfacesHint")}
                        </FieldDescription>
                      </FieldContent>
                    </Field>
                  )
                }}
              </form.Field>

              <FieldSeparator
                className={activeTab === "incoming" ? undefined : "hidden"}
              />

              <form.Field name={SETTINGS_FIELD_NAMES.internalVpnServers}>
                {(field) => (
                  <form.Subscribe
                    selector={(state) => state.values.inboundInterfaces}
                  >
                    {(legacyInboundInterfaces) => {
                      const error = getFirstFieldError(field.state.meta.errors)
                      return (
                        <Field
                          className={
                            activeTab === "incoming" ? undefined : "hidden"
                          }
                          invalid={Boolean(error)}
                        >
                          <FieldContent>
                            <InternalVpnServersField
                              authoritativeServices={
                                internalVpnServiceInventoryState === "ready"
                                  ? nativeVpnServices
                                  : undefined
                              }
                              baselineOverrides={
                                loadedConfig.route?.internal_vpn_servers
                              }
                              copy={{
                                title: t(
                                  "pages.settings.general.internalVpnServersTitle"
                                ),
                                description: t(
                                  "pages.settings.general.internalVpnServersDescription"
                                ),
                                emptyTitle: t(
                                  "pages.settings.general.internalVpnServersEmptyTitle"
                                ),
                                emptyDescription: t(
                                  "pages.settings.general.internalVpnServersEmptyDescription"
                                ),
                                loadingTitle: t(
                                  "pages.settings.general.internalVpnServersLoadingTitle"
                                ),
                                loadingDescription: t(
                                  "pages.settings.general.internalVpnServersLoadingDescription"
                                ),
                                unavailableTitle: t(
                                  "pages.settings.general.internalVpnServersUnavailableTitle"
                                ),
                                unavailableDescription: t(
                                  "pages.settings.general.internalVpnServersUnavailableDescription"
                                ),
                                staleTitle: t(
                                  "pages.settings.general.internalVpnServersStaleTitle"
                                ),
                                staleDescription: t(
                                  "pages.settings.general.internalVpnServersStaleDescription"
                                ),
                                loadErrorTitle: t(
                                  "pages.settings.general.internalVpnServersLoadErrorTitle"
                                ),
                                loadErrorDescription: t(
                                  "pages.settings.general.internalVpnServersLoadErrorDescription"
                                ),
                                confirmationTitle: t(
                                  "pages.settings.general.internalVpnServersConfirmationTitle"
                                ),
                                confirmationDescription: t(
                                  "pages.settings.general.internalVpnServersConfirmationDescription"
                                ),
                                confirmationAction: t(
                                  "pages.settings.general.internalVpnServersConfirmationAction"
                                ),
                                processLabel: t(
                                  "pages.settings.general.internalVpnServersProcessLabel"
                                ),
                                inheritLabel: t(
                                  "pages.settings.general.internalVpnServersInheritLabel"
                                ),
                                statusUp: t(
                                  "pages.settings.general.internalVpnServersStatusUp"
                                ),
                                statusDown: t(
                                  "pages.settings.general.internalVpnServersStatusDown"
                                ),
                                statusMissing: t(
                                  "pages.settings.general.internalVpnServersStatusMissing"
                                ),
                                statusUnknown: t(
                                  "pages.settings.general.internalVpnServersStatusUnknown"
                                ),
                                missingHint: t(
                                  "pages.settings.general.internalVpnServersMissingHint"
                                ),
                                confirmationAriaLabel: (serverLabel) =>
                                  t(
                                    "pages.settings.general.internalVpnServersConfirmationAriaLabel",
                                    { server: serverLabel }
                                  ),
                                toggleAriaLabel: (serverLabel) =>
                                  t(
                                    "pages.settings.general.internalVpnServersToggleAriaLabel",
                                    { server: serverLabel }
                                  ),
                                inheritAriaLabel: (serverLabel) =>
                                  t(
                                    "pages.settings.general.internalVpnServersInheritAriaLabel",
                                    { server: serverLabel }
                                  ),
                              }}
                              disabled={isPending}
                              inventoryState={internalVpnServerInventoryState}
                              legacyInboundInterfaces={legacyInboundInterfaces}
                              nativeInterfaces={nativeInterfaces}
                              onChange={field.handleChange}
                              onRolelessConfirmationChange={(
                                ndmsId,
                                confirmed
                              ) => {
                                if (confirmed) {
                                  rolelessConfirmationNdmsIdsRef.current.add(
                                    ndmsId
                                  )
                                } else {
                                  rolelessConfirmationNdmsIdsRef.current.delete(
                                    ndmsId
                                  )
                                }
                              }}
                              overrides={field.state.value}
                              runtimeState={internalVpnServerRuntimeState}
                            />
                            <FieldHint error={error ?? null} />
                          </FieldContent>
                        </Field>
                      )
                    }}
                  </form.Subscribe>
                )}
              </form.Field>

              <FieldSeparator
                className={activeTab === "incoming" ? undefined : "hidden"}
              />

              <form.Field name={SETTINGS_FIELD_NAMES.internalVpnServices}>
                {(field) => (
                  <form.Subscribe
                    selector={(state) => state.values.inboundInterfaces}
                  >
                    {(legacyInboundInterfaces) => {
                      const error = getFirstFieldError(field.state.meta.errors)
                      return (
                        <Field
                          className={
                            activeTab === "incoming" ? undefined : "hidden"
                          }
                          invalid={Boolean(error)}
                        >
                          <FieldContent>
                            <InternalVpnServicesField
                              baselineOverrides={
                                loadedConfig.route?.internal_vpn_services
                              }
                              copy={{
                                title: t(
                                  "pages.settings.general.internalVpnServicesTitle"
                                ),
                                description: t(
                                  "pages.settings.general.internalVpnServicesDescription"
                                ),
                                emptyTitle: t(
                                  "pages.settings.general.internalVpnServicesEmptyTitle"
                                ),
                                emptyDescription: t(
                                  "pages.settings.general.internalVpnServicesEmptyDescription"
                                ),
                                loadingTitle: t(
                                  "pages.settings.general.internalVpnServicesLoadingTitle"
                                ),
                                loadingDescription: t(
                                  "pages.settings.general.internalVpnServicesLoadingDescription"
                                ),
                                unavailableTitle: t(
                                  "pages.settings.general.internalVpnServicesUnavailableTitle"
                                ),
                                unavailableDescription: t(
                                  "pages.settings.general.internalVpnServicesUnavailableDescription"
                                ),
                                staleTitle: t(
                                  "pages.settings.general.internalVpnServicesStaleTitle"
                                ),
                                staleDescription: t(
                                  "pages.settings.general.internalVpnServicesStaleDescription"
                                ),
                                loadErrorTitle: t(
                                  "pages.settings.general.internalVpnServicesLoadErrorTitle"
                                ),
                                loadErrorDescription: t(
                                  "pages.settings.general.internalVpnServicesLoadErrorDescription"
                                ),
                                processLabel: t(
                                  "pages.settings.general.internalVpnServicesProcessLabel"
                                ),
                                inheritLabel: t(
                                  "pages.settings.general.internalVpnServicesInheritLabel"
                                ),
                                statusEnabled: t(
                                  "pages.settings.general.internalVpnServicesStatusEnabled"
                                ),
                                statusDisabled: t(
                                  "pages.settings.general.internalVpnServicesStatusDisabled"
                                ),
                                statusMissing: t(
                                  "pages.settings.general.internalVpnServicesStatusMissing"
                                ),
                                poolLabel: t(
                                  "pages.settings.general.internalVpnServicesPoolLabel"
                                ),
                                boundInterfaceLabel: t(
                                  "pages.settings.general.internalVpnServicesBoundInterfaceLabel"
                                ),
                                unavailableHint: t(
                                  "pages.settings.general.internalVpnServicesUnavailableHint"
                                ),
                                toggleAriaLabel: (serviceLabel) =>
                                  t(
                                    "pages.settings.general.internalVpnServicesToggleAriaLabel",
                                    { server: serviceLabel }
                                  ),
                                inheritAriaLabel: (serviceLabel) =>
                                  t(
                                    "pages.settings.general.internalVpnServicesInheritAriaLabel",
                                    { server: serviceLabel }
                                  ),
                              }}
                              disabled={isPending}
                              inventoryState={internalVpnServiceInventoryState}
                              legacyInboundInterfaces={legacyInboundInterfaces}
                              onChange={field.handleChange}
                              overrides={field.state.value}
                              services={nativeVpnServices}
                            />
                            <FieldHint error={error ?? null} />
                          </FieldContent>
                        </Field>
                      )
                    }}
                  </form.Subscribe>
                )}
              </form.Field>
            </FieldGroup>
          </CardContent>
        </Card>

        <Card hidden={activeTab !== "general"} size="sm">
          <CardHeader>
            <CardTitle>{t("pages.settings.autoupdate.title")}</CardTitle>
            <CardDescription>
              {t("pages.settings.autoupdate.description")}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <FieldGroup>
              <form.Field name={SETTINGS_FIELD_NAMES.listsAutoupdateEnabled}>
                {(field) => (
                  <Field>
                    <FieldContent>
                      <div className="flex items-center space-x-3">
                        <Checkbox
                          checked={field.state.value}
                          id="autoupdate-lists"
                          onCheckedChange={(checked) =>
                            field.handleChange(checked === true)
                          }
                        />
                        <FieldLabel
                          className="cursor-pointer flex-col items-start gap-0"
                          htmlFor="autoupdate-lists"
                        >
                          {t("pages.settings.autoupdate.enabledLabel")}
                        </FieldLabel>
                      </div>
                      <FieldHint
                        description={t("pages.settings.autoupdate.enabledHint")}
                      />
                    </FieldContent>
                  </Field>
                )}
              </form.Field>

              <FieldSeparator />

              <form.Field name={SETTINGS_FIELD_NAMES.cron}>
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)

                  return (
                    <Field invalid={Boolean(error)}>
                      <FieldLabel>
                        {t("pages.settings.autoupdate.cronLabel")}
                      </FieldLabel>
                      <FieldContent>
                        <SchedulePicker
                          onChange={(value) => field.handleChange(value)}
                          value={field.state.value}
                        />
                        <FieldHint
                          description={t(
                            "pages.settings.autoupdate.scheduleHint"
                          )}
                          error={error}
                        />
                      </FieldContent>
                    </Field>
                  )
                }}
              </form.Field>
            </FieldGroup>
          </CardContent>
        </Card>
      </div>

      <div
        aria-hidden={activeTab !== "access"}
        className="settings-sections"
        hidden={activeTab !== "access"}
        role="tabpanel"
      >
        <AuthSettingsCard
          onStateChange={(state) => updateDeferredState("auth", state)}
          ref={authSettingsRef}
        />
        <RemoteAccessCard
          onStateChange={(state) => updateDeferredState("remoteAccess", state)}
          ref={remoteAccessRef}
        />
      </div>

      <div
        aria-hidden={activeTab !== "logging"}
        className="settings-sections"
        hidden={activeTab !== "logging"}
        role="tabpanel"
      >
        <LoggingSettingsCard
          onStateChange={(state) => updateDeferredState("logging", state)}
          ref={loggingSettingsRef}
        />
      </div>

      <div
        aria-hidden={activeTab !== "advanced"}
        className="settings-sections"
        hidden={activeTab !== "advanced"}
        role="tabpanel"
      >
        <Card size="sm">
          <CardHeader>
            <CardTitle>{t("pages.settings.advanced.title")}</CardTitle>
            <CardDescription>
              {t("pages.settings.advanced.description")}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <FieldGroup>
              <form.Field
                name={
                  SETTINGS_FIELD_NAMES.reconnectUnmarkedFlowsOnRoutingChange
                }
              >
                {(field) => (
                  <Field>
                    <FieldContent>
                      <div className="flex items-center space-x-3">
                        <Checkbox
                          checked={field.state.value}
                          id="reconnect-unmarked-flows-on-routing-change"
                          onCheckedChange={(checked) =>
                            field.handleChange(checked === true)
                          }
                        />
                        <FieldLabel
                          className="cursor-pointer flex-col items-start gap-0"
                          htmlFor="reconnect-unmarked-flows-on-routing-change"
                        >
                          {t(
                            "pages.settings.advanced.reconnectUnmarkedFlowsOnRoutingChangeLabel"
                          )}
                        </FieldLabel>
                      </div>
                      <FieldHint
                        description={t(
                          "pages.settings.advanced.reconnectUnmarkedFlowsOnRoutingChangeHint"
                        )}
                      />
                    </FieldContent>
                  </Field>
                )}
              </form.Field>

              <FieldSeparator />

              <form.Field name={SETTINGS_FIELD_NAMES.fwmarkStart}>
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)

                  return (
                    <Field invalid={Boolean(error)}>
                      <FieldLabel htmlFor="fwmark-start">
                        {t("pages.settings.advanced.fwmarkStartLabel")}
                      </FieldLabel>
                      <FieldContent>
                        <Input
                          aria-invalid={Boolean(error)}
                          id="fwmark-start"
                          onBlur={field.handleBlur}
                          onChange={(event) =>
                            field.handleChange(event.target.value)
                          }
                          value={field.state.value}
                        />
                        <FieldHint
                          description={t(
                            "pages.settings.advanced.fwmarkStartHint"
                          )}
                          error={error ?? null}
                        />
                      </FieldContent>
                    </Field>
                  )
                }}
              </form.Field>

              <FieldSeparator />

              <form.Field name={SETTINGS_FIELD_NAMES.fwmarkMask}>
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)

                  return (
                    <Field invalid={Boolean(error)}>
                      <FieldLabel htmlFor="fwmark-mask">
                        {t("pages.settings.advanced.fwmarkMaskLabel")}
                      </FieldLabel>
                      <FieldContent>
                        <Input
                          aria-invalid={Boolean(error)}
                          id="fwmark-mask"
                          onBlur={field.handleBlur}
                          onChange={(event) =>
                            field.handleChange(event.target.value)
                          }
                          value={field.state.value}
                        />
                        <FieldHint
                          description={
                            <>
                              {t(
                                "pages.settings.advanced.fwmarkMaskHintPrefix"
                              )}{" "}
                              <code>f</code>{" "}
                              {t(
                                "pages.settings.advanced.fwmarkMaskHintSuffix"
                              )}{" "}
                              <code>0x00ff0000</code>.
                            </>
                          }
                          error={error ?? null}
                        />
                      </FieldContent>
                    </Field>
                  )
                }}
              </form.Field>

              <FieldSeparator />

              <form.Field name={SETTINGS_FIELD_NAMES.tableStart}>
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)

                  return (
                    <Field invalid={Boolean(error)}>
                      <FieldLabel htmlFor="table-start">
                        {t("pages.settings.advanced.tableStartLabel")}
                      </FieldLabel>
                      <FieldContent>
                        <Input
                          aria-invalid={Boolean(error)}
                          id="table-start"
                          onBlur={field.handleBlur}
                          onChange={(event) =>
                            field.handleChange(event.target.value)
                          }
                          value={field.state.value}
                        />
                        <FieldHint
                          description={t(
                            "pages.settings.advanced.tableStartHint"
                          )}
                          error={error ?? null}
                        />
                      </FieldContent>
                    </Field>
                  )
                }}
              </form.Field>
            </FieldGroup>
          </CardContent>
        </Card>
      </div>

      <div
        aria-hidden={activeTab !== "maintenance"}
        className="settings-sections"
        hidden={activeTab !== "maintenance"}
        role="tabpanel"
      >
        <SoftwareUpdateCard />
        <BackupAndRestoreCard />
      </div>

      <ServerValidationAlert errors={unmappedServerErrors} />

      <form.Subscribe
        selector={(state) => ({
          canSubmit: state.canSubmit,
          isDefaultValue: state.isDefaultValue,
        })}
      >
        {({ canSubmit, isDefaultValue }) => {
          const actionState = getGeneralConfigActionState({
            canSubmit,
            deferredDirty,
            deferredValid,
            isDefaultValue,
            isPending,
          })

          return (
            <BottomActionBar contentClassName="justify-end">
              <Button
                disabled={actionState.cancelDisabled}
                onClick={handleCancel}
                size="xl"
                variant="outline"
              >
                {t("common.cancel")}
              </Button>
              <Button
                disabled={actionState.saveDisabled}
                onClick={() => void handleSaveAll(isDefaultValue)}
                size="xl"
              >
                {isPending
                  ? t("pages.settings.actions.saving")
                  : t("pages.settings.actions.save")}
              </Button>
            </BottomActionBar>
          )
        }}
      </form.Subscribe>
    </>
  )
}

function GeneralConfigPageSkeleton() {
  return (
    <>
      <Card>
        <CardHeader>
          <Skeleton className="h-6 w-28" />
          <Skeleton className="h-4 w-56" />
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            <div className="flex items-start gap-3">
              <Skeleton className="mt-0.5 h-4 w-4 rounded-sm" />
              <div className="space-y-2">
                <Skeleton className="h-4 w-48" />
                <Skeleton className="h-4 w-full max-w-3xl" />
                <Skeleton className="h-4 w-5/6 max-w-2xl" />
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <Skeleton className="h-6 w-40" />
          <Skeleton className="h-4 w-64" />
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            <div className="flex items-start gap-3">
              <Skeleton className="mt-0.5 h-4 w-4 rounded-sm" />
              <div className="space-y-2">
                <Skeleton className="h-4 w-44" />
                <Skeleton className="h-4 w-full max-w-3xl" />
              </div>
            </div>
            <Skeleton className="h-px w-full" />
            <div className="space-y-3">
              <Skeleton className="h-4 w-14" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-4 w-80" />
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <Skeleton className="h-6 w-56" />
          <Skeleton className="h-4 w-72" />
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {[0, 1, 2].map((index) => (
              <div className="space-y-6" key={index}>
                {index > 0 ? <Skeleton className="h-px w-full" /> : null}
                <div className="space-y-3">
                  <Skeleton className="h-4 w-52" />
                  <Skeleton className="h-10 w-full" />
                  <Skeleton className="h-4 w-full max-w-2xl" />
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <div className="flex justify-end gap-2">
        <Skeleton className="h-11 w-24" />
        <Skeleton className="h-11 w-24" />
      </div>
    </>
  )
}

function getFirstFieldError(errors: unknown[]) {
  const firstError = errors[0]
  return typeof firstError === "string" ? firstError : null
}

function getDraftFromConfig(config: ConfigObject): SettingsDraft {
  return {
    strictEnforcement:
      config.daemon?.strict_enforcement === undefined
        ? "automatic"
        : config.daemon.strict_enforcement
          ? "enabled"
          : "disabled",
    skipMarkedPackets:
      config.daemon?.skip_marked_packets ?? fallbackDraft.skipMarkedPackets,
    clearDynamicSetsOnApply:
      config.daemon?.clear_dynamic_sets_on_apply ??
      fallbackDraft.clearDynamicSetsOnApply,
    reconnectUnmarkedFlowsOnRoutingChange:
      config.daemon?.reconnect_unmarked_flows_on_routing_change ??
      fallbackDraft.reconnectUnmarkedFlowsOnRoutingChange,
    ipv6Enabled: config.daemon?.ipv6_enabled ?? fallbackDraft.ipv6Enabled,
    clientDnsEnforcement:
      config.dns?.client_dns_enforcement?.enabled ??
      fallbackDraft.clientDnsEnforcement,
    inboundInterfaces: normalizeInternalVpnServerInterfaceNames(
      config.route?.inbound_interfaces ?? fallbackDraft.inboundInterfaces
    ),
    internalVpnServers: config.route?.internal_vpn_servers?.map((server) => ({
      ...server,
    })),
    internalVpnServices: config.route?.internal_vpn_services?.map(
      (service) => ({ ...service })
    ),
    listsAutoupdateEnabled:
      config.lists_autoupdate?.enabled ?? fallbackDraft.listsAutoupdateEnabled,
    cron: config.lists_autoupdate?.cron ?? fallbackDraft.cron,
    fwmarkStart: toHex32(config.fwmark?.start, fallbackDraft.fwmarkStart),
    fwmarkMask: toHex32(config.fwmark?.mask, fallbackDraft.fwmarkMask),
    tableStart: toStringInt(
      config.iproute?.table_start,
      fallbackDraft.tableStart
    ),
  }
}

function buildUpdatedConfig(
  config: ConfigObject,
  draft: SettingsDraft
): ConfigObject {
  const tableStart = parseStrictDecimalToNumber(draft.tableStart)

  return {
    ...config,
    daemon: {
      ...config.daemon,
      strict_enforcement:
        draft.strictEnforcement === "automatic"
          ? undefined
          : draft.strictEnforcement === "enabled",
      skip_marked_packets: draft.skipMarkedPackets,
      clear_dynamic_sets_on_apply: draft.clearDynamicSetsOnApply,
      reconnect_unmarked_flows_on_routing_change:
        draft.reconnectUnmarkedFlowsOnRoutingChange,
      ipv6_enabled: draft.ipv6Enabled,
    },
    route: {
      ...config.route,
      inbound_interfaces: normalizeInternalVpnServerInterfaceNames(
        draft.inboundInterfaces
      ),
      internal_vpn_servers: draft.internalVpnServers,
      internal_vpn_services: draft.internalVpnServices,
    },
    dns: {
      ...config.dns,
      client_dns_enforcement: {
        ...config.dns?.client_dns_enforcement,
        enabled: draft.clientDnsEnforcement,
      },
    },
    fwmark: {
      ...config.fwmark,
      start: draft.fwmarkStart.trim(),
      mask: draft.fwmarkMask.trim(),
    },
    iproute: {
      ...config.iproute,
      table_start: toBackendIntegerValue(tableStart, draft.tableStart.trim()),
    },
    lists_autoupdate: {
      ...config.lists_autoupdate,
      enabled: draft.listsAutoupdateEnabled,
      cron: draft.cron.trim(),
    },
  }
}

function toHex32(value: string | undefined, fallback: string) {
  if (!value) {
    return fallback
  }

  const trimmed = value.trim()
  if (!/^0x[0-9a-fA-F]+$/.test(trimmed)) {
    return fallback
  }

  const normalized = trimmed.slice(2).replace(/^0+/, "") || "0"
  return `0x${normalized.padStart(8, "0")}`
}

function toStringInt(value: number | undefined, fallback: string) {
  if (!Number.isInteger(value)) {
    return fallback
  }

  return String(value)
}

function parseStrictDecimalToNumber(value: string) {
  const trimmed = value.trim()
  if (!/^\d+$/.test(trimmed)) {
    return null
  }

  return Number.parseInt(trimmed, 10)
}

function toBackendIntegerValue(parsed: number | null, raw: string): number {
  if (parsed !== null) {
    return parsed
  }

  return raw as unknown as number
}

function resolveSettingsFieldPath(path: string): SettingsFieldName | undefined {
  if (
    path === "route.inbound_interfaces" ||
    path.startsWith("route.inbound_interfaces[")
  ) {
    return SETTINGS_FIELD_NAMES.inboundInterfaces
  }

  if (
    path === "route.internal_vpn_servers" ||
    path.startsWith("route.internal_vpn_servers[")
  ) {
    return SETTINGS_FIELD_NAMES.internalVpnServers
  }

  if (
    path === "route.internal_vpn_services" ||
    path.startsWith("route.internal_vpn_services[")
  ) {
    return SETTINGS_FIELD_NAMES.internalVpnServices
  }

  switch (path) {
    case "daemon.strict_enforcement":
      return SETTINGS_FIELD_NAMES.strictEnforcement
    case "daemon.skip_marked_packets":
      return SETTINGS_FIELD_NAMES.skipMarkedPackets
    case "daemon.clear_dynamic_sets_on_apply":
      return SETTINGS_FIELD_NAMES.clearDynamicSetsOnApply
    case "daemon.reconnect_unmarked_flows_on_routing_change":
      return SETTINGS_FIELD_NAMES.reconnectUnmarkedFlowsOnRoutingChange
    case "daemon.ipv6_enabled":
      return SETTINGS_FIELD_NAMES.ipv6Enabled
    case "dns.client_dns_enforcement.enabled":
      return SETTINGS_FIELD_NAMES.clientDnsEnforcement
    case "lists_autoupdate.enabled":
      return SETTINGS_FIELD_NAMES.listsAutoupdateEnabled
    case "lists_autoupdate.cron":
      return SETTINGS_FIELD_NAMES.cron
    case "fwmark.start":
      return SETTINGS_FIELD_NAMES.fwmarkStart
    case "fwmark.mask":
      return SETTINGS_FIELD_NAMES.fwmarkMask
    case "iproute.table_start":
      return SETTINGS_FIELD_NAMES.tableStart
    default:
      return undefined
  }
}
