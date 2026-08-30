import { useTranslation } from "react-i18next"
import { useMemo, useRef, useState } from "react"

import { useForm } from "@tanstack/react-form"
import { useQueryClient } from "@tanstack/react-query"
import { useStore } from "@tanstack/react-store"

import type { ApiError } from "@/api/client"
import type { ConfigObject } from "@/api/generated/model/configObject"
import type { InternalVpnServer } from "@/api/generated/model/internalVpnServer"
import type { InternalVpnService } from "@/api/generated/model/internalVpnService"
import type { PpeDeoffloadMode } from "@/api/generated/model/ppeDeoffloadMode"
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
import { HelpHint } from "@/components/shared/help-hint"
import { ListRefreshRouteFields } from "@/components/lists/list-refresh-route-fields"
import { InterfaceMultiSelectList } from "@/components/shared/interface-picker"
import { ListIdentityLabel } from "@/components/shared/list-identity-label"
import { ListPlaceholder } from "@/components/shared/list-placeholder"
import { MultiSelectList } from "@/components/shared/multi-select-list"
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
import { getListSearchText, sortListIdsByDisplayName } from "@/lib/list-display"
import {
  getGlobalListRefreshRouteChain,
  getListRefreshDetourMode,
  normalizeListRefreshRouteChain,
} from "@/lib/list-refresh-route"
import { mapNativeInterfaces } from "@/lib/native-interfaces"
import { getGeneralConfigActionState } from "@/pages/general-config-form-state"
import {
  resolveNdmsInterfaceLabel,
  useInterfaceNames,
} from "@/hooks/use-interface-names"
import { useSectionTab } from "@/hooks/use-section-tab"
import { toast } from "sonner"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  getMetaUdp443Policy,
  type MetaUdp443Policy,
  withMetaUdp443Policy,
} from "@/lib/meta-udp-443-policy"
import { provisionTunnelProbe } from "@/lib/tunnel-probe-provisioning"

type StrictEnforcementOption = "automatic" | "enabled" | "disabled"

const WHATSAPP_RECONNECT_CATALOG_IDENTITY =
  "0475c85d06ea258343fdda22ee85bfd0a3e1fb2fa88751ab39ee0ffb64efedbe"

type SettingsDraft = {
  strictEnforcement: StrictEnforcementOption
  skipMarkedPackets: boolean
  clearDynamicSetsOnApply: boolean
  ttlBypassEnabled: boolean
  ppeDeoffloadMode: PpeDeoffloadMode
  ppeDeoffloadQuicEnabled: boolean
  reconnectUnmarkedFlowsOnRoutingChange: boolean
  reconnectOwnedFlowsOnRoutingChangeLists: string[] | undefined
  metaUdp443Policy: MetaUdp443Policy
  ipv6Enabled: boolean
  ipsetHashsize: string
  ipsetMaxelem: string
  clientDnsEnforcement: boolean
  inboundInterfaces: string[]
  internalVpnServers?: InternalVpnServer[]
  internalVpnServices?: InternalVpnService[]
  listsAutoupdateEnabled: boolean
  cron: string
  listRefreshDetour: string
  listRefreshFallbackDetours: string[]
  fwmarkStart: string
  fwmarkMask: string
  tableStart: string
  tunnelProbeEnabled: boolean
  tunnelProbeOutbound: string
  tunnelProbeList: string
}

const fallbackDraft: SettingsDraft = {
  strictEnforcement: "automatic",
  skipMarkedPackets: true,
  clearDynamicSetsOnApply: true,
  ttlBypassEnabled: true,
  ppeDeoffloadMode: "off",
  ppeDeoffloadQuicEnabled: false,
  reconnectUnmarkedFlowsOnRoutingChange: true,
  reconnectOwnedFlowsOnRoutingChangeLists: undefined,
  metaUdp443Policy: "balanced",
  ipv6Enabled: true,
  ipsetHashsize: "",
  ipsetMaxelem: "",
  clientDnsEnforcement: false,
  inboundInterfaces: [],
  listsAutoupdateEnabled: false,
  cron: "0 4 * * 0",
  listRefreshDetour: "",
  listRefreshFallbackDetours: [],
  fwmarkStart: "0x00010000",
  fwmarkMask: "0xffff0000",
  tableStart: "150",
  // Off, and naming nothing. Switching this on moves traffic on the strength
  // of a measurement, and the move is not reversible in practice.
  tunnelProbeEnabled: false,
  tunnelProbeOutbound: "",
  tunnelProbeList: "",
}

const SETTINGS_FIELD_NAMES = {
  strictEnforcement: "strictEnforcement",
  skipMarkedPackets: "skipMarkedPackets",
  clearDynamicSetsOnApply: "clearDynamicSetsOnApply",
  ttlBypassEnabled: "ttlBypassEnabled",
  ppeDeoffloadMode: "ppeDeoffloadMode",
  ppeDeoffloadQuicEnabled: "ppeDeoffloadQuicEnabled",
  reconnectUnmarkedFlowsOnRoutingChange:
    "reconnectUnmarkedFlowsOnRoutingChange",
  reconnectOwnedFlowsOnRoutingChangeLists:
    "reconnectOwnedFlowsOnRoutingChangeLists",
  metaUdp443Policy: "metaUdp443Policy",
  ipv6Enabled: "ipv6Enabled",
  ipsetHashsize: "ipsetHashsize",
  ipsetMaxelem: "ipsetMaxelem",
  clientDnsEnforcement: "clientDnsEnforcement",
  inboundInterfaces: "inboundInterfaces",
  internalVpnServers: "internalVpnServers",
  internalVpnServices: "internalVpnServices",
  listsAutoupdateEnabled: "listsAutoupdateEnabled",
  cron: "cron",
  listRefreshDetour: "listRefreshDetour",
  listRefreshFallbackDetours: "listRefreshFallbackDetours",
  fwmarkStart: "fwmarkStart",
  fwmarkMask: "fwmarkMask",
  tableStart: "tableStart",
  tunnelProbeEnabled: "tunnelProbeEnabled",
  tunnelProbeOutbound: "tunnelProbeOutbound",
  tunnelProbeList: "tunnelProbeList",
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
    // Единственная страница без ритма в корне: был голый <div>, а расстояние
    // между заголовком и содержимым подпиралось `mt-3` вручную.
    <div className="space-y-3">
      <PageHeader
        description={t("pages.settings.description")}
        title={t("pages.settings.title")}
      />

      <div>
        {configQuery.isLoading ? (
          <GeneralConfigPageSkeleton />
        ) : configQuery.isError || !loadedConfig ? (
          <ListPlaceholder
            description={t("common.loadErrorDescription")}
            title={t("common.unableToLoadData")}
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
  const inheritedUrlListCount = Object.values(loadedConfig.lists ?? {}).filter(
    (list) => Boolean(list.url) && getListRefreshDetourMode(list) === "inherit"
  ).length
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
  // «Привязан к: Bridge0» → «Привязан к: Домашняя сеть»: имя берётся из
  // данных NDMS (каталог имён интерфейсов и инвентарь туннелей), а не из
  // словаря — переименованный сегмент покажется своим настоящим именем.
  // Если прошивка имени не дала, остаётся технический идентификатор.
  const ndmsInterfaceNames = useInterfaceNames()
  const resolveBoundInterfaceName = useMemo(() => {
    const names = ndmsInterfaceNames.names
    return (ndmsId: string): string | undefined => {
      const wanted = ndmsId.trim()
      if (!wanted) {
        return undefined
      }
      for (const nativeInterface of nativeInterfaces) {
        if (
          nativeInterface.id === wanted ||
          nativeInterface.logicalName === wanted
        ) {
          const label = nativeInterface.label.trim()
          if (label && label !== wanted) {
            return label
          }
        }
      }
      return resolveNdmsInterfaceLabel(names, wanted)
    }
  }, [nativeInterfaces, ndmsInterfaceNames.names])
  const reconnectListOptions = useMemo(
    () =>
      sortListIdsByDisplayName(
        Object.keys(loadedConfig.lists ?? {}),
        loadedConfig.lists
      ),
    [loadedConfig.lists]
  )
  const recommendedReconnectListIds = useMemo(
    () =>
      reconnectListOptions.filter(
        (listId) =>
          loadedConfig.lists?.[listId]?.catalog_identity ===
          WHATSAPP_RECONNECT_CATALOG_IDENTITY
      ),
    [loadedConfig.lists, reconnectListOptions]
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
            <CardDescription className="max-w-[480px]">
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
                    width="short"
                    className={activeTab === "general" ? undefined : "hidden"}
                  >
                    <FieldLabel>
                      {t("pages.settings.general.strictEnforcementLabel")}
                      {/* Подсказка под полем говорит, что делает выбранный
                          вариант; знак вопроса — что такое kill-switch вообще.
                          Это разные сведения, поэтому дублирования нет. */}
                      <HelpHint
                        text={t("pages.settings.general.strictEnforcementHelp")}
                      />
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
                    width="short"
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
                        {/* Пояснение переехало под знак вопроса целиком.
                            Прежняя строка под флажком повторяла то же самое
                            через fwmark и policy routing — для того, кто эти
                            слова знает, она была не нужна, а остальным не
                            помогала. */}
                        <HelpHint
                          text={t(
                            "pages.settings.general.skipMarkedPacketsHelp"
                          )}
                        />
                      </div>
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
                    width="short"
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

              <form.Field name={SETTINGS_FIELD_NAMES.ttlBypassEnabled}>
                {(field) => (
                  <Field
                    width="short"
                    className={activeTab === "general" ? undefined : "hidden"}
                  >
                    <FieldContent>
                      <div className="flex items-center space-x-3">
                        <Checkbox
                          checked={field.state.value}
                          id="ttl-bypass-enabled"
                          onCheckedChange={(checked) =>
                            field.handleChange(checked === true)
                          }
                        />
                        <FieldLabel
                          className="cursor-pointer flex-col items-start gap-0"
                          htmlFor="ttl-bypass-enabled"
                        >
                          {t("pages.settings.general.ttlBypassEnabledLabel")}
                        </FieldLabel>
                      </div>
                      <FieldHint
                        description={t(
                          "pages.settings.general.ttlBypassEnabledHint"
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
                    width="short"
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
                    width="short"
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

              {/* Автоматика «nfqws2 не справился — уводим в туннель».
                  Выключена по умолчанию, и это не осторожность ради
                  осторожности: правила nfqws2 привязаны к провайдерскому
                  интерфейсу, поэтому уведённый хост исчезает из его поля
                  зрения и перестаёт давать то свидетельство, по которому его
                  туда отправили. Обратной дороги на практике нет. */}
              <form.Field name={SETTINGS_FIELD_NAMES.tunnelProbeEnabled}>
                {(field) => (
                  <Field
                    width="short"
                    className={activeTab === "general" ? undefined : "hidden"}
                  >
                    <FieldContent>
                      <div className="flex items-center space-x-3">
                        <Checkbox
                          checked={field.state.value}
                          id="tunnel-probe-enabled"
                          onCheckedChange={(checked) =>
                            field.handleChange(checked === true)
                          }
                        />
                        <FieldLabel
                          className="cursor-pointer flex-col items-start gap-0"
                          htmlFor="tunnel-probe-enabled"
                        >
                          {t("pages.settings.general.tunnelProbeEnabledLabel")}
                        </FieldLabel>
                        <HelpHint
                          text={t("pages.settings.general.tunnelProbeHelp")}
                        />
                      </div>
                      <FieldHint
                        description={t(
                          "pages.settings.general.tunnelProbeEnabledHint"
                        )}
                      />
                    </FieldContent>
                  </Field>
                )}
              </form.Field>

              <form.Field name={SETTINGS_FIELD_NAMES.tunnelProbeOutbound}>
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)

                  return (
                    <Field
                      width="short"
                      invalid={Boolean(error)}
                      className={activeTab === "general" ? undefined : "hidden"}
                    >
                      <FieldLabel htmlFor="tunnel-probe-outbound">
                        {t("pages.settings.general.tunnelProbeOutboundLabel")}
                      </FieldLabel>
                      <FieldContent>
                        <Input
                          aria-invalid={Boolean(error)}
                          id="tunnel-probe-outbound"
                          onBlur={field.handleBlur}
                          onChange={(event) =>
                            field.handleChange(event.target.value)
                          }
                          value={field.state.value}
                        />
                        <FieldHint
                          description={t(
                            "pages.settings.general.tunnelProbeOutboundHint"
                          )}
                          error={error ?? null}
                        />
                      </FieldContent>
                    </Field>
                  )
                }}
              </form.Field>

              <form.Field name={SETTINGS_FIELD_NAMES.tunnelProbeList}>
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)

                  return (
                    <Field
                      width="short"
                      invalid={Boolean(error)}
                      className={activeTab === "general" ? undefined : "hidden"}
                    >
                      <FieldLabel htmlFor="tunnel-probe-list">
                        {t("pages.settings.general.tunnelProbeListLabel")}
                      </FieldLabel>
                      <FieldContent>
                        <Input
                          aria-invalid={Boolean(error)}
                          id="tunnel-probe-list"
                          onBlur={field.handleBlur}
                          onChange={(event) =>
                            field.handleChange(event.target.value)
                          }
                          value={field.state.value}
                        />
                        <FieldHint
                          description={t(
                            "pages.settings.general.tunnelProbeListHint"
                          )}
                          error={error ?? null}
                        />
                      </FieldContent>
                    </Field>
                  )
                }}
              </form.Field>

              <FieldSeparator
                className={activeTab === "general" ? undefined : "hidden"}
              />

              <form.Field name={SETTINGS_FIELD_NAMES.inboundInterfaces}>
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)
                  return (
                    <Field
                      width="short"
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
                          width="short"
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
                          width="short"
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
                                // Имя собирается из вида службы: NDMS отдаёт
                                // свои идентификаторы вроде `VirtualIPServerIKE2`,
                                // по которым не понять ни что это VPN-сервер,
                                // ни какой именно.
                                serviceName: (kind) =>
                                  t(
                                    `pages.settings.general.internalVpnServiceNames.${kind}`
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
                              resolveBoundInterfaceName={
                                resolveBoundInterfaceName
                              }
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
            <CardDescription className="max-w-[480px]">
              {t("pages.settings.autoupdate.description")}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <FieldGroup>
              <form.Field name={SETTINGS_FIELD_NAMES.listsAutoupdateEnabled}>
                {(field) => (
                  <Field width="short">
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
                    <Field width="short" invalid={Boolean(error)}>
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

              <FieldSeparator />

              <div className="max-w-[480px] space-y-1">
                <FieldLabel>
                  {t("pages.settings.autoupdate.routeTitle")}
                </FieldLabel>
                <FieldDescription>
                  {t("pages.settings.autoupdate.routeDescription")}
                </FieldDescription>
              </div>

              <form.Field name={SETTINGS_FIELD_NAMES.listRefreshDetour}>
                {(detourField) => (
                  <form.Field
                    name={SETTINGS_FIELD_NAMES.listRefreshFallbackDetours}
                  >
                    {(fallbackField) => (
                      <ListRefreshRouteFields
                        fieldWidth="short"
                        chain={{
                          detour: detourField.state.value,
                          fallbackDetours: fallbackField.state.value,
                        }}
                        detourError={getFirstFieldError(
                          detourField.state.meta.errors
                        )}
                        detourFieldName={SETTINGS_FIELD_NAMES.listRefreshDetour}
                        fallbackError={getFirstFieldError(
                          fallbackField.state.meta.errors
                        )}
                        fallbackFieldName={
                          SETTINGS_FIELD_NAMES.listRefreshFallbackDetours
                        }
                        onChange={(chain) => {
                          detourField.handleChange(chain.detour)
                          fallbackField.handleChange(chain.fallbackDetours)
                        }}
                        outbounds={loadedConfig.outbounds ?? []}
                      />
                    )}
                  </form.Field>
                )}
              </form.Field>

              <div className="max-w-[480px]">
                <FieldHint
                  description={t(
                    "pages.settings.autoupdate.inheritedListsCount",
                    { count: inheritedUrlListCount }
                  )}
                />
              </div>
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
            <CardDescription className="max-w-[480px]">
              {t("pages.settings.advanced.description")}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <FieldGroup>
              <form.Field name={SETTINGS_FIELD_NAMES.ppeDeoffloadMode}>
                {(field) => (
                  <Field width="short">
                    <FieldLabel htmlFor="ppe-deoffload-mode">
                      {t("pages.settings.advanced.ppeDeoffloadModeLabel")}
                    </FieldLabel>
                    <FieldContent>
                      <Select
                        items={[
                          {
                            value: "off",
                            label: t(
                              "pages.settings.advanced.ppeDeoffloadModeOptions.off"
                            ),
                          },
                          {
                            value: "auto",
                            label: t(
                              "pages.settings.advanced.ppeDeoffloadModeOptions.auto"
                            ),
                          },
                        ]}
                        onValueChange={(value) => {
                          if (value !== "off" && value !== "auto") return
                          field.handleChange(value)
                          if (value === "off") {
                            form.setFieldValue(
                              SETTINGS_FIELD_NAMES.ppeDeoffloadQuicEnabled,
                              false
                            )
                          }
                        }}
                        value={field.state.value}
                      >
                        <SelectTrigger id="ppe-deoffload-mode">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            <SelectItem value="off">
                              {t(
                                "pages.settings.advanced.ppeDeoffloadModeOptions.off"
                              )}
                            </SelectItem>
                            <SelectItem value="auto">
                              {t(
                                "pages.settings.advanced.ppeDeoffloadModeOptions.auto"
                              )}
                            </SelectItem>
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                      <FieldHint
                        description={t(
                          "pages.settings.advanced.ppeDeoffloadModeHint"
                        )}
                      />
                    </FieldContent>
                  </Field>
                )}
              </form.Field>

              <FieldSeparator />

              <form.Field name={SETTINGS_FIELD_NAMES.ppeDeoffloadQuicEnabled}>
                {(field) => (
                  <form.Subscribe
                    selector={(state) => state.values.ppeDeoffloadMode}
                  >
                    {(mode) => (
                      <Field width="short">
                        <FieldContent>
                          <div className="flex items-center space-x-3">
                            <Checkbox
                              checked={field.state.value}
                              disabled={mode !== "auto"}
                              id="ppe-deoffload-quic-enabled"
                              onCheckedChange={(checked) =>
                                field.handleChange(checked === true)
                              }
                            />
                            <FieldLabel
                              className="cursor-pointer flex-col items-start gap-0"
                              htmlFor="ppe-deoffload-quic-enabled"
                            >
                              {t(
                                "pages.settings.advanced.ppeDeoffloadQuicEnabledLabel"
                              )}
                            </FieldLabel>
                          </div>
                          <FieldHint
                            description={t(
                              "pages.settings.advanced.ppeDeoffloadQuicEnabledHint"
                            )}
                          />
                        </FieldContent>
                      </Field>
                    )}
                  </form.Subscribe>
                )}
              </form.Field>

              <FieldSeparator />

              <form.Field
                name={
                  SETTINGS_FIELD_NAMES.reconnectUnmarkedFlowsOnRoutingChange
                }
              >
                {(field) => (
                  <Field width="short">
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

              <form.Field
                name={
                  SETTINGS_FIELD_NAMES.reconnectOwnedFlowsOnRoutingChangeLists
                }
              >
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)

                  return (
                    <form.Subscribe
                      selector={(state) =>
                        state.values.reconnectUnmarkedFlowsOnRoutingChange
                      }
                    >
                      {(reconnectEnabled) => {
                        const configuredListIds = field.state.value
                        const usesAutomaticRecommendation =
                          configuredListIds === undefined
                        const selectedListIds = usesAutomaticRecommendation
                          ? recommendedReconnectListIds
                          : configuredListIds
                        const reconnectMode = usesAutomaticRecommendation
                          ? "automatic"
                          : "manual"
                        const status = !reconnectEnabled
                          ? t(
                              "pages.settings.advanced.reconnectOwnedFlowsOnRoutingChangeListsDisabledStatus"
                            )
                          : usesAutomaticRecommendation
                            ? t(
                                recommendedReconnectListIds.length > 0
                                  ? "pages.settings.advanced.reconnectOwnedFlowsOnRoutingChangeListsAutomaticStatus"
                                  : "pages.settings.advanced.reconnectOwnedFlowsOnRoutingChangeListsAutomaticUnavailableStatus"
                              )
                            : selectedListIds.length === 0
                              ? t(
                                  "pages.settings.advanced.reconnectOwnedFlowsOnRoutingChangeListsOptOutStatus"
                                )
                              : t(
                                  "pages.settings.advanced.reconnectOwnedFlowsOnRoutingChangeListsExplicitStatus"
                                )

                        return (
                          <Field width="short" invalid={Boolean(error)}>
                            <FieldLabel id="reconnect-owned-flows-on-routing-change-lists-label">
                              {t(
                                "pages.settings.advanced.reconnectOwnedFlowsOnRoutingChangeListsLabel"
                              )}
                            </FieldLabel>
                            <FieldContent>
                              <Select
                                disabled={!reconnectEnabled}
                                items={[
                                  {
                                    value: "automatic",
                                    label: t(
                                      "pages.settings.advanced.reconnectOwnedFlowsOnRoutingChangeModeOptions.automatic"
                                    ),
                                  },
                                  {
                                    value: "manual",
                                    label: t(
                                      "pages.settings.advanced.reconnectOwnedFlowsOnRoutingChangeModeOptions.manual"
                                    ),
                                  },
                                ]}
                                onValueChange={(value) => {
                                  if (value === "automatic") {
                                    field.handleChange(undefined)
                                    return
                                  }
                                  if (value === "manual") {
                                    field.handleChange([
                                      ...recommendedReconnectListIds,
                                    ])
                                  }
                                }}
                                value={reconnectMode}
                              >
                                <SelectTrigger
                                  aria-label={t(
                                    "pages.settings.advanced.reconnectOwnedFlowsOnRoutingChangeModeLabel"
                                  )}
                                >
                                  <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                  <SelectGroup>
                                    <SelectItem value="automatic">
                                      {t(
                                        "pages.settings.advanced.reconnectOwnedFlowsOnRoutingChangeModeOptions.automatic"
                                      )}
                                    </SelectItem>
                                    <SelectItem value="manual">
                                      {t(
                                        "pages.settings.advanced.reconnectOwnedFlowsOnRoutingChangeModeOptions.manual"
                                      )}
                                    </SelectItem>
                                  </SelectGroup>
                                </SelectContent>
                              </Select>
                              <fieldset
                                aria-labelledby="reconnect-owned-flows-on-routing-change-lists-label"
                                className="min-w-0 border-0 p-0 disabled:opacity-60"
                                disabled={
                                  !reconnectEnabled ||
                                  usesAutomaticRecommendation
                                }
                              >
                                <MultiSelectList
                                  addLabel={t(
                                    "pages.settings.advanced.reconnectOwnedFlowsOnRoutingChangeListsAddAction"
                                  )}
                                  emptyMessage={t(
                                    "pages.settings.advanced.reconnectOwnedFlowsOnRoutingChangeListsNoAvailable"
                                  )}
                                  error={error}
                                  getSearchText={(listId) =>
                                    getListSearchText(
                                      listId,
                                      loadedConfig.lists
                                    )
                                  }
                                  name={
                                    SETTINGS_FIELD_NAMES.reconnectOwnedFlowsOnRoutingChangeLists
                                  }
                                  onChange={field.handleChange}
                                  options={reconnectListOptions}
                                  placeholderDescription={t(
                                    "pages.settings.advanced.reconnectOwnedFlowsOnRoutingChangeListsEmptyDescription"
                                  )}
                                  placeholderTitle={t(
                                    "pages.settings.advanced.reconnectOwnedFlowsOnRoutingChangeListsEmptyTitle"
                                  )}
                                  renderItem={(listId) => (
                                    <ListIdentityLabel
                                      lists={loadedConfig.lists}
                                      technicalId={listId}
                                    />
                                  )}
                                  usageSubtitle={(listId) =>
                                    recommendedReconnectListIds.includes(listId)
                                      ? t(
                                          "pages.settings.advanced.reconnectOwnedFlowsOnRoutingChangeListsRecommended"
                                        )
                                      : undefined
                                  }
                                  value={selectedListIds}
                                />
                              </fieldset>
                              <FieldHint
                                description={
                                  <>
                                    <span className="block">
                                      {t(
                                        "pages.settings.advanced.reconnectOwnedFlowsOnRoutingChangeListsHint"
                                      )}
                                    </span>
                                    <span className="mt-1 block">{status}</span>
                                  </>
                                }
                              />
                            </FieldContent>
                          </Field>
                        )
                      }}
                    </form.Subscribe>
                  )
                }}
              </form.Field>

              <FieldSeparator />

              <form.Field name={SETTINGS_FIELD_NAMES.metaUdp443Policy}>
                {(field) => (
                  <Field width="short">
                    <FieldLabel htmlFor="meta-udp-443-policy">
                      {t("pages.settings.advanced.metaUdp443PolicyLabel")}
                    </FieldLabel>
                    <FieldContent>
                      <Select
                        items={[
                          {
                            value: "balanced",
                            label: t(
                              "pages.settings.advanced.metaUdp443PolicyOptions.balanced"
                            ),
                          },
                          {
                            value: "messages_first",
                            label: t(
                              "pages.settings.advanced.metaUdp443PolicyOptions.messagesFirst"
                            ),
                          },
                        ]}
                        onValueChange={(value) => {
                          if (
                            value === "balanced" ||
                            value === "messages_first"
                          ) {
                            field.handleChange(value)
                          }
                        }}
                        value={field.state.value}
                      >
                        <SelectTrigger id="meta-udp-443-policy">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            <SelectItem value="balanced">
                              {t(
                                "pages.settings.advanced.metaUdp443PolicyOptions.balanced"
                              )}
                            </SelectItem>
                            <SelectItem value="messages_first">
                              {t(
                                "pages.settings.advanced.metaUdp443PolicyOptions.messagesFirst"
                              )}
                            </SelectItem>
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                      <FieldHint
                        description={t(
                          "pages.settings.advanced.metaUdp443PolicyHint"
                        )}
                      />
                      <Alert className="mt-2">
                        <AlertTitle>
                          {t(
                            "pages.settings.advanced.metaUdp443AndroidBackgroundTitle"
                          )}
                        </AlertTitle>
                        <AlertDescription>
                          {t(
                            "pages.settings.advanced.metaUdp443AndroidBackgroundDescription"
                          )}
                        </AlertDescription>
                      </Alert>
                      {field.state.value === "messages_first" ? (
                        <Alert className="mt-2" variant="warning">
                          <AlertTitle>
                            {t(
                              "pages.settings.advanced.metaUdp443PolicyWarningTitle"
                            )}
                          </AlertTitle>
                          <AlertDescription>
                            {t(
                              "pages.settings.advanced.metaUdp443PolicyWarningDescription"
                            )}
                          </AlertDescription>
                        </Alert>
                      ) : null}
                    </FieldContent>
                  </Field>
                )}
              </form.Field>

              <FieldSeparator />

              <form.Field name={SETTINGS_FIELD_NAMES.fwmarkStart}>
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)

                  return (
                    <Field width="short" invalid={Boolean(error)}>
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
                    <Field width="short" invalid={Boolean(error)}>
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

              <form.Field name={SETTINGS_FIELD_NAMES.ipsetHashsize}>
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)

                  return (
                    <Field width="short" invalid={Boolean(error)}>
                      <FieldLabel htmlFor="ipset-hashsize">
                        {t("pages.settings.advanced.ipsetHashsizeLabel")}
                      </FieldLabel>
                      <FieldContent>
                        <Input
                          aria-invalid={Boolean(error)}
                          id="ipset-hashsize"
                          inputMode="numeric"
                          max={2147483648}
                          min={1}
                          onBlur={field.handleBlur}
                          onChange={(event) =>
                            field.handleChange(event.target.value)
                          }
                          placeholder="1024"
                          type="number"
                          value={field.state.value}
                        />
                        <FieldHint
                          description={t(
                            "pages.settings.advanced.ipsetHashsizeHint"
                          )}
                          error={error ?? null}
                        />
                      </FieldContent>
                    </Field>
                  )
                }}
              </form.Field>

              <FieldSeparator />

              <form.Field name={SETTINGS_FIELD_NAMES.ipsetMaxelem}>
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)

                  return (
                    <Field width="short" invalid={Boolean(error)}>
                      <FieldLabel htmlFor="ipset-maxelem">
                        {t("pages.settings.advanced.ipsetMaxelemLabel")}
                      </FieldLabel>
                      <FieldContent>
                        <Input
                          aria-invalid={Boolean(error)}
                          id="ipset-maxelem"
                          inputMode="numeric"
                          max={4294967295}
                          min={1}
                          onBlur={field.handleBlur}
                          onChange={(event) =>
                            field.handleChange(event.target.value)
                          }
                          placeholder="65536"
                          type="number"
                          value={field.state.value}
                        />
                        <FieldHint
                          description={t(
                            "pages.settings.advanced.ipsetMaxelemHint"
                          )}
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
                    <Field width="short" invalid={Boolean(error)}>
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
        <Skeleton className="h-10 w-24" />
        <Skeleton className="h-10 w-24" />
      </div>
    </>
  )
}

function getFirstFieldError(errors: unknown[]) {
  const firstError = errors[0]
  return typeof firstError === "string" ? firstError : null
}

function getDraftFromConfig(config: ConfigObject): SettingsDraft {
  const ppeDeoffloadMode =
    config.daemon?.ppe_deoffload_mode ?? fallbackDraft.ppeDeoffloadMode

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
    ttlBypassEnabled:
      config.daemon?.ttl_bypass_enabled ?? fallbackDraft.ttlBypassEnabled,
    ppeDeoffloadMode,
    ppeDeoffloadQuicEnabled:
      ppeDeoffloadMode === "auto" &&
      (config.daemon?.ppe_deoffload_quic_enabled ??
        fallbackDraft.ppeDeoffloadQuicEnabled),
    reconnectUnmarkedFlowsOnRoutingChange:
      config.daemon?.reconnect_unmarked_flows_on_routing_change ??
      fallbackDraft.reconnectUnmarkedFlowsOnRoutingChange,
    reconnectOwnedFlowsOnRoutingChangeLists:
      config.daemon?.reconnect_owned_flows_on_routing_change_lists ??
      fallbackDraft.reconnectOwnedFlowsOnRoutingChangeLists,
    metaUdp443Policy: getMetaUdp443Policy(config.daemon),
    ipv6Enabled: config.daemon?.ipv6_enabled ?? fallbackDraft.ipv6Enabled,
    ipsetHashsize: toStringInt(config.daemon?.ipset_hashsize, ""),
    ipsetMaxelem: toStringInt(config.daemon?.ipset_maxelem, ""),
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
    listRefreshDetour: getGlobalListRefreshRouteChain(config.list_refresh)
      .detour,
    listRefreshFallbackDetours: getGlobalListRefreshRouteChain(
      config.list_refresh
    ).fallbackDetours,
    fwmarkStart: toHex32(config.fwmark?.start, fallbackDraft.fwmarkStart),
    fwmarkMask: toHex32(config.fwmark?.mask, fallbackDraft.fwmarkMask),
    tableStart: toStringInt(
      config.iproute?.table_start,
      fallbackDraft.tableStart
    ),
    tunnelProbeEnabled:
      config.tunnel_probe?.enabled ?? fallbackDraft.tunnelProbeEnabled,
    tunnelProbeOutbound:
      config.tunnel_probe?.outbound ?? fallbackDraft.tunnelProbeOutbound,
    tunnelProbeList: config.tunnel_probe?.list ?? fallbackDraft.tunnelProbeList,
  }
}

function buildUpdatedConfig(
  config: ConfigObject,
  draft: SettingsDraft
): ConfigObject {
  const tableStart = parseStrictDecimalToNumber(draft.tableStart)
  const listRefreshRoute = normalizeListRefreshRouteChain({
    detour: draft.listRefreshDetour,
    fallbackDetours: draft.listRefreshFallbackDetours,
  })

  const updatedConfig: ConfigObject = {
    ...config,
    daemon: withMetaUdp443Policy(
      {
        ...config.daemon,
        strict_enforcement:
          draft.strictEnforcement === "automatic"
            ? undefined
            : draft.strictEnforcement === "enabled",
        skip_marked_packets: draft.skipMarkedPackets,
        clear_dynamic_sets_on_apply: draft.clearDynamicSetsOnApply,
        ttl_bypass_enabled: draft.ttlBypassEnabled,
        ppe_deoffload_mode: draft.ppeDeoffloadMode,
        ppe_deoffload_quic_enabled:
          draft.ppeDeoffloadMode === "auto" && draft.ppeDeoffloadQuicEnabled,
        reconnect_unmarked_flows_on_routing_change:
          draft.reconnectUnmarkedFlowsOnRoutingChange,
        reconnect_owned_flows_on_routing_change_lists:
          draft.reconnectOwnedFlowsOnRoutingChangeLists,
        ipv6_enabled: draft.ipv6Enabled,
        ipset_hashsize: toOptionalBackendInteger(draft.ipsetHashsize),
        ipset_maxelem: toOptionalBackendInteger(draft.ipsetMaxelem),
      },
      draft.metaUdp443Policy
    ),
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

  if (listRefreshRoute.detour) {
    updatedConfig.list_refresh = {
      detour: listRefreshRoute.detour,
      fallback_detours: listRefreshRoute.fallbackDetours,
    }
  } else {
    delete updatedConfig.list_refresh
  }

  // Switching the automation on has to be one click, so the three things it
  // needs - a list, a file for that list to read, and a rule sending that list
  // through the tunnel the probe measures against - are staged here rather
  // than left to the operator. The daemon never edits the configuration, which
  // is why this belongs to the panel.
  const provisioned = provisionTunnelProbe(updatedConfig, {
    enabled: draft.tunnelProbeEnabled,
    outbound: draft.tunnelProbeOutbound,
    list: draft.tunnelProbeList,
  })

  return {
    ...provisioned.config,
    tunnel_probe: {
      ...config.tunnel_probe,
      enabled: draft.tunnelProbeEnabled,
      // Empty means "not named". Sending "" would be a name that matches
      // nothing, and the daemon would refuse it as a missing outbound rather
      // than as an unset one.
      outbound: provisioned.resolved.outbound || undefined,
      list: provisioned.resolved.list || undefined,
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

function toStringInt(value: number | null | undefined, fallback: string) {
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

function toOptionalBackendInteger(raw: string): number | undefined {
  if (!raw.trim()) {
    return undefined
  }

  const parsed = parseStrictDecimalToNumber(raw)
  return parsed ?? (raw as unknown as number)
}

function resolveSettingsFieldPath(path: string): SettingsFieldName | undefined {
  if (path.startsWith("list_refresh.fallback_detours")) {
    return SETTINGS_FIELD_NAMES.listRefreshFallbackDetours
  }

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

  if (
    path === "daemon.reconnect_owned_flows_on_routing_change_lists" ||
    path.startsWith("daemon.reconnect_owned_flows_on_routing_change_lists[")
  ) {
    return SETTINGS_FIELD_NAMES.reconnectOwnedFlowsOnRoutingChangeLists
  }

  switch (path) {
    case "daemon.strict_enforcement":
      return SETTINGS_FIELD_NAMES.strictEnforcement
    case "daemon.skip_marked_packets":
      return SETTINGS_FIELD_NAMES.skipMarkedPackets
    case "daemon.clear_dynamic_sets_on_apply":
      return SETTINGS_FIELD_NAMES.clearDynamicSetsOnApply
    case "daemon.ttl_bypass_enabled":
      return SETTINGS_FIELD_NAMES.ttlBypassEnabled
    case "daemon.ppe_deoffload_mode":
      return SETTINGS_FIELD_NAMES.ppeDeoffloadMode
    case "daemon.ppe_deoffload_quic_enabled":
      return SETTINGS_FIELD_NAMES.ppeDeoffloadQuicEnabled
    case "daemon.reconnect_unmarked_flows_on_routing_change":
      return SETTINGS_FIELD_NAMES.reconnectUnmarkedFlowsOnRoutingChange
    case "daemon.meta_udp443_policy":
      return SETTINGS_FIELD_NAMES.metaUdp443Policy
    case "daemon.ipv6_enabled":
      return SETTINGS_FIELD_NAMES.ipv6Enabled
    case "daemon.ipset_hashsize":
      return SETTINGS_FIELD_NAMES.ipsetHashsize
    case "daemon.ipset_maxelem":
      return SETTINGS_FIELD_NAMES.ipsetMaxelem
    case "dns.client_dns_enforcement.enabled":
      return SETTINGS_FIELD_NAMES.clientDnsEnforcement
    case "lists_autoupdate.enabled":
      return SETTINGS_FIELD_NAMES.listsAutoupdateEnabled
    case "lists_autoupdate.cron":
      return SETTINGS_FIELD_NAMES.cron
    case "list_refresh.detour":
      return SETTINGS_FIELD_NAMES.listRefreshDetour
    case "list_refresh.fallback_detours":
      return SETTINGS_FIELD_NAMES.listRefreshFallbackDetours
    case "fwmark.start":
      return SETTINGS_FIELD_NAMES.fwmarkStart
    case "fwmark.mask":
      return SETTINGS_FIELD_NAMES.fwmarkMask
    case "iproute.table_start":
      return SETTINGS_FIELD_NAMES.tableStart
    case "tunnel_probe.enabled":
      return SETTINGS_FIELD_NAMES.tunnelProbeEnabled
    case "tunnel_probe.outbound":
      return SETTINGS_FIELD_NAMES.tunnelProbeOutbound
    case "tunnel_probe.list":
      return SETTINGS_FIELD_NAMES.tunnelProbeList
    default:
      return undefined
  }
}
