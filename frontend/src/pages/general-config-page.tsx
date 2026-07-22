import { useTranslation } from "react-i18next"

import { useForm } from "@tanstack/react-form"
import { useQueryClient } from "@tanstack/react-query"
import { useStore } from "@tanstack/react-store"

import type { ApiError } from "@/api/client"
import type { ConfigObject } from "@/api/generated/model/configObject"
import { usePostConfigMutation } from "@/api/mutations"
import { queryKeys } from "@/api/query-keys"
import { useGetConfig, useGetRuntimeInterfaces } from "@/api/queries"
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
import { InterfaceMultiSelectList } from "@/components/shared/interface-picker"
import { ListPlaceholder } from "@/components/shared/list-placeholder"
import { PageHeader } from "@/components/shared/page-header"
import { SchedulePicker } from "@/components/shared/schedule-picker"
import { AuthSettingsCard } from "@/components/settings/auth-settings-card"
import { LoggingSettingsCard } from "@/components/settings/logging-settings-card"
import {
  BackupAndRestoreCard,
  SoftwareUpdateCard,
} from "@/components/settings/maintenance-cards"
import { RemoteAccessCard } from "@/components/settings/remote-access-card"
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
import { Skeleton } from "@/components/ui/skeleton"
import {
  clearFormServerErrors,
  setFormServerErrors,
  splitFormApiErrors,
} from "@/lib/form-api-errors"
import { toast } from "sonner"

type SettingsDraft = {
  skipMarkedPackets: boolean
  ipv6Enabled: boolean
  clientDnsEnforcement: boolean
  inboundInterfaces: string[]
  listsAutoupdateEnabled: boolean
  cron: string
  fwmarkStart: string
  fwmarkMask: string
  tableStart: string
}

const fallbackDraft: SettingsDraft = {
  skipMarkedPackets: true,
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
  skipMarkedPackets: "skipMarkedPackets",
  ipv6Enabled: "ipv6Enabled",
  clientDnsEnforcement: "clientDnsEnforcement",
  inboundInterfaces: "inboundInterfaces",
  listsAutoupdateEnabled: "listsAutoupdateEnabled",
  cron: "cron",
  fwmarkStart: "fwmarkStart",
  fwmarkMask: "fwmarkMask",
  tableStart: "tableStart",
} as const

type SettingsFieldName =
  (typeof SETTINGS_FIELD_NAMES)[keyof typeof SETTINGS_FIELD_NAMES]

export function GeneralConfigPage() {
  const { t } = useTranslation()
  const configQuery = useGetConfig()
  const loadedConfig = selectConfig(configQuery.data)

  return (
    <div className="space-y-3">
      <PageHeader
        description={t("pages.settings.description")}
        title={t("pages.settings.title")}
      />

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
  const runtimeInterfacesQuery = useGetRuntimeInterfaces({
    query: {
      refetchInterval: 10_000,
      refetchIntervalInBackground: false,
    },
  })

  const postConfigMutation = usePostConfigMutation()

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

  const isPending = postConfigMutation.isPending
  const runtimeInterfaces =
    runtimeInterfacesQuery.data?.status === 200
      ? runtimeInterfacesQuery.data.data.interfaces
      : []

  const handleCancel = () => {
    form.reset(getDraftFromConfig(loadedConfig))
    clearFormServerErrors(form)
  }

  return (
    <>
      <SoftwareUpdateCard />
      <BackupAndRestoreCard />

      <Card size="sm">
        <CardHeader>
          <CardTitle>{t("pages.settings.general.title")}</CardTitle>
          <CardDescription>
            {t("pages.settings.general.description")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <FieldGroup>
            <form.Field name={SETTINGS_FIELD_NAMES.skipMarkedPackets}>
              {(field) => (
                <Field>
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

            <FieldSeparator />

            <form.Field name={SETTINGS_FIELD_NAMES.ipv6Enabled}>
              {(field) => (
                <Field>
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
                      description={t("pages.settings.general.ipv6EnabledHint")}
                    />
                  </FieldContent>
                </Field>
              )}
            </form.Field>

            <FieldSeparator />

            <form.Field name={SETTINGS_FIELD_NAMES.clientDnsEnforcement}>
              {(field) => (
                <Field>
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
                        {t("pages.settings.general.clientDnsEnforcementLabel")}
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

            <FieldSeparator />

            <form.Field name={SETTINGS_FIELD_NAMES.inboundInterfaces}>
              {(field) => {
                const error = getFirstFieldError(field.state.meta.errors)
                return (
                  <Field invalid={Boolean(error)}>
                    <FieldLabel htmlFor="inbound-interfaces">
                      {t("pages.settings.general.inboundInterfacesLabel")}
                    </FieldLabel>
                    <FieldContent>
                      <div id="inbound-interfaces">
                        <InterfaceMultiSelectList
                          name={SETTINGS_FIELD_NAMES.inboundInterfaces}
                          interfaces={runtimeInterfaces}
                          value={field.state.value}
                          onChange={field.handleChange}
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
          </FieldGroup>
        </CardContent>
      </Card>

      <AuthSettingsCard />

      <LoggingSettingsCard />

      <RemoteAccessCard />

      <Card size="sm">
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

      <Card size="sm">
        <CardHeader>
          <CardTitle>{t("pages.settings.advanced.title")}</CardTitle>
          <CardDescription>
            {t("pages.settings.advanced.description")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <FieldGroup>
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
                            {t("pages.settings.advanced.fwmarkMaskHintPrefix")}{" "}
                            <code>f</code>{" "}
                            {t("pages.settings.advanced.fwmarkMaskHintSuffix")}{" "}
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

      <ServerValidationAlert errors={unmappedServerErrors} />

      <div
        className="sticky z-20 -mx-4 flex justify-end gap-2 border-t bg-background px-4 py-3 shadow-[0_-8px_18px_-14px_rgba(0,0,0,0.55)] md:-mx-6 md:px-6"
        style={{ bottom: "var(--warning-banner-height, 0px)" }}
      >
        <Button
          disabled={isPending}
          onClick={handleCancel}
          size="xl"
          variant="outline"
        >
          {t("common.cancel")}
        </Button>
        <form.Subscribe
          selector={(state) => ({
            canSubmit: state.canSubmit,
            isPristine: state.isPristine,
          })}
        >
          {({ canSubmit, isPristine }) => (
            <Button
              disabled={isPending || isPristine || !canSubmit}
              onClick={() => form.handleSubmit()}
              size="xl"
            >
              {isPending
                ? t("pages.settings.actions.saving")
                : t("pages.settings.actions.save")}
            </Button>
          )}
        </form.Subscribe>
      </div>
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
    skipMarkedPackets:
      config.daemon?.skip_marked_packets ?? fallbackDraft.skipMarkedPackets,
    ipv6Enabled: config.daemon?.ipv6_enabled ?? fallbackDraft.ipv6Enabled,
    clientDnsEnforcement:
      config.dns?.client_dns_enforcement?.enabled ??
      fallbackDraft.clientDnsEnforcement,
    inboundInterfaces:
      config.route?.inbound_interfaces ?? fallbackDraft.inboundInterfaces,
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
      skip_marked_packets: draft.skipMarkedPackets,
      ipv6_enabled: draft.ipv6Enabled,
    },
    route: {
      ...config.route,
      inbound_interfaces: draft.inboundInterfaces,
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

  switch (path) {
    case "daemon.skip_marked_packets":
      return SETTINGS_FIELD_NAMES.skipMarkedPackets
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
