import { useForm } from "@tanstack/react-form"
import { useQueryClient } from "@tanstack/react-query"
import { useStore } from "@tanstack/react-store"
import {
  CheckCircle2Icon,
  CircleIcon,
  CloudIcon,
  FileTextIcon,
  ScrollTextIcon,
  SparklesIcon,
} from "lucide-react"
import { useEffect, useState } from "react"
import { useTranslation } from "react-i18next"
import { useLocation } from "wouter"
import { toast } from "sonner"

import type { ApiError } from "@/api/client"
import type { ConfigObject } from "@/api/generated/model/configObject"
import type { Outbound } from "@/api/generated/model/outbound"
import {
  usePostConfigMutation,
  usePostListDeleteStageMutation,
  usePostRecommendedListSetupMutation,
} from "@/api/mutations"
import { getListDeleteImpactItems } from "@/components/delete-impact/list-items"
import { ListDeleteReplacementPicker } from "@/components/lists/list-delete-replacement-picker"
import { UpsertDeleteAction } from "@/components/shared/upsert-delete-action"
import { getApiErrorMessage } from "@/lib/api-errors"
import { getDnsRuleDisplayName } from "@/lib/dns-display"
import { getListReferenceLabel } from "@/lib/list-display"
import {
  buildListDeleteTargets,
  getListDeleteImpact,
} from "@/pages/lists-utils"
import { queryKeys } from "@/api/query-keys"
import { useGetConfig } from "@/api/queries"
import { selectConfig, selectConfigRevision } from "@/api/selectors"
import { DnsPresetPicker } from "@/components/dns/dns-preset-picker"
import {
  resolveDnsTemplateSelection,
  type DnsPresetSelection,
} from "@/components/dns/dns-preset-selection"
import { OutboundSelect } from "@/components/shared/outbound-select"
import { ListRefreshRouteFields } from "@/components/lists/list-refresh-route-fields"
import {
  Field,
  FieldContent,
  FieldGroup,
  FieldHint,
  FieldLabel,
} from "@/components/shared/field"
import { CodeEditor } from "@/components/shared/code-editor"
import { TemplatePicker } from "@/components/lists/template-picker"
import { ServerValidationAlert } from "@/components/shared/server-validation-alert"
import {
  UpsertPage,
  type UpsertPagePresentation,
} from "@/components/shared/upsert-page"
import { useUpsertPageClose } from "@/components/shared/upsert-page-context"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { SectionHeading } from "@/components/shared/section-heading"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  clearFormServerErrors,
  setFormServerErrors,
  splitFormApiErrors,
} from "@/lib/form-api-errors"
import { cn } from "@/lib/utils"
import { getTagNameValidationError } from "@/lib/tag-name-validation"
import { isSemanticallyDirty } from "@/lib/semantic-dirty"
import { semanticJsonEqual } from "@/lib/semantic-json"
import { makeTechnicalId } from "@/lib/technical-id"
import {
  getGlobalListRefreshRouteChain,
  getListRefreshCapableOutbounds,
} from "@/lib/list-refresh-route"
import { getOutboundDisplayName } from "@/lib/outbound-display"
import { useIsMobile } from "@/hooks/use-mobile"
import {
  NO_DNS_RULE,
  addRecommendedDnsServer,
  buildUpdatedConfigForListUpsert,
  createListDnsServerSelectItems,
  createListDraft,
  getDraftFromMapEntry,
  normalizeListDraftForComparison,
  normalizeQuickSetupForComparison,
  splitLines,
  type ListDraft,
  type QuickSetup,
} from "@/pages/list-upsert-utils"

type ListSourceGroup = "url" | "file" | "inline"
type ListFieldName = (typeof LIST_FIELD_NAMES)[keyof typeof LIST_FIELD_NAMES]

const LIST_SOURCE_GROUPS: ListSourceGroup[] = ["url", "file", "inline"]
const DEFAULT_SOURCE_GROUP: ListSourceGroup = "url"
const LIST_FIELD_NAMES = {
  displayName: "displayName",
  name: "name",
  ttlMs: "ttlMs",
  refreshDetourMode: "refreshDetourMode",
  detour: "detour",
  fallbackDetours: "fallbackDetours",
  domains: "domains",
  ipCidrs: "ipCidrs",
  url: "url",
  file: "file",
} as const
const LIST_SOURCE_GROUP_ICONS = {
  url: CloudIcon,
  file: FileTextIcon,
  inline: ScrollTextIcon,
} satisfies Record<ListSourceGroup, typeof CloudIcon>
const LIST_SOURCE_GROUP_FIELDS = {
  url: [LIST_FIELD_NAMES.url],
  file: [LIST_FIELD_NAMES.file],
  inline: [LIST_FIELD_NAMES.domains, LIST_FIELD_NAMES.ipCidrs],
} satisfies Record<ListSourceGroup, ListFieldName[]>

const sampleNewList: ListDraft = {
  displayName: "",
  name: "",
  ttlMs: "7200000",
  refreshDetourMode: "inherit",
  detour: "",
  fallbackDetours: [],
  domains: "",
  ipCidrs: "",
  url: "",
  file: "",
}

export function ListUpsertPage({
  mode,
  listId,
  presentation = "page",
}: {
  mode: "create" | "edit"
  listId?: string
  presentation?: UpsertPagePresentation
}) {
  const { t } = useTranslation()
  const [, navigate] = useLocation()
  const [dirty, setDirty] = useState(false)
  const configQuery = useGetConfig()
  const loadedConfig = selectConfig(configQuery.data)
  const loadedConfigRevision = selectConfigRevision(configQuery.data)

  if (!loadedConfig || !loadedConfigRevision) {
    return (
      <UpsertPage
        cardDescription={t(
          presentation === "dialog"
            ? "pages.listUpsert.simpleCardDescription"
            : "pages.listUpsert.cardDescription"
        )}
        cardTitle={
          mode === "create"
            ? t("pages.listUpsert.createTitle")
            : t("pages.listUpsert.editTitle")
        }
        description={t("pages.listUpsert.description")}
        onClose={() => navigate("/lists")}
        presentation={presentation}
        title={
          mode === "create"
            ? t("pages.listUpsert.createTitle")
            : t("pages.listUpsert.editTitle")
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

  const listsMap = loadedConfig.lists ?? {}
  const draft =
    mode === "edit"
      ? getDraftFromMapEntry(listId, listId ? listsMap[listId] : undefined)
      : sampleNewList

  if (mode === "edit" && !draft) {
    return (
      <UpsertPage
        cardDescription={t("pages.listUpsert.missing.cardDescription")}
        cardTitle={t("pages.listUpsert.missing.cardTitle")}
        description={t("pages.listUpsert.missing.description")}
        onClose={() => navigate("/lists")}
        presentation={presentation}
        title={t("pages.listUpsert.editTitle")}
      >
        <div className="flex justify-end">
          <Button onClick={() => navigate("/lists")} variant="outline">
            {t("pages.listUpsert.missing.back")}
          </Button>
        </div>
      </UpsertPage>
    )
  }

  return (
    <UpsertPage
      cardDescription={t(
        presentation === "dialog"
          ? "pages.listUpsert.simpleCardDescription"
          : "pages.listUpsert.cardDescription"
      )}
      cardTitle={
        mode === "create"
          ? t("pages.listUpsert.createTitle")
          : t("pages.listUpsert.editCardTitle", {
              name:
                draft?.displayName.trim() ||
                draft?.name ||
                t("pages.listUpsert.fallbackName"),
            })
      }
      description={t("pages.listUpsert.description")}
      dirty={dirty}
      onClose={() => navigate("/lists")}
      presentation={presentation}
      title={
        mode === "create"
          ? t("pages.listUpsert.createTitle")
          : t("pages.listUpsert.editTitle")
      }
    >
      <ListForm
        key={`${mode}:${listId ?? "new"}`}
        outbounds={loadedConfig.outbounds ?? []}
        draft={draft ?? sampleNewList}
        existingListNames={Object.keys(listsMap)}
        listId={listId}
        loadedConfig={loadedConfig}
        loadedConfigRevision={loadedConfigRevision}
        mode={mode}
        onDirtyChange={setDirty}
        presentation={presentation}
      />
    </UpsertPage>
  )
}

function ListForm({
  mode,
  outbounds,
  draft,
  existingListNames,
  listId,
  loadedConfig,
  loadedConfigRevision,
  onDirtyChange,
  presentation,
}: {
  mode: "create" | "edit"
  outbounds: Outbound[]
  draft: ListDraft
  existingListNames: string[]
  listId?: string
  loadedConfig: ConfigObject
  loadedConfigRevision: string
  onDirtyChange: (dirty: boolean) => void
  presentation: UpsertPagePresentation
}) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [, navigate] = useLocation()
  const close = useUpsertPageClose()
  const recommendedSetup = presentation === "dialog" && mode === "create"
  const [activeSourceGroups, setActiveSourceGroups] = useState<
    ListSourceGroup[]
  >(() => getActiveSourceGroupsFromDraft(draft))
  const postConfigMutation = usePostConfigMutation()
  const postRecommendedListSetupMutation = usePostRecommendedListSetupMutation()
  const isMobile = useIsMobile()
  const dnsServers = loadedConfig.dns?.servers ?? []
  const savedDnsTemplates =
    loadedConfig.ui_preferences?.plain_dns_templates ?? []
  const dnsServerTags = dnsServers.map((server) => server.tag)
  const dnsServerSelectItems = createListDnsServerSelectItems(
    dnsServers,
    t("pages.listUpsert.dnsRule.none")
  )
  const downloadOutbounds = getListRefreshCapableOutbounds(outbounds)
  const downloadOutboundByTag = new Map(
    downloadOutbounds.map((outbound) => [outbound.tag, outbound])
  )
  const globalRefreshRoute = getGlobalListRefreshRouteChain(
    loadedConfig.list_refresh
  )
  const recommendedPair = downloadOutbounds
    .map((outbound) => ({
      outbound: outbound.tag,
      dnsServer:
        dnsServers.find((server) => server.detour === outbound.tag)?.tag ?? "",
    }))
    .find((candidate) => candidate.dnsServer)
  const [baselineDraft] = useState<ListDraft>(() => {
    if (mode !== "create" || draft.name.trim()) {
      return draft
    }
    return { ...createListDraft(), ...draft }
  })
  const [technicalIdManuallyEdited, setTechnicalIdManuallyEdited] =
    useState(false)
  const [initialQuickSetup] = useState<QuickSetup>(() => ({
    createRouteRule: recommendedSetup,
    routeOutbound: recommendedSetup ? (recommendedPair?.outbound ?? "") : "",
    createDnsRule: recommendedSetup,
    dnsServer: recommendedSetup
      ? (recommendedPair?.dnsServer ?? "")
      : (dnsServerTags[0] ?? ""),
  }))
  const [quickSetup, setQuickSetup] = useState<QuickSetup>(initialQuickSetup)
  const [initialRecommendedDnsPreset] =
    useState<DnsPresetSelection>("cloudflare")
  const [recommendedDnsPreset, setRecommendedDnsPreset] =
    useState<DnsPresetSelection>(initialRecommendedDnsPreset)
  const compatibleDnsServers = quickSetup.routeOutbound
    ? dnsServers.filter((server) => server.detour === quickSetup.routeOutbound)
    : []
  const selectedQuickSetupOutbound = downloadOutboundByTag.get(
    quickSetup.routeOutbound
  )
  const selectedQuickSetupDnsServer = dnsServers.find(
    (server) => server.tag === quickSetup.dnsServer
  )
  const selectedRecommendedDnsTemplate = recommendedSetup
    ? resolveDnsTemplateSelection(recommendedDnsPreset, savedDnsTemplates)
    : undefined
  // DNS rules are edited where they belong — next to the list they apply to —
  // instead of in a separate section listing every rule at once.
  const dnsRulesForList = (loadedConfig.dns?.rules ?? [])
    .map((rule, index) => ({ rule, index }))
    .filter(({ rule }) => (rule.list ?? []).includes(listId ?? ""))
  // Общее правило (на несколько списков) отсюда не редактируется: молчаливое
  // «отцепить список и завести ему отдельное правило» меняло бы поведение
  // соседних списков без их ведома. Такое правило показывается честно, со
  // ссылкой в «Правила». То же — редкий случай нескольких правил на список.
  const dnsRuleEditable =
    dnsRulesForList.length <= 1 &&
    dnsRulesForList.every(({ rule }) => (rule.list ?? []).length === 1)
  const currentDnsServer = dnsRuleEditable
    ? (dnsRulesForList[0]?.rule.server ?? "")
    : ""
  const [initialDnsServerForList] = useState(currentDnsServer)
  const [dnsServerForList, setDnsServerForList] = useState(
    initialDnsServerForList
  )
  const [replacementListId, setReplacementListId] = useState("")
  const deleteStageMutation = usePostListDeleteStageMutation({
    mutation: {
      onSuccess: async () => {
        toast.success(t("pages.lists.deleteDialog.staged"))
        await queryClient.invalidateQueries({ queryKey: queryKeys.config() })
        navigate("/lists")
      },
      onError: async (error) => {
        if (error.status === 409) {
          // Конфигурация изменилась под руками: показываем свежую и даём
          // повторить — сам диалог пересчитает последствия по новым данным.
          toast.warning(t("pages.lists.deleteDialog.revisionChanged"), {
            richColors: true,
          })
          await queryClient.invalidateQueries({ queryKey: queryKeys.config() })
          deleteStageMutation.reset()
          return
        }
        toast.error(getApiErrorMessage(error), { richColors: true })
      },
    },
  })
  const deleteImpact =
    mode === "edit" && listId
      ? getListDeleteImpact(
          loadedConfig,
          [listId],
          replacementListId || undefined
        )
      : null
  const [templatePickerOpen, setTemplatePickerOpen] = useState(false)
  const form = useForm({
    defaultValues: baselineDraft,
    validators: {
      onSubmitAsync: async ({ value }) => {
        clearFormServerErrors(form)
        const displayNameError = getDisplayNameError(value.displayName, t)
        if (displayNameError) {
          setFormServerErrors(form, {
            fields: {
              [LIST_FIELD_NAMES.displayName]: displayNameError,
            },
          })
          return {
            fields: {
              [LIST_FIELD_NAMES.displayName]: displayNameError,
            },
          }
        }

        const valueToPersist =
          mode === "create" && !value.name.trim()
            ? {
                ...value,
                name: makeTechnicalId(value.displayName, existingListNames, {
                  prefix: "list",
                }),
              }
            : value
        const nameError = getListNameError(
          valueToPersist.name,
          existingListNames,
          isCreate ? undefined : draft.name,
          t
        )
        if (nameError) {
          setFormServerErrors(form, {
            fields: {
              [LIST_FIELD_NAMES.name]: nameError,
            },
          })
          return {
            fields: {
              [LIST_FIELD_NAMES.name]: nameError,
            },
          }
        }

        if (
          presentation === "dialog" &&
          mode === "create" &&
          !activeSourceGroups.some((group) =>
            isSourceGroupPopulated(group, valueToPersist)
          )
        ) {
          toast.error(t("pages.listUpsert.validation.sourceRequired"), {
            richColors: true,
          })
          return undefined
        }
        if (
          valueToPersist.url.trim() &&
          valueToPersist.refreshDetourMode === "override" &&
          !valueToPersist.detour.trim()
        ) {
          const message = t("pages.listUpsert.validation.refreshDetourRequired")
          setFormServerErrors(form, {
            fields: { [LIST_FIELD_NAMES.detour]: message },
          })
          return { fields: { [LIST_FIELD_NAMES.detour]: message } }
        }
        if (
          mode === "create" &&
          (recommendedSetup || quickSetup.createRouteRule) &&
          !quickSetup.routeOutbound
        ) {
          toast.error(t("pages.listUpsert.quickSetup.routeRequired"), {
            richColors: true,
          })
          return undefined
        }
        if (
          mode === "create" &&
          (recommendedSetup || quickSetup.createDnsRule) &&
          !quickSetup.dnsServer &&
          !selectedRecommendedDnsTemplate
        ) {
          toast.error(t("pages.listUpsert.quickSetup.dnsRequired"), {
            richColors: true,
          })
          return undefined
        }
        let configForList = loadedConfig
        let quickSetupForSave = quickSetup
        if (
          recommendedSetup &&
          quickSetup.createDnsRule &&
          !quickSetup.dnsServer &&
          selectedRecommendedDnsTemplate
        ) {
          const outbound = downloadOutboundByTag.get(quickSetup.routeOutbound)
          if (!outbound) {
            toast.error(t("pages.listUpsert.quickSetup.routeRequired"), {
              richColors: true,
            })
            return undefined
          }
          const dnsServerResult = addRecommendedDnsServer(
            loadedConfig,
            selectedRecommendedDnsTemplate,
            outbound.tag,
            getOutboundDisplayName(outbound)
          )
          if (!dnsServerResult) {
            toast.error(t("pages.listUpsert.quickSetup.dnsCreateFailed"), {
              richColors: true,
            })
            return undefined
          }
          configForList = dnsServerResult.config
          quickSetupForSave = {
            ...quickSetup,
            dnsServer: dnsServerResult.serverTag,
          }
        }
        const updatedConfig = buildUpdatedConfigForListUpsert(
          configForList,
          mode,
          valueToPersist,
          listId,
          mode === "create" ? quickSetupForSave : undefined,
          // Селект DNS пишет правило только когда он показан и правит 1:1:
          // общее правило соседей отсюда не трогается. В диалоге создания
          // DNS-правило создаёт быстрая настройка, а не этот селект.
          (mode === "edit" || presentation === "page") && dnsRuleEditable
            ? dnsServerForList
            : undefined
        )

        try {
          if (recommendedSetup) {
            await postRecommendedListSetupMutation.mutateAsync({
              data: {
                base_revision: loadedConfigRevision,
                config: updatedConfig,
                list_id: valueToPersist.name,
              },
            })
          } else {
            await postConfigMutation.mutateAsync({ data: updatedConfig })
          }
          toast.success(
            mode === "create"
              ? t("pages.listUpsert.messages.created")
              : t("pages.listUpsert.messages.updated")
          )
          clearFormServerErrors(form)
          await Promise.all([
            queryClient.invalidateQueries({ queryKey: queryKeys.config() }),
            queryClient.invalidateQueries({ queryKey: queryKeys.dnsTest() }),
          ])
          navigate("/lists")
          return undefined
        } catch (error) {
          const apiError = error as ApiError
          const result = splitFormApiErrors({
            error: apiError,
            fieldNames: Object.values(LIST_FIELD_NAMES),
            resolvePath: (path) =>
              resolveListFieldPath(
                path,
                valueToPersist.name || baselineDraft.name
              ),
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
          | {
              unmapped?: { path: string; message: string }[]
            }
          | undefined
      )?.unmapped ?? []
  )
  const formIsDirty = useStore(form.store, (state) =>
    isSemanticallyDirty(state.values, baselineDraft, {
      equals: semanticJsonEqual,
      normalize: normalizeListDraftForComparison,
    })
  )

  const isCreate = mode === "create"
  const hasDnsServerChange =
    (mode === "edit" || presentation === "page") &&
    dnsRuleEditable &&
    dnsServerForList !== initialDnsServerForList
  const hasQuickSetupChange =
    mode === "create" &&
    isSemanticallyDirty(quickSetup, initialQuickSetup, {
      equals: semanticJsonEqual,
      normalize: normalizeQuickSetupForComparison,
    })
  const hasRecommendedDnsPresetChange =
    recommendedSetup &&
    recommendedDnsPreset !== initialRecommendedDnsPreset &&
    compatibleDnsServers.length === 0
  const isDirty =
    formIsDirty ||
    hasDnsServerChange ||
    hasQuickSetupChange ||
    hasRecommendedDnsPresetChange

  useEffect(() => {
    onDirtyChange(isDirty)
  }, [isDirty, onDirtyChange])

  const handleSourceGroupSelect = (group: ListSourceGroup) => {
    const currentValues = form.state.values
    const filledActiveGroups = activeSourceGroups.filter((sourceGroup) =>
      isSourceGroupPopulated(sourceGroup, currentValues)
    )
    const groupsToClear = filledActiveGroups.filter(
      (sourceGroup) => sourceGroup !== group
    )

    if (
      groupsToClear.length === 0 &&
      activeSourceGroups.length === 1 &&
      activeSourceGroups[0] === group
    ) {
      return
    }

    if (
      groupsToClear.length > 0 &&
      !window.confirm(t("pages.listUpsert.sourceSwitcher.confirmChange"))
    ) {
      return
    }

    setActiveSourceGroups([group])
    clearFormServerErrors(form)

    for (const sourceGroup of LIST_SOURCE_GROUPS) {
      if (sourceGroup === group) {
        continue
      }

      for (const fieldName of LIST_SOURCE_GROUP_FIELDS[sourceGroup]) {
        form.setFieldValue(fieldName, "")
      }
    }

    if (group !== "inline") {
      form.setFieldValue(LIST_FIELD_NAMES.domains, "")
      form.setFieldValue(LIST_FIELD_NAMES.ipCidrs, "")
    }
    if (group !== "url") {
      form.setFieldValue(LIST_FIELD_NAMES.refreshDetourMode, "inherit")
      form.setFieldValue(LIST_FIELD_NAMES.detour, "")
      form.setFieldValue(LIST_FIELD_NAMES.fallbackDetours, [])
    }
  }

  return (
    <form
      className="space-y-6"
      onSubmit={(event) => {
        event.preventDefault()
        form.handleSubmit()
      }}
    >
      <section className="space-y-4">
        <SectionHeading
          description={t("pages.listUpsert.common.description")}
          title={t("pages.listUpsert.common.title")}
        />
        <div>
          <FieldGroup>
            <form.Field
              name={LIST_FIELD_NAMES.displayName}
              validators={{
                onChange: ({ value }) =>
                  getDisplayNameError(value, t) ?? undefined,
              }}
            >
              {(field) => {
                const error = getFirstFieldError(field.state.meta.errors)

                return (
                  <Field invalid={Boolean(error)}>
                    <FieldLabel htmlFor="list-display-name">
                      {t("pages.listUpsert.fields.displayName")}
                    </FieldLabel>
                    <FieldContent>
                      <Input
                        aria-invalid={Boolean(error)}
                        id="list-display-name"
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
                              LIST_FIELD_NAMES.name,
                              makeTechnicalId(
                                nextDisplayName,
                                existingListNames,
                                { prefix: "list" }
                              )
                            )
                          }
                        }}
                        value={field.state.value}
                      />
                      <FieldHint
                        description={t(
                          "pages.listUpsert.fields.displayNameHint"
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
                name={LIST_FIELD_NAMES.name}
                validators={{
                  onChange: ({ value }) =>
                    getListNameError(
                      value,
                      existingListNames,
                      isCreate ? undefined : draft.name,
                      t
                    ) ?? undefined,
                }}
              >
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)

                  return (
                    <Field invalid={Boolean(error)}>
                      <FieldLabel htmlFor="list-name">
                        {t("pages.listUpsert.fields.technicalId")}
                      </FieldLabel>
                      <FieldContent>
                        <Input
                          aria-invalid={Boolean(error)}
                          disabled={!isCreate}
                          id="list-name"
                          onBlur={field.handleBlur}
                          onChange={(event) => {
                            setTechnicalIdManuallyEdited(true)
                            field.handleChange(event.target.value)
                          }}
                          value={field.state.value}
                        />
                        <FieldHint
                          description={t(
                            isCreate
                              ? "pages.listUpsert.fields.technicalIdCreateHint"
                              : "pages.listUpsert.fields.technicalIdEditHint"
                          )}
                          error={error ?? null}
                        />
                      </FieldContent>
                    </Field>
                  )
                }}
              </form.Field>
            ) : null}

            {presentation === "page" ? (
              <form.Field
                name={LIST_FIELD_NAMES.ttlMs}
                validators={{
                  onMount: ({ value }) => getTtlError(value, t) ?? undefined,
                  onChange: ({ value }) => getTtlError(value, t) ?? undefined,
                }}
              >
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)

                  return (
                    <Field invalid={Boolean(error)}>
                      <FieldLabel htmlFor="list-ttl-ms">
                        {t("pages.listUpsert.fields.ttlMs")}
                      </FieldLabel>
                      <FieldContent>
                        <Input
                          aria-invalid={Boolean(error)}
                          id="list-ttl-ms"
                          onBlur={field.handleBlur}
                          onChange={(event) =>
                            field.handleChange(event.target.value)
                          }
                          value={field.state.value}
                        />
                        <FieldHint
                          description={t("pages.listUpsert.fields.ttlMsHint")}
                          error={error ?? null}
                        />
                      </FieldContent>
                    </Field>
                  )
                }}
              </form.Field>
            ) : null}
          </FieldGroup>
        </div>
      </section>

      <section className="space-y-4">
        <SectionHeading
          description={t("pages.listUpsert.sourceSwitcher.description")}
          title={t("pages.listUpsert.sourceSwitcher.title")}
        />
        <div>
          {/* Тот же переключатель, что и при добавлении туннеля: ndw-picker
              KeeneticOS. Здесь он с множественным выбором — источников можно
              указать сразу несколько, — поэтому кнопки, а не радиогруппа. */}
          <div
            className={cn("keen-picker", isMobile && "keen-picker--vertical")}
            role="group"
          >
            {LIST_SOURCE_GROUPS.map((group) => {
              const Icon = LIST_SOURCE_GROUP_ICONS[group]
              const active = activeSourceGroups.includes(group)

              return (
                <button
                  aria-pressed={active}
                  className={cn(
                    "keen-picker__button",
                    active && "keen-picker__button--active"
                  )}
                  key={group}
                  onClick={() => handleSourceGroupSelect(group)}
                  type="button"
                >
                  {isMobile ? (
                    active ? (
                      <CheckCircle2Icon className="size-4 shrink-0 text-primary" />
                    ) : (
                      <CircleIcon className="size-4 shrink-0 text-muted-foreground" />
                    )
                  ) : null}
                  <Icon className="size-4 shrink-0" />
                  <span className="truncate">
                    {t(`pages.listUpsert.sourceGroups.${group}.button`)}
                  </span>
                </button>
              )
            })}
          </div>
        </div>
      </section>

      {activeSourceGroups.includes("url") ? (
        <section className="space-y-4">
          <div className="flex items-start justify-between gap-3">
            <SectionHeading
              description={t("pages.listUpsert.sourceGroups.url.description")}
              title={t("pages.listUpsert.sourceGroups.url.title")}
            />
            <Button
              onClick={() => setTemplatePickerOpen(true)}
              size="sm"
              type="button"
              variant="outline"
            >
              <SparklesIcon className="mr-1 h-4 w-4" />
              {t("pages.listUpsert.templates.button")}
            </Button>
          </div>
          <div>
            <FieldGroup>
              <form.Field name={LIST_FIELD_NAMES.url}>
                {(field) => (
                  <Field>
                    <FieldLabel htmlFor="list-url">
                      {t("pages.listUpsert.fields.url")}
                    </FieldLabel>
                    <FieldContent>
                      <Input
                        id="list-url"
                        onBlur={field.handleBlur}
                        onChange={(event) =>
                          field.handleChange(event.target.value)
                        }
                        value={field.state.value}
                      />
                      <FieldHint
                        description={t("pages.listUpsert.fields.urlHint")}
                      />
                    </FieldContent>
                  </Field>
                )}
              </form.Field>

              {presentation === "page" ? (
                <form.Field name={LIST_FIELD_NAMES.refreshDetourMode}>
                  {(field) => (
                    <Field>
                      <FieldLabel>
                        {t("pages.listUpsert.refreshRoute.modeLabel")}
                      </FieldLabel>
                      <FieldContent>
                        <Select
                          // items обязательны: без них кнопка селекта
                          // показывала сырое значение inherit/override
                          // вместо человеческой подписи.
                          items={[
                            {
                              value: "inherit",
                              label: t(
                                "pages.listUpsert.refreshRoute.modes.inherit"
                              ),
                            },
                            {
                              value: "override",
                              label: t(
                                "pages.listUpsert.refreshRoute.modes.override"
                              ),
                            },
                          ]}
                          onValueChange={(value) => {
                            const nextMode = value as "inherit" | "override"
                            field.handleChange(nextMode)
                            if (nextMode === "inherit") {
                              form.setFieldValue(LIST_FIELD_NAMES.detour, "")
                              form.setFieldValue(
                                LIST_FIELD_NAMES.fallbackDetours,
                                []
                              )
                              return
                            }

                            if (
                              !form.state.values.detour &&
                              globalRefreshRoute.detour
                            ) {
                              form.setFieldValue(
                                LIST_FIELD_NAMES.detour,
                                globalRefreshRoute.detour
                              )
                              form.setFieldValue(
                                LIST_FIELD_NAMES.fallbackDetours,
                                globalRefreshRoute.fallbackDetours
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
                              <SelectItem value="inherit">
                                {t(
                                  "pages.listUpsert.refreshRoute.modes.inherit"
                                )}
                              </SelectItem>
                              <SelectItem value="override">
                                {t(
                                  "pages.listUpsert.refreshRoute.modes.override"
                                )}
                              </SelectItem>
                            </SelectGroup>
                          </SelectContent>
                        </Select>
                        <FieldHint
                          description={t(
                            `pages.listUpsert.refreshRoute.${field.state.value}Hint`
                          )}
                        />
                      </FieldContent>
                    </Field>
                  )}
                </form.Field>
              ) : null}

              <form.Subscribe
                selector={(state) => ({
                  detour: state.values.detour,
                  fallbackDetours: state.values.fallbackDetours,
                  mode: state.values.refreshDetourMode,
                })}
              >
                {(refreshRoute) =>
                  presentation === "page" &&
                  refreshRoute.mode === "override" ? (
                    <form.Field name={LIST_FIELD_NAMES.detour}>
                      {(detourField) => (
                        <form.Field name={LIST_FIELD_NAMES.fallbackDetours}>
                          {(fallbackField) => (
                            <ListRefreshRouteFields
                              chain={refreshRoute}
                              detourError={getFirstFieldError(
                                detourField.state.meta.errors
                              )}
                              detourFieldName={LIST_FIELD_NAMES.detour}
                              fallbackError={getFirstFieldError(
                                fallbackField.state.meta.errors
                              )}
                              fallbackFieldName={
                                LIST_FIELD_NAMES.fallbackDetours
                              }
                              onChange={(chain) => {
                                detourField.handleChange(chain.detour)
                                fallbackField.handleChange(
                                  chain.fallbackDetours
                                )
                                if (!chain.detour) {
                                  form.setFieldValue(
                                    LIST_FIELD_NAMES.refreshDetourMode,
                                    "inherit"
                                  )
                                }
                              }}
                              outbounds={outbounds}
                              primaryEmptyLabel={t(
                                "pages.listUpsert.fields.detourEmpty"
                              )}
                            />
                          )}
                        </form.Field>
                      )}
                    </form.Field>
                  ) : (
                    <Alert>
                      <AlertDescription>
                        {t(
                          refreshRoute.mode === "override"
                            ? "pages.listUpsert.refreshRoute.overrideSummary"
                            : "pages.listUpsert.refreshRoute.inheritSummary",
                          {
                            chain: formatListRefreshRouteChain(
                              refreshRoute.mode === "override"
                                ? refreshRoute
                                : globalRefreshRoute,
                              downloadOutboundByTag,
                              t("common.listRefreshRoute.systemDirect")
                            ),
                          }
                        )}
                      </AlertDescription>
                    </Alert>
                  )
                }
              </form.Subscribe>
            </FieldGroup>
          </div>
        </section>
      ) : null}

      {activeSourceGroups.includes("file") ? (
        <section className="space-y-4">
          <SectionHeading
            description={t("pages.listUpsert.sourceGroups.file.description")}
            title={t("pages.listUpsert.sourceGroups.file.title")}
          />
          <div>
            <FieldGroup>
              <form.Field name={LIST_FIELD_NAMES.file}>
                {(field) => (
                  <Field>
                    <FieldLabel htmlFor="list-file">
                      {t("pages.listUpsert.fields.file")}
                    </FieldLabel>
                    <FieldContent>
                      <Input
                        id="list-file"
                        onBlur={field.handleBlur}
                        onChange={(event) =>
                          field.handleChange(event.target.value)
                        }
                        value={field.state.value}
                      />
                      <FieldHint
                        description={t("pages.listUpsert.fields.fileHint")}
                      />
                    </FieldContent>
                  </Field>
                )}
              </form.Field>
            </FieldGroup>
          </div>
        </section>
      ) : null}

      {activeSourceGroups.includes("inline") ? (
        <section className="space-y-4">
          <SectionHeading
            description={t("pages.listUpsert.sourceGroups.inline.description")}
            title={t("pages.listUpsert.sourceGroups.inline.title")}
          />
          <div>
            <FieldGroup>
              <form.Field name={LIST_FIELD_NAMES.domains}>
                {(field) => (
                  <Field>
                    <FieldLabel htmlFor="list-domains">
                      {t("pages.listUpsert.fields.domains")}
                    </FieldLabel>
                    <FieldContent>
                      <CodeEditor
                        className="min-h-24"
                        id="list-domains"
                        onBlur={field.handleBlur}
                        onChange={(next) => field.handleChange(next)}
                        syntax="list"
                        value={field.state.value}
                      />
                      <FieldHint
                        description={t("pages.listUpsert.fields.domainsHint")}
                      />
                    </FieldContent>
                  </Field>
                )}
              </form.Field>
              <form.Field name={LIST_FIELD_NAMES.ipCidrs}>
                {(field) => (
                  <Field>
                    <FieldLabel htmlFor="list-ip-cidrs">
                      {t("pages.listUpsert.fields.ipCidrs")}
                    </FieldLabel>
                    <FieldContent>
                      <CodeEditor
                        className="min-h-24"
                        id="list-ip-cidrs"
                        onBlur={field.handleBlur}
                        onChange={(next) => field.handleChange(next)}
                        syntax="list"
                        value={field.state.value}
                      />
                      <FieldHint
                        description={t("pages.listUpsert.fields.ipCidrsHint")}
                      />
                    </FieldContent>
                  </Field>
                )}
              </form.Field>
            </FieldGroup>
          </div>
        </section>
      ) : null}

      {!isCreate || presentation === "page" ? (
        <section className="space-y-4">
          <SectionHeading
            description={t("pages.listUpsert.dnsRule.description")}
            title={t("pages.listUpsert.dnsRule.title")}
          />
          {dnsRuleEditable ? (
            <div className="space-y-3">
              <Select
                items={dnsServerSelectItems}
                onValueChange={(value) => setDnsServerForList(value ?? "")}
                value={dnsServerForList || NO_DNS_RULE}
              >
                <SelectTrigger>
                  <SelectValue
                    placeholder={t(
                      "pages.listUpsert.quickSetup.selectDnsServer"
                    )}
                  />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value={NO_DNS_RULE}>
                      {t("pages.listUpsert.dnsRule.none")}
                    </SelectItem>
                    {dnsServers.map((server) => (
                      <SelectItem key={server.tag} value={server.tag}>
                        {server.display_name?.trim() || server.tag}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
              {dnsServerTags.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  {t("pages.listUpsert.quickSetup.noDnsServers")}
                </p>
              ) : null}
            </div>
          ) : (
            // Общее правило честно показывается, а не молча переписывается:
            // оно обслуживает и другие списки, и менять его нужно там, где
            // видно всех, кого это заденет.
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                {t("pages.listUpsert.dnsRule.shared", {
                  names: dnsRulesForList
                    .map(({ rule, index }) =>
                      getDnsRuleDisplayName(rule, index)
                    )
                    .join(", "),
                })}
              </p>
              <Button
                onClick={() => {
                  if (
                    isDirty &&
                    !window.confirm(
                      `${t("common.unsavedChanges.title")}\n\n${t(
                        "common.unsavedChanges.description"
                      )}`
                    )
                  ) {
                    return
                  }
                  navigate("/dns-rules")
                }}
                type="button"
                variant="outline"
              >
                {t("pages.listUpsert.dnsRule.openRules")}
              </Button>
            </div>
          )}
        </section>
      ) : null}

      <TemplatePicker
        onOpenCatalog={(presetId) => {
          if (
            isDirty &&
            !window.confirm(
              `${t("common.unsavedChanges.title")}\n\n${t(
                "common.unsavedChanges.description"
              )}`
            )
          ) {
            return false
          }
          navigate(`/catalog?search=${encodeURIComponent(presetId)}`)
          return true
        }}
        onOpenChange={setTemplatePickerOpen}
        onSelect={(template) => {
          form.setFieldValue(LIST_FIELD_NAMES.url, template.url)
          if (
            isCreate &&
            !form.getFieldValue(LIST_FIELD_NAMES.displayName).trim()
          ) {
            form.setFieldValue(LIST_FIELD_NAMES.displayName, template.name)
          }
          if (isCreate && !form.getFieldValue(LIST_FIELD_NAMES.name)) {
            form.setFieldValue(LIST_FIELD_NAMES.name, template.id)
          }
        }}
        open={templatePickerOpen}
      />

      {isCreate ? (
        <section className="space-y-4">
          <SectionHeading
            description={t(
              recommendedSetup
                ? "pages.listUpsert.quickSetup.recommendedDescription"
                : "pages.listUpsert.quickSetup.description"
            )}
            title={t("pages.listUpsert.quickSetup.title")}
          />
          <div className="space-y-5">
            {recommendedSetup ? (
              <Alert className="border-primary/25 bg-primary/5">
                <CheckCircle2Icon />
                <AlertDescription className="space-y-2">
                  <p className="font-medium text-foreground">
                    {t("pages.listUpsert.quickSetup.recommendedPlan.title")}
                  </p>
                  <p>
                    {t(
                      "pages.listUpsert.quickSetup.recommendedPlan.description"
                    )}
                  </p>
                  <div className="space-y-1 text-foreground">
                    <p>
                      {t("pages.listUpsert.quickSetup.recommendedPlan.route", {
                        route: selectedQuickSetupOutbound
                          ? getOutboundDisplayName(selectedQuickSetupOutbound)
                          : t(
                              "pages.listUpsert.quickSetup.recommendedPlan.notSelected"
                            ),
                      })}
                    </p>
                    <p>
                      {t(
                        selectedQuickSetupDnsServer
                          ? "pages.listUpsert.quickSetup.recommendedPlan.dnsReuse"
                          : "pages.listUpsert.quickSetup.recommendedPlan.dnsCreate",
                        {
                          dns: selectedQuickSetupDnsServer
                            ? selectedQuickSetupDnsServer.display_name?.trim() ||
                              selectedQuickSetupDnsServer.tag
                            : (selectedRecommendedDnsTemplate?.name ??
                              t(
                                "pages.listUpsert.quickSetup.recommendedPlan.notSelected"
                              )),
                        }
                      )}
                    </p>
                  </div>
                </AlertDescription>
              </Alert>
            ) : null}

            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <Checkbox
                  checked={quickSetup.createRouteRule}
                  disabled={recommendedSetup}
                  id="list-create-route-rule"
                  onCheckedChange={(checked) =>
                    setQuickSetup((current) => ({
                      ...current,
                      createRouteRule: checked === true,
                    }))
                  }
                />
                <FieldLabel
                  className="cursor-pointer"
                  htmlFor="list-create-route-rule"
                >
                  {t("pages.listUpsert.quickSetup.createRouteRule")}
                </FieldLabel>
              </div>
              {quickSetup.createRouteRule ? (
                <OutboundSelect
                  onValueChange={(value) =>
                    setQuickSetup((current) => ({
                      ...current,
                      routeOutbound: value,
                      dnsServer: recommendedSetup
                        ? (dnsServers.find((server) => server.detour === value)
                            ?.tag ?? "")
                        : current.dnsServer,
                    }))
                  }
                  outbounds={outbounds}
                  placeholder={t("pages.listUpsert.quickSetup.selectOutbound")}
                  value={quickSetup.routeOutbound}
                />
              ) : null}
            </div>

            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <Checkbox
                  checked={quickSetup.createDnsRule}
                  disabled={
                    recommendedSetup ||
                    (!recommendedSetup && dnsServerTags.length === 0)
                  }
                  id="list-create-dns-rule"
                  onCheckedChange={(checked) =>
                    setQuickSetup((current) => ({
                      ...current,
                      createDnsRule: checked === true,
                    }))
                  }
                />
                <FieldLabel
                  className="cursor-pointer"
                  htmlFor="list-create-dns-rule"
                >
                  {t("pages.listUpsert.quickSetup.createDnsRule")}
                </FieldLabel>
              </div>
              {quickSetup.createDnsRule &&
              (!recommendedSetup || compatibleDnsServers.length > 0) ? (
                <Select
                  onValueChange={(value) =>
                    setQuickSetup((current) => ({
                      ...current,
                      dnsServer: value ?? "",
                    }))
                  }
                  value={quickSetup.dnsServer}
                >
                  <SelectTrigger>
                    <SelectValue
                      placeholder={t(
                        "pages.listUpsert.quickSetup.selectDnsServer"
                      )}
                    />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      {(recommendedSetup
                        ? compatibleDnsServers
                        : dnsServers
                      ).map((server) => (
                        <SelectItem key={server.tag} value={server.tag}>
                          {server.display_name?.trim() || server.tag}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
              ) : null}
              {recommendedSetup &&
              quickSetup.createDnsRule &&
              quickSetup.routeOutbound &&
              compatibleDnsServers.length === 0 ? (
                <>
                  <DnsPresetPicker
                    customLabel={t("pages.dnsServerUpsert.presets.custom")}
                    label={t(
                      "pages.listUpsert.quickSetup.createDnsServerFromPreset"
                    )}
                    onValueChange={setRecommendedDnsPreset}
                    savedTemplates={savedDnsTemplates}
                    showCustom={false}
                    value={recommendedDnsPreset}
                  />
                  <p className="text-sm text-muted-foreground">
                    {t(
                      "pages.listUpsert.quickSetup.createDnsServerFromPresetHint"
                    )}
                  </p>
                </>
              ) : !recommendedSetup && dnsServerTags.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  {t("pages.listUpsert.quickSetup.noDnsServers")}
                </p>
              ) : null}
            </div>

            <p className="text-sm text-muted-foreground">
              {t(
                recommendedSetup
                  ? "pages.listUpsert.quickSetup.recommendedHint"
                  : "pages.listUpsert.quickSetup.manualHint"
              )}
            </p>
          </div>
        </section>
      ) : null}

      {apiErrorMessage ? (
        <Alert className="border-destructive/30 bg-destructive/5 text-destructive">
          <AlertDescription className="whitespace-pre-wrap">
            {apiErrorMessage}
          </AlertDescription>
        </Alert>
      ) : null}

      <ServerValidationAlert errors={unmappedServerErrors} />

      <div className="flex justify-end gap-3" data-upsert-actions>
        {mode === "edit" && listId && deleteImpact ? (
          <UpsertDeleteAction
            confirmLabel={t("pages.lists.deleteDialog.confirm")}
            description={t("pages.lists.deleteDialog.description", {
              names: getListReferenceLabel(listId, loadedConfig.lists),
            })}
            impactItems={getListDeleteImpactItems(
              loadedConfig,
              [listId],
              deleteImpact,
              replacementListId || undefined,
              t
            )}
            isPending={deleteStageMutation.isPending}
            label={t("common.delete")}
            onConfirm={() =>
              deleteStageMutation.mutate({
                data: {
                  base_revision: loadedConfigRevision,
                  targets: buildListDeleteTargets(
                    [listId],
                    replacementListId || undefined
                  ),
                },
              })
            }
            title={t("pages.lists.deleteDialog.title")}
          >
            <ListDeleteReplacementPicker
              config={loadedConfig}
              deletedIds={[listId]}
              onChange={setReplacementListId}
              replacementListId={replacementListId}
            />
          </UpsertDeleteAction>
        ) : null}
        <Button onClick={close} size="xl" type="button" variant="outline">
          {t("common.cancel")}
        </Button>
        <form.Subscribe selector={(state) => state.canSubmit}>
          {(canSubmit) => (
            <Button
              disabled={
                postConfigMutation.isPending ||
                postRecommendedListSetupMutation.isPending ||
                !isDirty ||
                !canSubmit
              }
              size="xl"
              type="submit"
            >
              {postConfigMutation.isPending ||
              postRecommendedListSetupMutation.isPending
                ? t("pages.listUpsert.actions.saving")
                : mode === "create"
                  ? t("pages.listUpsert.actions.create")
                  : t("pages.listUpsert.actions.save")}
            </Button>
          )}
        </form.Subscribe>
      </div>
    </form>
  )
}

function getActiveSourceGroupsFromDraft(draft: ListDraft): ListSourceGroup[] {
  const populatedGroups: ListSourceGroup[] = []

  if (draft.url.trim()) {
    populatedGroups.push("url")
  }

  if (draft.file.trim()) {
    populatedGroups.push("file")
  }

  if (
    splitLines(draft.domains).length > 0 ||
    splitLines(draft.ipCidrs).length > 0
  ) {
    populatedGroups.push("inline")
  }

  return populatedGroups.length > 0 ? populatedGroups : [DEFAULT_SOURCE_GROUP]
}

function isSourceGroupPopulated(group: ListSourceGroup, draft: ListDraft) {
  if (group === "inline") {
    return (
      splitLines(draft.domains).length > 0 ||
      splitLines(draft.ipCidrs).length > 0
    )
  }

  return draft[group].trim().length > 0
}

function getFirstFieldError(errors: unknown[]) {
  const firstError = errors[0]
  return typeof firstError === "string" ? firstError : null
}

function getDisplayNameError(value: string, t: (key: string) => string) {
  const normalized = value.trim()
  if (!normalized) {
    return t("pages.listUpsert.validation.displayNameRequired")
  }
  return [...normalized].length > 80
    ? t("pages.listUpsert.validation.displayNameTooLong")
    : null
}

function getListNameError(
  value: string,
  existingListNames: string[],
  currentName?: string,
  t?: (key: string) => string
) {
  const trimmedName = value.trim()
  const duplicateError =
    existingListNames.includes(trimmedName) && trimmedName !== currentName
      ? (t?.("pages.listUpsert.validation.duplicateName") ??
        "A list with this name already exists.")
      : null

  return getTagNameValidationError(value, {
    requiredError:
      t?.("pages.listUpsert.validation.nameRequired") ?? "Name is required.",
    invalidError:
      t?.("common.validation.tagNamePattern") ??
      "Must match [a-z][a-z0-9_]{0,23}.",
    duplicateError,
  })
}

function getTtlError(value: string, t?: (key: string) => string) {
  const trimmed = value.trim()
  if (!/^\d+$/.test(trimmed)) {
    return (
      t?.("pages.listUpsert.validation.invalidTtl") ??
      "TTL must be a non-negative integer."
    )
  }

  return null
}

function resolveListFieldPath(
  path: string,
  name: string
): ListFieldName | undefined {
  const normalizedName = name.trim()

  if (path === "lists") {
    return LIST_FIELD_NAMES.name
  }

  if (normalizedName && path === `lists.${normalizedName}`) {
    return LIST_FIELD_NAMES.name
  }

  if (normalizedName && path === `lists.${normalizedName}.ttl_ms`) {
    return LIST_FIELD_NAMES.ttlMs
  }

  if (normalizedName && path === `lists.${normalizedName}.display_name`) {
    return LIST_FIELD_NAMES.displayName
  }

  if (normalizedName && path === `lists.${normalizedName}.domains`) {
    return LIST_FIELD_NAMES.domains
  }

  if (normalizedName && path === `lists.${normalizedName}.ip_cidrs`) {
    return LIST_FIELD_NAMES.ipCidrs
  }

  if (normalizedName && path === `lists.${normalizedName}.url`) {
    return LIST_FIELD_NAMES.url
  }

  if (normalizedName && path === `lists.${normalizedName}.file`) {
    return LIST_FIELD_NAMES.file
  }

  if (normalizedName && path === `lists.${normalizedName}.detour`) {
    return LIST_FIELD_NAMES.detour
  }

  if (
    normalizedName &&
    path === `lists.${normalizedName}.refresh_detour_mode`
  ) {
    return LIST_FIELD_NAMES.refreshDetourMode
  }

  if (
    normalizedName &&
    (path === `lists.${normalizedName}.fallback_detours` ||
      path.startsWith(`lists.${normalizedName}.fallback_detours[`))
  ) {
    return LIST_FIELD_NAMES.fallbackDetours
  }

  return undefined
}

function formatListRefreshRouteChain(
  chain: { detour: string; fallbackDetours: string[] },
  outboundByTag: ReadonlyMap<string, Outbound>,
  systemDirectLabel: string
) {
  const tags = [chain.detour, ...chain.fallbackDetours].filter(Boolean)
  if (tags.length === 0) {
    return systemDirectLabel
  }

  return tags
    .map((tag) => {
      const outbound = outboundByTag.get(tag)
      return outbound ? getOutboundDisplayName(outbound) : tag
    })
    .join(" → ")
}
