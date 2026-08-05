import { Plus, Save, SparklesIcon, Trash2 } from "lucide-react"
import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import { useQueryClient } from "@tanstack/react-query"
import { useLocation } from "wouter"

import type { ApiError } from "@/api/client"
import type { ConfigObject } from "@/api/generated/model/configObject"
import type { DnsRule } from "@/api/generated/model/dnsRule"
import {
  useConfigMutationPending,
  usePostConfigMutation,
} from "@/api/mutations"
import { queryKeys } from "@/api/query-keys"
import { useGetConfig } from "@/api/queries"
import { selectConfig } from "@/api/selectors"
import { KeenPencilIcon } from "@/components/shared/keen-icons"
import { ActionButtons } from "@/components/shared/action-buttons"
import { BulkSelectionToolbar } from "@/components/shared/bulk-selection-toolbar"
import { ConfigSaveErrorAlert } from "@/components/shared/config-save-error-alert"
import { DataTable } from "@/components/shared/data-table"
import { TableSearch } from "@/components/shared/table-search"
import { ListPlaceholder } from "@/components/shared/list-placeholder"
import { PageActionBar } from "@/components/shared/page-action-bar"
import { PageHeader } from "@/components/shared/page-header"
import { TableSkeleton } from "@/components/shared/table-skeleton"
import { useRowSelection } from "@/hooks/use-row-selection"
import { filterBySearchQuery } from "@/lib/table-search"
import { useSemanticEditSession } from "@/hooks/use-semantic-edit-session"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { getApiErrorMessage } from "@/lib/api-errors"
import {
  createDnsServerDisplayNameMap,
  getDnsRuleDisplayName,
  getDnsRuleTechnicalId,
} from "@/lib/dns-display"
import { formatListReferenceLabels } from "@/lib/list-display"
import { getRuleEditHref } from "@/lib/rule-route"
import { stableJsonStringify } from "@/lib/semantic-json"
import {
  buildUpdatedConfigWithRules,
  getRuleDraft,
  normalizeDnsRuleDraft,
  validateRules,
} from "@/pages/dns-rules-utils"

function getDnsRulesSemanticKey(rules: readonly DnsRule[]) {
  return stableJsonStringify(
    rules.map((rule) => normalizeDnsRuleDraft(getRuleDraft(rule)))
  )
}

function areDnsRulesSemanticallyEqual(
  left: readonly DnsRule[],
  right: readonly DnsRule[]
) {
  return getDnsRulesSemanticKey(left) === getDnsRulesSemanticKey(right)
}

export function DnsRulesPage({
  embedded = false,
}: { embedded?: boolean } = {}) {
  const configQuery = useGetConfig()
  const loadedConfig = selectConfig(configQuery.data)
  const baselineRules = loadedConfig?.dns?.rules ?? []
  const editorKey = loadedConfig
    ? getDnsRulesSemanticKey(baselineRules)
    : configQuery.isError
      ? "error"
      : "loading"

  return (
    <DnsRulesEditor
      configError={configQuery.isError}
      configLoading={configQuery.isLoading}
      embedded={embedded}
      key={editorKey}
      loadedConfig={loadedConfig}
    />
  )
}

function DnsRulesEditor({
  loadedConfig,
  configLoading,
  configError,
  embedded,
}: {
  loadedConfig?: ConfigObject
  configLoading: boolean
  configError: boolean
  embedded: boolean
}) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [, navigate] = useLocation()
  const configMutationPending = useConfigMutationPending()
  const baselineRules = loadedConfig?.dns?.rules ?? []
  const rulesSession = useSemanticEditSession(
    baselineRules,
    areDnsRulesSemanticallyEqual
  )
  const rules = rulesSession.value

  const serverTags = useMemo(
    () =>
      (loadedConfig?.dns?.servers ?? [])
        .map((server) => server.tag)
        .filter(Boolean),
    [loadedConfig]
  )
  const serverNames = useMemo(
    () => createDnsServerDisplayNameMap(loadedConfig?.dns?.servers ?? []),
    [loadedConfig?.dns?.servers]
  )

  const listOptions = useMemo(
    () => Object.keys(loadedConfig?.lists ?? {}),
    [loadedConfig]
  )

  const postConfigMutation = usePostConfigMutation({
    mutation: {
      onSuccess: async () => {
        await queryClient.invalidateQueries({ queryKey: queryKeys.dnsTest() })
        toast.success(t("pages.dnsRules.messages.saved"))
      },
      onError: (error) => {
        const apiError = error as ApiError
        toast.error(getApiErrorMessage(apiError), { richColors: true })
      },
    },
  })

  const [search, setSearch] = useState("")
  // Индекс едет вместе со строкой. Имя правила выводится из него
  // (`DNS ${index + 1}`), и если фильтровать сам массив, оставшиеся правила
  // перенумеруются: третье покажется первым, а ссылка на редактирование
  // уведёт не туда.
  const indexedRules = rules.map((rule, index) => ({ rule, index }))
  const visibleRules = filterBySearchQuery(indexedRules, search, (entry) => [
    getDnsRuleDisplayName(entry.rule, entry.index),
    entry.rule.id,
    serverNames.get(entry.rule.server) ?? entry.rule.server,
    formatListReferenceLabels(entry.rule.list, loadedConfig?.lists),
  ])
  const ruleRowIds = visibleRules.map((entry) =>
    getDnsRuleTechnicalId(entry.rule, entry.index)
  )
  const ruleNames = new Map(
    rules.map((rule, index) => [
      getDnsRuleTechnicalId(rule, index),
      getDnsRuleDisplayName(rule, index),
    ])
  )
  const ruleSelection = useRowSelection(ruleRowIds)

  const validateNextRules = (nextRules: DnsRule[]) => {
    const draftRules = nextRules.map((rule) => getRuleDraft(rule))
    const validation = validateRules(draftRules, serverTags, listOptions)
    if (Object.keys(validation).length > 0) {
      toast.error(t("pages.dnsRules.validation.invalidResult"), {
        richColors: true,
      })
      return null
    }

    return draftRules
  }

  const saveRules = () => {
    if (!loadedConfig || !rulesSession.isDirty) {
      return
    }

    const nextDraftRules = validateNextRules(rules)
    if (!nextDraftRules) {
      return
    }

    postConfigMutation.mutate({
      data: buildUpdatedConfigWithRules(
        loadedConfig,
        loadedConfig.dns?.fallback ?? [],
        nextDraftRules
      ),
    })
  }

  const updateRules = (
    update: DnsRule[] | ((currentRules: DnsRule[]) => DnsRule[]),
    options?: { clearSelection?: boolean }
  ) => {
    const nextRules =
      typeof update === "function" ? update(rulesSession.value) : update
    if (!validateNextRules(nextRules)) {
      return
    }

    rulesSession.setValue(nextRules)
    if (options?.clearSelection) {
      ruleSelection.clear()
    }
  }

  const cancelLocalChanges = () => {
    rulesSession.reset()
    ruleSelection.clear()
  }

  const handleEnabledChange = (index: number, enabled: boolean) => {
    updateRules((currentRules) =>
      currentRules.map((rule, ruleIndex) =>
        ruleIndex === index ? { ...rule, enabled } : rule
      )
    )
  }

  const handleBulkDeleteRules = () => {
    if (ruleSelection.selectedCount === 0) {
      return
    }

    if (
      !window.confirm(
        t("pages.dnsRules.bulk.confirmDelete", {
          count: ruleSelection.selectedCount,
        })
      )
    ) {
      return
    }

    updateRules(
      rules.filter(
        (rule, index) =>
          !ruleSelection.selectedIds.has(getDnsRuleTechnicalId(rule, index))
      ),
      { clearSelection: true }
    )
  }

  const handleBulkSetEnabled = (enabled: boolean) => {
    if (ruleSelection.selectedCount === 0) {
      return
    }

    updateRules(
      rules.map((rule, index) => ({
        ...rule,
        enabled: ruleSelection.selectedIds.has(
          getDnsRuleTechnicalId(rule, index)
        )
          ? enabled
          : (rule.enabled ?? true),
      }))
    )
  }

  return (
    <div className="space-y-3">
      {embedded ? null : (
        <PageHeader
          description={t("pages.dnsRules.description")}
          title={t("pages.dnsRules.title")}
        />
      )}
      <PageActionBar
        primary={
          <Button
            disabled={configMutationPending || rulesSession.isDirty}
            onClick={() => navigate("/dns-rules/create")}
          >
            <Plus className="mr-1 h-4 w-4" />
            {t("pages.dnsRules.actions.add")}
          </Button>
        }
        leading={
          rules.length > 0 ? (
            <TableSearch
              matchCount={visibleRules.length}
              onChange={(next) => {
                setSearch(next)
                ruleSelection.clear()
              }}
              placeholder={t("pages.dnsRules.searchPlaceholder")}
              totalCount={rules.length}
              value={search}
            />
          ) : null
        }
      >
        {rulesSession.isDirty ? (
          <>
            <Button
              disabled={configMutationPending}
              onClick={cancelLocalChanges}
              variant="ghost"
            >
              {t("common.cancel")}
            </Button>
            <Button disabled={configMutationPending} onClick={saveRules}>
              <Save className="mr-1 h-4 w-4" />
              {postConfigMutation.isPending
                ? t("common.saving")
                : t("common.save")}
            </Button>
          </>
        ) : null}
      </PageActionBar>

      <ConfigSaveErrorAlert error={postConfigMutation.error} />

      {configLoading ? (
        <TableSkeleton />
      ) : configError ? (
        <ListPlaceholder
          description={t("common.loadErrorDescription")}
          title={t("common.unableToLoadData")}
          variant="error"
        />
      ) : rules.length === 0 ? (
        <ListPlaceholder
          action={
            <Button onClick={() => navigate("/catalog")} variant="outline">
              <SparklesIcon className="mr-1 h-4 w-4" />
              {t("common.setupFromCatalog")}
            </Button>
          }
          description={t("pages.dnsRules.empty.description")}
          title={t("pages.dnsRules.empty.title")}
        />
      ) : (
        <div className="space-y-3">
          {visibleRules.length === 0 ? (
            <ListPlaceholder
              description={t("common.tableSearch.empty")}
              title={t("pages.dnsRules.empty.title")}
            />
          ) : null}
          <div className="relative h-0">
            {ruleSelection.hasSelection ? (
              <BulkSelectionToolbar
                cancelLabel={t("common.cancel")}
                countLabel={t("pages.dnsRules.bulk.selected", {
                  count: ruleSelection.selectedCount,
                })}
                onCancel={ruleSelection.clear}
              >
                <Button
                  disabled={configMutationPending}
                  onClick={() => handleBulkSetEnabled(true)}
                  size="sm"
                  variant="outline"
                >
                  {t("pages.dnsRules.bulk.enable")}
                </Button>
                <Button
                  disabled={configMutationPending}
                  onClick={() => handleBulkSetEnabled(false)}
                  size="sm"
                  variant="outline"
                >
                  {t("pages.dnsRules.bulk.disable")}
                </Button>
                <Button
                  disabled={configMutationPending}
                  onClick={handleBulkDeleteRules}
                  size="sm"
                  variant="destructive"
                >
                  <Trash2 className="mr-1 h-4 w-4" />
                  {t("pages.dnsRules.bulk.delete")}
                </Button>
              </BulkSelectionToolbar>
            ) : null}
          </div>
          <DataTable
            headers={[
              t("pages.dnsRules.headers.enabled"),
              t("pages.dnsRules.headers.name"),
              t("pages.dnsRules.headers.criteria"),
              t("pages.dnsRules.headers.serverTag"),
              t("pages.dnsRules.headers.allowDomainRebinding"),
              t("pages.dnsRules.headers.actions"),
            ]}
            narrowColumns={[0]}
            mobileLayout={{ titleColumn: 1, controlColumns: [0] }}
            rows={visibleRules.map(({ rule, index }) => [
              <div className="flex items-center" key={`enabled-${index}`}>
                <Switch
                  aria-label={t(
                    (rule.enabled ?? true)
                      ? "pages.dnsRules.actions.disableRule"
                      : "pages.dnsRules.actions.enableRule"
                  )}
                  checked={rule.enabled ?? true}
                  disabled={configMutationPending}
                  onCheckedChange={(checked) =>
                    handleEnabledChange(index, checked)
                  }
                  title={t(
                    (rule.enabled ?? true)
                      ? "pages.dnsRules.actions.disableRule"
                      : "pages.dnsRules.actions.enableRule"
                  )}
                />
              </div>,
              <span
                className="font-medium"
                key={`name-${index}`}
                title={rule.id}
              >
                {getDnsRuleDisplayName(rule, index)}
              </span>,
              <ul
                className="list-disc space-y-1 pl-5 text-sm"
                key={`criteria-${index}`}
              >
                <li className="text-muted-foreground">
                  <span className="font-medium text-foreground">
                    {t("pages.dnsRules.criteriaLabels.lists")}:
                  </span>{" "}
                  {formatListReferenceLabels(rule.list, loadedConfig?.lists)}
                </li>
              </ul>,
              <span className="font-medium" key={`server-${index}`}>
                <span title={rule.server}>
                  {serverNames.get(rule.server) ?? rule.server}
                </span>
              </span>,
              <Badge
                key={`allow-domain-rebinding-${index}`}
                variant={rule.allow_domain_rebinding ? "default" : "outline"}
              >
                {rule.allow_domain_rebinding
                  ? t("pages.dnsRules.rebinding.enabled")
                  : t("pages.dnsRules.rebinding.disabled")}
              </Badge>,
              <ActionButtons
                actions={[
                  {
                    disabled: configMutationPending || rulesSession.isDirty,
                    icon: <KeenPencilIcon className="h-4 w-4" />,
                    label: t("common.edit"),
                    onClick: () =>
                      navigate(getRuleEditHref("dns-rules", rule, index)),
                  },
                ]}
                key={`actions-${index}`}
              />,
            ])}
            selection={{
              rowIds: ruleRowIds,
              selectedIds: ruleSelection.selectedIds,
              disabled: configMutationPending,
              onToggle: ruleSelection.toggleOne,
              onToggleAll: ruleSelection.setAllVisible,
              selectAllLabel: t("common.selection.selectAll"),
              getRowLabel: (rowId) =>
                t("common.selection.selectRow", {
                  rowLabel: ruleNames.get(rowId) ?? rowId,
                }),
            }}
          />
        </div>
      )}
    </div>
  )
}
