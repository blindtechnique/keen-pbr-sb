import { Pencil, Plus, Save, SparklesIcon, Trash2 } from "lucide-react"
import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"
import { useLocation } from "wouter"

import type { ApiError } from "@/api/client"
import type { ConfigObject } from "@/api/generated/model/configObject"
import type { RouteRule } from "@/api/generated/model/routeRule"
import {
  useConfigMutationPending,
  usePostConfigMutation,
} from "@/api/mutations"
import type { RuntimeOutboundState } from "@/api/generated/model"
import { useGetConfig, useGetRuntimeOutbounds } from "@/api/queries"
import { selectConfig } from "@/api/selectors"
import { ActionButtons } from "@/components/shared/action-buttons"
import { BulkSelectionToolbar } from "@/components/shared/bulk-selection-toolbar"
import { ConfigSaveErrorAlert } from "@/components/shared/config-save-error-alert"
import { ConfigTransferButtons } from "@/components/shared/config-transfer-buttons"
import { DataTable } from "@/components/shared/data-table"
import { TableSearch } from "@/components/shared/table-search"
import { SortableCards } from "@/components/shared/sortable-cards"
import { ListPlaceholder } from "@/components/shared/list-placeholder"
import { PageHeader } from "@/components/shared/page-header"
import { PageActionBar } from "@/components/shared/page-action-bar"
import { RuntimeOutboundEntry } from "@/components/shared/runtime-outbound-state"
import { TableSkeleton } from "@/components/shared/table-skeleton"
import { useRowSelection } from "@/hooks/use-row-selection"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Checkbox } from "@/components/ui/checkbox"
import { useSemanticEditSession } from "@/hooks/use-semantic-edit-session"
import { formatListReferenceLabels } from "@/lib/list-display"
import { createOutboundDisplayNameMap } from "@/lib/outbound-display"
import { getRuleEditHref } from "@/lib/rule-route"
import { filterBySearchQuery, normalizeSearchQuery } from "@/lib/table-search"
import { cn } from "@/lib/utils"
import {
  areRouteRulesSemanticallyEqual,
  getApiErrorMessage,
  getRouteRulesSemanticKey,
  getRouteRuleDisplayName,
  getRoutingRuleRowId,
  isRouteRuleNameGenerated,
  reorderRules,
  setRouteRuleEnabled,
} from "@/pages/routing-rules-utils"

export function RoutingRulesPage({
  embedded = false,
}: { embedded?: boolean } = {}) {
  const configQuery = useGetConfig()
  const loadedConfig = selectConfig(configQuery.data)
  const baselineRules = loadedConfig?.route?.rules ?? []
  const editorKey = loadedConfig
    ? getRouteRulesSemanticKey(baselineRules)
    : configQuery.isError
      ? "error"
      : "loading"

  return (
    <RoutingRulesEditor
      configError={configQuery.isError}
      configLoading={configQuery.isLoading}
      embedded={embedded}
      key={editorKey}
      loadedConfig={loadedConfig}
    />
  )
}

function RoutingRulesEditor({
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
  const [, navigate] = useLocation()

  const configMutationPending = useConfigMutationPending()
  const baselineRules = loadedConfig?.route?.rules ?? []
  const rulesSession = useSemanticEditSession(
    baselineRules,
    areRouteRulesSemanticallyEqual
  )
  const routeRules = rulesSession.value
  const [search, setSearch] = useState("")
  // Порядок правил — это их смысл, а перетаскивание работает по индексам
  // полного списка. Пока фильтр активен, индексы отфильтрованной таблицы
  // полному списку не соответствуют, поэтому перетаскивание выключается,
  // а не «почти работает».
  const searchActive = Boolean(normalizeSearchQuery(search))
  const ruleSelection = useRowSelection(
    routeRules.map((rule, index) => getRoutingRuleRowId(rule, index))
  )
  const runtimeOutboundsQuery = useGetRuntimeOutbounds()
  const runtimeOutbounds = useMemo(
    () =>
      runtimeOutboundsQuery.data?.status === 200
        ? runtimeOutboundsQuery.data.data.outbounds
        : [],
    [runtimeOutboundsQuery.data]
  )
  const runtimeOutboundByTag = useMemo(
    () =>
      new Map(
        runtimeOutbounds.map((runtimeOutbound) => [
          runtimeOutbound.tag,
          runtimeOutbound,
        ])
      ),
    [runtimeOutbounds]
  )
  const outboundDisplayNames = useMemo(
    () => createOutboundDisplayNameMap(loadedConfig?.outbounds ?? []),
    [loadedConfig?.outbounds]
  )

  const allRows = routeRules.map((rule: RouteRule, index: number) => {
    const runtimeState = runtimeOutboundByTag.get(rule.outbound)
    return getRouteRuleRow(
      rule,
      index,
      t,
      loadedConfig?.lists,
      runtimeState,
      outboundDisplayNames
    )
  })
  const tableRows = filterBySearchQuery(allRows, search, (row) => [
    row.nameIsGenerated ? "" : row.displayName,
    row.technicalId,
    row.outbound,
    ...row.conditions.map((condition) => condition.value),
  ])
  const ruleRowIds = tableRows.map((row) => row.id)

  const postConfigMutation = usePostConfigMutation({
    mutation: {
      onSuccess: () => {
        toast.success(t("pages.routingRules.messages.saved"))
      },
      onError: (error) => {
        const apiError = error as ApiError
        toast.error(getApiErrorMessage(apiError), { richColors: true })
      },
    },
  })

  const stageRules = () => {
    if (!loadedConfig || !rulesSession.isDirty) {
      return
    }

    postConfigMutation.mutate({
      data: {
        ...loadedConfig,
        route: {
          ...loadedConfig.route,
          rules: routeRules,
        },
      },
    })
  }

  const updateRules = (
    update: RouteRule[] | ((currentRules: RouteRule[]) => RouteRule[]),
    options?: { clearSelection?: boolean }
  ) => {
    rulesSession.setValue((currentRules) =>
      typeof update === "function" ? update(currentRules) : update
    )
    if (options?.clearSelection) {
      ruleSelection.clear()
    }
  }

  const cancelLocalChanges = () => {
    rulesSession.reset()
    ruleSelection.clear()
  }

  const handleReorder = (fromIndex: number, toIndex: number) => {
    if (fromIndex === toIndex || toIndex < 0 || toIndex >= routeRules.length) {
      return
    }

    updateRules(
      (currentRules) => reorderRules(currentRules, fromIndex, toIndex),
      { clearSelection: true }
    )
  }

  const handleEnabledChange = (index: number, enabled: boolean) => {
    updateRules((currentRules) =>
      setRouteRuleEnabled(currentRules, index, enabled)
    )
  }

  const handleBulkDelete = () => {
    if (ruleSelection.selectedCount === 0) {
      return
    }

    if (
      !window.confirm(
        t("pages.routingRules.bulk.confirmDelete", {
          count: ruleSelection.selectedCount,
        })
      )
    ) {
      return
    }

    const nextRules = routeRules.filter(
      (_rule, index) =>
        !ruleSelection.selectedIds.has(getRoutingRuleRowId(_rule, index))
    )
    updateRules(nextRules, { clearSelection: true })
  }

  const handleBulkSetEnabled = (enabled: boolean) => {
    if (ruleSelection.selectedCount === 0) {
      return
    }

    if (
      !window.confirm(
        t("pages.routingRules.bulk.confirmSetEnabled", {
          count: ruleSelection.selectedCount,
          action: t(
            enabled
              ? "pages.routingRules.bulk.enableAction"
              : "pages.routingRules.bulk.disableAction"
          ),
        })
      )
    ) {
      return
    }

    const nextRules = routeRules.map((rule, index) =>
      ruleSelection.selectedIds.has(getRoutingRuleRowId(rule, index))
        ? { ...rule, enabled }
        : rule
    )
    updateRules(nextRules)
  }

  return (
    <div className="space-y-3">
      {embedded ? null : (
        <PageHeader
          description={t("pages.routingRules.description")}
          title={t("pages.routingRules.title")}
        />
      )}
      <PageActionBar
        primary={
          <Button
            disabled={configMutationPending || rulesSession.isDirty}
            onClick={() => navigate("/routing-rules/create")}
          >
            <Plus className="mr-1 h-4 w-4" />
            {t("pages.routingRules.actions.addRule")}
          </Button>
        }
        leading={
          allRows.length > 0 ? (
            <TableSearch
              matchCount={tableRows.length}
              onChange={(next) => {
                setSearch(next)
                ruleSelection.clear()
              }}
              placeholder={t("pages.routingRules.searchPlaceholder")}
              totalCount={allRows.length}
              value={search}
            />
          ) : null
        }
      >
        <ConfigTransferButtons
          config={loadedConfig}
          disabled={configMutationPending || rulesSession.isDirty}
          kind="routing-rules"
          onImport={(nextConfig) =>
            postConfigMutation.mutate({ data: nextConfig })
          }
        />

        {rulesSession.isDirty ? (
          <>
            <Button
              disabled={configMutationPending}
              onClick={cancelLocalChanges}
              variant="ghost"
            >
              {t("common.cancel")}
            </Button>
            <Button disabled={configMutationPending} onClick={stageRules}>
              <Save className="mr-1 h-4 w-4" />
              {postConfigMutation.isPending
                ? t("common.saving")
                : t("pages.routingRules.actions.saveChanges")}
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
      ) : allRows.length === 0 ? (
        <ListPlaceholder
          action={
            <Button onClick={() => navigate("/catalog")} variant="outline">
              <SparklesIcon className="mr-1 h-4 w-4" />
              {t("common.setupFromCatalog")}
            </Button>
          }
          description={t("pages.routingRules.empty.description")}
          title={t("pages.routingRules.empty.title")}
        />
      ) : (
        <div className="space-y-3">
          {searchActive ? (
            <p className="text-xs text-muted-foreground">
              {t("pages.routingRules.reorderPausedBySearch")}
            </p>
          ) : null}
          {tableRows.length === 0 ? (
            <ListPlaceholder
              description={t("common.tableSearch.empty")}
              title={t("pages.routingRules.empty.title")}
            />
          ) : null}
          {/* The toolbar shares a fixed-height slot so selecting a rule does not
              push the whole table down. */}
          <div className="relative h-0">
            {ruleSelection.hasSelection ? (
              <BulkSelectionToolbar
                cancelLabel={t("common.cancel")}
                countLabel={t("pages.routingRules.bulk.selected", {
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
                  {t("pages.routingRules.bulk.enable")}
                </Button>
                <Button
                  disabled={configMutationPending}
                  onClick={() => handleBulkSetEnabled(false)}
                  size="sm"
                  variant="outline"
                >
                  {t("pages.routingRules.bulk.disable")}
                </Button>
                <Button
                  disabled={configMutationPending}
                  onClick={handleBulkDelete}
                  size="sm"
                  variant="destructive"
                >
                  <Trash2 className="mr-1 h-4 w-4" />
                  {t("pages.routingRules.bulk.delete")}
                </Button>
              </BulkSelectionToolbar>
            ) : null}
          </div>
          {/* На телефоне остаётся компактная карточная раскладка, но механизм
              сортировки у неё тот же pointer-sortable, что у desktop-строк. */}
          <div className="md:hidden">
            <SortableCards
              disabled={configMutationPending || searchActive}
              getKey={(row) => row.id}
              handleLabel={t("pages.routingRules.actions.reorder")}
              items={tableRows}
              onReorder={handleReorder}
              renderCard={(row) => (
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2">
                    <Checkbox
                      aria-label={t("common.selection.selectRow", {
                        rowLabel: row.displayName,
                      })}
                      checked={ruleSelection.selectedIds.has(row.id)}
                      disabled={configMutationPending}
                      onCheckedChange={() => ruleSelection.toggleOne(row.id)}
                    />
                    {/* The rule name and the route shared one line and truncated
                        equally, so a long route squeezed a short name down to
                        nothing: "#3" rendered as "#.". The name owns the line
                        now and the route sits underneath. */}
                    <span
                      className={cn(
                        "min-w-0 flex-1 truncate text-sm font-medium",
                        row.nameIsGenerated &&
                          "font-normal text-muted-foreground italic"
                      )}
                      title={row.technicalId}
                    >
                      {row.nameIsGenerated
                        ? t("pages.routingRules.unnamed")
                        : row.displayName}
                    </span>
                    <span className="ml-auto flex shrink-0 items-center gap-1">
                      <Switch
                        aria-label={t(
                          row.enabled
                            ? "pages.routingRules.actions.disableRule"
                            : "pages.routingRules.actions.enableRule"
                        )}
                        checked={row.enabled}
                        disabled={configMutationPending}
                        onCheckedChange={(checked) =>
                          handleEnabledChange(row.index, checked)
                        }
                      />
                      <Button
                        aria-label={t("common.edit")}
                        className="size-8"
                        disabled={configMutationPending || rulesSession.isDirty}
                        onClick={() =>
                          navigate(
                            getRuleEditHref(
                              "routing-rules",
                              routeRules[row.index],
                              row.index
                            )
                          )
                        }
                        size="icon"
                        variant="ghost"
                      >
                        <Pencil className="size-4" />
                      </Button>
                    </span>
                  </div>
                  <div
                    className="truncate pl-6 text-sm text-muted-foreground"
                    title={row.outbound}
                  >
                    → {row.outbound}
                  </div>
                  <div className="flex flex-wrap gap-1 pl-6">
                    {row.conditions.map((condition) => (
                      <span
                        className="rounded bg-muted px-1.5 py-0.5 text-xs text-muted-foreground"
                        key={`${row.id}-${condition.label}`}
                      >
                        {condition.value}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            />
          </div>

          <div className="hidden md:block">
            <DataTable
              columnClassNames={[
                "w-[3.25rem] px-0.5",
                "w-12 px-1 text-center",
                "w-[18%]",
                undefined,
                "w-[20%]",
                "w-[5.5rem] px-2",
              ]}
              fixedLayout
              headers={[
                t("pages.routingRules.headers.enabled"),
                t("pages.routingRules.headers.orderShort"),
                t("pages.routingRules.headers.name"),
                t("pages.routingRules.headers.criteria"),
                t("pages.routingRules.headers.outbound"),
                t("pages.routingRules.headers.actions"),
              ]}
              narrowColumns={[0, 1]}
              reorder={{
                disabled: configMutationPending || searchActive,
                handleLabel: t("pages.routingRules.actions.reorder"),
                onReorder: handleReorder,
              }}
              rows={tableRows.map((row: ReturnType<typeof getRouteRuleRow>) => [
                <div
                  className="flex items-center justify-center"
                  key={`${row.id}-enabled`}
                >
                  <Switch
                    aria-label={t(
                      row.enabled
                        ? "pages.routingRules.actions.disableRule"
                        : "pages.routingRules.actions.enableRule"
                    )}
                    checked={row.enabled}
                    className="after:-inset-x-2"
                    disabled={configMutationPending}
                    onCheckedChange={(checked) =>
                      handleEnabledChange(row.index, checked)
                    }
                    title={t(
                      row.enabled
                        ? "pages.routingRules.actions.disableRule"
                        : "pages.routingRules.actions.enableRule"
                    )}
                  />
                </div>,
                <span
                  className="font-medium tabular-nums"
                  key={`${row.id}-order`}
                >
                  #{row.order}
                </span>,
                <div
                  className="min-w-0"
                  key={`${row.id}-name`}
                  title={row.technicalId}
                >
                  <span
                    className={cn(
                      "block truncate font-medium",
                      row.nameIsGenerated &&
                        "font-normal text-muted-foreground italic"
                    )}
                  >
                    {row.nameIsGenerated
                      ? t("pages.routingRules.unnamed")
                      : row.displayName}
                  </span>
                </div>,
                <ul
                  className="min-w-0 list-disc space-y-1 pl-5 text-sm break-words"
                  key={`${row.id}-conditions`}
                >
                  {row.conditions.map((condition) => (
                    <li
                      className="text-muted-foreground"
                      key={`${row.id}-${condition.label}`}
                    >
                      <span className="font-medium text-foreground">
                        {condition.label}:
                      </span>{" "}
                      {condition.value}
                    </li>
                  ))}
                </ul>,
                <div className="min-w-0" key={`${row.id}-outbound`}>
                  <RuntimeOutboundEntry
                    runtimeState={row.runtimeState}
                    title={row.outbound}
                    t={t}
                  />
                </div>,
                <ActionButtons
                  actions={[
                    {
                      disabled: configMutationPending || rulesSession.isDirty,
                      icon: <Pencil className="h-4 w-4" />,
                      label: t("common.edit"),
                      onClick: () =>
                        navigate(
                          getRuleEditHref(
                            "routing-rules",
                            routeRules[row.index],
                            row.index
                          )
                        ),
                    },
                  ]}
                  key={`${row.id}-actions`}
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
                    rowLabel:
                      tableRows.find((row) => row.id === rowId)?.displayName ??
                      rowId,
                  }),
              }}
            />
          </div>
        </div>
      )}
    </div>
  )
}

function getRouteRuleRow(
  rule: RouteRule,
  index: number,
  t: (key: string) => string,
  lists: ConfigObject["lists"],
  runtimeState?: RuntimeOutboundState,
  outboundDisplayNames: ReadonlyMap<string, string> = new Map()
) {
  const conditions = [
    {
      label: t("pages.routingRules.criteriaLabels.lists"),
      value: formatListReferenceLabels(rule.list ?? [], lists),
    },
    {
      label: t("pages.routingRules.criteriaLabels.proto"),
      value: rule.proto,
    },
    {
      label: t("pages.routingRules.criteriaLabels.dscp"),
      value: rule.dscp?.toString(),
    },
    {
      label: t("pages.routingRules.criteriaLabels.sourceIp"),
      value: rule.src_addr,
    },
    {
      label: t("pages.routingRules.criteriaLabels.destinationIp"),
      value: rule.dest_addr,
    },
    {
      label: t("pages.routingRules.criteriaLabels.sourcePort"),
      value: rule.src_port,
    },
    {
      label: t("pages.routingRules.criteriaLabels.destinationPort"),
      value: rule.dest_port,
    },
  ].filter(
    (
      condition
    ): condition is {
      label: string
      value: string
    } =>
      typeof condition.value === "string" && condition.value.trim().length > 0
  )

  return {
    id: getRoutingRuleRowId(rule, index),
    technicalId: rule.id ?? "",
    displayName: getRouteRuleDisplayName(rule, index),
    nameIsGenerated: isRouteRuleNameGenerated(rule),
    enabled: rule.enabled ?? true,
    index,
    order: index + 1,
    conditions,
    outbound: outboundDisplayNames.get(rule.outbound) ?? rule.outbound,
    runtimeState,
  }
}
