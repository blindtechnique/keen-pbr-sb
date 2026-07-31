import { useQueryClient } from "@tanstack/react-query"
import {
  ArrowRight,
  ExternalLink,
  Pencil,
  Plus,
  RefreshCw,
  Trash2,
} from "lucide-react"
import type { ReactNode } from "react"
import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import { useLocation } from "wouter"

import type { ApiError } from "@/api/client"
import type { ConfigObject } from "@/api/generated/model/configObject"
import type { ConfigStateResponseListRefreshState } from "@/api/generated/model/configStateResponseListRefreshState"
import type { DnsRule } from "@/api/generated/model/dnsRule"
import type { RouteRule } from "@/api/generated/model/routeRule"
import {
  useConfigMutationPending,
  usePostListDeleteStageMutation,
  usePostConfigMutation,
  usePostListsRefreshMutation,
} from "@/api/mutations"
import { queryKeys } from "@/api/query-keys"
import { useGetConfig } from "@/api/queries"
import {
  selectConfig,
  selectConfigIsDraft,
  selectConfigRevision,
  selectListRefreshState,
} from "@/api/selectors"
import { ActionButtons } from "@/components/shared/action-buttons"
import { BulkSelectionToolbar } from "@/components/shared/bulk-selection-toolbar"
import { ConfigSaveErrorAlert } from "@/components/shared/config-save-error-alert"
import { ConfigTransferButtons } from "@/components/shared/config-transfer-buttons"
import { DataTable } from "@/components/shared/data-table"
import { DependencyList } from "@/components/shared/dependency-list"
import {
  DeleteImpactDialog,
  type DeleteImpactItem,
} from "@/components/shared/delete-impact-dialog"
import { ListPlaceholder } from "@/components/shared/list-placeholder"
import { PageHeader } from "@/components/shared/page-header"
import { PageActionBar } from "@/components/shared/page-action-bar"
import { StatsDisplay } from "@/components/shared/stats-display"
import { TableSkeleton } from "@/components/shared/table-skeleton"
import { useRowSelection } from "@/hooks/use-row-selection"
import { useConfigDependencies } from "@/hooks/use-config-dependencies"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { getApiErrorMessage } from "@/lib/api-errors"
import {
  createDnsServerDisplayNameMap,
  getDnsRuleDisplayName,
} from "@/lib/dns-display"
import {
  createOutboundDisplayNameMap,
} from "@/lib/outbound-display"
import {
  formatListReferenceLabels,
  getListDisplayName,
  getListReferenceLabel,
} from "@/lib/list-display"
import { getRouteRuleDisplayName } from "@/pages/routing-rules-utils"
import {
  buildListDeleteTargets,
  getListDeleteImpact,
  type ListDeleteImpact,
} from "@/pages/lists-utils"

type ListDraft = {
  name: string
  ttlMs: string
  domains: string
  ipCidrs: string
  url: string
  file: string
}

type ListTableRow = {
  id: string
  displayName: string
  technicalId?: string
  draft: ListDraft
  locationLabel: string
  locationIcon?: "external"
  lastUpdated?: string
  lastAttempt?: string
  lastError?: string
  lastDetour?: string
  stats?: {
    totalHosts: number
    ipv4Subnets: number
    ipv6Subnets: number
  }
  canRefresh?: boolean
}

const MAX_FAILED_LIST_NAMES_IN_TOAST = 5
const REFRESH_ALL_TARGET = "__all__"
const DELETE_REFERENCES = "__delete_references__"

function isRefreshIconActive(
  activeRefreshTarget: string | null,
  bulkRefreshRunning: boolean,
  selectedIds: ReadonlySet<string>,
  listId: string
) {
  return (
    activeRefreshTarget === REFRESH_ALL_TARGET ||
    activeRefreshTarget === listId ||
    (bulkRefreshRunning && selectedIds.has(listId))
  )
}

export function ListsPage() {
  const { t } = useTranslation()
  const [, navigate] = useLocation()
  const queryClient = useQueryClient()
  const configMutationPending = useConfigMutationPending()
  const configQuery = useGetConfig()
  const loadedConfig = selectConfig(configQuery.data)
  const configRevision = selectConfigRevision(configQuery.data)
  const isDraft = selectConfigIsDraft(configQuery.data)
  const listRefreshState = selectListRefreshState(configQuery.data)
  const [activeRefreshTarget, setActiveRefreshTarget] = useState<string | null>(
    null
  )
  const [bulkRefreshRunning, setBulkRefreshRunning] = useState(false)
  const [deleteRequest, setDeleteRequest] = useState<{
    ids: string[]
    config: ConfigObject
    baseRevision: string
    clearSelectionOnSuccess: boolean
  } | null>(null)
  const [deletePreview, setDeletePreview] = useState<typeof deleteRequest>(null)
  const [replacementListId, setReplacementListId] = useState("")
  const visibleDeleteRequest = deleteRequest ?? deletePreview

  const listRefreshMutation = usePostListsRefreshMutation({
    mutation: {
      onSuccess: async (response, variables) => {
        const requestedName = variables?.data?.name
        const failedLists =
          response.status === 200 ? response.data.failed_lists : []
        if (failedLists.length > 0) {
          toast.error(
            failedLists.length === 1
              ? t("pages.lists.messages.refreshFailedOne", {
                  names: getListReferenceLabel(
                    failedLists[0],
                    loadedConfig?.lists
                  ),
                })
              : t("pages.lists.messages.refreshFailedMany", {
                  count: failedLists.length,
                  names: formatFailedListNamesForToast(
                    failedLists,
                    loadedConfig?.lists,
                    t
                  ),
                }),
            { richColors: true }
          )
          return
        }

        toast.success(
          requestedName
            ? t("pages.lists.messages.refreshedOne")
            : t("pages.lists.messages.refreshedAll")
        )
      },
      onError: (error) => {
        toast.error(getApiErrorMessage(error as ApiError), { richColors: true })
      },
      onSettled: () => {
        setActiveRefreshTarget(null)
        void queryClient.invalidateQueries({ queryKey: queryKeys.config() })
      },
    },
  })

  const tableRows = useMemo(
    () =>
      getTableRowsFromListMap(
        loadedConfig?.lists,
        listRefreshState,
        createOutboundDisplayNameMap(loadedConfig?.outbounds ?? []),
        t
      ),
    [loadedConfig?.lists, loadedConfig?.outbounds, listRefreshState, t]
  )
  const tableRowsById = useMemo(
    () => new Map(tableRows.map((row) => [row.id, row])),
    [tableRows]
  )
  const dependencyTargets = useMemo(
    () => tableRows.map((row) => ({ kind: "list" as const, id: row.id })),
    [tableRows]
  )
  const dependencyAnalysis = useConfigDependencies(
    loadedConfig,
    dependencyTargets
  )
  const dependenciesByList = useMemo(
    () =>
      new Map(
        tableRows.map((row) => [
          row.id,
          dependencyAnalysis.dependenciesByTarget.get(`list:${row.id}`) ?? [],
        ])
      ),
    [dependencyAnalysis.dependenciesByTarget, tableRows]
  )
  const listRowIds = tableRows.map((row) => row.id)
  const listSelection = useRowSelection(listRowIds)
  const hasRefreshableLists = tableRows.some((row) => row.canRefresh)
  const selectedRefreshableLists = tableRows.filter(
    (row) => listSelection.selectedIds.has(row.id) && row.canRefresh
  )
  const refreshDisabled =
    listRefreshMutation.isPending || bulkRefreshRunning || configMutationPending

  const deleteImpact = useMemo(
    () =>
      visibleDeleteRequest
        ? getListDeleteImpact(
            visibleDeleteRequest.config,
            visibleDeleteRequest.ids,
            replacementListId || undefined
          )
        : null,
    [replacementListId, visibleDeleteRequest]
  )
  const replacementCandidates = useMemo(() => {
    if (!visibleDeleteRequest) {
      return []
    }
    const deletedIds = new Set(visibleDeleteRequest.ids)
    return Object.keys(visibleDeleteRequest.config.lists ?? {})
      .filter((listId) => !deletedIds.has(listId))
      .sort((left, right) =>
        getListReferenceLabel(
          left,
          visibleDeleteRequest.config.lists
        ).localeCompare(
          getListReferenceLabel(right, visibleDeleteRequest.config.lists)
        )
      )
  }, [visibleDeleteRequest])

  const postConfigMutation = usePostConfigMutation({
    mutation: {
      onSuccess: async () => {
        await Promise.all([
          queryClient.invalidateQueries({ queryKey: queryKeys.config() }),
          queryClient.invalidateQueries({ queryKey: queryKeys.dnsTest() }),
        ])
      },
    },
  })

  const deleteStageMutation = usePostListDeleteStageMutation({
    mutation: {
      onSuccess: async () => {
        toast.success(t("pages.lists.deleteDialog.staged"))
        if (deleteRequest?.clearSelectionOnSuccess) {
          listSelection.clear()
        }
        setDeleteRequest(null)
        setReplacementListId("")
      },
      onError: async (error) => {
        if (error.status !== 409) {
          toast.error(getApiErrorMessage(error), { richColors: true })
          return
        }

        toast.warning(t("pages.lists.deleteDialog.revisionChanged"), {
          richColors: true,
        })
        const latest = await configQuery.refetch()
        const latestConfig = selectConfig(latest.data)
        const latestRevision = selectConfigRevision(latest.data)
        if (!latestConfig || !latestRevision) {
          return
        }

        setDeleteRequest((current) => {
          if (!current) {
            return current
          }
          const remainingIds = current.ids.filter(
            (listId) => latestConfig.lists?.[listId] !== undefined
          )
          if (remainingIds.length === 0) {
            listSelection.clear()
            return null
          }
          return {
            ...current,
            ids: remainingIds,
            config: latestConfig,
            baseRevision: latestRevision,
          }
        })
        if (
          replacementListId &&
          latestConfig.lists?.[replacementListId] === undefined
        ) {
          setReplacementListId("")
        }
        deleteStageMutation.reset()
      },
    },
  })

  const handleBulkDelete = () => {
    if (
      !loadedConfig ||
      !configRevision ||
      listSelection.selectedCount === 0
    ) {
      return
    }

    const listIds = [...listSelection.selectedIds]
    const request = {
      ids: listIds,
      config: loadedConfig,
      baseRevision: configRevision,
      clearSelectionOnSuccess: true,
    }
    setReplacementListId("")
    setDeletePreview(request)
    setDeleteRequest(request)
  }

  const confirmDelete = () => {
    if (!deleteRequest) {
      return
    }

    deleteStageMutation.mutate({
      data: {
        base_revision: deleteRequest.baseRevision,
        targets: buildListDeleteTargets(
          deleteRequest.ids,
          replacementListId || undefined
        ),
      },
    })
  }

  const handleRefreshAll = () => {
    if (isDraft) {
      toast.warning(t("pages.lists.refresh.draftBlocked"), { richColors: true })
      return
    }

    setActiveRefreshTarget(REFRESH_ALL_TARGET)
    listRefreshMutation.mutate({ data: {} })
  }

  const handleRefreshOne = (listId: string) => {
    if (isDraft) {
      toast.warning(t("pages.lists.refresh.draftBlocked"), { richColors: true })
      return
    }

    setActiveRefreshTarget(listId)
    listRefreshMutation.mutate({ data: { name: listId } })
  }

  const handleBulkRefreshSelected = async () => {
    if (isDraft) {
      toast.warning(t("pages.lists.refresh.draftBlocked"), { richColors: true })
      return
    }

    if (selectedRefreshableLists.length === 0) {
      toast.warning(t("pages.lists.bulk.noUrlBacked"), { richColors: true })
      return
    }

    setBulkRefreshRunning(true)
    try {
      for (const list of selectedRefreshableLists) {
        await listRefreshMutation.mutateAsync({ data: { name: list.id } })
      }
      listSelection.clear()
    } finally {
      setBulkRefreshRunning(false)
    }
  }

  return (
    <div className="space-y-3">
      <PageHeader
        description={t("pages.lists.description")}
        title={t("pages.lists.title")}
      />
      <PageActionBar>
        {hasRefreshableLists ? (
          <Button
            disabled={refreshDisabled}
            onClick={handleRefreshAll}
            variant="outline"
          >
            <RefreshCw
              className={`mr-1 h-4 w-4 ${
                activeRefreshTarget === REFRESH_ALL_TARGET ? "animate-spin" : ""
              }`}
            />
            {t("pages.lists.actions.updateAll")}
          </Button>
        ) : null}
        <ConfigTransferButtons
          config={loadedConfig}
          disabled={configMutationPending}
          kind="lists"
          onImport={(nextConfig) =>
            postConfigMutation.mutate({ data: nextConfig })
          }
        />
        <Button
          disabled={configMutationPending}
          onClick={() => navigate("/lists/create")}
        >
          <Plus className="mr-1 h-4 w-4" />
          {t("pages.lists.actions.new")}
        </Button>
      </PageActionBar>

      <ConfigSaveErrorAlert error={postConfigMutation.error} />

      {configQuery.isLoading ? (
        <TableSkeleton />
      ) : configQuery.isError ? (
        <ListPlaceholder
          description={t("common.loadErrorDescription")}
          title={t("common.unableToLoadData")}
          variant="error"
        />
      ) : tableRows.length === 0 ? (
        <ListPlaceholder
          description={t("pages.lists.empty.description")}
          title={t("pages.lists.empty.title")}
        />
      ) : (
        <div className="space-y-3">
          <div className="relative h-0">
            {listSelection.hasSelection ? (
              <BulkSelectionToolbar
                cancelLabel={t("common.cancel")}
                countLabel={t("pages.lists.bulk.selected", {
                  count: listSelection.selectedCount,
                })}
                onCancel={() => {
                  listSelection.clear()
                }}
              >
                <Button
                  className="md:hidden"
                  disabled={configMutationPending}
                  onClick={() => listSelection.setAllVisible(true)}
                  size="sm"
                  variant="outline"
                >
                  {t("common.selection.selectAllShort")}
                </Button>
                {hasRefreshableLists ? (
                  <Button
                    disabled={
                      refreshDisabled || selectedRefreshableLists.length === 0
                    }
                    onClick={() => void handleBulkRefreshSelected()}
                    size="sm"
                    variant="outline"
                  >
                    <RefreshCw
                      className={`mr-1 h-4 w-4 ${
                        bulkRefreshRunning ? "animate-spin" : ""
                      }`}
                    />
                    {t("pages.lists.bulk.refreshSelected")}
                  </Button>
                ) : null}
                <Button
                  disabled={configMutationPending}
                  onClick={handleBulkDelete}
                  size="sm"
                  variant="destructive"
                >
                  <Trash2 className="mr-1 h-4 w-4" />
                  {t("pages.lists.bulk.deleteSelected")}
                </Button>
              </BulkSelectionToolbar>
            ) : null}
          </div>
          <div className="divide-y divide-border/70 border-b border-border/70 md:hidden">
            {tableRows.map((list) => (
              <div
                className="flex items-start gap-3 bg-card px-1 py-3"
                key={list.id}
              >
                <Checkbox
                  aria-label={t("common.selection.selectRow", {
                    rowLabel: getListAccessibleLabel(list),
                  })}
                  checked={listSelection.selectedIds.has(list.id)}
                  className="mt-0.5 shrink-0"
                  disabled={configMutationPending}
                  onCheckedChange={() => listSelection.toggleOne(list.id)}
                />
                <div className="min-w-0 flex-1 space-y-2">
                  <div className="flex min-w-0 items-start gap-2">
                    <div className="min-w-0 flex-1">
                      <p
                        className="truncate text-sm font-medium"
                        title={getListAccessibleLabel(list)}
                      >
                        {list.displayName}
                      </p>
                      <p className="truncate text-xs text-muted-foreground">
                        {list.locationLabel}
                      </p>
                      <ListRefreshSummary list={list} t={t} />
                    </div>
                    <Badge size="xs" variant="outline">
                      {getListSourceLabel(list.draft, t)}
                    </Badge>
                  </div>
                  {list.stats ? (
                    <StatsDisplay
                      ipv4Subnets={list.stats.ipv4Subnets}
                      ipv6Subnets={list.stats.ipv6Subnets}
                      totalHosts={list.stats.totalHosts}
                    />
                  ) : null}
                  <DependencyList
                    dependencies={dependenciesByList.get(list.id) ?? []}
                    emptyHint={t("common.dependencies.none")}
                  />
                  <div className="flex justify-end gap-1">
                    {list.canRefresh ? (
                      <Button
                        disabled={refreshDisabled}
                        onClick={() => handleRefreshOne(list.id)}
                        size="icon-sm"
                        variant="ghost"
                        aria-label={t("pages.lists.actions.update")}
                      >
                        <RefreshCw
                          className={
                            isRefreshIconActive(
                              activeRefreshTarget,
                              bulkRefreshRunning,
                              listSelection.selectedIds,
                              list.id
                            )
                              ? "animate-spin"
                              : ""
                          }
                        />
                      </Button>
                    ) : null}
                    <Button
                      disabled={configMutationPending}
                      onClick={() => navigate(`/lists/${list.id}/edit`)}
                      size="icon-sm"
                      variant="ghost"
                      aria-label={t("common.edit")}
                    >
                      <Pencil />
                    </Button>
                  </div>
                </div>
              </div>
            ))}
          </div>
          <div className="hidden md:block">
            <DataTable
              headers={[
                t("pages.lists.headers.name"),
                t("pages.lists.headers.type"),
                t("pages.lists.headers.stats"),
                t("pages.lists.headers.rules"),
                t("pages.lists.headers.actions"),
              ]}
              rows={tableRows.map((list) => [
                <div className="space-y-1" key={`${list.id}-name`}>
                  <div
                    className="flex items-center gap-2 font-medium"
                    title={getListAccessibleLabel(list)}
                  >
                    {list.displayName}
                    {list.locationIcon === "external" ? (
                      <a
                        aria-label={list.locationLabel}
                        className="text-muted-foreground transition-colors hover:text-foreground"
                        href={list.draft.url}
                        rel="noreferrer"
                        target="_blank"
                      >
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    ) : null}
                  </div>
                  <div className="text-sm text-muted-foreground md:text-xs">
                    {list.locationLabel}
                  </div>
                  <ListRefreshSummary list={list} t={t} />
                </div>,
                <Badge key={`${list.id}-type`} variant="outline">
                  {getListSourceLabel(list.draft, t)}
                </Badge>,
                list.stats ? (
                  <StatsDisplay
                    ipv4Subnets={list.stats.ipv4Subnets}
                    ipv6Subnets={list.stats.ipv6Subnets}
                    key={`${list.id}-stats`}
                    totalHosts={list.stats.totalHosts}
                  />
                ) : (
                  <span
                    className="text-sm text-muted-foreground"
                    key={`${list.id}-stats-empty`}
                  >
                    {t("pages.lists.noStats")}
                  </span>
                ),
                <DependencyList
                  dependencies={dependenciesByList.get(list.id) ?? []}
                  emptyHint={t("common.dependencies.none")}
                  key={`${list.id}-dependencies`}
                />,
                <ActionButtons
                  actions={[
                    ...(list.canRefresh
                      ? [
                          {
                            disabled: refreshDisabled,
                            icon: (
                              <RefreshCw
                                className={`h-4 w-4 ${
                                  isRefreshIconActive(
                                    activeRefreshTarget,
                                    bulkRefreshRunning,
                                    listSelection.selectedIds,
                                    list.id
                                  )
                                    ? "animate-spin"
                                    : ""
                                }`}
                              />
                            ),
                            label: t("pages.lists.actions.update"),
                            onClick: () => handleRefreshOne(list.id),
                          },
                        ]
                      : []),
                    {
                      disabled: configMutationPending,
                      icon: <Pencil className="h-4 w-4" />,
                      label: t("common.edit"),
                      onClick: () => navigate(`/lists/${list.id}/edit`),
                    },
                  ]}
                  key={`${list.id}-actions`}
                />,
              ])}
              selection={{
                rowIds: listRowIds,
                selectedIds: listSelection.selectedIds,
                disabled: configMutationPending,
                onToggle: listSelection.toggleOne,
                onToggleAll: listSelection.setAllVisible,
                selectAllLabel: t("common.selection.selectAll"),
                getRowLabel: (rowId) =>
                  t("common.selection.selectRow", {
                    rowLabel: getListAccessibleLabel(tableRowsById.get(rowId)),
                  }),
              }}
            />
          </div>
        </div>
      )}
      <DeleteImpactDialog
        confirmLabel={t("pages.lists.deleteDialog.confirm")}
        description={t("pages.lists.deleteDialog.description", {
          names: visibleDeleteRequest
            ? formatListReferenceLabels(
                visibleDeleteRequest.ids,
                visibleDeleteRequest.config.lists
              )
            : "",
        })}
        impactItems={
          visibleDeleteRequest && deleteImpact
            ? getListDeleteImpactItems(
                visibleDeleteRequest.config,
                visibleDeleteRequest.ids,
                deleteImpact,
                replacementListId || undefined,
                t
              )
            : []
        }
        isPending={deleteStageMutation.isPending}
        onConfirm={confirmDelete}
        onOpenChange={(open) => {
          if (!open && !deleteStageMutation.isPending) {
            setDeleteRequest(null)
            setReplacementListId("")
          }
        }}
        open={deleteRequest !== null}
        title={t("pages.lists.deleteDialog.title")}
      >
        {visibleDeleteRequest ? (
          <div className="space-y-2 rounded-[4px] border border-border/70 bg-secondary/30 p-3">
            <label
              className="text-sm font-medium"
              htmlFor="list-delete-replacement"
            >
              {t("pages.lists.deleteDialog.referencesLabel")}
            </label>
            <Select
              items={[
                {
                  label: t(
                    "pages.lists.deleteDialog.referencesRemoveOption"
                  ),
                  value: DELETE_REFERENCES,
                },
                ...replacementCandidates.map((listId) => ({
                  label: getListReferenceLabel(
                    listId,
                    visibleDeleteRequest.config.lists
                  ),
                  value: listId,
                })),
              ]}
              onValueChange={(value) =>
                setReplacementListId(
                  value && value !== DELETE_REFERENCES ? value : ""
                )
              }
              value={replacementListId || DELETE_REFERENCES}
            >
              <SelectTrigger id="list-delete-replacement">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value={DELETE_REFERENCES}>
                    {t("pages.lists.deleteDialog.referencesRemoveOption")}
                  </SelectItem>
                  {replacementCandidates.map((listId) => (
                    <SelectItem key={listId} value={listId}>
                      {getListReferenceLabel(
                        listId,
                        visibleDeleteRequest.config.lists
                      )}
                    </SelectItem>
                  ))}
                </SelectGroup>
              </SelectContent>
            </Select>
            <p className="text-xs leading-5 text-muted-foreground">
              {replacementListId
                ? t("pages.lists.deleteDialog.referencesReplaceHint", {
                    name: getListReferenceLabel(
                      replacementListId,
                      visibleDeleteRequest.config.lists
                    ),
                  })
                : t("pages.lists.deleteDialog.referencesRemoveHint")}
            </p>
          </div>
        ) : null}
      </DeleteImpactDialog>
    </div>
  )
}

function getListDeleteImpactItems(
  config: ConfigObject | undefined,
  listIds: string[],
  impact: ListDeleteImpact,
  replacementListId: string | undefined,
  t: (key: string, options?: Record<string, unknown>) => string
) {
  const items: DeleteImpactItem[] = []
  const deletedListIds = new Set(listIds)

  for (const listId of listIds) {
    items.push({
      label: (
        <>
          {t("pages.lists.deleteDialog.items.listPrefix")}{" "}
          <strong>{getListReferenceLabel(listId, config?.lists)}</strong>{" "}
          {t("pages.lists.deleteDialog.items.listSuffix")}
        </>
      ),
    })
  }

  for (const index of impact.removedRouteRuleIndexes) {
    const rule = config?.route?.rules?.[index]
    items.push({
      label: t("pages.lists.deleteDialog.items.routeRuleRemoved", {
        name: rule ? getRouteRuleDisplayName(rule, index) : `#${index + 1}`,
      }),
      details: getRouteRuleDetails(
        rule,
        deletedListIds,
        true,
        replacementListId,
        config?.lists,
        t
      ),
    })
  }

  for (const index of impact.routeRuleIndexes) {
    if (impact.removedRouteRuleIndexes.includes(index)) {
      continue
    }
    const rule = config?.route?.rules?.[index]
    items.push({
      label: t("pages.lists.deleteDialog.items.routeRuleUpdated", {
        name: rule ? getRouteRuleDisplayName(rule, index) : `#${index + 1}`,
      }),
      details: getRouteRuleDetails(
        rule,
        deletedListIds,
        false,
        replacementListId,
        config?.lists,
        t
      ),
    })
  }

  for (const index of impact.removedDnsRuleIndexes) {
    const rule = config?.dns?.rules?.[index]
    items.push({
      label: t("pages.lists.deleteDialog.items.dnsRuleRemoved", {
        name: getDnsRuleDisplayName(rule, index),
      }),
      details: getDnsRuleDetails(
        rule,
        deletedListIds,
        true,
        replacementListId,
        config,
        t
      ),
    })
  }

  for (const index of impact.dnsRuleIndexes) {
    if (impact.removedDnsRuleIndexes.includes(index)) {
      continue
    }
    const rule = config?.dns?.rules?.[index]
    items.push({
      label: t("pages.lists.deleteDialog.items.dnsRuleUpdated", {
        name: getDnsRuleDisplayName(rule, index),
      }),
      details: getDnsRuleDetails(
        rule,
        deletedListIds,
        false,
        replacementListId,
        config,
        t
      ),
    })
  }

  return items
}

function getRouteRuleDetails(
  rule: RouteRule | undefined,
  deletedListIds: ReadonlySet<string>,
  isRemoved: boolean,
  replacementListId: string | undefined,
  lists: ConfigObject["lists"],
  t: (key: string, options?: Record<string, unknown>) => string
) {
  if (!rule) {
    return []
  }

  const beforeLists = rule.list ?? []
  const afterLists = rewriteDisplayedListReferences(
    beforeLists,
    deletedListIds,
    replacementListId
  )
  const details: ReactNode[] = []

  if (beforeLists.length > 0) {
    details.push(
      formatDetail(
        t("pages.routingRules.criteriaLabels.lists"),
        isRemoved
          ? formatListValue(beforeLists, lists, t)
          : formatTransition(beforeLists, afterLists, lists, t)
      )
    )
  }

  appendOptionalDetail(
    details,
    t("pages.routingRules.criteriaLabels.proto"),
    rule.proto
  )
  appendOptionalDetail(
    details,
    t("pages.routingRules.criteriaLabels.dscp"),
    rule.dscp?.toString()
  )
  appendOptionalDetail(
    details,
    t("pages.routingRules.criteriaLabels.sourceIp"),
    rule.src_addr
  )
  appendOptionalDetail(
    details,
    t("pages.routingRules.criteriaLabels.destinationIp"),
    rule.dest_addr
  )
  appendOptionalDetail(
    details,
    t("pages.routingRules.criteriaLabels.sourcePort"),
    rule.src_port
  )
  appendOptionalDetail(
    details,
    t("pages.routingRules.criteriaLabels.destinationPort"),
    rule.dest_port
  )

  return details
}

function getDnsRuleDetails(
  rule: DnsRule | undefined,
  deletedListIds: ReadonlySet<string>,
  isRemoved: boolean,
  replacementListId: string | undefined,
  config: ConfigObject | undefined,
  t: (key: string, options?: Record<string, unknown>) => string
) {
  if (!rule) {
    return []
  }

  const afterLists = rewriteDisplayedListReferences(
    rule.list,
    deletedListIds,
    replacementListId
  )
  const dnsServerNames = createDnsServerDisplayNameMap(
    config?.dns?.servers ?? []
  )

  return [
    formatDetail(
      t("pages.dnsRules.criteriaLabels.lists"),
      isRemoved
        ? formatListValue(rule.list, config?.lists, t)
        : formatTransition(rule.list, afterLists, config?.lists, t)
    ),
    formatDetail(
      t("pages.dnsRules.headers.serverTag"),
      dnsServerNames.get(rule.server) ?? rule.server
    ),
  ]
}

function appendOptionalDetail(
  details: ReactNode[],
  label: string,
  value: string | undefined
) {
  if (typeof value !== "string" || value.trim().length === 0) {
    return
  }

  details.push(formatDetail(label, value))
}

function rewriteDisplayedListReferences(
  references: readonly string[],
  deletedListIds: ReadonlySet<string>,
  replacementListId?: string
) {
  const rewritten: string[] = []
  for (const listId of references) {
    const next =
      deletedListIds.has(listId) && replacementListId
        ? replacementListId
        : deletedListIds.has(listId)
          ? undefined
          : listId
    if (next && !rewritten.includes(next)) {
      rewritten.push(next)
    }
  }
  return rewritten
}

function formatDetail(label: string, value: ReactNode) {
  return (
    <>
      {label}: {value}
    </>
  )
}

function formatTransition(
  before: string[],
  after: string[],
  lists: ConfigObject["lists"],
  t: (key: string, options?: Record<string, unknown>) => string
) {
  return (
    <ChangeValue
      after={formatListValue(after, lists, t)}
      before={formatListValue(before, lists, t)}
    />
  )
}

function ChangeValue({ after, before }: { after: string; before: string }) {
  return (
    <span className="inline-flex min-w-0 items-center gap-1 leading-4">
      <span className="min-w-0 truncate">{before}</span>
      <ArrowRight className="mt-px size-3 shrink-0" />
      <span className="min-w-0 truncate">{after}</span>
    </span>
  )
}

function formatListValue(
  values: string[],
  lists: ConfigObject["lists"],
  t: (key: string, options?: Record<string, unknown>) => string
) {
  return values.length > 0
    ? formatListReferenceLabels(values, lists)
    : t("common.noneShort")
}

function formatFailedListNamesForToast(
  names: string[],
  lists: ConfigObject["lists"],
  t: ReturnType<typeof useTranslation>["t"]
) {
  const visibleNames = names
    .slice(0, MAX_FAILED_LIST_NAMES_IN_TOAST)
    .map((name) => getListReferenceLabel(name, lists))
  const hiddenCount = names.length - visibleNames.length
  const label = visibleNames.join(", ")

  if (hiddenCount <= 0) {
    return label
  }

  return `${label}, ${t("pages.lists.messages.refreshFailedMore", {
    count: hiddenCount,
  })}`
}

function getListAccessibleLabel(list: ListTableRow | undefined) {
  if (!list) {
    return ""
  }
  return list.technicalId
    ? `${list.displayName} (${list.technicalId})`
    : list.displayName
}

function getTableRowsFromListMap(
  lists: ConfigObject["lists"],
  listRefreshState: ConfigStateResponseListRefreshState,
  outboundNames: ReadonlyMap<string, string>,
  t: (key: string) => string
): ListTableRow[] {
  return Object.entries(lists ?? {}).map(([name, listConfig]) => {
    const displayName = getListDisplayName(name, lists)
    const domains = listConfig.domains ?? []
    const ipCidrs = listConfig.ip_cidrs ?? []
    const showInlineStats = !listConfig.url && !listConfig.file

    return {
      id: name,
      displayName,
      technicalId: displayName !== name ? name : undefined,
      draft: {
        name,
        ttlMs: String(listConfig.ttl_ms ?? 0),
        domains: domains.join("\n"),
        ipCidrs: ipCidrs.join("\n"),
        url: listConfig.url ?? "",
        file: listConfig.file ?? "",
      },
      locationLabel:
        listConfig.url || listConfig.file || t("pages.lists.location.inline"),
      locationIcon: listConfig.url ? "external" : undefined,
      lastUpdated: listRefreshState[name]?.last_updated,
      lastAttempt: listRefreshState[name]?.last_attempt,
      lastError: listRefreshState[name]?.last_error,
      lastDetour: listRefreshState[name]?.last_detour
        ? (outboundNames.get(listRefreshState[name]?.last_detour ?? "") ??
          listRefreshState[name]?.last_detour)
        : undefined,
      stats: showInlineStats
        ? {
            totalHosts: domains.length + ipCidrs.length,
            ipv4Subnets: ipCidrs.filter((value) => value.includes(".")).length,
            ipv6Subnets: ipCidrs.filter((value) => value.includes(":")).length,
          }
        : undefined,
      canRefresh: Boolean(listConfig.url),
    }
  })
}

function ListRefreshSummary({
  list,
  t,
}: {
  list: ListTableRow
  t: ReturnType<typeof useTranslation>["t"]
}) {
  if (!list.canRefresh) {
    return null
  }

  const successfulAt = formatLastUpdatedLabel(
    list.lastUpdated,
    t("pages.lists.neverUpdated")
  )
  const attemptedAt = formatLastUpdatedLabel(
    list.lastAttempt,
    t("pages.lists.neverUpdated")
  )

  return (
    <div className="space-y-0.5 text-xs">
      <div className="text-muted-foreground">
        {t("pages.lists.lastUpdated", { value: successfulAt })}
      </div>
      {list.lastError ? (
        <div className="break-words text-destructive">
          {t(
            list.lastDetour
              ? "pages.lists.lastRefreshFailedVia"
              : "pages.lists.lastRefreshFailed",
            {
              value: attemptedAt,
              detour: list.lastDetour,
              message: list.lastError,
            }
          )}
        </div>
      ) : null}
    </div>
  )
}

function getListSourceLabel(draft: ListDraft, t: (key: string) => string) {
  const sources = [
    draft.url ? "url" : null,
    draft.file ? "file" : null,
    draft.domains ? "domains" : null,
    draft.ipCidrs ? "ip_cidrs" : null,
  ].filter(Boolean)

  if (sources.length === 0) {
    return t("pages.lists.source.empty")
  }

  return sources.map((source) => t(`pages.lists.source.${source}`)).join(", ")
}

function formatLastUpdatedLabel(value: string | undefined, fallback: string) {
  if (!value) {
    return fallback
  }

  const parsedDate = new Date(value)
  if (Number.isNaN(parsedDate.getTime())) {
    return value
  }

  return new Intl.DateTimeFormat(undefined, {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(parsedDate)
}
