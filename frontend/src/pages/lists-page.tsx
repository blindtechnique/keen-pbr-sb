import {
  keepPreviousData,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query"
import {
  ChevronLeft,
  ChevronRight,
  Download,
  ExternalLink,
  Plus,
  RefreshCw,
} from "lucide-react"
import { Fragment, useDeferredValue, useMemo, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import { useLocation } from "wouter"

import type { ConfigObject } from "@/api/generated/model/configObject"
import { queryLists } from "@/api/generated/keen-api"
import type { ListPageItem } from "@/api/generated/model/listPageItem"
import type { ConfigStateResponseListRefreshState } from "@/api/generated/model/configStateResponseListRefreshState"
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
import { KeenPencilIcon, KeenTrashIcon } from "@/components/shared/keen-icons"
import { ActionButtons } from "@/components/shared/action-buttons"
import { BulkSelectionToolbar } from "@/components/shared/bulk-selection-toolbar"
import { ConfigSaveErrorAlert } from "@/components/shared/config-save-error-alert"
import { ConfigTransferButtons } from "@/components/shared/config-transfer-buttons"
import { DataTable } from "@/components/shared/data-table"
import { TableSearch } from "@/components/shared/table-search"
import { DependencyList } from "@/components/shared/dependency-list"
import { ExpandableText } from "@/components/shared/expandable-text"
import { DeleteImpactDialog } from "@/components/shared/delete-impact-dialog"
import { getListDeleteImpactItems } from "@/components/delete-impact/list-items"
import { createDnsServerDisplayNameMap } from "@/lib/dns-display"
import { getRuleEditHref } from "@/lib/rule-route"
import type { Dependency } from "@/lib/dependencies"
import { ListDeleteReplacementPicker } from "@/components/lists/list-delete-replacement-picker"
import { ListShrinkNotice } from "@/components/lists/list-shrink-notice"
import { OperationErrorMessage } from "@/components/shared/operation-error-message"
import { ListPlaceholder } from "@/components/shared/list-placeholder"
import { PageHeader } from "@/components/shared/page-header"
import { PageActionBar } from "@/components/shared/page-action-bar"
import { StatsDisplay } from "@/components/shared/stats-display"
import { TableSkeleton } from "@/components/shared/table-skeleton"
import { useRowSelection } from "@/hooks/use-row-selection"
import { nextTableSortState, type TableSortState } from "@/hooks/use-table-sort"
import { useVirtualRows } from "@/hooks/use-virtual-rows"
import { buildListPageRequest } from "@/pages/lists-pagination"
import { useConfigDependencies } from "@/hooks/use-config-dependencies"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { getApiErrorMessage } from "@/lib/api-errors"
import {
  buildListRefreshRequest,
  didListRefreshComplete,
  type ListRefreshAction,
  type ListShrinkRejection,
} from "@/lib/list-refresh-controls"
import { createOutboundDisplayNameMap } from "@/lib/outbound-display"
import {
  formatListReferenceLabels,
  getListReferenceLabel,
} from "@/lib/list-display"
import {
  buildListDeleteTargets,
  getListDeleteImpact,
  getListStatsState,
} from "@/pages/lists-utils"

type ListDraft = {
  name: string
  ttlMs: string
  domains: boolean
  ipCidrs: boolean
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
  shrinkRejection?: ListShrinkRejection
  stats?: {
    domains: number
    ipv4Subnets: number
    ipv6Subnets: number
  }
  canRefresh?: boolean
}

const MAX_FAILED_LIST_NAMES_IN_TOAST = 5
const REFRESH_ALL_TARGET = "__all__"

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
  const [search, setSearch] = useState("")
  const deferredSearch = useDeferredValue(search)
  const [offset, setOffset] = useState(0)
  const [sortState, setSortState] = useState<{
    activeColumn: number | null
    direction: "asc" | "desc"
  }>({ activeColumn: null, direction: "asc" })
  const pageRequest = buildListPageRequest(deferredSearch, offset, sortState)
  const pageQuery = useQuery({
    // Config invalidation also refreshes pages, but a page is NEVER cached as
    // the full configuration used by editors and import/export.
    queryKey: [...queryKeys.config(), "lists-page", pageRequest],
    queryFn: async ({ signal }) => {
      const response = await queryLists(pageRequest, { signal })
      if (response.status !== 200) throw new Error(response.data.error)
      return response.data
    },
    placeholderData: keepPreviousData,
  })
  const page = pageQuery.data
  const pageBusy = pageQuery.isFetching || search !== deferredSearch
  const sort: TableSortState = {
    ...sortState,
    sortable: [0, 1],
    onToggle: (column) => {
      setSortState((current) => nextTableSortState(current, column))
      setOffset(0)
    },
  }
  const [activeRefreshTarget, setActiveRefreshTarget] = useState<string | null>(
    null
  )
  const [bulkRefreshRunning, setBulkRefreshRunning] = useState(false)
  const refreshRequestRef = useRef(false)
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
          response.status === 200 && Array.isArray(response.data.failed_lists)
            ? response.data.failed_lists
            : []
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

        if (!didListRefreshComplete(response, requestedName)) {
          toast.error(
            <OperationErrorMessage
              error={response}
              fallbackSummary={t("pages.lists.messages.refreshUnconfirmed")}
            />,
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
        toast.error(
          <OperationErrorMessage
            error={error}
            fallbackSummary={t("pages.lists.messages.refreshRequestFailed")}
          />,
          { richColors: true }
        )
      },
      onSettled: () => {
        setActiveRefreshTarget(null)
        void queryClient.invalidateQueries({ queryKey: queryKeys.config() })
      },
    },
  })

  const tableRows = useMemo(
    () =>
      getTableRowsFromListPage(
        page?.items,
        listRefreshState,
        createOutboundDisplayNameMap(loadedConfig?.outbounds ?? []),
        t
      ),
    [page?.items, loadedConfig?.outbounds, listRefreshState, t]
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
  const dependenciesByList = useMemo(() => {
    // «Правила DNS: правило → сервер» заменены на «DNS: сервер» (решение
    // владельца): по новой концепции DNS назначается списку, а правило —
    // деталь реализации. Сервер берётся из правил, покрывающих список;
    // ссылка ведёт в редактор правила — для общего правила там видно всех.
    const dnsServerNames = createDnsServerDisplayNameMap(
      loadedConfig?.dns?.servers ?? []
    )
    const dnsChipsByList = new Map<string, Dependency[]>()
    for (const [index, rule] of (loadedConfig?.dns?.rules ?? []).entries()) {
      for (const listId of rule.list ?? []) {
        if (!tableRowsById.has(listId)) continue
        const chips = dnsChipsByList.get(listId) ?? []
        const label = dnsServerNames.get(rule.server) ?? rule.server
        if (!chips.some((chip) => chip.label === label)) {
          chips.push({
            kind: "dns",
            label,
            href: getRuleEditHref("dns-rules", rule, index),
          })
        }
        dnsChipsByList.set(listId, chips)
      }
    }
    return new Map(
      tableRows.map((row) => [
        row.id,
        [
          ...(
            dependencyAnalysis.dependenciesByTarget.get(`list:${row.id}`) ?? []
          ).filter((dependency) => dependency.kind !== "dnsRule"),
          ...(dnsChipsByList.get(row.id) ?? []),
        ],
      ])
    )
  }, [
    dependencyAnalysis.dependenciesByTarget,
    loadedConfig,
    tableRows,
    tableRowsById,
  ])
  // Search and ordering happen before pagination on the router.
  const sortedRows = tableRows
  const visibleRows = tableRows
  const listRowIds = sortedRows.map((row) => row.id)
  const allListIds = useMemo(
    () => Object.keys(loadedConfig?.lists ?? {}),
    [loadedConfig?.lists]
  )
  const listSelection = useRowSelection(allListIds)
  const hasRefreshableLists = page?.has_refreshable_lists ?? false
  // Explicit selections survive page changes; select-all remains page-scoped.
  const selectedRefreshableLists = [...listSelection.selectedIds]
    .filter((id) => Boolean(loadedConfig?.lists?.[id]?.url))
    .map((id) => ({ id }))
  const mobileRows = useVirtualRows({
    enabled: true,
    keys: listRowIds,
    estimateSize: 220,
  })
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
    if (!loadedConfig || !configRevision || listSelection.selectedCount === 0) {
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
    if (refreshDisabled || refreshRequestRef.current) return
    if (isDraft) {
      toast.warning(t("pages.lists.refresh.draftBlocked"), { richColors: true })
      return
    }

    setActiveRefreshTarget(REFRESH_ALL_TARGET)
    refreshRequestRef.current = true
    listRefreshMutation.mutate(
      { data: {} },
      {
        onSettled: () => {
          refreshRequestRef.current = false
        },
      }
    )
  }

  const handleRefreshOne = (
    listId: string,
    action: ListRefreshAction = "refresh"
  ) => {
    if (refreshDisabled || refreshRequestRef.current) return
    if (isDraft) {
      toast.warning(t("pages.lists.refresh.draftBlocked"), { richColors: true })
      return
    }

    const data = buildListRefreshRequest(
      listId,
      action,
      tableRowsById.get(listId)?.shrinkRejection
    )
    if (!data) return
    setActiveRefreshTarget(listId)
    refreshRequestRef.current = true
    listRefreshMutation.mutate(
      { data },
      {
        onSettled: () => {
          refreshRequestRef.current = false
        },
      }
    )
  }

  const handleBulkRefreshSelected = async () => {
    if (refreshDisabled || refreshRequestRef.current) return
    if (isDraft) {
      toast.warning(t("pages.lists.refresh.draftBlocked"), { richColors: true })
      return
    }

    if (selectedRefreshableLists.length === 0) {
      toast.warning(t("pages.lists.bulk.noUrlBacked"), { richColors: true })
      return
    }

    refreshRequestRef.current = true
    setBulkRefreshRunning(true)
    try {
      for (const list of selectedRefreshableLists) {
        await listRefreshMutation.mutateAsync({ data: { name: list.id } })
      }
      listSelection.clear()
    } catch {
      // The existing mutation error handler presents the failed request.
    } finally {
      refreshRequestRef.current = false
      setBulkRefreshRunning(false)
    }
  }

  return (
    <div className="space-y-3">
      <PageHeader
        description={t("pages.lists.description")}
        title={t("pages.lists.title")}
      />
      <PageActionBar
        primary={
          <Button
            disabled={configMutationPending}
            onClick={() => navigate("/lists/create")}
          >
            <Plus className="mr-1 h-4 w-4" />
            {t("pages.lists.actions.new")}
          </Button>
        }
        leading={
          (page?.total ?? 0) > 0 ? (
            <TableSearch
              matchCount={page?.filtered_total ?? 0}
              onChange={(next) => {
                setSearch(next)
                setOffset(0)
                listSelection.clear()
              }}
              placeholder={t("pages.lists.searchPlaceholder")}
              totalCount={page?.total ?? 0}
              value={search}
            />
          ) : null
        }
      >
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
      </PageActionBar>

      <ConfigSaveErrorAlert error={postConfigMutation.error} />

      {configQuery.isLoading || pageQuery.isPending ? (
        <TableSkeleton />
      ) : configQuery.isError || pageQuery.isError ? (
        <ListPlaceholder
          description={t("common.loadErrorDescription")}
          title={t("common.unableToLoadData")}
          variant="error"
        />
      ) : page?.total === 0 ? (
        <ListPlaceholder
          description={t("pages.lists.empty.description")}
          title={t("pages.lists.empty.title")}
        />
      ) : (
        <div className="space-y-3" aria-busy={pageBusy}>
          {page && page.filtered_total > page.limit ? (
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-sm text-muted-foreground" aria-live="polite">
                {t("listPagination.range", {
                  from: page.offset + 1,
                  to: page.offset + page.items.length,
                  total: page.filtered_total,
                })}
              </p>
              <div className="flex gap-1">
                <Button
                  size="sm"
                  variant="outline"
                  disabled={pageBusy || page.offset === 0}
                  onClick={() =>
                    setOffset(Math.max(0, page.offset - page.limit))
                  }
                >
                  <ChevronLeft className="size-4" />
                  {t("listPagination.previous")}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={
                    pageBusy ||
                    page.offset + page.items.length >= page.filtered_total
                  }
                  onClick={() => setOffset(page.offset + page.limit)}
                >
                  {t("listPagination.next")}
                  <ChevronRight className="size-4" />
                </Button>
              </div>
            </div>
          ) : null}
          {visibleRows.length === 0 ? (
            <ListPlaceholder
              description={t("common.tableSearch.empty")}
              title={t("pages.lists.empty.title")}
            />
          ) : null}
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
                  onClick={() => listSelection.setAllVisible(true, listRowIds)}
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
                  <KeenTrashIcon className="mr-1 h-4 w-4" />
                  {t("pages.lists.bulk.deleteSelected")}
                </Button>
              </BulkSelectionToolbar>
            ) : null}
          </div>
          <div
            ref={mobileRows.containerRef}
            className="border-b border-border/70 md:hidden"
          >
            {mobileRows.items.map((item) => {
              const list = sortedRows[item.index]
              return (
                <Fragment key={item.key}>
                  {item.paddingBefore > 0 ? (
                    <div
                      aria-hidden="true"
                      style={{ height: item.paddingBefore }}
                    />
                  ) : null}
                  <div
                    className="flex items-start gap-3 border-b border-border/70 bg-card px-1 py-3"
                    data-index={item.index}
                    ref={mobileRows.measureElement}
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
                          {/* Адрес остаётся обрезанным намеренно. Раскрывать его
                          здесь я пробовал: на строку с неудачной загрузкой
                          выходит две кнопки «Читать далее» подряд, и неясно,
                          какая к чему. Полный адрес показывает экран
                          редактирования, до которого один шаг — карандаш в этой
                          же строке. `title` помогает мыши на узком окне. */}
                          <p
                            className="truncate text-xs text-muted-foreground"
                            title={list.locationLabel}
                          >
                            {list.locationLabel}
                          </p>
                          <ListRefreshSummary
                            list={list}
                            t={t}
                            disabled={refreshDisabled}
                            pending={isRefreshIconActive(
                              activeRefreshTarget,
                              bulkRefreshRunning,
                              listSelection.selectedIds,
                              list.id
                            )}
                            onAccept={() => handleRefreshOne(list.id, "accept")}
                          />
                        </div>
                        <Badge size="xs" variant="outline">
                          {getListSourceLabel(list.draft, t)}
                        </Badge>
                      </div>
                      {list.stats ? (
                        <StatsDisplay
                          domains={list.stats.domains}
                          ipv4Subnets={list.stats.ipv4Subnets}
                          ipv6Subnets={list.stats.ipv6Subnets}
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
                        {list.canRefresh ? (
                          <Button
                            disabled={refreshDisabled}
                            onClick={() => handleRefreshOne(list.id, "force")}
                            size="icon-sm"
                            variant="ghost"
                            aria-label={t(
                              "pages.lists.actions.forceRefreshHint"
                            )}
                            title={t("pages.lists.actions.forceRefreshHint")}
                          >
                            <Download />
                          </Button>
                        ) : null}
                        <Button
                          disabled={configMutationPending}
                          onClick={() => navigate(`/lists/${list.id}/edit`)}
                          size="icon-sm"
                          variant="ghost"
                          aria-label={t("common.edit")}
                        >
                          <KeenPencilIcon />
                        </Button>
                      </div>
                    </div>
                  </div>
                </Fragment>
              )
            })}
            {mobileRows.paddingAfter > 0 ? (
              <div
                aria-hidden="true"
                style={{ height: mobileRows.paddingAfter }}
              />
            ) : null}
          </div>
          <div className="hidden md:block">
            <DataTable
              virtualize
              desktopOnly
              headers={[
                t("pages.lists.headers.name"),
                t("pages.lists.headers.type"),
                t("pages.lists.headers.stats"),
                t("pages.lists.headers.rules"),
                t("pages.lists.headers.actions"),
              ]}
              rows={sortedRows.map((list) => [
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
                  <ListRefreshSummary
                    list={list}
                    t={t}
                    disabled={refreshDisabled}
                    pending={isRefreshIconActive(
                      activeRefreshTarget,
                      bulkRefreshRunning,
                      listSelection.selectedIds,
                      list.id
                    )}
                    onAccept={() => handleRefreshOne(list.id, "accept")}
                  />
                </div>,
                <Badge key={`${list.id}-type`} variant="outline">
                  {getListSourceLabel(list.draft, t)}
                </Badge>,
                // «0» и «не загружен» выглядели одинаково — прочерком. Свои
                // записи панель считает сама, а что лежит в скачанном файле,
                // она не знает: демон количество не отдаёт. Поэтому здесь не
                // выдуманное число, а честное состояние загрузки.
                getListStatsState(list) === "counted" && list.stats ? (
                  <StatsDisplay
                    domains={list.stats.domains}
                    ipv4Subnets={list.stats.ipv4Subnets}
                    ipv6Subnets={list.stats.ipv6Subnets}
                    key={`${list.id}-stats`}
                  />
                ) : getListStatsState(list) === "loaded" ? (
                  <span
                    className="text-sm text-muted-foreground"
                    key={`${list.id}-stats-loaded`}
                  >
                    {t("pages.lists.statsLoaded")}
                  </span>
                ) : (
                  <span
                    className="text-sm text-warning-foreground"
                    key={`${list.id}-stats-empty`}
                    title={
                      list.lastError
                        ? t("pages.lists.statsNotLoadedFailed")
                        : undefined
                    }
                  >
                    {t("pages.lists.statsNotLoaded")}
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
                          {
                            disabled: refreshDisabled,
                            icon: <Download className="h-4 w-4" />,
                            label: t("pages.lists.actions.forceRefreshHint"),
                            onClick: () => handleRefreshOne(list.id, "force"),
                          },
                        ]
                      : []),
                    {
                      disabled: configMutationPending,
                      icon: <KeenPencilIcon className="h-4 w-4" />,
                      label: t("common.edit"),
                      onClick: () => navigate(`/lists/${list.id}/edit`),
                    },
                  ]}
                  key={`${list.id}-actions`}
                />,
              ])}
              sort={sort}
              selection={{
                rowIds: listRowIds,
                selectedIds: listSelection.selectedIds,
                disabled: configMutationPending,
                onToggle: listSelection.toggleOne,
                onToggleAll: listSelection.setAllVisible,
                selectAllLabel: t("listPagination.selectPage"),
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
          <ListDeleteReplacementPicker
            config={visibleDeleteRequest.config}
            deletedIds={visibleDeleteRequest.ids}
            onChange={setReplacementListId}
            replacementListId={replacementListId}
          />
        ) : null}
      </DeleteImpactDialog>
    </div>
  )
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

function getTableRowsFromListPage(
  items: ListPageItem[] | undefined,
  listRefreshState: ConfigStateResponseListRefreshState,
  outboundNames: ReadonlyMap<string, string>,
  t: (key: string) => string
): ListTableRow[] {
  return (items ?? []).map((listConfig) => {
    const name = listConfig.id
    const displayName = listConfig.display_name?.trim() || name
    const showInlineStats = !listConfig.url && !listConfig.file

    return {
      id: name,
      displayName,
      technicalId: displayName !== name ? name : undefined,
      draft: {
        name,
        ttlMs: "",
        domains: listConfig.domain_count > 0,
        ipCidrs: listConfig.ipv4_count + listConfig.ipv6_count > 0,
        url: listConfig.url ?? "",
        file: listConfig.file ?? "",
      },
      locationLabel:
        listConfig.url || listConfig.file || t("pages.lists.location.inline"),
      locationIcon: listConfig.url ? "external" : undefined,
      lastUpdated: listRefreshState[name]?.last_updated,
      lastAttempt: listRefreshState[name]?.last_attempt,
      lastError: listRefreshState[name]?.last_error,
      shrinkRejection: listRefreshState[name]?.shrink_rejection ?? undefined,
      lastDetour: listRefreshState[name]?.last_detour
        ? (outboundNames.get(listRefreshState[name]?.last_detour ?? "") ??
          listRefreshState[name]?.last_detour)
        : undefined,
      stats: showInlineStats
        ? {
            domains: listConfig.domain_count,
            ipv4Subnets: listConfig.ipv4_count,
            ipv6Subnets: listConfig.ipv6_count,
          }
        : undefined,
      canRefresh: Boolean(listConfig.url),
    }
  })
}

function ListRefreshSummary({
  list,
  t,
  disabled,
  pending,
  onAccept,
}: {
  list: ListTableRow
  t: ReturnType<typeof useTranslation>["t"]
  disabled: boolean
  pending: boolean
  onAccept: () => void
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
      {list.shrinkRejection ? (
        <ListShrinkNotice
          rejection={list.shrinkRejection}
          disabled={disabled}
          pending={pending}
          onAccept={onAccept}
        />
      ) : list.lastError ? (
        // Ошибка демона содержит адрес и системное сообщение целиком: на
        // телефоне это десять строк, после которых следующий список уезжает за
        // экран. Две строки говорят, что обновление не прошло; подробности —
        // по «Читать далее».
        <ExpandableText
          className="text-destructive"
          lines={2}
          text={t(
            list.lastDetour
              ? "pages.lists.lastRefreshFailedVia"
              : "pages.lists.lastRefreshFailed",
            {
              value: attemptedAt,
              detour: list.lastDetour,
              message: list.lastError,
            }
          )}
        />
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
