import { ArrowRight, Plus, RotateCw } from "lucide-react"
import type { ReactNode } from "react"
import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"

import { useQueryClient } from "@tanstack/react-query"
import { useLocation } from "wouter"

import type { ApiError } from "@/api/client"
import type { ConfigObject } from "@/api/generated/model/configObject"
import type { Outbound } from "@/api/generated/model/outbound"
import type { RouteRule } from "@/api/generated/model/routeRule"
import type { RuntimeInterfaceInventoryEntry } from "@/api/generated/model/runtimeInterfaceInventoryEntry"
import type { RuntimeOutboundState } from "@/api/generated/model/runtimeOutboundState"
import {
  useConfigMutationPending,
  usePostConfigMutation,
} from "@/api/mutations"
import { queryKeys } from "@/api/query-keys"
import {
  useGetConfig,
  useGetRuntimeInterfaces,
  useGetRuntimeOutbounds,
} from "@/api/queries"
import { selectConfig, selectOutbounds } from "@/api/selectors"
import { KeenPencilIcon, KeenTrashIcon } from "@/components/shared/keen-icons"
import { ActionButtons } from "@/components/shared/action-buttons"
import { BulkSelectionToolbar } from "@/components/shared/bulk-selection-toolbar"
import { ConfigSaveErrorAlert } from "@/components/shared/config-save-error-alert"
import { ConfigTransferButtons } from "@/components/shared/config-transfer-buttons"
import { DataTable } from "@/components/shared/data-table"
import { DependencyList } from "@/components/shared/dependency-list"
import {
  OutboundMemberChain,
  OutboundName,
  OutboundPurpose,
  OutboundStatus,
} from "@/components/outbounds/outbound-cells"
import { useInterfaceProtocols } from "@/hooks/use-interface-protocols"
import { useRunSystemProbes } from "@/hooks/use-run-system-probes"
import { useConfigDependencies } from "@/hooks/use-config-dependencies"
import { findBrokenReferences } from "@/lib/dependencies"
import {
  DeleteImpactDialog,
  type DeleteImpactItem,
} from "@/components/shared/delete-impact-dialog"
import { ListPlaceholder } from "@/components/shared/list-placeholder"

import { PageHeader } from "@/components/shared/page-header"
import { SectionHeading } from "@/components/shared/section-heading"
import { PageActionBar } from "@/components/shared/page-action-bar"
import { SectionTabs, type SectionTab } from "@/components/shared/section-tabs"
import { TableSkeleton } from "@/components/shared/table-skeleton"
import { useRowSelection } from "@/hooks/use-row-selection"
import { useSectionTab } from "@/hooks/use-section-tab"
import { useTableSort } from "@/hooks/use-table-sort"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { getApiErrorMessage } from "@/lib/api-errors"
import { cn } from "@/lib/utils"
import {
  createDnsServerDisplayNameMap,
  getDnsServerDisplayName,
} from "@/lib/dns-display"
import {
  formatListReferenceLabels,
  getListReferenceLabel,
} from "@/lib/list-display"
import {
  createOutboundDisplayNameMap,
  getOutboundDisplayName,
} from "@/lib/outbound-display"
import { getRouteRuleDisplayName } from "@/pages/routing-rules-utils"
import {
  buildUpdatedConfigForOutboundsDelete,
  filterDeletableOutboundTags,
  firstLatency,
  getOutboundDeleteImpact,
  type OutboundDeleteImpact,
} from "@/pages/outbounds-utils"

type OutboundItem = {
  id: string
  tag: string
  type: Outbound["type"]
  outbound: Outbound
  runtimeInterface?: RuntimeInterfaceInventoryEntry
  runtimeState?: RuntimeOutboundState
}

type OutboundGroupKey = "interfaces" | "failover" | "system"

export function OutboundsPage({
  embedded = false,
  group,
}: {
  embedded?: boolean
  /**
   * Показать только одну группу и не рисовать свои вкладки.
   *
   * Страница целиком живёт внутри «Маршрутов и туннелей»: вкладками там
   * управляет родитель, а две полосы вкладок друг под другом читались бы как
   * два разных раздела на одном экране.
   */
  group?: OutboundGroupKey
} = {}) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [, navigate] = useLocation()
  const [deleteRequest, setDeleteRequest] = useState<{
    tags: string[]
    impact: OutboundDeleteImpact
    config: ConfigObject
    clearSelectionOnSuccess: boolean
  } | null>(null)
  const [deletePreview, setDeletePreview] = useState<typeof deleteRequest>(null)
  const configMutationPending = useConfigMutationPending()
  const configQuery = useGetConfig()
  const runtimeOutboundsQuery = useGetRuntimeOutbounds()
  const runtimeInterfacesQuery = useGetRuntimeInterfaces()
  const loadedConfig = selectConfig(configQuery.data)
  const visibleDeleteRequest = deleteRequest ?? deletePreview
  // using toasts for mutation errors

  const runtimeOutboundByTag = useMemo(
    () =>
      new Map(
        (runtimeOutboundsQuery.data?.status === 200
          ? runtimeOutboundsQuery.data.data.outbounds
          : []
        ).map((runtimeOutbound) => [runtimeOutbound.tag, runtimeOutbound])
      ),
    [runtimeOutboundsQuery.data]
  )
  const runtimeInterfaceByName = useMemo(
    () =>
      new Map(
        (runtimeInterfacesQuery.data?.status === 200
          ? runtimeInterfacesQuery.data.data.interfaces
          : []
        ).map((runtimeInterface) => [runtimeInterface.name, runtimeInterface])
      ),
    [runtimeInterfacesQuery.data]
  )
  const outboundItems = useMemo(
    () =>
      selectOutbounds(loadedConfig).map((outbound) =>
        mapOutboundToItem(
          outbound,
          runtimeOutboundByTag.get(outbound.tag),
          runtimeInterfaceByName.get(outbound.interface ?? "")
        )
      ),
    [loadedConfig, runtimeOutboundByTag, runtimeInterfaceByName]
  )
  const outboundDisplayNames = useMemo(
    () => createOutboundDisplayNameMap(selectOutbounds(loadedConfig)),
    [loadedConfig]
  )
  const dependencyTargets = useMemo(
    () =>
      outboundItems.map((item) => ({
        kind: "outbound" as const,
        id: item.id,
      })),
    [outboundItems]
  )
  const dependencyAnalysis = useConfigDependencies(
    loadedConfig,
    dependencyTargets
  )
  const dependenciesByTag = useMemo(
    () =>
      new Map(
        outboundItems.map((item) => [
          item.id,
          dependencyAnalysis.dependenciesByTarget.get(`outbound:${item.id}`) ??
            [],
        ])
      ),
    [dependencyAnalysis.dependenciesByTarget, outboundItems]
  )
  const brokenReferences = useMemo(
    () =>
      findBrokenReferences(loadedConfig, {
        missingList: (values) =>
          t("common.dependencies.brokenReference.missingList", values),
        listDetour: (values) =>
          t("common.dependencies.brokenReference.listDetour", values),
        listRefresh: (values) =>
          t("common.dependencies.brokenReference.listRefresh", values),
      }),
    [loadedConfig, t]
  )
  // Сколько правил ведёт в это направление и сколько списков через них
  // проходит. Это единственное, чего в прежней таблице не было совсем, а
  // именно оно отвечает на вопрос «можно ли это удалить».
  // Проверка задержки бьёт по всем точкам выхода разом: у демона одна
  // общая проверка, отдельной «проверь только этот» не существует.
  const probeMutation = useRunSystemProbes()
  const { protocolOf, protocolOfGroup } = useInterfaceProtocols()
  // Тег группы резервирования складывается из тегов её участников, а те
  // известны только по их собственным outbound: отсюда поиск интерфейса
  // по имени участника.
  const interfaceOfTag = (tag: string) =>
    selectOutbounds(loadedConfig).find((item) => item.tag === tag)?.interface ??
    ""

  // Grouped so the page reads as "what carries traffic" first, then failover
  // groups, then the plumbing, instead of one undifferentiated list.
  const outboundGroups: Array<{
    key: OutboundGroupKey
    items: OutboundItem[]
  }> = [
    {
      key: "interfaces" as const,
      items: outboundItems.filter((item) => item.type === "interface"),
    },
    {
      key: "failover" as const,
      items: outboundItems.filter((item) => item.type === "urltest"),
    },
    {
      key: "system" as const,
      items: outboundItems.filter(
        (item) => item.type !== "interface" && item.type !== "urltest"
      ),
    },
  ]
  const outboundTabs: SectionTab<OutboundGroupKey>[] = outboundGroups.map(
    (group) => ({
      value: group.key,
      label: t(`pages.outbounds.groups.${group.key}`),
      count: group.items.length,
    })
  )
  const [hashGroupKey, setHashGroupKey] = useSectionTab<OutboundGroupKey>(
    ["interfaces", "failover", "system"],
    "interfaces"
  )
  const activeGroupKey = group ?? hashGroupKey
  const setActiveGroupKey = setHashGroupKey
  const activeOutboundGroup =
    outboundGroups.find((group) => group.key === activeGroupKey) ??
    outboundGroups[0]
  // Сортировка по названию и по задержке. Задержка — единственное число на
  // странице, и вопрос «какой выход быстрее» без неё решался глазами по
  // разбросанным карточкам.
  // Колонки у вкладок разные, поэтому и индекс колонки «Состояние» разный:
  // у туннелей она вторая, у резервирования третья, у системных маршрутов её
  // нет вовсе — там нечего измерять.
  const latencyColumnIndex =
    activeGroupKey === "interfaces" ? 1 : activeGroupKey === "failover" ? 2 : -1
  const { sorted: sortedOutbounds, sort } = useTableSort(
    activeOutboundGroup.items,
    [
      { index: 0, get: (item) => getOutboundDisplayName(item.outbound) },
      ...(latencyColumnIndex >= 0
        ? [
            {
              index: latencyColumnIndex,
              get: (item: OutboundItem) => firstLatency(item.runtimeState),
            },
          ]
        : []),
    ]
  )
  // Судить об отсутствии интерфейса можно только когда список интерфейсов
  // действительно приехал: пока запрос не ответил, карта пуста, и без этой
  // проверки «интерфейс не найден» показалось бы у всех сразу.
  const runtimeInterfacesKnown =
    runtimeInterfacesQuery.data?.status === 200 &&
    runtimeInterfaceByName.size > 0
  const isInterfaceMissing = (item: OutboundItem) =>
    runtimeInterfacesKnown &&
    item.outbound.type === "interface" &&
    typeof item.outbound.interface === "string" &&
    item.outbound.interface.length > 0 &&
    !runtimeInterfaceByName.has(item.outbound.interface)

  // Маршрут, чей интерфейс из системы исчез, — не «ещё один в списке», а
  // единственная причина, по которой в таблице два «sddvpn mooo VLESS».
  // Демон по обоим отдаёт healthy: он проверяет свою табличную часть, а не
  // наличие интерфейса. Значит, различать их должна страница.
  const brokenOutbounds = sortedOutbounds.filter((item) =>
    isInterfaceMissing(item)
  )
  const workingOutbounds = sortedOutbounds.filter(
    (item) => !isInterfaceMissing(item)
  )
  // Порядок строк один, таблица одна: две таблицы считали бы ширину колонок
  // каждая по своему содержимому, и «Название» вверху оказывалось заметно уже,
  // чем внизу.
  const orderedOutbounds =
    brokenOutbounds.length > 0
      ? [...workingOutbounds, ...brokenOutbounds]
      : sortedOutbounds
  const outboundGroupHeadings =
    brokenOutbounds.length > 0
      ? {
          0: (
            <SectionHeading
              size="compact"
              title={t("pages.outbounds.split.working")}
            />
          ),
          [workingOutbounds.length]: (
            <SectionHeading
              description={t("pages.outbounds.split.brokenDescription")}
              size="compact"
              title={t("pages.outbounds.split.broken")}
              tone="destructive"
            />
          ),
        }
      : undefined

  const systemGroupActive = activeGroupKey === "system"
  const outboundRowIds = orderedOutbounds.map((item) => item.id)
  const outboundSelection = useRowSelection(outboundRowIds)
  // Одна таблица, но с подзаголовком перед мёртвыми маршрутами. Разделять
  // именно так, а не сортировкой: два маршрута с одинаковым названием стоят
  // рядом и отличаются только красной точкой, а под разными заголовками
  // путать их уже нечем.
  const renderOutboundTable = (items: OutboundItem[]) => (
    <DataTable
      groupHeadings={outboundGroupHeadings}
      headers={[
        t("pages.outbounds.headers.tag"),
        ...(activeGroupKey === "failover"
          ? [t("pages.outbounds.headers.memberChain")]
          : []),
        ...(activeGroupKey === "system"
          ? [t("pages.outbounds.headers.purpose")]
          : [t("pages.outbounds.headers.runtime")]),
        t("pages.outbounds.headers.usedBy"),
        t("pages.outbounds.headers.actions"),
      ]}
      narrowColumns={latencyColumnIndex >= 0 ? [latencyColumnIndex] : []}
      rows={items.map((item) => [
        <OutboundName
          key={`${item.id}-name`}
          outbound={item.outbound}
          protocol={
            item.outbound.type === "urltest"
              ? protocolOfGroup(item.outbound, interfaceOfTag)
              : protocolOf(item.outbound.interface ?? "")
          }
          withInterface={activeGroupKey === "interfaces"}
        />,
        ...(activeGroupKey === "failover"
          ? [
              <OutboundMemberChain
                key={`${item.id}-chain`}
                outboundDisplayNames={outboundDisplayNames}
                runtimeState={item.runtimeState}
              />,
            ]
          : []),
        activeGroupKey === "system" ? (
          <OutboundPurpose
            key={`${item.id}-purpose`}
            outbound={item.outbound}
          />
        ) : (
          <OutboundStatus
            interfaceMissing={isInterfaceMissing(item)}
            key={`${item.id}-status`}
            runtimeState={item.runtimeState}
          />
        ),
        // Связи видно до удаления, а не из диалога, который перечислял
        // последствия постфактум.
        <DependencyList
          compact
          dependencies={dependenciesByTag.get(item.id) ?? []}
          emptyHint={t("pages.outbounds.usage.none")}
          key={`${item.id}-usage`}
        />,
        <ActionButtons
          actions={[
            {
              // Проверка задержки бьёт по всем выходам разом: у демона
              // одна общая проверка, отдельной «проверь только этот»
              // не существует.
              disabled: probeMutation.isPending,
              icon: (
                <RotateCw
                  className={cn(
                    "h-4 w-4",
                    probeMutation.isPending && "animate-spin"
                  )}
                />
              ),
              label: t("transports.latencyRefresh"),
              onClick: () => probeMutation.mutate(),
            },
            {
              icon: <KeenPencilIcon className="h-4 w-4" />,
              label: t("common.edit"),
              onClick: () => navigate(`/outbounds/${item.id}/edit`),
            },
          ]}
          key={`${item.id}-actions`}
        />,
      ])}
      // Системные маршруты выбирать нечем: удаление здесь — единственная
      // операция над выделением, а удалять их нельзя. Отключённые галочки
      // выглядели бы как «пока нельзя», хотя нельзя всегда.
      selection={
        systemGroupActive
          ? undefined
          : {
              rowIds: items.map((entry) => entry.id),
              selectedIds: outboundSelection.selectedIds,
              disabled: configMutationPending,
              onToggle: outboundSelection.toggleOne,
              onToggleAll: outboundSelection.setAllVisible,
              selectAllLabel: t("common.selection.selectAll"),
              getRowLabel: (rowId) =>
                t("common.selection.selectRow", {
                  rowLabel: outboundDisplayNames.get(rowId) ?? rowId,
                }),
            }
      }
      sort={sort}
    />
  )

  const changeActiveGroup = (nextGroup: OutboundGroupKey) => {
    outboundSelection.clear()
    setActiveGroupKey(nextGroup)
  }

  const postConfigMutation = usePostConfigMutation({
    mutation: {
      onSuccess: async () => {
        // success — nothing to show here (toasts handled on error)
        await Promise.all([
          queryClient.invalidateQueries({ queryKey: queryKeys.config() }),
          queryClient.invalidateQueries({
            queryKey: queryKeys.healthService(),
          }),
          queryClient.invalidateQueries({
            queryKey: queryKeys.healthRouting(),
          }),
          queryClient.invalidateQueries({
            queryKey: queryKeys.runtimeOutbounds(),
          }),
        ])
      },
      onError: (error) => {
        toast.error(getApiErrorMessage(error as ApiError), {
          richColors: true,
        })
      },
    },
  })

  const handleBulkDelete = () => {
    if (!loadedConfig || outboundSelection.selectedCount === 0) {
      return
    }

    const tags = filterDeletableOutboundTags(
      loadedConfig,
      outboundSelection.selectedIds
    )
    if (tags.length === 0) {
      return
    }
    const request = {
      tags,
      impact: getOutboundDeleteImpact(loadedConfig, tags),
      config: loadedConfig,
      clearSelectionOnSuccess: true,
    }
    setDeletePreview(request)
    setDeleteRequest(request)
  }

  const confirmDelete = () => {
    if (!loadedConfig || !deleteRequest) {
      return
    }

    postConfigMutation.mutate(
      {
        data: buildUpdatedConfigForOutboundsDelete(
          loadedConfig,
          deleteRequest.tags
        ),
      },
      {
        onSuccess: () => {
          if (deleteRequest.clearSelectionOnSuccess) {
            outboundSelection.clear()
          }
          setDeleteRequest(null)
        },
      }
    )
  }

  return (
    <div className="space-y-3">
      {embedded ? null : (
        <PageHeader
          description={t("pages.outbounds.description")}
          title={t("pages.outbounds.title")}
        />
      )}
      <PageActionBar
        primary={
          <Button
            disabled={configMutationPending}
            onClick={() => navigate("/outbounds/create")}
          >
            <Plus className="mr-1 h-4 w-4" />
            {t("pages.outbounds.actions.new")}
          </Button>
        }
      >
        <ConfigTransferButtons
          config={loadedConfig}
          disabled={configMutationPending}
          kind="outbounds"
          onImport={(nextConfig) =>
            postConfigMutation.mutate({ data: nextConfig })
          }
        />
      </PageActionBar>

      <ConfigSaveErrorAlert error={postConfigMutation.error} />

      {brokenReferences.length > 0 ? (
        <Alert variant="warning">
          <AlertTitle>{t("pages.outbounds.brokenReferences.title")}</AlertTitle>
          <AlertDescription className="flex flex-wrap gap-x-3 gap-y-1">
            {brokenReferences.map((reference) => (
              <a
                className="underline underline-offset-2"
                href={reference.href}
                key={reference.id}
              >
                {reference.label}
              </a>
            ))}
          </AlertDescription>
        </Alert>
      ) : null}

      {configQuery.isLoading ? (
        <TableSkeleton />
      ) : configQuery.isError ? (
        <ListPlaceholder
          description={t("common.loadErrorDescription")}
          title={t("common.unableToLoadData")}
          variant="error"
        />
      ) : outboundItems.length === 0 ? (
        <ListPlaceholder
          description={t("pages.outbounds.empty.description")}
          title={t("pages.outbounds.empty.title")}
        />
      ) : (
        <div className="space-y-3">
          {group ? null : (
            <SectionTabs
              ariaLabel={t("pages.outbounds.tabs.ariaLabel")}
              onValueChange={changeActiveGroup}
              tabs={outboundTabs}
              value={activeGroupKey}
            />
          )}
          <div className="relative h-0">
            {outboundSelection.hasSelection ? (
              <BulkSelectionToolbar
                countLabel={t("pages.outbounds.bulk.selected", {
                  count: outboundSelection.selectedCount,
                })}
              >
                <Button
                  disabled={configMutationPending}
                  onClick={handleBulkDelete}
                  size="sm"
                  variant="destructive"
                >
                  <KeenTrashIcon className="mr-1 h-4 w-4" />
                  {t("pages.outbounds.bulk.delete")}
                </Button>
              </BulkSelectionToolbar>
            ) : null}
          </div>
          {activeOutboundGroup.items.length === 0 ? (
            <ListPlaceholder
              description={t(
                `pages.outbounds.groupsEmpty.${activeOutboundGroup.key}`
              )}
              title={t(`pages.outbounds.groups.${activeOutboundGroup.key}`)}
            />
          ) : (
            renderOutboundTable(orderedOutbounds)
          )}
        </div>
      )}
      <DeleteImpactDialog
        confirmLabel={t("pages.outbounds.deleteDialog.confirm")}
        description={t("pages.outbounds.deleteDialog.description", {
          tags: visibleDeleteRequest?.tags.join(", ") ?? "",
        })}
        impactItems={
          visibleDeleteRequest
            ? getOutboundDeleteImpactItems(
                visibleDeleteRequest.config,
                visibleDeleteRequest.tags,
                visibleDeleteRequest.impact,
                t
              )
            : []
        }
        isPending={postConfigMutation.isPending}
        onConfirm={confirmDelete}
        onOpenChange={(open) => {
          if (!open && !postConfigMutation.isPending) {
            setDeleteRequest(null)
          }
        }}
        open={deleteRequest !== null}
        title={t("pages.outbounds.deleteDialog.title")}
      />
    </div>
  )
}

function getOutboundDeleteImpactItems(
  config: ConfigObject | undefined,
  requestedTags: string[],
  impact: OutboundDeleteImpact,
  t: (key: string, options?: Record<string, unknown>) => string
) {
  const items: DeleteImpactItem[] = []
  const requestedTagSet = new Set(requestedTags)
  const outboundNames = createOutboundDisplayNameMap(config?.outbounds ?? [])
  const dnsServerNames = createDnsServerDisplayNameMap(
    config?.dns?.servers ?? []
  )

  for (const tag of requestedTags) {
    const outbound = config?.outbounds?.find((item) => item.tag === tag)
    items.push({
      label: (
        <>
          {t("pages.outbounds.deleteDialog.items.outboundPrefix")}{" "}
          <strong>{outbound ? getOutboundDisplayName(outbound) : tag}</strong>{" "}
          {t("pages.outbounds.deleteDialog.items.outboundSuffix")}
        </>
      ),
    })
  }

  for (const tag of impact.deletedOutboundTags) {
    if (requestedTagSet.has(tag)) {
      continue
    }

    const outbound = config?.outbounds?.find((item) => item.tag === tag)
    items.push({
      label: (
        <>
          {t("pages.outbounds.deleteDialog.items.dependentOutboundPrefix")}{" "}
          <strong>{outbound ? getOutboundDisplayName(outbound) : tag}</strong>{" "}
          {t("pages.outbounds.deleteDialog.items.dependentOutboundSuffix")}
        </>
      ),
    })
  }

  for (const index of impact.routeRuleIndexes) {
    const rule = config?.route?.rules?.[index]
    items.push({
      label: t("pages.outbounds.deleteDialog.items.routingRule", {
        name: rule ? getRouteRuleDisplayName(rule, index) : `#${index + 1}`,
      }),
      details: getRouteRuleImpactDetails(
        rule,
        config?.lists,
        config?.outbounds,
        t
      ),
    })
  }

  for (const server of impact.dnsServerDetours) {
    const dnsServer = config?.dns?.servers?.find((item) => item.tag === server)
    items.push({
      label: t("pages.outbounds.deleteDialog.items.dnsDetour", {
        server: dnsServer
          ? getDnsServerDisplayName(dnsServer)
          : (dnsServerNames.get(server) ?? server),
      }),
      details: [
        formatDetail(
          t("pages.dnsServers.headers.outbound"),
          formatValueTransition(
            outboundNames.get(dnsServer?.detour ?? "") ??
              dnsServer?.detour ??
              t("common.noneShort"),
            t("common.noneShort")
          )
        ),
      ],
    })
  }

  for (const listRoute of impact.listDownloadRoutes) {
    items.push({
      label: t("pages.outbounds.deleteDialog.items.listDownloadRoutes", {
        list: getListReferenceLabel(listRoute.listName, config?.lists),
      }),
      details: [
        formatDetail(
          t("pages.outbounds.deleteDialog.items.downloadRoutes"),
          formatTransition(listRoute.before, listRoute.after, t, outboundNames)
        ),
      ],
    })
  }

  if (impact.globalListRefreshRoute) {
    items.push({
      label: t("pages.outbounds.deleteDialog.items.globalListRefreshRoutes"),
      details: [
        formatDetail(
          t("pages.outbounds.deleteDialog.items.downloadRoutes"),
          formatTransition(
            impact.globalListRefreshRoute.before,
            impact.globalListRefreshRoute.after,
            t,
            outboundNames
          )
        ),
      ],
    })
  }

  for (const membership of impact.urltestMemberships) {
    const group = config?.outbounds?.find(
      (outbound) => outbound.tag === membership.outboundTag
    )?.outbound_groups?.[membership.groupIndex]
    const remainingTags =
      group?.outbounds.filter(
        (tag) => !impact.deletedOutboundTags.includes(tag)
      ) ?? []
    const isRemoved = remainingTags.length === 0

    items.push({
      label: isRemoved
        ? t("pages.outbounds.deleteDialog.items.urltestGroupRemoved", {
            group: membership.groupIndex + 1,
            outbound:
              outboundNames.get(membership.outboundTag) ??
              membership.outboundTag,
          })
        : t("pages.outbounds.deleteDialog.items.urltestGroupChanged", {
            group: membership.groupIndex + 1,
            outbound:
              outboundNames.get(membership.outboundTag) ??
              membership.outboundTag,
          }),
      details: [
        formatDetail(
          t("pages.outbounds.deleteDialog.items.groupOutbounds"),
          isRemoved
            ? formatListValue(group?.outbounds ?? [], t, outboundNames)
            : formatTransition(
                group?.outbounds ?? [],
                remainingTags,
                t,
                outboundNames
              )
        ),
      ],
    })
  }

  return items
}

function getRouteRuleImpactDetails(
  rule: RouteRule | undefined,
  lists: ConfigObject["lists"],
  outbounds: Outbound[] | undefined,
  t: (key: string, options?: Record<string, unknown>) => string
) {
  if (!rule) {
    return []
  }

  const details = [
    {
      label: t("pages.routingRules.headers.outbound"),
      value:
        outbounds?.find((outbound) => outbound.tag === rule.outbound)
          ?.display_name ?? rule.outbound,
    },
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
  ]
    .filter(
      (
        item
      ): item is {
        label: string
        value: string
      } => typeof item.value === "string" && item.value.trim().length > 0
    )
    .map((item) =>
      t("pages.outbounds.deleteDialog.items.ruleDetail", {
        label: item.label,
        value: item.value,
      })
    )

  return details
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
  t: (key: string, options?: Record<string, unknown>) => string,
  displayNames?: ReadonlyMap<string, string>
) {
  return formatValueTransition(
    formatListValue(before, t, displayNames),
    formatListValue(after, t, displayNames)
  )
}

function formatValueTransition(before: string, after: string) {
  return <ChangeValue after={after} before={before} />
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
  t: (key: string, options?: Record<string, unknown>) => string,
  displayNames?: ReadonlyMap<string, string>
) {
  return values.length > 0
    ? values.map((value) => displayNames?.get(value) ?? value).join(", ")
    : t("common.noneShort")
}

function mapOutboundToItem(
  outbound: Outbound,
  runtimeState: RuntimeOutboundState | undefined,
  runtimeInterface: RuntimeInterfaceInventoryEntry | undefined
): OutboundItem {
  return {
    id: outbound.tag,
    tag: outbound.tag,
    type: outbound.type,
    outbound,
    runtimeInterface,
    runtimeState,
  }
}
