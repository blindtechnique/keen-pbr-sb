import { ArrowRight, Plus, Trash2 } from "lucide-react"
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
import { BulkSelectionToolbar } from "@/components/shared/bulk-selection-toolbar"
import { ConfigSaveErrorAlert } from "@/components/shared/config-save-error-alert"
import { ConfigTransferButtons } from "@/components/shared/config-transfer-buttons"
import { OutboundCard } from "@/components/outbounds/outbound-card"
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
import { PageActionBar } from "@/components/shared/page-action-bar"
import { TableSkeleton } from "@/components/shared/table-skeleton"
import { useRowSelection } from "@/hooks/use-row-selection"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { getApiErrorMessage } from "@/lib/api-errors"
import {
  buildUpdatedConfigForOutboundsDelete,
  getOutboundDeleteImpact,
  type OutboundDeleteImpact,
} from "@/pages/outbounds-utils"
import { OutboundCreateDialog } from "@/pages/outbound-upsert-page"

type OutboundItem = {
  id: string
  tag: string
  type: Outbound["type"]
  summary: ReactNode
  outbound: Outbound
  runtimeInterface?: RuntimeInterfaceInventoryEntry
  runtimeState?: RuntimeOutboundState
}

export function OutboundsPage() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [, navigate] = useLocation()
  const [createOpen, setCreateOpen] = useState(false)
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
          runtimeInterfaceByName.get(outbound.interface ?? ""),
          t
        )
      ),
    [loadedConfig, runtimeOutboundByTag, runtimeInterfaceByName, t]
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
    () => findBrokenReferences(loadedConfig),
    [loadedConfig]
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

  const outboundRowIds = outboundItems.map((outbound) => outbound.id)
  const outboundSelection = useRowSelection(outboundRowIds)
  // Grouped so the page reads as "what carries traffic" first, then failover
  // groups, then the plumbing, instead of one undifferentiated list.
  const outboundGroups = [
    {
      key: "interfaces",
      items: outboundItems.filter((item) => item.type === "interface"),
    },
    {
      key: "failover",
      items: outboundItems.filter((item) => item.type === "urltest"),
    },
    {
      key: "system",
      items: outboundItems.filter(
        (item) => item.type !== "interface" && item.type !== "urltest"
      ),
    },
  ].filter((group) => group.items.length > 0)

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

    const tags = [...outboundSelection.selectedIds]
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
      <PageHeader
        description={t("pages.outbounds.description")}
        title={t("pages.outbounds.title")}
      />
      <PageActionBar>
        <ConfigTransferButtons
          config={loadedConfig}
          disabled={configMutationPending}
          kind="outbounds"
          onImport={(nextConfig) =>
            postConfigMutation.mutate({ data: nextConfig })
          }
        />
        <Button
          disabled={configMutationPending}
          onClick={() => setCreateOpen(true)}
        >
          <Plus className="mr-1 h-4 w-4" />
          {t("pages.outbounds.actions.new")}
        </Button>
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
                  <Trash2 className="mr-1 h-4 w-4" />
                  {t("pages.outbounds.bulk.delete")}
                </Button>
              </BulkSelectionToolbar>
            ) : null}
          </div>
          {outboundGroups.map((group) => (
            <div className="space-y-2" key={group.key}>
              <h2 className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">
                {t(`pages.outbounds.groups.${group.key}`)}
              </h2>
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                {group.items.map((item) => (
                  <OutboundCard
                    key={item.id}
                    onEdit={() => navigate(`/outbounds/${item.id}/edit`)}
                    onToggleSelected={() =>
                      outboundSelection.toggleOne(item.id)
                    }
                    outbound={item.outbound}
                    protocol={
                      item.outbound.type === "urltest"
                        ? protocolOfGroup(item.outbound, interfaceOfTag)
                        : protocolOf(item.outbound.interface ?? "")
                    }
                    runtimeState={item.runtimeState}
                    selectLabel={t("common.selection.selectRow", {
                      rowLabel: item.id,
                    })}
                    selected={outboundSelection.selectedIds.has(item.id)}
                    dependencies={dependenciesByTag.get(item.id) ?? []}
                    onRefreshLatency={() => probeMutation.mutate()}
                    refreshingLatency={probeMutation.isPending}
                    selectionDisabled={configMutationPending}
                  />
                ))}
              </div>
            </div>
          ))}
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
      <OutboundCreateDialog onOpenChange={setCreateOpen} open={createOpen} />
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

  for (const tag of requestedTags) {
    items.push({
      label: (
        <>
          {t("pages.outbounds.deleteDialog.items.outboundPrefix")}{" "}
          <strong>{tag}</strong>{" "}
          {t("pages.outbounds.deleteDialog.items.outboundSuffix")}
        </>
      ),
    })
  }

  for (const tag of impact.deletedOutboundTags) {
    if (requestedTagSet.has(tag)) {
      continue
    }

    items.push({
      label: (
        <>
          {t("pages.outbounds.deleteDialog.items.dependentOutboundPrefix")}{" "}
          <strong>{tag}</strong>{" "}
          {t("pages.outbounds.deleteDialog.items.dependentOutboundSuffix")}
        </>
      ),
    })
  }

  for (const index of impact.routeRuleIndexes) {
    items.push({
      label: t("pages.outbounds.deleteDialog.items.routingRule", {
        number: index + 1,
      }),
      details: getRouteRuleImpactDetails(config?.route?.rules?.[index], t),
    })
  }

  for (const server of impact.dnsServerDetours) {
    items.push({
      label: t("pages.outbounds.deleteDialog.items.dnsDetour", { server }),
      details: [
        formatDetail(
          t("pages.dnsServers.headers.outbound"),
          formatValueTransition(
            config?.dns?.servers?.find((item) => item.tag === server)?.detour ??
              t("common.noneShort"),
            t("common.noneShort")
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
            outbound: membership.outboundTag,
          })
        : t("pages.outbounds.deleteDialog.items.urltestGroupChanged", {
            group: membership.groupIndex + 1,
            outbound: membership.outboundTag,
          }),
      details: [
        formatDetail(
          t("pages.outbounds.deleteDialog.items.groupOutbounds"),
          isRemoved
            ? formatListValue(group?.outbounds ?? [], t)
            : formatTransition(group?.outbounds ?? [], remainingTags, t)
        ),
      ],
    })
  }

  return items
}

function getRouteRuleImpactDetails(
  rule: RouteRule | undefined,
  t: (key: string, options?: Record<string, unknown>) => string
) {
  if (!rule) {
    return []
  }

  const details = [
    {
      label: t("pages.routingRules.headers.outbound"),
      value: rule.outbound,
    },
    {
      label: t("pages.routingRules.criteriaLabels.lists"),
      value: (rule.list ?? []).join(", "),
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
  t: (key: string, options?: Record<string, unknown>) => string
) {
  return formatValueTransition(
    formatListValue(before, t),
    formatListValue(after, t)
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
  t: (key: string, options?: Record<string, unknown>) => string
) {
  return values.length > 0 ? values.join(", ") : t("common.noneShort")
}

function mapOutboundToItem(
  outbound: Outbound,
  runtimeState: RuntimeOutboundState | undefined,
  runtimeInterface: RuntimeInterfaceInventoryEntry | undefined,
  t: (key: string, options?: Record<string, unknown>) => string
): OutboundItem {
  return {
    id: outbound.tag,
    tag: outbound.tag,
    type: outbound.type,
    summary: getOutboundSummary(outbound, t),
    outbound,
    runtimeInterface,
    runtimeState,
  }
}

function getOutboundSummary(
  outbound: Outbound,
  t: (key: string, options?: Record<string, unknown>) => string
): ReactNode {
  if (outbound.type === "interface") {
    return t("pages.outbounds.summary.interface", {
      value: outbound.interface ?? "-",
    })
  }

  if (outbound.type === "table") {
    return t("pages.outbounds.summary.table", {
      value: outbound.table ?? "-",
    })
  }

  if (outbound.type === "urltest") {
    const allOutbounds =
      outbound.outbound_groups?.flatMap((group) => group.outbounds) ?? []
    return t("pages.outbounds.summary.urltest", {
      value: allOutbounds.join(","),
    })
  }

  return t("common.noneShort")
}
