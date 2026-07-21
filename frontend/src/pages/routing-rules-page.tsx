import { Pencil, Plus, Trash2 } from "lucide-react"
import { useMemo } from "react"
import { useTranslation } from "react-i18next"
import { useLocation } from "wouter"

import type { ApiError } from "@/api/client"
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
import { SortableCards } from "@/components/shared/sortable-cards"
import { ListPlaceholder } from "@/components/shared/list-placeholder"
import { PageHeader } from "@/components/shared/page-header"
import { RuntimeOutboundEntry } from "@/components/shared/runtime-outbound-state"
import { TableSkeleton } from "@/components/shared/table-skeleton"
import { useRowSelection } from "@/hooks/use-row-selection"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import {
  getApiErrorMessage,
  reorderRules,
  setRouteRuleEnabled,
} from "@/pages/routing-rules-utils"

export function RoutingRulesPage() {
  const { t } = useTranslation()
  const [, navigate] = useLocation()

  const configMutationPending = useConfigMutationPending()
  const configQuery = useGetConfig()
  const loadedConfig = selectConfig(configQuery.data)
  const routeRules = loadedConfig?.route?.rules ?? []
  const ruleRowIds = routeRules.map((_rule, index) => String(index))
  const ruleSelection = useRowSelection(ruleRowIds)
  const runtimeOutboundsQuery = useGetRuntimeOutbounds({
    query: {
      refetchInterval: 10_000,
      refetchIntervalInBackground: false,
    },
  })
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

  const tableRows = routeRules.map((rule: RouteRule, index: number) => {
    const runtimeState = runtimeOutboundByTag.get(rule.outbound)
    return getRouteRuleRow(rule, index, t, runtimeState)
  })

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

  const persistRules = (
    config: NonNullable<typeof loadedConfig>,
    nextRules: RouteRule[],
    options?: { clearSelection?: boolean }
  ) => {
    postConfigMutation.mutate(
      {
        data: {
          ...config,
          route: {
            ...config.route,
            rules: nextRules,
          },
        },
      },
      options?.clearSelection
        ? {
            onSuccess: () => {
              ruleSelection.clear()
            },
          }
        : undefined
    )
  }

  const handleReorder = (fromIndex: number, toIndex: number) => {
    if (!loadedConfig) {
      return
    }
    if (
      fromIndex === toIndex ||
      toIndex < 0 ||
      toIndex >= routeRules.length
    ) {
      return
    }

    const nextRules = reorderRules(routeRules, fromIndex, toIndex)
    persistRules(loadedConfig, nextRules)
  }

  const handleEnabledChange = (index: number, enabled: boolean) => {
    if (!loadedConfig) {
      return
    }

    persistRules(loadedConfig, setRouteRuleEnabled(routeRules, index, enabled))
  }

  const handleBulkDelete = () => {
    if (!loadedConfig || ruleSelection.selectedCount === 0) {
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
      (_rule, index) => !ruleSelection.selectedIds.has(String(index))
    )
    persistRules(loadedConfig, nextRules, { clearSelection: true })
  }

  const handleBulkSetEnabled = (enabled: boolean) => {
    if (!loadedConfig || ruleSelection.selectedCount === 0) {
      return
    }

    const nextRules = routeRules.map((rule, index) =>
      ruleSelection.selectedIds.has(String(index)) ? { ...rule, enabled } : rule
    )
    persistRules(loadedConfig, nextRules)
  }

  return (
    <div className="space-y-3">
      <PageHeader
        actions={
          <div className="flex flex-wrap justify-end gap-2">
            <ConfigTransferButtons
              config={loadedConfig}
              disabled={configMutationPending}
              kind="routing-rules"
              onImport={(nextConfig) =>
                postConfigMutation.mutate({ data: nextConfig })
              }
            />
            <Button
              disabled={configMutationPending}
              onClick={() => navigate("/routing-rules/create")}
            >
              <Plus className="mr-1 h-4 w-4" />
              {t("pages.routingRules.actions.addRule")}
            </Button>
          </div>
        }
        description={t("pages.routingRules.description")}
        title={t("pages.routingRules.title")}
      />

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
          description={t("pages.routingRules.empty.description")}
          title={t("pages.routingRules.empty.title")}
        />
      ) : (
        <div className="space-y-3">
          {/* The toolbar shares a fixed-height slot so selecting a rule does not
              push the whole table down. */}
          <div className="relative h-0">
            {ruleSelection.hasSelection ? (
            <BulkSelectionToolbar
              countLabel={t("pages.routingRules.bulk.selected", {
                count: ruleSelection.selectedCount,
              })}
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
          {/* На телефоне таблица разворачивается в столбик подписей и
              читается как каша, а строки не перетаскиваются: HTML5-drag
              на сенсорных экранах не работает. Поэтому там своя раскладка
              карточками и своё перетаскивание на pointer-событиях. */}
          <div className="md:hidden">
            <SortableCards
              disabled={configMutationPending}
              getKey={(row) => row.id}
              handleLabel={t("pages.routingRules.actions.reorder")}
              items={tableRows}
              onReorder={handleReorder}
              renderCard={(row) => (
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">#{row.order}</span>
                    <span className="truncate text-sm text-muted-foreground">
                      → {row.outbound}
                    </span>
                    <span className="ml-auto flex items-center gap-1">
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
                        onClick={() =>
                          navigate(`/routing-rules/${row.index}/edit`)
                        }
                        size="icon"
                        variant="ghost"
                      >
                        <Pencil className="size-4" />
                      </Button>
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-1">
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
            headers={[
              "",
              t("pages.routingRules.headers.order"),
              t("pages.routingRules.headers.criteria"),
              t("pages.routingRules.headers.outbound"),
              t("pages.routingRules.headers.actions"),
            ]}
            narrowColumns={[0, 1]}
            reorder={{
              disabled: configMutationPending,
              handleLabel: t("pages.routingRules.actions.reorder"),
              onReorder: handleReorder,
            }}
            rows={tableRows.map((row: ReturnType<typeof getRouteRuleRow>) => [
              <div className="flex items-center" key={`${row.id}-enabled`}>
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
                  title={t(
                    row.enabled
                      ? "pages.routingRules.actions.disableRule"
                      : "pages.routingRules.actions.enableRule"
                  )}
                />
              </div>,
              <span className="font-medium" key={`${row.id}-order`}>
                #{row.order}
              </span>,
              <ul
                className="list-disc space-y-1 pl-5 text-sm"
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
              <div key={`${row.id}-outbound`}>
                <RuntimeOutboundEntry
                  runtimeState={row.runtimeState}
                  title={row.outbound}
                  t={t}
                />
              </div>,
              <ActionButtons
                actions={[
                  {
                    disabled: configMutationPending,
                    icon: <Pencil className="h-4 w-4" />,
                    label: t("common.edit"),
                    onClick: () => navigate(`/routing-rules/${row.index}/edit`),
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
                  rowLabel: `${t("pages.routingRules.title")} #${Number(rowId) + 1}`,
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
  runtimeState?: RuntimeOutboundState
) {
  const conditions = [
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
    id: `routing-rule-${index}`,
    enabled: rule.enabled ?? true,
    index,
    order: index + 1,
    conditions,
    outbound: rule.outbound,
    runtimeState,
  }
}
