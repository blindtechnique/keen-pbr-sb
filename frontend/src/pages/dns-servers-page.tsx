import { Plus, Save } from "lucide-react"
import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import { useLocation } from "wouter"

import type { getConfigResponse } from "@/api/generated/keen-api"
import type { ConfigObject } from "@/api/generated/model/configObject"
import { DnsServerType } from "@/api/generated/model/dnsServerType"
import {
  useConfigMutationPending,
  usePostConfigMutation,
} from "@/api/mutations"
import { useGetConfig } from "@/api/queries"
import { KeenPencilIcon, KeenTrashIcon } from "@/components/shared/keen-icons"
import {
  formatDnsServerNames,
  getDnsServerDeleteImpactItems,
} from "@/components/delete-impact/dns-server-items"
import { ActionButtons } from "@/components/shared/action-buttons"
import { BulkSelectionToolbar } from "@/components/shared/bulk-selection-toolbar"
import { ConfigSaveErrorAlert } from "@/components/shared/config-save-error-alert"
import { FallbackServersField } from "@/components/dns/fallback-servers-field"
import { DataTable } from "@/components/shared/data-table"
import { SectionHeading } from "@/components/shared/section-heading"
import { TableSearch } from "@/components/shared/table-search"
import { DeleteImpactDialog } from "@/components/shared/delete-impact-dialog"
import { ListPlaceholder } from "@/components/shared/list-placeholder"
import { PageActionBar } from "@/components/shared/page-action-bar"
import { PageHeader } from "@/components/shared/page-header"
import { TableSkeleton } from "@/components/shared/table-skeleton"
import { useRowSelection } from "@/hooks/use-row-selection"
import { useTableSort } from "@/hooks/use-table-sort"
import { filterBySearchQuery } from "@/lib/table-search"
import { useSemanticEditSession } from "@/hooks/use-semantic-edit-session"
import { createOutboundDisplayNameMap } from "@/lib/outbound-display"
import { semanticJsonEqual } from "@/lib/semantic-json"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { findDnsPresetByAddress } from "@/data/dns-presets"
import {
  buildUpdatedConfigForDnsServersDelete,
  getDnsServerDeleteImpact,
  type DnsServerDeleteImpact,
} from "@/pages/dns-servers-utils"

export function DnsServersPage() {
  const configQuery = useGetConfig()
  const config = getConfigData(configQuery.data)
  const fallback = config?.dns?.fallback ?? []
  const editorKey = config
    ? JSON.stringify(fallback)
    : configQuery.isError
      ? "error"
      : "loading"

  return (
    <DnsServersEditor
      config={config}
      configError={configQuery.isError}
      configLoading={configQuery.isLoading}
      key={editorKey}
    />
  )
}

function DnsServersEditor({
  config,
  configError,
  configLoading,
}: {
  config?: ConfigObject
  configError: boolean
  configLoading: boolean
}) {
  const { t } = useTranslation()
  const [, navigate] = useLocation()
  const [deleteRequest, setDeleteRequest] = useState<{
    tags: string[]
    impact: DnsServerDeleteImpact
    config: ConfigObject
    clearSelectionOnSuccess: boolean
  } | null>(null)
  const [deletePreview, setDeletePreview] = useState<typeof deleteRequest>(null)
  const configMutationPending = useConfigMutationPending()
  const postConfigMutation = usePostConfigMutation()
  const fallbackSession = useSemanticEditSession(
    config?.dns?.fallback ?? [],
    semanticJsonEqual
  )

  // The fallback chain lives here now: it is a property of the servers
  // themselves, not of the per-list rules.
  const handleFallbackChange = (fallback: string[]) => {
    fallbackSession.setValue(fallback)
  }
  const saveFallback = () => {
    if (!config || !fallbackSession.isDirty) {
      return
    }

    postConfigMutation.mutate(
      {
        data: {
          ...config,
          dns: { ...config.dns, fallback: fallbackSession.value },
        },
      },
      {
        onSuccess: () => {
          toast.success(t("pages.dnsServers.fallbackSaved"))
        },
      }
    )
  }
  const visibleDeleteRequest = deleteRequest ?? deletePreview
  const dnsServers = useMemo(() => config?.dns?.servers ?? [], [config])
  const outboundNames = useMemo(
    () => createOutboundDisplayNameMap(config?.outbounds ?? []),
    [config?.outbounds]
  )
  const [search, setSearch] = useState("")
  const visibleServers = filterBySearchQuery(dnsServers, search, (server) => [
    server.tag,
    server.address,
    findDnsPresetByAddress(server.address)?.name,
    server.detour,
  ])
  const { sorted: sortedServers, sort } = useTableSort(visibleServers, [
    {
      index: 0,
      get: (server) =>
        findDnsPresetByAddress(server.address)?.name ?? server.tag,
    },
    { index: 1, get: (server) => server.address },
  ])
  const serverRowIds = sortedServers.map((server) => server.tag)
  const serverSelection = useRowSelection(serverRowIds)

  const deleteServersBulk = () => {
    if (!config || serverSelection.selectedCount === 0) {
      return
    }

    const selectedTags = [...serverSelection.selectedIds]

    const request = {
      tags: selectedTags,
      impact: getDnsServerDeleteImpact(config, selectedTags),
      config,
      clearSelectionOnSuccess: true,
    }
    setDeletePreview(request)
    setDeleteRequest(request)
  }

  const confirmDelete = () => {
    if (!config || !deleteRequest) {
      return
    }

    const updatedConfig = buildUpdatedConfigForDnsServersDelete(
      config,
      deleteRequest.tags,
      true
    )

    postConfigMutation.mutate(
      { data: updatedConfig },
      {
        onSuccess: () => {
          if (deleteRequest.clearSelectionOnSuccess) {
            serverSelection.clear()
          }
          setDeleteRequest(null)
        },
      }
    )
  }

  return (
    <div className="space-y-3">
      <PageHeader
        description={t("pages.dnsServers.description")}
        title={t("pages.dnsServers.title")}
      />
      <PageActionBar
        primary={
          <Button
            disabled={configMutationPending || fallbackSession.isDirty}
            onClick={() => navigate("/dns-servers/create")}
          >
            <Plus className="mr-1 h-4 w-4" />
            {t("pages.dnsServers.actions.add")}
          </Button>
        }
        leading={
          dnsServers.length > 0 ? (
            <TableSearch
              matchCount={visibleServers.length}
              onChange={(next) => {
                setSearch(next)
                serverSelection.clear()
              }}
              placeholder={t("pages.dnsServers.searchPlaceholder")}
              totalCount={dnsServers.length}
              value={search}
            />
          ) : null
        }
      >
        {fallbackSession.isDirty ? (
          <>
            <Button
              disabled={configMutationPending}
              onClick={fallbackSession.reset}
              variant="ghost"
            >
              {t("common.cancel")}
            </Button>
            <Button disabled={configMutationPending} onClick={saveFallback}>
              <Save className="mr-1 h-4 w-4" />
              {postConfigMutation.isPending
                ? t("common.saving")
                : t("common.save")}
            </Button>
          </>
        ) : null}
      </PageActionBar>

      <ConfigSaveErrorAlert error={postConfigMutation.error} />

      {/* На странице два блока — резервная цепочка и сами серверы, — и ни у
          одного не было имени. Первый подписан своей меткой поля, у второго не
          было ничего: таблица начиналась сразу после чужого блока, и понять,
          где кончается одно и начинается другое, можно было только по рамке. */}
      {!configLoading && !configError ? (
        <div className="mb-4">
          <FallbackServersField
            config={
              config
                ? {
                    ...config,
                    dns: {
                      ...config.dns,
                      fallback: fallbackSession.value,
                    },
                  }
                : undefined
            }
            onChange={handleFallbackChange}
          />
        </div>
      ) : null}

      {configLoading ? (
        <TableSkeleton />
      ) : configError ? (
        <ListPlaceholder
          description={t("pages.dnsServers.loadErrorDescription")}
          title={t("common.unableToLoadData")}
          variant="error"
        />
      ) : dnsServers.length === 0 ? (
        <ListPlaceholder
          description={t("pages.dnsServers.empty.description")}
          title={t("pages.dnsServers.empty.title")}
        />
      ) : (
        <div className="space-y-3">
          <SectionHeading
            description={t("pages.dnsServers.sections.servers.description")}
            title={t("pages.dnsServers.sections.servers.title")}
          />
          <div className="relative h-0">
            {serverSelection.hasSelection ? (
              <BulkSelectionToolbar
                cancelLabel={t("common.cancel")}
                countLabel={t("pages.dnsServers.bulk.selected", {
                  count: serverSelection.selectedCount,
                })}
                onCancel={serverSelection.clear}
              >
                <Button
                  disabled={configMutationPending || fallbackSession.isDirty}
                  onClick={deleteServersBulk}
                  size="sm"
                  variant="destructive"
                >
                  <KeenTrashIcon className="mr-1 h-4 w-4" />
                  {t("pages.dnsServers.bulk.delete")}
                </Button>
              </BulkSelectionToolbar>
            ) : null}
          </div>
          <DataTable
            headers={[
              t("pages.dnsServers.headers.name"),
              t("pages.dnsServers.headers.address"),
              t("pages.dnsServers.headers.outbound"),
              t("pages.dnsServers.headers.actions"),
            ]}
            rows={sortedServers.map((server) => [
              <div
                className="font-medium"
                key={`${server.tag}-tag`}
                title={
                  server.display_name || findDnsPresetByAddress(server.address)
                    ? server.tag
                    : undefined
                }
              >
                {server.display_name ??
                  findDnsPresetByAddress(server.address)?.name ??
                  server.tag}
              </div>,
              <span
                className="text-sm text-muted-foreground"
                key={`${server.tag}-address`}
              >
                {server.type === DnsServerType.keenetic
                  ? t("pages.dnsServers.keeneticAddress")
                  : server.address}
              </span>,
              <Badge
                key={`${server.tag}-detour`}
                variant={server.detour ? "outline" : "secondary"}
              >
                {server.detour
                  ? (outboundNames.get(server.detour) ?? server.detour)
                  : t("pages.dnsServers.none")}
              </Badge>,
              <ActionButtons
                actions={[
                  {
                    disabled: configMutationPending || fallbackSession.isDirty,
                    icon: <KeenPencilIcon className="h-4 w-4" />,
                    label: t("common.edit"),
                    onClick: () =>
                      navigate(
                        `/dns-servers/${encodeURIComponent(server.tag)}/edit`
                      ),
                  },
                ]}
                key={`${server.tag}-actions`}
              />,
            ])}
            sort={sort}
            selection={{
              rowIds: serverRowIds,
              selectedIds: serverSelection.selectedIds,
              disabled: configMutationPending || fallbackSession.isDirty,
              onToggle: serverSelection.toggleOne,
              onToggleAll: serverSelection.setAllVisible,
              selectAllLabel: t("common.selection.selectAll"),
              getRowLabel: (rowId) =>
                t("common.selection.selectRow", {
                  rowLabel:
                    dnsServers.find((server) => server.tag === rowId)
                      ?.display_name ??
                    findDnsPresetByAddress(
                      dnsServers.find((server) => server.tag === rowId)?.address
                    )?.name ??
                    rowId,
                }),
            }}
          />
        </div>
      )}
      <DeleteImpactDialog
        confirmLabel={t("pages.dnsServers.deleteDialog.confirm")}
        description={t("pages.dnsServers.deleteDialog.description", {
          tags: visibleDeleteRequest
            ? formatDnsServerNames(
                visibleDeleteRequest.config,
                visibleDeleteRequest.tags
              )
            : "",
        })}
        impactItems={
          visibleDeleteRequest
            ? getDnsServerDeleteImpactItems(
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
        title={t("pages.dnsServers.deleteDialog.title")}
      />
    </div>
  )
}

function getConfigData(response: getConfigResponse | undefined) {
  if (!response || response.status !== 200) {
    return undefined
  }

  return response.data.config
}
