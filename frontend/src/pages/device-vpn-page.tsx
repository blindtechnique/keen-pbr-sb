import { Plus, Pencil } from "lucide-react"
import { useTranslation } from "react-i18next"
import { useLocation } from "wouter"
import { useGetConfig, useGetRuntimeOutbounds } from "@/api/queries"
import { useConfigMutationPending } from "@/api/mutations"
import { selectConfig } from "@/api/selectors"
import { PageHeader } from "@/components/shared/page-header"
import { PageActionBar } from "@/components/shared/page-action-bar"
import { TableSkeleton } from "@/components/shared/table-skeleton"
import { ListPlaceholder } from "@/components/shared/list-placeholder"
import { RuntimeOutboundEntry } from "@/components/shared/runtime-outbound-state"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { deviceRuleAddress } from "@/lib/device-vpn"
import { getRuleEditHref } from "@/lib/rule-route"
import { getOutboundSelectDisplayName } from "@/lib/outbound-display"
import { useInterfaceDisplayNames } from "@/hooks/use-interface-display-names"

export function DeviceVpnPage() {
  const { t } = useTranslation()
  const [, navigate] = useLocation()
  const query = useGetConfig()
  const config = selectConfig(query.data)
  const pending = useConfigMutationPending()
  const runtime = useGetRuntimeOutbounds()
  const runtimeRows =
    runtime.data?.status === 200 ? runtime.data.data.outbounds : []
  const { labelFor } = useInterfaceDisplayNames()
  const names = new Map(
    (config?.outbounds ?? []).map((outbound) => [
      outbound.tag,
      getOutboundSelectDisplayName(outbound, labelFor),
    ])
  )
  const rows = (config?.route?.rules ?? []).flatMap((rule, index) => {
    const address = deviceRuleAddress(rule)
    return address ? [{ rule, index, address }] : []
  })
  return (
    <div className="space-y-4">
      <PageHeader
        title={t("deviceVpn.title")}
        description={t("deviceVpn.description")}
      />
      <PageActionBar
        primary={
          <Button
            disabled={!config || pending}
            onClick={() => navigate("/device-vpn/create")}
          >
            <Plus className="mr-1 size-4" />
            {t("deviceVpn.add")}
          </Button>
        }
      >
        <Button variant="outline" onClick={() => navigate("/routing-rules")}>
          {t("deviceVpn.allRules")}
        </Button>
      </PageActionBar>
      <p className="text-sm text-muted-foreground">
        {t("deviceVpn.addressHint")}
      </p>
      {query.isLoading ? (
        <TableSkeleton />
      ) : !config ? (
        <ListPlaceholder
          title={t("common.unableToLoadData")}
          description={t("common.loadErrorDescription")}
          variant="error"
        />
      ) : rows.length === 0 ? (
        <ListPlaceholder
          title={t("deviceVpn.emptyTitle")}
          description={t("deviceVpn.emptyDescription")}
        />
      ) : (
        <div className="divide-y border-y">
          {rows.map(({ rule, index, address }) => (
            <div
              className="flex flex-wrap items-center gap-x-6 gap-y-3 py-4"
              key={rule.id ?? index}
            >
              <div className="min-w-0 flex-1 basis-48">
                <div className="flex flex-wrap items-center gap-2">
                  <strong className="break-words">
                    {rule.display_name?.trim() || address}
                  </strong>
                  {rule.enabled === false ? (
                    <Badge variant="outline">{t("deviceVpn.disabled")}</Badge>
                  ) : null}
                </div>
                <div className="mt-1 font-mono text-sm text-muted-foreground">
                  {address}
                </div>
                {(config?.route?.rules ?? [])
                  .slice(0, index)
                  .some(
                    (earlier) =>
                      earlier.enabled !== false && !deviceRuleAddress(earlier)
                  ) ? (
                  <p className="mt-1 text-sm text-warning-foreground">
                    {t("deviceVpn.lowerPriority")}
                  </p>
                ) : null}
              </div>
              <div className="min-w-0 flex-1 basis-48">
                <span className="text-xs text-muted-foreground">
                  {t("deviceVpn.outbound")}
                </span>
                <RuntimeOutboundEntry
                  title={names.get(rule.outbound) ?? rule.outbound}
                  runtimeState={runtimeRows.find(
                    (entry) => entry.tag === rule.outbound
                  )}
                  t={t}
                />
              </div>
              <Button
                variant="outline"
                size="icon"
                disabled={pending}
                aria-label={t("deviceVpn.editNamed", {
                  name: rule.display_name?.trim() || address,
                })}
                onClick={() =>
                  navigate(getRuleEditHref("device-vpn", rule, index))
                }
              >
                <Pencil className="size-4" />
              </Button>
            </div>
          ))}
        </div>
      )}
      <p className="text-sm text-muted-foreground">
        {t("deviceVpn.rulesHint")}
      </p>
    </div>
  )
}
