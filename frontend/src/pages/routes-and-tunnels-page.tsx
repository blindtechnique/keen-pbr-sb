import { useTranslation } from "react-i18next"

import { useGetConfig } from "@/api/queries"
import { selectConfig, selectOutbounds } from "@/api/selectors"
import { PageHeader } from "@/components/shared/page-header"
import { SectionTabs, type SectionTab } from "@/components/shared/section-tabs"
import { useSectionTab } from "@/hooks/use-section-tab"
import { OutboundsPage } from "@/pages/outbounds-page"
import { TransportsPage } from "@/pages/transports-page"

type ConnectionsTab = "tunnels" | "interfaces" | "failover" | "system"

const CONNECTIONS_TABS: ConnectionsTab[] = [
  "tunnels",
  "interfaces",
  "failover",
  "system",
]

/**
 * Подключения и маршруты на одной странице.
 *
 * Раньше это были два пункта меню, и одно и то же лежало под ними дважды:
 * туннель `tr_85f462c5` и маршрут `tr_85f462c5` — одинаковое имя в разных
 * разделах. Разными объектами они остались (демон так устроен) и создаются
 * одной операцией, но человек видел два «sddvpn mooo VLESS» и не мог понять,
 * чем они отличаются.
 *
 * Первая вкладка отвечает на вопрос «через что ходит трафик» — это
 * подключения, и новичку дальше идти не нужно: маршрут к туннелю создаётся
 * вместе с ним. Остальные вкладки — для тех, кому нужен сам маршрут:
 * привязка к интерфейсу, резервирование, системные направления.
 */
export function RoutesAndTunnelsPage({
  initialTab,
}: { initialTab?: ConnectionsTab } = {}) {
  const { t } = useTranslation()
  const [activeTab, setActiveTab] = useSectionTab<ConnectionsTab>(
    CONNECTIONS_TABS,
    initialTab ?? "tunnels"
  )
  const configQuery = useGetConfig()
  const outbounds = selectOutbounds(selectConfig(configQuery.data))
  const countOf = (predicate: (type: string) => boolean) =>
    outbounds.filter((item) => predicate(item.type)).length

  const tabs: SectionTab<ConnectionsTab>[] = [
    {
      value: "tunnels",
      label: t("pages.routesAndTunnels.tabs.tunnels"),
    },
    {
      value: "interfaces",
      label: t("pages.routesAndTunnels.tabs.interfaces"),
      count: countOf((type) => type === "interface"),
    },
    {
      value: "failover",
      label: t("pages.routesAndTunnels.tabs.failover"),
      count: countOf((type) => type === "urltest"),
    },
    {
      value: "system",
      label: t("pages.routesAndTunnels.tabs.system"),
      count: countOf((type) => type !== "interface" && type !== "urltest"),
    },
  ]

  return (
    <div className="space-y-3">
      <PageHeader
        description={t("pages.routesAndTunnels.description")}
        title={t("pages.routesAndTunnels.title")}
      />
      <SectionTabs
        ariaLabel={t("pages.routesAndTunnels.tabs.ariaLabel")}
        onValueChange={setActiveTab}
        tabs={tabs}
        value={activeTab}
      />
      {activeTab === "tunnels" ? (
        <TransportsPage embedded />
      ) : (
        <OutboundsPage embedded group={activeTab} />
      )}
    </div>
  )
}
