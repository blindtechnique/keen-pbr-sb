import { useTranslation } from "react-i18next"

import { useGetConfig, useGetTransportConfig } from "@/api/queries"
import { selectConfig, selectOutbounds } from "@/api/selectors"
import { PageHeader } from "@/components/shared/page-header"
import { SectionHeading } from "@/components/shared/section-heading"
import { SectionTabs, type SectionTab } from "@/components/shared/section-tabs"
import { useSectionTab } from "@/hooks/use-section-tab"
import { OutboundsPage } from "@/pages/outbounds-page"
import { TransportsPage } from "@/pages/transports-page"

type ConnectionsTab = "tunnels" | "interfaces" | "failover" | "system"

// «interfaces» остаётся в списке ради старых ссылок с #interfaces: такая
// ссылка открывает объединённую первую вкладку, а не ломается.
const CONNECTIONS_TABS: ConnectionsTab[] = [
  "tunnels",
  "interfaces",
  "failover",
  "system",
]

/**
 * Подключения и маршруты на одной странице.
 *
 * Раньше туннели и их маршруты были двумя вкладками, и одно и то же лежало
 * под ними дважды: человек видел два «sddvpn mooo VLESS» и не мог понять, чем
 * они отличаются. По решению владельца туннель и есть маршрут: первая вкладка
 * показывает туннели (маршрут создаётся и удаляется вместе с туннелем), а
 * редкие маршруты без туннеля — на интерфейсы прошивки или чужих пакетов —
 * живут ниже отдельным блоком «Прочие маршруты» и не прячутся.
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
  const transportConfigQuery = useGetTransportConfig()
  const transports =
    transportConfigQuery.data?.status === 200
      ? transportConfigQuery.data.data
      : []

  // Маршрут принадлежит туннелю, если совпал тег или интерфейс. Всё, что не
  // совпало, — «прочее»: прятать его нельзя, у владельца может жить маршрут
  // на tun0 чужого пакета Entware.
  const transportTags = new Set(transports.map((item) => item.tag))
  const transportInterfaces = new Set(transports.map((item) => item.interface))
  const linkedOutboundTags = new Set(
    outbounds
      .filter(
        (outbound) =>
          outbound.type === "interface" &&
          (transportTags.has(outbound.tag) ||
            (outbound.interface
              ? transportInterfaces.has(outbound.interface)
              : false))
      )
      .map((outbound) => outbound.tag)
  )
  const otherRouteCount = outbounds.filter(
    (outbound) =>
      outbound.type === "interface" && !linkedOutboundTags.has(outbound.tag)
  ).length
  const countOf = (predicate: (type: string) => boolean) =>
    outbounds.filter((item) => predicate(item.type)).length

  const tabs: SectionTab<ConnectionsTab>[] = [
    {
      value: "tunnels",
      label: t("pages.routesAndTunnels.tabs.tunnels"),
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
  const mergedTabActive = activeTab === "tunnels" || activeTab === "interfaces"

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
        value={mergedTabActive ? "tunnels" : activeTab}
      />
      {mergedTabActive ? (
        <>
          <TransportsPage embedded />
          {otherRouteCount > 0 ? (
            <div className="space-y-3 border-t border-border pt-4">
              <SectionHeading
                description={t(
                  "pages.routesAndTunnels.otherRoutes.description"
                )}
                title={t("pages.routesAndTunnels.otherRoutes.title")}
              />
              <OutboundsPage
                embedded
                excludeTags={linkedOutboundTags}
                group="interfaces"
              />
            </div>
          ) : null}
        </>
      ) : (
        <OutboundsPage embedded group={activeTab} />
      )}
    </div>
  )
}
