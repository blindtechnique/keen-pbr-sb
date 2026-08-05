import { useTranslation } from "react-i18next"

import { useGetConfig } from "@/api/queries"
import { selectConfig } from "@/api/selectors"
import { PageHeader } from "@/components/shared/page-header"
import { SectionTabs, type SectionTab } from "@/components/shared/section-tabs"
import { useSectionTab } from "@/hooks/use-section-tab"
import { DnsRulesPage } from "@/pages/dns-rules-page"
import { RoutingRulesPage } from "@/pages/routing-rules-page"

type RulesTab = "routing" | "dns"

const RULES_TABS: RulesTab[] = ["routing", "dns"]

/**
 * Правила маршрутизации и DNS — одна страница с двумя вкладками.
 *
 * Разделять их по пунктам меню было нечестно по отношению к человеку: чтобы
 * «отправить YouTube в туннель», обычно нужны оба правила на один и тот же
 * список, и раньше это означало две страницы и два одинаковых выбора списка.
 * Каталог давно делает и то и другое одной операцией — здесь просто пропал
 * шов, который автоматика уже не видит.
 *
 * Объекты при этом остались разными, и не случайно: правило маршрутизации
 * умеет работать без списка вовсе — по адресам, портам, DSCP, — а у DNS-правила
 * список обязателен. Сливать их в один объект значило бы отнять половину
 * возможностей ради одной строчки в меню.
 */
export function RulesPage({ initialTab }: { initialTab?: RulesTab } = {}) {
  const { t } = useTranslation()
  const [activeTab, setActiveTab] = useSectionTab<RulesTab>(
    RULES_TABS,
    initialTab ?? "routing"
  )
  const configQuery = useGetConfig()
  const loadedConfig = selectConfig(configQuery.data)

  const tabs: SectionTab<RulesTab>[] = [
    {
      value: "routing",
      label: t("pages.rules.tabs.routing"),
      count: loadedConfig?.route?.rules?.length,
    },
    {
      value: "dns",
      label: t("pages.rules.tabs.dns"),
      count: loadedConfig?.dns?.rules?.length,
    },
  ]

  return (
    <div className="space-y-3">
      <PageHeader
        description={t("pages.rules.description")}
        title={t("pages.rules.title")}
      />
      <SectionTabs
        ariaLabel={t("pages.rules.tabs.ariaLabel")}
        onValueChange={setActiveTab}
        tabs={tabs}
        value={activeTab}
      />
      {activeTab === "routing" ? (
        <RoutingRulesPage embedded />
      ) : (
        <DnsRulesPage embedded />
      )}
    </div>
  )
}
