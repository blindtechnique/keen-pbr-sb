import { useTranslation } from "react-i18next"

import { PageHeader } from "@/components/shared/page-header"
import { RoutingRulesPage } from "@/pages/routing-rules-page"

/**
 * «Правила» — это правила маршрутизации.
 *
 * Вкладка DNS убрана по решению владельца после приёмки нового потока:
 * DNS-сервер списка назначается в редакторе самого списка, и отдельный
 * раздел со всеми DNS-правилами обычному человеку больше не нужен. Общий
 * список DNS-правил остался по прямому адресу /dns-rules — туда ведёт
 * честный блок из редактора списка, когда правило общее для нескольких
 * списков.
 */
export function RulesPage() {
  const { t } = useTranslation()

  return (
    <div className="space-y-3">
      <PageHeader
        description={t("pages.rules.description")}
        title={t("pages.rules.title")}
      />
      <RoutingRulesPage embedded />
    </div>
  )
}
