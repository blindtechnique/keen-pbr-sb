import { useTranslation } from "react-i18next"

import { BackupPanel, RestorePanel } from "@/components/settings/backup-dialogs"
import { PageHeader } from "@/components/shared/page-header"
import { SectionHeading } from "@/components/shared/section-heading"

/**
 * Резервная копия и восстановление.
 *
 * Обе страницы были единственными во всей панели без корневой обёртки — просто
 * фрагмент, — и единственными, где заголовки написаны русскими строками мимо
 * i18n. Отсюда и ощущение чужой страницы: ритм не тот, а в английской версии
 * они оставались русскими.
 */
export function BackupPage() {
  const { t } = useTranslation()

  return (
    <div className="space-y-3">
      <PageHeader
        description={t("pages.backup.description")}
        title={t("pages.backup.title")}
      />
      <SectionHeading
        description={t("pages.backup.sectionDescription")}
        title={t("pages.backup.sectionTitle")}
      />
      <div className="max-w-3xl">
        <BackupPanel />
      </div>
    </div>
  )
}

export function RestorePage() {
  const { t } = useTranslation()

  return (
    <div className="space-y-3">
      <PageHeader
        description={t("pages.restore.description")}
        title={t("pages.restore.title")}
      />
      <SectionHeading
        description={t("pages.restore.sectionDescription")}
        title={t("pages.restore.sectionTitle")}
      />
      <div className="max-w-3xl">
        <RestorePanel />
      </div>
    </div>
  )
}
