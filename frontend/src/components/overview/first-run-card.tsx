import { WandSparklesIcon } from "lucide-react"
import { useTranslation } from "react-i18next"
import { Link } from "wouter"

import { SectionCard } from "@/components/shared/section-card"
import { Button } from "@/components/ui/button"

export function FirstRunCard() {
  const { t } = useTranslation()
  return (
    <SectionCard title={t("overview.firstRun.title")}>
      <div className="space-y-3">
        <p className="text-sm text-muted-foreground">
          {t("overview.firstRun.description")}
        </p>
        <ol className="grid list-inside list-decimal gap-2 text-sm sm:grid-cols-2">
          <li>{t("overview.firstRun.connection")}</li>
          <li>{t("overview.firstRun.dns")}</li>
          <li>{t("overview.firstRun.catalog")}</li>
          <li>{t("overview.firstRun.check")}</li>
        </ol>
        <div className="flex flex-wrap gap-2">
          <Button render={<Link href="/setup" />}>
            <WandSparklesIcon />
            {t("overview.outbounds.startSetup")}
          </Button>
          <Button render={<Link href="/restore" />} variant="outline">
            {t("overview.firstRun.restore")}
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">
          {t("overview.firstRun.repeatHint")}
        </p>
      </div>
    </SectionCard>
  )
}
