import { useTranslation } from "react-i18next"

import type { ConfigApplyImpact } from "@/lib/config-apply-guidance"

export function PostApplyDescription({
  impact,
}: {
  impact: ConfigApplyImpact
}) {
  const { t } = useTranslation()
  if (impact === "none" || impact === "unknown") return null
  return (
    <span>
      {impact === "dns" ? t("postApply.dns") : t("postApply.routing")}
    </span>
  )
}
