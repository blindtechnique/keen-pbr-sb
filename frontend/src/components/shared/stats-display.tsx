import { useTranslation } from "react-i18next"

export function StatsDisplay({
  domains,
  ipv4Subnets,
  ipv6Subnets,
}: {
  domains: number
  ipv4Subnets: number
  ipv6Subnets: number
}) {
  const { t } = useTranslation()
  const parts = [
    { label: t("pages.lists.statsParts.domains"), value: domains },
    { label: t("pages.lists.statsParts.ipv4"), value: ipv4Subnets },
    { label: t("pages.lists.statsParts.ipv6"), value: ipv6Subnets },
  ]
  const visible = parts.filter((part) => part.value > 0)
  const title = parts.map((part) => `${part.label}: ${part.value}`).join(" · ")

  if (visible.length === 0) {
    return (
      <span className="text-sm text-muted-foreground italic" title={title}>
        {t("pages.lists.statsParts.empty")}
      </span>
    )
  }

  return (
    <span className="text-sm text-muted-foreground" title={title}>
      {visible.map((part) => `${part.label}: ${part.value}`).join(" · ")}
    </span>
  )
}
