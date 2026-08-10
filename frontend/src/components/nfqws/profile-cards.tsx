import { PlayIcon } from "lucide-react"
import { useMemo } from "react"
import { useTranslation } from "react-i18next"

import { KeeneticStatus } from "@/components/shared/keenetic-status"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  parseNfqwsStrategy,
  type NfqwsProfileTier,
} from "@/pages/nfqws-strategy-model"

export interface NfqwsProfileEntry {
  readonly name: string
  readonly tier: NfqwsProfileTier
  readonly content: string
  readonly active: boolean
}

export function NfqwsProfileCards({
  profiles,
  onApply,
  onOpen,
}: {
  readonly profiles: readonly NfqwsProfileEntry[]
  readonly onApply: (name: string) => void
  readonly onOpen: (name: string) => void
}) {
  if (profiles.length === 0) return null

  return (
    <ul className="grid gap-3 lg:grid-cols-3">
      {profiles.map((profile) => (
        <ProfileCard
          key={profile.name}
          onApply={() => onApply(profile.name)}
          onOpen={() => onOpen(profile.name)}
          profile={profile}
        />
      ))}
    </ul>
  )
}

function ProfileCard({
  profile,
  onApply,
  onOpen,
}: {
  readonly profile: NfqwsProfileEntry
  readonly onApply: () => void
  readonly onOpen: () => void
}) {
  const { t } = useTranslation()
  const summary = useMemo(
    () => parseNfqwsStrategy(profile.content),
    [profile.content]
  )
  const hasDomainPools = summary.pools.some((pool) => pool.domains.length > 0)

  return (
    <li className="flex min-w-0 flex-col gap-3 rounded-xl border p-4">
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <span className="text-sm font-semibold">
          {t(`nfqws.profiles.tier.${profile.tier}`)}
        </span>
        {profile.tier === "balanced" ? (
          <Badge size="xs" variant="secondary">
            {t("nfqws.profiles.recommended")}
          </Badge>
        ) : null}
        {profile.active ? (
          <KeeneticStatus className="ml-auto" tone="success">
            {t("nfqws.strategyState.active")}
          </KeeneticStatus>
        ) : null}
      </div>

      <p className="text-sm text-muted-foreground">
        {t(`nfqws.profiles.description.${profile.tier}`)}
      </p>

      {summary.parseable ? (
        <p className="text-xs text-muted-foreground">
          {t("nfqws.profiles.poolSummary", { count: summary.pools.length })}
          {hasDomainPools
            ? ` · ${t("nfqws.profiles.domainPools")}`
            : ` · ${t("nfqws.profiles.sharedPools")}`}
        </p>
      ) : null}

      <div className="mt-auto flex flex-wrap gap-2 pt-1">
        <Button disabled={profile.active} onClick={onApply} size="sm">
          <PlayIcon />
          {profile.active
            ? t("nfqws.profiles.applied")
            : t("nfqws.applyStrategy")}
        </Button>
        <Button onClick={onOpen} size="sm" variant="outline">
          {t("nfqws.profiles.details")}
        </Button>
      </div>
    </li>
  )
}
