import { Loader2, ShieldQuestion } from "lucide-react"
import { useEffect, useState } from "react"
import { useTranslation } from "react-i18next"

import { usePostRoutingRegistryCheckMutation } from "@/api/mutations"
import type { RoutingTestNfqws } from "@/api/generated/model"
import { Button } from "@/components/ui/button"

import {
  nfqwsVerdict,
  registryVerdict,
  summariseNfqwsCoverage,
} from "./target-facts-model"

/**
 * Two facts about the target that the routing verdict does not answer, shown
 * as two facts.
 *
 * They are deliberately not combined into "it works" or "it does not": nfqws
 * coverage, the registry and the route are three independent things, and any
 * two of them can disagree without either being wrong. A single verdict would
 * have to pick a winner and would be wrong in both directions.
 */
export function TargetFacts({
  nfqws,
  target,
}: {
  nfqws?: RoutingTestNfqws
  target: string
}) {
  const { t } = useTranslation()
  const coverage = summariseNfqwsCoverage(nfqws)
  const verdict = nfqwsVerdict(coverage)
  const registryMutation = usePostRoutingRegistryCheckMutation()

  // A verdict belongs to the target it was asked about. Without this a new
  // search shows the previous target's answer until the request returns.
  const [askedFor, setAskedFor] = useState<string | null>(null)
  useEffect(() => {
    if (askedFor !== null && askedFor !== target) {
      registryMutation.reset()
      setAskedFor(null)
    }
  }, [target, askedFor, registryMutation])

  const registry =
    registryMutation.data?.status === 200 && askedFor === target
      ? registryMutation.data.data
      : undefined
  const registryState = registry ? registryVerdict(registry) : null

  return (
    <div className="space-y-3 border-t pt-3">
      <div className="space-y-1">
        <div className="text-xs font-medium">
          {t("overview.targetFacts.nfqwsTitle")}
        </div>
        <p className="text-sm text-muted-foreground">
          {t(`overview.targetFacts.nfqws.${verdict}`)}
        </p>
        {/* The entry, not just the fact: it is what an operator edits, and a
            parent domain matching is different from the domain itself. */}
        {[...coverage.excluding, ...coverage.covering].map((match) => (
          <p
            className="text-xs text-muted-foreground"
            key={`${match.list}:${match.entry}:${match.matched}`}
          >
            {t("overview.targetFacts.nfqwsMatch", {
              entry: match.entry,
              list: match.list,
              matched: match.matched,
              role: t(`overview.targetFacts.role.${match.role}`),
            })}
          </p>
        ))}
      </div>

      <div className="space-y-1">
        <div className="text-xs font-medium">
          {t("overview.targetFacts.registryTitle")}
        </div>
        {!registry ? (
          <>
            <p className="text-sm text-muted-foreground">
              {t("overview.targetFacts.registryPrompt")}
            </p>
            <Button
              className="mt-1"
              disabled={registryMutation.isPending || !target}
              onClick={() => {
                setAskedFor(target)
                registryMutation.mutate({
                  data: { target, allow_external_lookup: true },
                })
              }}
              size="sm"
              variant="outline"
            >
              {registryMutation.isPending ? (
                <Loader2 className="mr-1 h-4 w-4 animate-spin" />
              ) : (
                <ShieldQuestion className="mr-1 h-4 w-4" />
              )}
              {t("overview.targetFacts.registryCheck")}
            </Button>
          </>
        ) : (
          <>
            <p className="text-sm text-muted-foreground">
              {t(`overview.targetFacts.registry.${registryState}`)}
            </p>
            {registry.blocked_subnets?.length ? (
              <p className="text-xs text-muted-foreground">
                {t("overview.targetFacts.registrySubnets", {
                  subnets: registry.blocked_subnets.join(", "),
                })}
              </p>
            ) : null}
            {registry.cdn_providers?.length ? (
              <p className="text-xs text-muted-foreground">
                {t("overview.targetFacts.registryCdn", {
                  providers: registry.cdn_providers.join(", "),
                })}
              </p>
            ) : null}
            <p className="text-xs text-muted-foreground">
              {t("overview.targetFacts.registrySource", {
                service: registry.service,
              })}
            </p>
          </>
        )}
        {registryMutation.isError ? (
          <p className="text-xs text-destructive">
            {t("overview.targetFacts.registry.not-checked")}
          </p>
        ) : null}
      </div>
    </div>
  )
}
