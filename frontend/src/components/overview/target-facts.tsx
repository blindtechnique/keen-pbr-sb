import { CircleCheck, CircleX, Loader2 } from "lucide-react"
import { useEffect, useRef } from "react"
import { useTranslation } from "react-i18next"

import { usePostRoutingRegistryCheckMutation } from "@/api/mutations"
import type { RoutingTestNfqws } from "@/api/generated/model"

import {
  nfqwsVerdict,
  registryVerdict,
  summariseNfqwsCoverage,
} from "./target-facts-model"

export type SiteAvailability =
  "idle" | "checking" | "reachable" | "unreachable" | "error"

/**
 * Three facts about the target that the routing verdict does not answer,
 * shown before the routing details.
 *
 * They are deliberately not combined into one verdict: reachability, nfqws
 * coverage, the registry and the route are independent, and any two of them
 * can disagree without either being wrong.
 */
export function TargetFacts({
  nfqws,
  nfqwsPending = false,
  registryEnabled,
  siteAvailability,
  target,
}: {
  nfqws?: RoutingTestNfqws
  nfqwsPending?: boolean
  registryEnabled: boolean
  siteAvailability: SiteAvailability
  target: string
}) {
  const { t } = useTranslation()
  const coverage = summariseNfqwsCoverage(nfqws)
  const verdict = nfqwsVerdict(coverage)
  const registryMutation = usePostRoutingRegistryCheckMutation()

  // One lookup per target per switch state, fired from the effect rather than
  // from a button: the preference is the consent, so a checked target should
  // not need a second click. The ref is what keeps a re-render from asking
  // again for a target already asked about.
  const askedRef = useRef<string | null>(null)
  const { mutate: askRegistry, reset: resetRegistry } = registryMutation
  useEffect(() => {
    if (!registryEnabled) {
      if (askedRef.current !== null) {
        askedRef.current = null
        resetRegistry()
      }
      return
    }
    if (!target || askedRef.current === target) return
    askedRef.current = target
    askRegistry({ data: { target } })
  }, [registryEnabled, target, askRegistry, resetRegistry])

  const registry =
    registryMutation.data?.status === 200 &&
    registryMutation.data.data.target === target
      ? registryMutation.data.data
      : undefined
  const registryState = registry ? registryVerdict(registry) : null

  return (
    <div className="space-y-3 rounded-md border bg-muted/20 p-3">
      <div className="space-y-1">
        <div className="text-xs font-medium">
          {t("overview.targetFacts.availabilityTitle")}
        </div>
        <div aria-atomic="true" aria-live="polite">
          {siteAvailability === "checking" ? (
            <p className="inline-flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              {t("overview.targetFacts.availability.checking")}
            </p>
          ) : siteAvailability === "reachable" ? (
            <p className="inline-flex items-center gap-2 text-sm text-green-700">
              <CircleCheck className="h-4 w-4" />
              {t("overview.targetFacts.availability.reachable")}
            </p>
          ) : siteAvailability === "unreachable" ? (
            <p className="inline-flex items-center gap-2 text-sm text-destructive">
              <CircleX className="h-4 w-4" />
              {t("overview.targetFacts.availability.unreachable")}
            </p>
          ) : siteAvailability === "error" ? (
            <p className="text-sm text-destructive">
              {t("overview.targetFacts.availability.error")}
            </p>
          ) : (
            <p className="text-sm text-muted-foreground">
              {t("overview.targetFacts.availability.idle")}
            </p>
          )}
        </div>
      </div>

      <div className="space-y-1">
        <div className="text-xs font-medium">
          {t("overview.targetFacts.nfqwsTitle")}
        </div>
        <p className="text-sm text-muted-foreground">
          {nfqwsPending
            ? t("overview.targetFacts.nfqwsChecking")
            : t(`overview.targetFacts.nfqws.${verdict}`)}
        </p>
        {/* The entry, not just the fact: it is what an operator edits, and a
            parent domain matching is different from the domain itself. */}
        {[...coverage.excluding, ...coverage.covering].map((match) => (
          <p
            className="text-xs [overflow-wrap:anywhere] break-words text-muted-foreground"
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
        <div aria-atomic="true" aria-live="polite">
          {!registryEnabled ? (
            <p className="text-sm text-muted-foreground">
              {t("overview.targetFacts.registryDisabled")}
            </p>
          ) : registryMutation.isPending ? (
            <p className="text-sm text-muted-foreground" role="status">
              {t("overview.targetFacts.registryChecking")}
            </p>
          ) : registryMutation.isError ? (
            <p className="text-sm text-destructive">
              {t("overview.targetFacts.registry.not-checked")}
            </p>
          ) : registry ? (
            <>
              <p className="text-sm text-muted-foreground">
                {t(`overview.targetFacts.registry.${registryState}`)}
              </p>
              {registry.blocked_subnets?.length ? (
                <p className="text-xs [overflow-wrap:anywhere] break-words text-muted-foreground">
                  {t("overview.targetFacts.registrySubnets", {
                    subnets: registry.blocked_subnets.join(", "),
                  })}
                </p>
              ) : null}
              {registry.cdn_providers?.length ? (
                <p className="text-xs [overflow-wrap:anywhere] break-words text-muted-foreground">
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
          ) : null}
        </div>
      </div>
    </div>
  )
}
