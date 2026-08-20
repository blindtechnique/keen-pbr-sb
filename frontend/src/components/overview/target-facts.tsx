import { Loader2 } from "lucide-react"
import { useEffect, useRef } from "react"
import { useTranslation } from "react-i18next"

import { toast } from "sonner"

import type { ApiError } from "@/api/client"
import {
  usePostRoutingRegistryCheckMutation,
  usePostRoutingRegistryConsentMutation,
} from "@/api/mutations"
import { useGetRoutingRegistryConsent } from "@/api/queries"
import type { RoutingTestNfqws } from "@/api/generated/model"
import { Checkbox } from "@/components/ui/checkbox"
import { Label } from "@/components/ui/label"
import { getApiErrorMessage } from "@/lib/api-errors"

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
  const registryConsentQuery = useGetRoutingRegistryConsent()
  const registryEnabled = Boolean(
    registryConsentQuery.data?.status === 200 &&
      registryConsentQuery.data.data.enabled
  )
  const consentMutation = usePostRoutingRegistryConsentMutation({
    mutation: {
      onError: (mutationError) =>
        toast.error(getApiErrorMessage(mutationError as ApiError), {
          richColors: true,
        }),
      onSuccess: (response) => {
        if (response.status === 200 && !response.data.durable) {
          toast.error(t("overview.targetFacts.registryDurabilityUnknown"), {
            richColors: true,
          })
        }
      },
    },
  })
  const registrySaving =
    registryConsentQuery.isPending || consentMutation.isPending

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
            className="break-words text-xs text-muted-foreground [overflow-wrap:anywhere]"
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

        {/* The switch sits with the answer it governs. Its dedicated endpoint
            writes a private file atomically; it never stages an unrelated
            routing draft. */}
        <div className="flex items-start gap-2 py-1">
          <Checkbox
            checked={registryEnabled}
            className="mt-0.5"
            disabled={registrySaving || registryConsentQuery.isError}
            id="registry-lookup-enabled"
            onCheckedChange={(checked) =>
              consentMutation.mutate({ data: { enabled: checked === true } })
            }
          />
          <Label
            className="text-sm font-normal text-muted-foreground"
            htmlFor="registry-lookup-enabled"
          >
            {t("overview.targetFacts.registryConsent")}
          </Label>
          {registrySaving ? (
            <span aria-live="polite" role="status">
              <Loader2
                aria-label={t("overview.targetFacts.registrySaving")}
                className="mt-0.5 h-4 w-4 animate-spin"
              />
            </span>
          ) : null}
        </div>

        <div aria-atomic="true" aria-live="polite">
          {registryConsentQuery.isError ? (
            <p className="text-sm text-destructive" role="alert">
              {t("overview.targetFacts.registryConsentLoadFailed")}
            </p>
          ) : !registryEnabled ? null : registryMutation.isPending ? (
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
                <p className="break-words text-xs text-muted-foreground [overflow-wrap:anywhere]">
                  {t("overview.targetFacts.registrySubnets", {
                    subnets: registry.blocked_subnets.join(", "),
                  })}
                </p>
              ) : null}
              {registry.cdn_providers?.length ? (
                <p className="break-words text-xs text-muted-foreground [overflow-wrap:anywhere]">
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
