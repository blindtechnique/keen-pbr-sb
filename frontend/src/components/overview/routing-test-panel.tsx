import { Loader2, Search } from "lucide-react"
import { useState } from "react"
import { useTranslation } from "react-i18next"
import { useMutation } from "@tanstack/react-query"
import { toast } from "sonner"

import type { ApiError } from "@/api/client"
import type { NfqwsActionResult } from "@/api/generated/model"
import {
  usePostRoutingRegistryConsentMutation,
  usePostRoutingTestMutation,
} from "@/api/mutations"
import { nfqwsAction } from "@/api/nfqws"
import { useGetRoutingRegistryConsent } from "@/api/queries"
import type { ConfigObject } from "@/api/generated/model"
import { SectionCard } from "@/components/shared/section-card"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Checkbox } from "@/components/ui/checkbox"
import { Label } from "@/components/ui/label"
import { ListPlaceholder } from "@/components/shared/list-placeholder"
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
  InputGroupText,
} from "@/components/ui/input-group"
import { Skeleton } from "@/components/ui/skeleton"
import { getApiErrorMessage } from "@/lib/api-errors"

import { RoutingDiagnosticsResult } from "./routing-diagnostics-result"
import { sanitizeRoutingTarget } from "./sanitize-routing-target"
import { TargetFacts } from "./target-facts"
import {
  probeBrowserReachability,
  routerProbeRequestFailure,
  routerProbeResult,
  type SiteProbeResult,
  type SiteProbeState,
} from "./site-probe-model"

export function RoutingTestPanel({
  lists,
  outbounds,
}: {
  lists?: ConfigObject["lists"]
  outbounds?: ConfigObject["outbounds"]
}) {
  const { t } = useTranslation()
  const [testTarget, setTestTarget] = useState("")
  const [routingInputError, setRoutingInputError] = useState<string | null>(
    null
  )
  const [activeTarget, setActiveTarget] = useState<string | null>(null)

  const routingTestMutation = usePostRoutingTestMutation()
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
  const browserProbeMutation = useMutation({
    mutationFn: async ({ target, url }: { target: string; url: string }) => {
      return { target, result: await probeBrowserReachability(url) }
    },
  })
  const routerProbeMutation = useMutation({
    mutationFn: async ({ target, url }: { target: string; url: string }) => {
      let result: SiteProbeResult
      try {
        const response = await nfqwsAction<NfqwsActionResult>({
          action: "check_url",
          url,
        })
        result = routerProbeResult(response)
      } catch (error) {
        result = routerProbeRequestFailure(error)
      }
      return { target, result }
    },
  })
  const routingDiagnostics =
    routingTestMutation.data?.status === 200
      ? routingTestMutation.data.data.target === activeTarget
        ? routingTestMutation.data.data
        : undefined
      : undefined
  const browserProbe: SiteProbeState = browserProbeMutation.isPending
    ? { status: "checking" }
    : browserProbeMutation.data?.target === activeTarget
      ? browserProbeMutation.data.result
      : { status: "idle" }
  const routerProbe: SiteProbeState = routerProbeMutation.isPending
    ? { status: "checking" }
    : routerProbeMutation.data?.target === activeTarget
      ? routerProbeMutation.data.result
      : { status: "idle" }

  return (
    <SectionCard title={t("overview.routingTest.title")}>
      <form
        className="space-y-3"
        onSubmit={(event) => {
          event.preventDefault()
          if (routingTestMutation.isPending) {
            return
          }

          const sanitized = sanitizeRoutingTarget(testTarget)
          if (!sanitized) {
            setRoutingInputError(t("overview.routingTest.invalidTarget"))
            return
          }
          setRoutingInputError(null)
          if (sanitized !== testTarget) {
            setTestTarget(sanitized)
          }
          setActiveTarget(sanitized)
          routingTestMutation.mutate({ data: { target: sanitized } })
          const probe = {
            target: sanitized,
            url: siteCheckUrl(testTarget, sanitized),
          }
          browserProbeMutation.mutate(probe)
          routerProbeMutation.mutate(probe)
        }}
      >
        <InputGroup>
          <InputGroupAddon>
            <InputGroupText>
              <Search className="h-4 w-4" />
            </InputGroupText>
          </InputGroupAddon>
          <InputGroupInput
            onChange={(event) => setTestTarget(event.target.value)}
            onKeyDown={(event) => {
              if (
                event.key === "Enter" &&
                testTarget.trim() &&
                !routingTestMutation.isPending
              ) {
                event.preventDefault()
                const form = event.currentTarget.form
                form?.requestSubmit()
              }
            }}
            placeholder={t("overview.routingTest.placeholder")}
            value={testTarget}
          />
          <InputGroupAddon align="inline-end">
            <InputGroupButton
              className="whitespace-nowrap"
              disabled={routingTestMutation.isPending}
              type="submit"
              variant="default"
            >
              {routingTestMutation.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : null}
              {t("overview.routingTest.submit")}
            </InputGroupButton>
          </InputGroupAddon>
        </InputGroup>

        {/* This is a stored consent for the external registry lookup, so it
            belongs with the address that will be disclosed rather than below
            a previous result. */}
        <div className="flex items-start gap-2 px-1">
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

        {registryConsentQuery.isError ? (
          <p className="px-1 text-sm text-destructive" role="alert">
            {t("overview.targetFacts.registryConsentLoadFailed")}
          </p>
        ) : null}
      </form>

      {activeTarget ? (
        <TargetFacts
          nfqws={routingDiagnostics?.nfqws}
          nfqwsPending={routingTestMutation.isPending}
          registryEnabled={registryEnabled}
          browserProbe={browserProbe}
          routerProbe={routerProbe}
          target={activeTarget}
        />
      ) : null}

      {routingTestMutation.isPending ? (
        <div className="space-y-2">
          <Skeleton className="h-4 w-2/3" />
          <Skeleton className="h-4 w-1/2" />
        </div>
      ) : null}

      {routingInputError ? (
        <Alert variant="destructive">
          <AlertDescription>{routingInputError}</AlertDescription>
        </Alert>
      ) : null}

      {routingTestMutation.isError ? (
        <Alert variant="destructive">
          <AlertDescription>
            {t("overview.routingTest.requestFailed")}
          </AlertDescription>
        </Alert>
      ) : null}

      {routingTestMutation.isSuccess &&
      routingDiagnostics &&
      routingDiagnostics.results.length === 0 &&
      routingDiagnostics.rule_diagnostics.length === 0 ? (
        <ListPlaceholder
          description={t("overview.routingTest.emptyDescription")}
          title={t("overview.routingTest.emptyTitle")}
        />
      ) : null}

      {routingDiagnostics ? (
        <RoutingDiagnosticsResult
          diagnostics={routingDiagnostics}
          lists={lists}
          outbounds={outbounds}
        />
      ) : null}
    </SectionCard>
  )
}

function siteCheckUrl(input: string, target: string): string {
  const trimmed = input.trim()
  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed
  }
  const host = target.includes(":") ? `[${target}]` : target
  return `https://${host}/`
}
