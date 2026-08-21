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
import { TargetFacts, type SiteAvailability } from "./target-facts"

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
  const siteAvailabilityMutation = useMutation({
    mutationFn: async ({ target, url }: { target: string; url: string }) => {
      const [browserProbe, routerProbe] = await Promise.allSettled([
        probeBrowserReachability(url),
        nfqwsAction<NfqwsActionResult>({
          action: "check_url",
          url,
        }).then((response) => {
          if (typeof response.reachable !== "boolean") {
            throw new TypeError()
          }
          return response.reachable
        }),
      ])

      const browserReachable =
        browserProbe.status === "fulfilled" && browserProbe.value
      const routerReachable =
        routerProbe.status === "fulfilled" && routerProbe.value

      if (!browserReachable && routerProbe.status === "rejected") {
        throw routerProbe.reason
      }

      return { reachable: browserReachable || routerReachable, target }
    },
  })
  const routingDiagnostics =
    routingTestMutation.data?.status === 200
      ? routingTestMutation.data.data.target === activeTarget
        ? routingTestMutation.data.data
        : undefined
      : undefined
  const siteAvailability: SiteAvailability = !activeTarget
    ? "idle"
    : siteAvailabilityMutation.isPending
      ? "checking"
      : siteAvailabilityMutation.isError
        ? "error"
        : siteAvailabilityMutation.data?.target === activeTarget
          ? siteAvailabilityMutation.data.reachable
            ? "reachable"
            : "unreachable"
          : "idle"

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
          siteAvailabilityMutation.mutate({
            target: sanitized,
            url: siteCheckUrl(testTarget, sanitized),
          })
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
          siteAvailability={siteAvailability}
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

async function probeBrowserReachability(url: string): Promise<boolean> {
  const controller = new AbortController()
  const timeout = window.setTimeout(() => controller.abort(), 10_000)

  try {
    const response = await fetch(url, {
      cache: "no-store",
      credentials: "omit",
      mode: "no-cors",
      referrerPolicy: "no-referrer",
      signal: controller.signal,
    })
    await response.body?.cancel().catch(() => undefined)
    return true
  } catch {
    return false
  } finally {
    window.clearTimeout(timeout)
  }
}
