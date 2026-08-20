import { Loader2, Search } from "lucide-react"
import { useState } from "react"
import { useTranslation } from "react-i18next"

import { usePostRoutingTestMutation } from "@/api/mutations"
import type { ConfigObject } from "@/api/generated/model"
import { SectionCard } from "@/components/shared/section-card"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { ListPlaceholder } from "@/components/shared/list-placeholder"
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
  InputGroupText,
} from "@/components/ui/input-group"
import { Skeleton } from "@/components/ui/skeleton"

import { RoutingDiagnosticsResult } from "./routing-diagnostics-result"
import { sanitizeRoutingTarget } from "./sanitize-routing-target"
import { TargetFacts } from "./target-facts"

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

  const routingTestMutation = usePostRoutingTestMutation()
  const routingDiagnostics =
    routingTestMutation.data?.status === 200
      ? routingTestMutation.data.data
      : undefined

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
          routingTestMutation.mutate({ data: { target: sanitized } })
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
      </form>

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
        <>
          <RoutingDiagnosticsResult
            diagnostics={routingDiagnostics}
            lists={lists}
            outbounds={outbounds}
          />
          {/* Below the routing verdict, not merged into it: nfqws coverage and
              the registry are separate facts that the route does not answer. */}
          <TargetFacts
            nfqws={routingDiagnostics.nfqws}
            target={routingDiagnostics.target}
          />
        </>
      ) : null}
    </SectionCard>
  )
}
