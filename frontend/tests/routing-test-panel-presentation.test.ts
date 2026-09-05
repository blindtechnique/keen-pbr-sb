import { expect, test } from "bun:test"
import { readFileSync } from "node:fs"

test("site diagnostics keeps useful results without the technical path card", () => {
  const result = readFileSync(
    new URL(
      "../src/components/overview/routing-diagnostics-result.tsx",
      import.meta.url
    ),
    "utf8"
  )
  expect(result).not.toContain("overview.routingDiagnostics.pathTitle")
  expect(result).not.toContain("<RoutingPathStep")
  expect(result).toContain("overview.routingDiagnostics.resultTitle")
  expect(result).toContain("overview.routingDiagnostics.ruleDetailsTitle")

  const panel = readFileSync(
    new URL(
      "../src/components/overview/routing-test-panel.tsx",
      import.meta.url
    ),
    "utf8"
  )
  expect(panel).toContain("<TargetFacts")
  expect(panel).toContain("browserProbe={browserProbe}")
  expect(panel).toContain("routerProbe={routerProbe}")
  expect(panel).toContain("registryEnabled={registryEnabled}")
  expect(panel).toContain("nfqws={routingDiagnostics?.nfqws}")
})
