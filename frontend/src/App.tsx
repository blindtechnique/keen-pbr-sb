import { Suspense, lazy } from "react"
import { Redirect, Route, Switch } from "wouter"

import { AppShell } from "@/components/layout/app-shell"
import { AuthGate } from "@/components/auth-gate"
import { ScrollToTopOnRouteChange } from "@/components/layout/scroll-route"
import { Skeleton } from "@/components/ui/skeleton"
import { OverviewPage } from "@/pages/overview-page"

/**
 * Every page except the dashboard is loaded on demand.
 *
 * The whole interface used to arrive as one megabyte of JavaScript, so a
 * router with a slow link paid for the nfqws2 editor and the connections table
 * before it could show anything. The dashboard stays in the main bundle
 * because it is what opens first; the rest costs nothing until visited.
 */
const CatalogPage = lazy(() =>
  import("@/pages/catalog-page").then((m) => ({ default: m.CatalogPage }))
)
const ConnectionsPage = lazy(() =>
  import("@/pages/connections-page").then((m) => ({
    default: m.ConnectionsPage,
  }))
)
const DnsRuleUpsertPage = lazy(() =>
  import("@/pages/dns-rule-upsert-page").then((m) => ({
    default: m.DnsRuleUpsertPage,
  }))
)
const DnsRulesPage = lazy(() =>
  import("@/pages/dns-rules-page").then((m) => ({ default: m.DnsRulesPage }))
)
const DnsServerUpsertPage = lazy(() =>
  import("@/pages/dns-servers-upsert-page").then((m) => ({
    default: m.DnsServerUpsertPage,
  }))
)
const DnsServersPage = lazy(() =>
  import("@/pages/dns-servers-page").then((m) => ({
    default: m.DnsServersPage,
  }))
)
const GeneralConfigPage = lazy(() =>
  import("@/pages/general-config-page").then((m) => ({
    default: m.GeneralConfigPage,
  }))
)
const BackupPage = lazy(() => import("@/pages/backup-page").then((m) => ({ default: m.BackupPage })))
const RestorePage = lazy(() => import("@/pages/backup-page").then((m) => ({ default: m.RestorePage })))
const ListUpsertPage = lazy(() =>
  import("@/pages/list-upsert-page").then((m) => ({ default: m.ListUpsertPage }))
)
const ListsPage = lazy(() =>
  import("@/pages/lists-page").then((m) => ({ default: m.ListsPage }))
)
const NfqwsPage = lazy(() =>
  import("@/pages/nfqws-page").then((m) => ({ default: m.NfqwsPage }))
)
const OutboundUpsertPage = lazy(() =>
  import("@/pages/outbound-upsert-page").then((m) => ({
    default: m.OutboundUpsertPage,
  }))
)
const OutboundsPage = lazy(() =>
  import("@/pages/outbounds-page").then((m) => ({ default: m.OutboundsPage }))
)
const RoutingRuleUpsertPage = lazy(() =>
  import("@/pages/routing-rule-upsert-page").then((m) => ({
    default: m.RoutingRuleUpsertPage,
  }))
)
const RoutingRulesPage = lazy(() =>
  import("@/pages/routing-rules-page").then((m) => ({
    default: m.RoutingRulesPage,
  }))
)
const TransportsPage = lazy(() =>
  import("@/pages/transports-page").then((m) => ({ default: m.TransportsPage }))
)

/** Shown while a page chunk arrives; on a LAN this is a single frame. */
function PageFallback() {
  return (
    <div className="space-y-3">
      <Skeleton className="h-9 w-64" />
      <Skeleton className="h-5 w-full max-w-xl" />
      <Skeleton className="h-64 w-full" />
    </div>
  )
}

function App() {
  return (
    <AuthGate>
      <AppShell>
        <ScrollToTopOnRouteChange />
        <Suspense fallback={<PageFallback />}>
          <Switch>
            <Route component={OverviewPage} path="/" />
            <Route component={GeneralConfigPage} path="/general" />
            <Route component={BackupPage} path="/backup" />
            <Route component={RestorePage} path="/restore" />
            <Route path="/lists/create">
              <ListUpsertPage mode="create" />
            </Route>
            <Route path="/lists/:listId/edit">
              {(params) => <ListUpsertPage listId={params.listId} mode="edit" />}
            </Route>
            <Route component={CatalogPage} path="/catalog" />
            <Route component={ListsPage} path="/lists" />
            <Route path="/outbounds/create">
              <OutboundUpsertPage mode="create" />
            </Route>
            <Route path="/outbounds/:outboundId/edit">
              {(params) => (
                <OutboundUpsertPage mode="edit" outboundId={params.outboundId} />
              )}
            </Route>
            <Route component={OutboundsPage} path="/outbounds" />
            <Route component={TransportsPage} path="/transports" />
            <Route component={ConnectionsPage} path="/connections" />
            <Route component={NfqwsPage} path="/nfqws" />
            <Route path="/dns-servers/create">
              <DnsServerUpsertPage mode="create" />
            </Route>
            <Route path="/dns-servers/:serverTag/edit">
              {(params) => (
                <DnsServerUpsertPage
                  mode="edit"
                  serverTag={decodeURIComponent(params.serverTag)}
                />
              )}
            </Route>
            <Route component={DnsServersPage} path="/dns-servers" />
            <Route path="/dns-rules/create">
              <DnsRuleUpsertPage mode="create" />
            </Route>
            <Route path="/dns-rules/:ruleIndex/edit">
              {(params) => (
                <DnsRuleUpsertPage mode="edit" ruleIndex={params.ruleIndex} />
              )}
            </Route>
            <Route component={DnsRulesPage} path="/dns-rules" />
            <Route path="/routing-rules/create">
              <RoutingRuleUpsertPage mode="create" />
            </Route>
            <Route path="/routing-rules/:ruleIndex/edit">
              {(params) => (
                <RoutingRuleUpsertPage mode="edit" ruleIndex={params.ruleIndex} />
              )}
            </Route>
            <Route component={RoutingRulesPage} path="/routing-rules" />
            <Route>
              <Redirect to="/" />
            </Route>
          </Switch>
        </Suspense>
      </AppShell>
    </AuthGate>
  )
}

export default App
