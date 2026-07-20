import { Redirect, Route, Switch } from "wouter"

import { AppShell } from "@/components/layout/app-shell"
import { AuthGate } from "@/components/auth-gate"
import { ScrollToTopOnRouteChange } from "@/components/layout/scroll-route"
import { CatalogPage } from "@/pages/catalog-page"
import { DnsRuleUpsertPage } from "@/pages/dns-rule-upsert-page"
import { DnsRulesPage } from "@/pages/dns-rules-page"
import { DnsServersPage } from "@/pages/dns-servers-page"
import { DnsServerUpsertPage } from "@/pages/dns-servers-upsert-page"
import { GeneralConfigPage } from "@/pages/general-config-page"
import { ListUpsertPage } from "@/pages/list-upsert-page"
import { ListsPage } from "@/pages/lists-page"
import { OutboundUpsertPage } from "@/pages/outbound-upsert-page"
import { OutboundsPage } from "@/pages/outbounds-page"
import { OverviewPage } from "@/pages/overview-page"
import { RoutingRuleUpsertPage } from "@/pages/routing-rule-upsert-page"
import { RoutingRulesPage } from "@/pages/routing-rules-page"
import { TransportsPage } from "@/pages/transports-page"
import { ConnectionsPage } from "@/pages/connections-page"
import { NfqwsPage } from "@/pages/nfqws-page"

function App() {
  return (
    <AuthGate>
      <AppShell>
        <ScrollToTopOnRouteChange />
        <Switch>
          <Route component={OverviewPage} path="/" />
          <Route component={GeneralConfigPage} path="/general" />
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
      </AppShell>
    </AuthGate>
  )
}

export default App
