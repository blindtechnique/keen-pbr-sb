import { Suspense, lazy } from "react"
import { useTranslation } from "react-i18next"
import { Redirect, Route, Switch, useSearch } from "wouter"

import { AppShell } from "@/components/layout/app-shell"
import { AuthGate } from "@/components/auth-gate"
import { ScrollToTopOnRouteChange } from "@/components/layout/scroll-route"
import { KeenSpinner } from "@/components/shared/keen-spinner"
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
const RulesPage = lazy(() =>
  import("@/pages/rules-page").then((m) => ({ default: m.RulesPage }))
)
const RoutesAndTunnelsPage = lazy(() =>
  import("@/pages/routes-and-tunnels-page").then((m) => ({
    default: m.RoutesAndTunnelsPage,
  }))
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
const BackupPage = lazy(() =>
  import("@/pages/backup-page").then((m) => ({ default: m.BackupPage }))
)
const RestorePage = lazy(() =>
  import("@/pages/backup-page").then((m) => ({ default: m.RestorePage }))
)
const ListUpsertPage = lazy(() =>
  import("@/pages/list-upsert-page").then((m) => ({
    default: m.ListUpsertPage,
  }))
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
const RoutingRuleUpsertPage = lazy(() =>
  import("@/pages/routing-rule-upsert-page").then((m) => ({
    default: m.RoutingRuleUpsertPage,
  }))
)
const TransportUpsertPage = lazy(() =>
  import("@/pages/transport-upsert-page").then((m) => ({
    default: m.TransportUpsertPage,
  }))
)

/**
 * Пока приезжает код страницы.
 *
 * Здесь стоял скелетон из трёх серых полос. Он отвечает на вопрос «что тут
 * будет», а при переходе между страницами вопрос другой — «оно грузится или
 * зависло». Конфигуратор на этот вопрос отвечает вращающимся индикатором,
 * и это правильный ответ: полосы, которые просто лежат, от зависшей страницы
 * не отличить.
 */
function PageFallback() {
  const { t } = useTranslation()

  return (
    <div className="flex min-h-[50vh] flex-1 items-center justify-center">
      <KeenSpinner label={t("common.loading")} />
    </div>
  )
}

function useEditorPresentation() {
  const search = useSearch()
  return new URLSearchParams(search).get("view") === "page" ? "page" : "dialog"
}

function ListEditorRoute({
  mode,
  listId,
}: {
  mode: "create" | "edit"
  listId?: string
}) {
  const presentation = useEditorPresentation()

  if (presentation === "page") {
    return <ListUpsertPage listId={listId} mode={mode} presentation="page" />
  }

  return (
    <>
      <ListsPage />
      <ListUpsertPage listId={listId} mode={mode} presentation="dialog" />
    </>
  )
}

function DnsServerEditorRoute({
  mode,
  serverTag,
}: {
  mode: "create" | "edit"
  serverTag?: string
}) {
  const presentation = useEditorPresentation()

  if (presentation === "page") {
    return (
      <DnsServerUpsertPage
        mode={mode}
        presentation="page"
        serverTag={serverTag}
      />
    )
  }

  return (
    <>
      <DnsServersPage />
      <DnsServerUpsertPage
        mode={mode}
        presentation="dialog"
        serverTag={serverTag}
      />
    </>
  )
}

function RoutingRuleEditorRoute({
  mode,
  ruleId,
}: {
  mode: "create" | "edit"
  ruleId?: string
}) {
  const presentation = useEditorPresentation()

  if (presentation === "page") {
    return (
      <RoutingRuleUpsertPage mode={mode} presentation="page" ruleId={ruleId} />
    )
  }

  return (
    <>
      <RulesPage />
      <RoutingRuleUpsertPage
        mode={mode}
        presentation="dialog"
        ruleId={ruleId}
      />
    </>
  )
}

function DnsRuleEditorRoute({
  mode,
  ruleId,
}: {
  mode: "create" | "edit"
  ruleId?: string
}) {
  const presentation = useEditorPresentation()

  if (presentation === "page") {
    return <DnsRuleUpsertPage mode={mode} presentation="page" ruleId={ruleId} />
  }

  return (
    <>
      <RulesPage initialTab="dns" />
      <DnsRuleUpsertPage mode={mode} presentation="dialog" ruleId={ruleId} />
    </>
  )
}

function OutboundEditorRoute({
  mode,
  outboundId,
}: {
  mode: "create" | "edit"
  outboundId?: string
}) {
  const presentation = useEditorPresentation()

  if (presentation === "page") {
    return (
      <OutboundUpsertPage
        mode={mode}
        outboundId={outboundId}
        presentation="page"
      />
    )
  }

  return (
    <>
      <RoutesAndTunnelsPage initialTab="interfaces" />
      <OutboundUpsertPage
        mode={mode}
        outboundId={outboundId}
        presentation="dialog"
      />
    </>
  )
}

function TransportEditorRoute({
  mode,
  transportTag,
}: {
  mode: "create" | "edit"
  transportTag?: string
}) {
  const presentation = useEditorPresentation()

  if (presentation === "page") {
    return (
      <TransportUpsertPage
        mode={mode}
        presentation="page"
        transportTag={transportTag}
      />
    )
  }

  return (
    <>
      <RoutesAndTunnelsPage />
      <TransportUpsertPage
        mode={mode}
        presentation="dialog"
        transportTag={transportTag}
      />
    </>
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
              <ListEditorRoute mode="create" />
            </Route>
            <Route path="/lists/:listId/edit">
              {(params) => (
                <ListEditorRoute listId={params.listId} mode="edit" />
              )}
            </Route>
            <Route component={CatalogPage} path="/catalog" />
            <Route component={ListsPage} path="/lists" />
            <Route path="/outbounds/create">
              <OutboundEditorRoute mode="create" />
            </Route>
            <Route path="/outbounds/:outboundId/edit">
              {(params) => (
                <OutboundEditorRoute
                  mode="edit"
                  outboundId={params.outboundId}
                />
              )}
            </Route>
            <Route path="/outbounds">
              <RoutesAndTunnelsPage initialTab="interfaces" />
            </Route>
            <Route path="/transports/create">
              <TransportEditorRoute mode="create" />
            </Route>
            <Route path="/transports/:transportTag/edit">
              {(params) => (
                <TransportEditorRoute
                  mode="edit"
                  transportTag={decodeURIComponent(params.transportTag)}
                />
              )}
            </Route>
            <Route path="/transports">
              <RoutesAndTunnelsPage />
            </Route>
            <Route component={ConnectionsPage} path="/connections" />
            <Route component={NfqwsPage} path="/nfqws" />
            <Route path="/dns-servers/create">
              <DnsServerEditorRoute mode="create" />
            </Route>
            <Route path="/dns-servers/:serverTag/edit">
              {(params) => (
                <DnsServerEditorRoute
                  mode="edit"
                  serverTag={decodeURIComponent(params.serverTag)}
                />
              )}
            </Route>
            <Route component={DnsServersPage} path="/dns-servers" />
            <Route path="/dns-rules/create">
              <DnsRuleEditorRoute mode="create" />
            </Route>
            <Route path="/dns-rules/:ruleId/edit">
              {(params) => (
                <DnsRuleEditorRoute
                  mode="edit"
                  ruleId={decodeURIComponent(params.ruleId)}
                />
              )}
            </Route>
            <Route path="/dns-rules">
              <RulesPage initialTab="dns" />
            </Route>
            <Route path="/routing-rules/create">
              <RoutingRuleEditorRoute mode="create" />
            </Route>
            <Route path="/routing-rules/:ruleId/edit">
              {(params) => (
                <RoutingRuleEditorRoute
                  mode="edit"
                  ruleId={decodeURIComponent(params.ruleId)}
                />
              )}
            </Route>
            <Route path="/routing-rules">
              <RulesPage />
            </Route>
            <Route path="/rules">
              <RulesPage />
            </Route>
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
