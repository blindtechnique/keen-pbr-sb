import { expect, test } from "bun:test"
import { readFileSync } from "node:fs"

const source = (path: string) =>
  readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8")

test("the sing-box card operates on the service once, not competing member commands", () => {
  const card = source("components/overview/services-status-card.tsx")
  expect(card).toContain("postSingBoxServiceAction")
  expect(card).not.toContain("postTransportAction")
  expect(card).not.toContain("usePostTransportActionMutation")
  expect(card).toContain('singboxServiceMutation.mutate("restart")')
})

test("routing list selector explains installed lists and links to list management", () => {
  const page = source("pages/routing-rule-upsert-page.tsx")
  expect(
    /addLabel=\{t\(\s*"pages\.routingRuleUpsert\.fields\.selectInstalledList"\s*\)\}/.test(
      page
    )
  ).toBe(true)
  // A real link retains the UpsertPage beforeunload warning for dirty forms.
  expect(page).toContain('href="/lists"')
  expect(page).toContain('t("pages.routingRuleUpsert.fields.openLists")')
})

test("quick DNS selector receives alias items, as does the advanced editor", () => {
  const page = source("pages/list-upsert-page.tsx")
  expect(page.match(/items=\{createListDnsServerSelectItems\(/g)).toHaveLength(
    1
  )
  expect(page).toContain("compatibleDnsServers")
})
