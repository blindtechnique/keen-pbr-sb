import { describe, expect, test } from "bun:test"
import { escapeHTML } from "bun"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"
import { Router } from "wouter"

import {
  RuntimeEventsCard,
  type RuntimeEventView,
} from "../src/components/overview/runtime-events-card"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

async function render(
  events: readonly RuntimeEventView[],
  state: "loading" | "ready" | "error" = "ready",
  language: "ru" | "en" = "ru"
) {
  const local = createInstance()
  const translation = language === "ru" ? ruTranslation : enTranslation
  await local.init({
    lng: language,
    resources: { [language]: { translation } },
  })
  return renderToStaticMarkup(
    <I18nextProvider i18n={local}>
      <Router ssrPath="/">
        <RuntimeEventsCard events={events} state={state} />
      </Router>
    </I18nextProvider>
  )
}

const event: RuntimeEventView = {
  id: "event-1",
  text: "AWG North: связь восстановлена",
  timestamp: "2026-09-06 16:42:21",
  tone: "success",
  href: "/transports#groups",
}

describe("important runtime events dashboard card", () => {
  test.each(["ru", "en"] as const)(
    "renders localized empty/loading/failure states without claiming health in %s",
    async (language) => {
      const copy = (language === "ru" ? ruTranslation : enTranslation).overview
        .runtimeEvents
      const empty = await render([], "ready", language)
      expect(empty).toContain(copy.title)
      expect(empty).toContain(copy.description)
      expect(empty).toContain(copy.empty)
      expect(empty).not.toContain("overview.runtimeEvents.")
      expect(empty).not.toContain("<ol")
      const pending = await render([], "loading", language)
      expect(pending).toContain(copy.loading)
      expect(pending).not.toContain(copy.empty)
      const error = await render([], "error", language)
      expect(error).toContain(copy.loadFailed)
      expect(error).not.toContain(copy.empty)
      expect(error).not.toContain(copy.stale)
    }
  )

  test.each(["ru", "en"] as const)(
    "keeps previous events with an explicit stale message and real links in %s",
    async (language) => {
      const copy = (language === "ru" ? ruTranslation : enTranslation).overview
        .runtimeEvents
      const html = await render([event], "error", language)
      expect(html).toContain(copy.stale)
      expect(html).not.toContain(copy.loadFailed)
      expect(html).toContain(event.text)
      expect(html).toContain('href="/general#logging"')
      expect(html).toContain('href="/transports#groups"')
      expect(html).toContain(copy.openJournal)
      expect(html).toContain(copy.openDetails)
      expect(html).toContain(`title="${escapeHTML(copy.observedTime)}"`)
      expect(html).toContain(event.timestamp)
      expect(html).not.toContain("datetime=")
    }
  )

  test("shows five newest supplied entries initially without reordering them", async () => {
    const events = Array.from({ length: 25 }, (_, index) => ({
      ...event,
      id: `event-${index}`,
      text: `Provided-event-${index}-end`,
    }))
    const html = await render(events)
    expect(html.match(/<li /g)).toHaveLength(5)
    for (let index = 0; index < 5; index++) {
      expect(html).toContain(events[index].text)
    }
    expect(html).not.toContain(events[5].text)
    expect(html.indexOf(events[0].text)).toBeLessThan(
      html.indexOf(events[1].text)
    )
    expect(html).toContain('aria-expanded="false"')
    expect(html).toContain('aria-controls="')
    expect(html).toContain(ruTranslation.overview.runtimeEvents.showMore)
  })

  test("does not offer expansion for five or fewer events and retains old entries during refresh", async () => {
    const html = await render([event], "loading")
    expect(html).toContain(event.text)
    expect(html).toContain(ruTranslation.overview.runtimeEvents.loading)
    expect(html).not.toContain("aria-expanded=")
  })

  test("escapes event aliases and link attributes, and wraps long mobile text", async () => {
    const alias = '<img src=x onerror="alert(1)"> &' + "LongVPN".repeat(50)
    const html = await render([
      { ...event, text: alias, href: '/transports?tag=a&name="quoted"' },
    ])
    expect(html).not.toContain("<img")
    expect(html).toContain("&lt;img")
    expect(html).toContain("&amp;")
    expect(html).toContain("&quot;quoted&quot;")
    expect(html).toContain("LongVPN".repeat(50))
    expect(html).toContain("[overflow-wrap:anywhere]")
    expect(html).toContain("flex-wrap")
    expect(html).not.toContain("<table")
  })

  test("distinguishes event tones with icons as well as color", async () => {
    const html = await render(
      (["info", "warning", "success"] as const).map((tone) => ({
        ...event,
        id: tone,
        tone,
      }))
    )
    expect(html).toContain("lucide-info")
    expect(html).toContain("lucide-circle-alert")
    expect(html).toContain("lucide-circle-check")
    expect(html.match(/<li /g)).toHaveLength(3)
  })

  test("expansion stays bounded in component state without fetching or storing history", async () => {
    const source = await Bun.file(
      new URL(
        "../src/components/overview/runtime-events-card.tsx",
        import.meta.url
      )
    ).text()
    expect(source).toContain("events.slice(0, expanded ? 20 : 5)")
    expect(source).toContain("setExpanded((value) => !value)")
    expect(source).toContain('t("overview.runtimeEvents.showLess")')
    expect(source).not.toMatch(
      /localStorage|sessionStorage|useQuery|useMutation|fetch\(|setInterval|setTimeout|new Date/
    )
  })
})
