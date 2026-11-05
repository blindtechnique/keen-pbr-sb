// After bun run build: node --test tests/browser/dns-compat-routing-footer.browser.cjs
// Like the nfqws browser smoke, PLAYWRIGHT_MODULE may point to a shared install.
const assert = require("node:assert/strict")
const path = require("node:path")
const { after, before, test } = require("node:test")
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright")

const dist = path.resolve(__dirname, "../../dist")
const origin = "http://127.0.0.1:12129"
let browser
before(async () => {
  browser = await chromium.launch({
    channel: process.env.PLAYWRIGHT_CHANNEL || "msedge",
  })
})
after(() => browser?.close())

async function fixture(
  t,
  { legacy = false, loggedIn = true, mobile = false } = {}
) {
  const context = await browser.newContext({
    locale: "ru-RU",
    serviceWorkers: "block",
    isMobile: mobile,
    hasTouch: mobile,
  })
  t.after(() => context.close())
  const page = await context.newPage()
  page.setDefaultTimeout(6500)
  const errors = []
  const writes = []
  page.on("pageerror", (error) => errors.push(error.message))
  let isDraft = false
  let config = {
    lists: { sites: { domains: ["example.invalid"] } },
    outbounds: [{ tag: "vpn", type: "interface", interface: "nwg0" }],
    route: {
      rules: [
        {
          id: "local_rule",
          display_name: "Тестовое правило",
          list: ["sites"],
          outbound: "vpn",
        },
      ],
    },
    dns: {
      servers: [{ tag: "primary", address: "192.0.2.53" }],
      fallback: ["primary"],
      rules: Array.from({ length: 7 }, (_, i) => ({
        id: "dns_" + i,
        list: ["sites"],
        enabled: null,
        ...(legacy
          ? { server: "primary", servers: null }
          : { servers: ["primary"] }),
      })),
    },
  }
  // Every request is fulfilled locally; never forward a login, API call or asset request.
  await context.route("**/*", async (route) => {
    const req = route.request()
    const url = new URL(req.url())
    if (url.origin !== origin) return route.abort()
    const endpoint = url.pathname
    const json = (body, status = 200) => route.fulfill({ status, json: body })
    if (endpoint === "/api/auth/status")
      return json({ enabled: true, authenticated: loggedIn, provider: "local" })
    if (req.method() !== "GET") {
      // The shell checks nfqws updates with a read-only POST.
      if (
        endpoint === "/api/nfqws" &&
        req.postDataJSON()?.action === "check_update"
      )
        return json({ error: "No update source in fixture" }, 503)
      // The lists page reads its visible rows with POST, including when the editor closes.
      if (
        loggedIn &&
        endpoint === "/api/lists/query" &&
        req.method() === "POST"
      ) {
        const { limit = 50, offset = 0 } = req.postDataJSON()
        const rows = Object.entries(config.lists).map(([id, list]) => ({
          id,
          display_name: list.display_name,
          domain_count: list.domains?.length ?? 0,
          ipv4_count: 0,
          ipv6_count: 0,
        }))
        return json({
          items: rows.slice(offset, offset + limit),
          total: rows.length,
          filtered_total: rows.length,
          offset,
          limit,
          has_refreshable_lists: false,
          is_draft: isDraft,
          revision: (isDraft ? "2" : "1").repeat(64),
        })
      }
      if (
        loggedIn &&
        endpoint === "/api/config/dependencies" &&
        req.method() === "POST"
      )
        return json(
          { error: "Dependency preview not provided by fixture" },
          503
        )
      writes.push(endpoint)
      if (endpoint === "/api/auth/login" && req.method() === "POST") {
        loggedIn = true
        return json({ ok: true })
      }
      if (loggedIn && endpoint === "/api/config" && req.method() === "POST") {
        config = req.postDataJSON()
        isDraft = true
        return json({ status: "ok" })
      }
      return json({ error: "Unexpected write" }, 405)
    }
    if (endpoint.startsWith("/api/")) {
      if (!loggedIn) return json({ error: "unauthenticated" }, 401)
      if (endpoint === "/api/config")
        return json({
          config,
          is_draft: isDraft,
          revision: (isDraft ? "2" : "1").repeat(64),
          list_refresh_state: {},
        })
      if (endpoint === "/api/runtime/outbounds") return json({ outbounds: [] })
      if (endpoint === "/api/runtime/interfaces")
        return json({ interfaces: [] })
      if (req.resourceType() === "eventsource")
        return route.fulfill({ status: 204 })
      return json({ error: "Not provided by fixture" }, 503)
    }
    const relative = endpoint.replace(/^\/+/, "")
    const file = path.resolve(
      dist,
      path.extname(relative) ? relative : "index.html"
    )
    if (!file.startsWith(dist + path.sep)) return route.abort()
    return route.fulfill({ path: file })
  })
  return { page, writes, errors }
}

test("the authenticated app mounts with seven legacy DNS rules from GET /api/config", async (t) => {
  const { page, writes, errors } = await fixture(t, {
    legacy: true,
    loggedIn: false,
  })
  await page.goto(origin)
  const login = page.getByRole("form")
  await login.locator('input[type="password"]').fill("fixture-only")
  await login.getByRole("button", { name: "Войти", exact: true }).click()
  try {
    // The rule is data from the config, not just a shell rendered before /api/config returns.
    await page
      .getByRole("link", { name: "Правила маршрутизации", exact: true })
      .first()
      .click()
    await page
      .getByText("Тестовое правило", { exact: true })
      .filter({ visible: true })
      .first()
      .waitFor()
  } finally {
    assert.deepEqual(errors, [])
  }
  assert.deepEqual(writes, ["/api/auth/login"])
})

async function verifyEditorActions(t, editor) {
  const phone = await fixture(t, { mobile: true })
  const desktop = await fixture(t)
  const edit = editor.base + "/" + editor.id + "/edit"
  for (const [width, route, count] of [
    [320, edit, 3],
    [360, edit, 3],
    [390, edit, 3],
    [320, edit + "?view=page", 3],
    [320, editor.base + "/create", 2],
    [1280, edit, 3],
  ]) {
    const { page, writes } = width < 640 ? phone : desktop
    await page.setViewportSize({ width, height: width === 320 ? 568 : 800 })
    await page.goto(origin + route)
    const footer = page.locator("[data-upsert-actions]")
    await footer.scrollIntoViewIfNeeded()
    await page.evaluate(() => document.fonts.ready.then(() => undefined))
    const boxes = await footer
      .locator(":scope > button")
      .evaluateAll((buttons) =>
        buttons.map((button) => {
          const r = button.getBoundingClientRect()
          return {
            label: button.textContent.trim(),
            left: r.left,
            right: r.right,
            top: r.top,
            bottom: r.bottom,
            height: r.height,
            clipped: button.scrollWidth > button.clientWidth + 1,
          }
        })
      )
    const label = width + "px " + route + ": " + JSON.stringify(boxes)
    assert.deepEqual(
      boxes.map((b) => b.label),
      count === 3
        ? ["Удалить", "Отмена", editor.save]
        : ["Отмена", editor.create],
      label
    )
    assert.ok(
      boxes.every((b) => b.left >= 0 && b.right <= width + 1 && !b.clipped),
      label
    )
    if (width < 640) {
      const overflow = await footer.evaluate((element) => {
        const body =
          element.closest(".upsert-dialog-body") ?? document.documentElement
        return Math.max(
          element.scrollWidth - element.clientWidth,
          body.scrollWidth - body.clientWidth,
          document.documentElement.scrollWidth -
            document.documentElement.clientWidth
        )
      })
      assert.ok(overflow <= 1, label + " overflow=" + overflow)
      assert.ok(
        boxes.every((b) => b.height >= 44),
        label
      )
      assert.ok(boxes.at(-1).top >= boxes.at(-2).bottom, label)
      assert.ok(Math.abs(boxes.at(-1).left - boxes[0].left) <= 1, label)
      assert.ok(Math.abs(boxes.at(-1).right - boxes.at(-2).right) <= 1, label)
      if (count === 3) assert.ok(boxes[0].right < boxes[1].left, label)
    } else {
      assert.ok(
        boxes.every((b) => Math.abs(b.top - boxes[0].top) <= 1),
        label
      )
    }
    assert.ok(await footer.locator('button[type="submit"]').isDisabled())
    if (width === 360) {
      if (process.env[editor.screenshot])
        await page.screenshot({ path: process.env[editor.screenshot] })
      await footer.getByRole("button", { name: "Удалить", exact: true }).tap()
      await page
        .getByRole("dialog")
        .filter({
          has: page.getByRole("button", { name: "Отмена", exact: true }),
        })
        .last()
        .getByRole("button", { name: "Отмена", exact: true })
        .tap()
      await footer.getByRole("button", { name: "Отмена", exact: true }).tap()
      await page.waitForURL(origin + editor.back)
      assert.deepEqual(writes, [])
    } else if (width === 390) {
      await page.locator(editor.nameField).fill("Новое имя")
      const submitted = page.waitForRequest(
        (req) =>
          req.method() === "POST" &&
          new URL(req.url()).pathname === "/api/config"
      )
      await footer.getByRole("button", { name: editor.save, exact: true }).tap()
      const staged = (await submitted).postDataJSON()
      assert.equal(editor.savedName(staged), "Новое имя")
      await page.waitForURL(origin + editor.back)
    }
  }
  assert.deepEqual([...phone.errors, ...desktop.errors], [])
  assert.deepEqual(phone.writes, ["/api/config"])
  assert.deepEqual(desktop.writes, [])
}

for (const editor of [
  {
    base: "/routing-rules",
    back: "/routing-rules",
    id: "local_rule",
    nameField: "#routing-rule-display-name",
    save: "Сохранить правило",
    create: "Создать правило",
    savedName: (c) =>
      c.route.rules.length === 1 && c.route.rules[0].display_name,
    screenshot: "ROUTING_FOOTER_SCREENSHOT",
  },
  {
    base: "/lists",
    back: "/lists",
    id: "sites",
    nameField: "#list-display-name",
    save: "Сохранить список",
    create: "Создать список",
    savedName: (c) => c.lists.sites.display_name,
    screenshot: "LIST_FOOTER_SCREENSHOT",
  },
  {
    base: "/dns-servers",
    back: "/dns-servers",
    id: "primary",
    nameField: "#dns-server-display-name",
    save: "Сохранить DNS-сервер",
    create: "Создать DNS-сервер",
    savedName: (c) =>
      c.dns.servers.find((s) => s.tag === "primary")?.display_name,
    screenshot: "DNS_SERVER_FOOTER_SCREENSHOT",
  },
]) {
  test(
    editor.base +
      ": responsive actions, safe cancel/delete and single draft save",
    (t) => verifyEditorActions(t, editor)
  )
}
