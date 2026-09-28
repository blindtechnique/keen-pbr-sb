// Run from frontend after `bun run build` and bundling the sibling fixture to
// <output>/nfqws-draft-editor.js. Requires Playwright; PLAYWRIGHT_MODULE may
// point at an existing shared install. Uses only a loopback mock, never a router.
const http = require("node:http")
const fs = require("node:fs")
const path = require("node:path")
const assert = require("node:assert/strict")
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright")
const output = path.resolve(process.argv[2])
const assets = path.resolve(__dirname, "../../dist/assets")
const css = fs.readdirSync(assets).find((name) => name.endsWith(".css"))
const requests = []
const status = {
  installed: true,
  running: true,
  process_running: true,
  queue_active: true,
  version: "1.3.1",
  files: [],
  active_strategy: "saved",
  strategies: [
    "saved",
    ...Array.from({ length: 9 }, (_, i) => `custom-${i}`),
  ].map((name) => ({
    name,
    builtin: false,
    content: 'NFQWS_OPT="--filter-tcp=443"\n',
  })),
  rotator_state: {
    schema: 1,
    status: "warming",
    observed_at: null,
    truncated: false,
    pools: {},
  },
}
const server = http.createServer(async (req, res) => {
  if (req.url === "/api/nfqws") {
    res.setHeader("Content-Type", "application/json")
    if (req.method === "GET") return res.end(JSON.stringify(status))
    let raw = ""
    for await (const chunk of req) raw += chunk
    const body = JSON.parse(raw)
    requests.push(body)
    if (body.action === "read_file")
      return res.end(JSON.stringify({ content: status.strategies[0].content }))
    if (body.action === "save_strategy") {
      status.strategies = [
        ...status.strategies.filter((s) => s.name !== body.name),
        { name: body.name, builtin: false, content: body.content },
      ]
      return res.end(JSON.stringify({ ok: true }))
    }
    res.statusCode = 400
    return res.end(JSON.stringify({ error: "Unexpected mutation" }))
  }
  if (req.url === "/fixture.js") {
    res.setHeader("Content-Type", "text/javascript")
    return res.end(fs.readFileSync(path.join(output, "nfqws-draft-editor.js")))
  }
  if (req.url === "/fixture.css") {
    res.setHeader("Content-Type", "text/css")
    return res.end(fs.readFileSync(path.join(assets, css)))
  }
  res.setHeader("Content-Type", "text/html")
  res.end(
    '<!doctype html><html lang="ru"><meta charset="utf-8"><link rel="stylesheet" href="/fixture.css"><body style="padding:24px"><div id="root"></div><script type="module" src="/fixture.js"></script></body></html>'
  )
})

;(async () => {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve))
  let browser
  let page
  try {
    browser = await chromium.launch({
      channel: process.env.PLAYWRIGHT_CHANNEL || "msedge",
      headless: true,
    })
    page = await browser.newPage({ viewport: { width: 1200, height: 800 } })
    page.setDefaultTimeout(10000)
    const errors = []
    page.on("pageerror", (error) => errors.push(error.message))
    await page.addInitScript(() => {
      window.editorScrollRequests = 0
      const scroll = Element.prototype.scrollIntoView
      Element.prototype.scrollIntoView = function (options) {
        window.editorScrollRequests += 1
        return scroll.call(this, options)
      }
    })
    await page.goto(`http://127.0.0.1:${server.address().port}`)
    await page
      .getByRole("button", { name: "Новая стратегия", exact: true })
      .click()
    const dialog = page.getByRole("dialog")
    await dialog.getByRole("textbox").fill("test")
    await dialog
      .getByRole("button", { name: "Новая стратегия", exact: true })
      .click()
    const editor = page.locator("textarea")
    await editor.waitFor()
    assert.equal(
      await page
        .getByRole("radio", { name: "Текст", exact: true })
        .getAttribute("aria-checked"),
      "true"
    )
    const content = 'NFQWS_OPT="--filter-tcp=80,443"\n# unsaved draft\n'
    await editor.fill(content)
    const draftRow = page
      .getByRole("row")
      .filter({ has: page.getByRole("button", { name: "test", exact: true }) })
    assert.equal(
      await draftRow
        .getByRole("button", { name: "Применить", exact: true })
        .isDisabled(),
      true
    )
    await page.getByRole("radio", { name: "Разбор", exact: true }).click()
    assert.equal(await page.locator("textarea").count(), 0)
    const before = await page.evaluate(() => window.editorScrollRequests)
    await draftRow.hover()
    await draftRow
      .getByRole("button", { name: "Открыть для правки", exact: true })
      .click()
    await editor.waitFor()
    assert.equal(await editor.inputValue(), content)
    await page.waitForFunction(
      (previous) => window.editorScrollRequests > previous,
      before
    )
    await page.waitForFunction(() => {
      const box = document.querySelector("textarea")?.getBoundingClientRect()
      return box && box.top >= 0 && box.top < innerHeight
    })
    const repeated = await page.evaluate(() => window.editorScrollRequests)
    await draftRow.hover()
    await draftRow
      .getByRole("button", { name: "Открыть для правки", exact: true })
      .focus()
    await page.keyboard.press("Enter")
    await page.waitForFunction(
      (previous) => window.editorScrollRequests > previous,
      repeated
    )
    assert.equal(await editor.inputValue(), content)
    assert.equal(
      await editor.evaluate((element) => element === document.activeElement),
      true
    )
    await page.getByRole("button", { name: "Сохранить", exact: true }).click()
    await page.waitForFunction(
      () => !document.body.textContent.includes("Черновик, не сохранена")
    )
    assert.equal(requests.filter((r) => r.action === "save_strategy").length, 1)
    assert.equal(
      status.strategies.find((s) => s.name === "test").content,
      content
    )
    await page.getByRole("radio", { name: "Разбор", exact: true }).click()
    await draftRow.hover()
    await draftRow
      .getByRole("button", { name: "Открыть для правки", exact: true })
      .click()
    await editor.waitFor()
    assert.equal(await editor.inputValue(), content)
    assert.equal(status.active_strategy, "saved")
    assert.equal(
      requests.some((r) => !["read_file", "save_strategy"].includes(r.action)),
      false
    )
    assert.deepEqual(errors, [])
    await page.screenshot({
      path: path.join(output, "nfqws-draft-editor.png"),
      fullPage: true,
    })
    console.log(
      "PASS create draft -> text; pencil -> text + scroll; repeated/keyboard open; save/reopen; no apply/restart"
    )
  } catch (error) {
    if (page) {
      await page.screenshot({
        path: path.join(output, "nfqws-draft-editor-failure.png"),
        fullPage: true,
      })
      console.error((await page.locator("body").innerText()).slice(-6000))
    }
    throw error
  } finally {
    if (browser) await browser.close()
    await new Promise((resolve) => server.close(resolve))
  }
})().catch((error) => {
  console.error(error)
  process.exitCode = 1
})
