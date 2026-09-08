import { describe, expect, mock, spyOn, test } from "bun:test"
import { createInstance } from "i18next"
import type { ReactNode } from "react"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"

import type {
  PeriodicTaskMetricsEntry,
  PeriodicTaskMetricsResponse,
} from "../src/api/generated/model"
import {
  BackgroundTasksDetails,
  BackgroundTasksResult,
} from "../src/components/settings/background-tasks-details"
import {
  backgroundTaskNextRun,
  backgroundTaskNumber,
  backgroundTaskOutcome,
  backgroundTaskTitle,
  createBackgroundTaskRequest,
  loadBackgroundTasks,
  type BackgroundTaskState,
} from "../src/components/settings/background-tasks-model"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

const nextRun = Date.UTC(2026, 8, 8, 12, 34, 56)

function task(
  overrides: Partial<PeriodicTaskMetricsEntry> = {}
): PeriodicTaskMetricsEntry {
  return {
    label: "resolver-hash-refresh",
    runs: 5,
    success: 1,
    noop: 1,
    failure: 2,
    skipped: 1,
    abandoned: 0,
    in_flight: 0,
    total_duration_ms: 200,
    max_duration_ms: 100,
    last_duration_ms: 0,
    last_outcome: "failure",
    consecutive_failures: 2,
    scheduling_state: "scheduled",
    next_run_at_unix_ms: nextRun,
    ...overrides,
  }
}

function snapshot(tasks = [task()]): PeriodicTaskMetricsResponse {
  return { capacity: 32, tracked: tasks.length, tasks }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((yes, no) => {
    resolve = yes
    reject = no
  })
  return { promise, resolve, reject }
}

async function translations(language = "ru") {
  const i18n = createInstance()
  await i18n.init({
    lng: language,
    resources: {
      ru: { translation: ruTranslation },
      en: { translation: enTranslation },
    },
    interpolation: { escapeValue: false },
  })
  return i18n
}

async function render(node: ReactNode, language = "ru") {
  const i18n = await translations(language)
  return renderToStaticMarkup(
    <I18nextProvider i18n={i18n}>{node}</I18nextProvider>
  )
}

describe("explicit background task diagnostics", () => {
  test("the detail view starts closed and neither rendering nor session creation loads it", async () => {
    const request = mock(async () => snapshot())
    const session = createBackgroundTaskRequest(request, () => {})
    const html = await render(<BackgroundTasksDetails request={request} />)
    expect(request).not.toHaveBeenCalled()
    expect(html).toContain("Фоновые задачи")
    expect(html).not.toMatch(/<details[^>]*\sopen(?:=|>)/)
    expect(html).not.toContain('role="dialog"')
    session.dispose()
  })

  test("an explicit load is single-flight and has no automatic retry after failure", async () => {
    const pending = deferred<PeriodicTaskMetricsResponse>()
    const request = mock(() => pending.promise)
    const states: BackgroundTaskState[] = []
    const session = createBackgroundTaskRequest(request, (state) =>
      states.push(state)
    )
    const loading = session.load()
    await session.load()
    expect(request).toHaveBeenCalledTimes(1)
    pending.reject(new Error("temporary failure"))
    await loading
    expect(states).toEqual([{ status: "loading" }, { status: "failed" }])
    expect(request).toHaveBeenCalledTimes(1)
    request.mockResolvedValue(snapshot())
    await session.load()
    expect(request).toHaveBeenCalledTimes(2)
    expect(states.at(-1)).toEqual({ status: "ready", result: snapshot() })
    session.dispose()
  })

  for (const fails of [false, true]) {
    test(
      "closing discards a late " +
        (fails ? "failure" : "success") +
        " without overwriting a reopened view",
      async () => {
        const old = deferred<PeriodicTaskMetricsResponse>()
        const current = deferred<PeriodicTaskMetricsResponse>()
        const signals: AbortSignal[] = []
        const request = mock((signal: AbortSignal) => {
          signals.push(signal)
          return signals.length === 1 ? old.promise : current.promise
        })
        const states: BackgroundTaskState[] = []
        const session = createBackgroundTaskRequest(request, (state) =>
          states.push(state)
        )
        const first = session.load()
        session.cancel()
        expect(signals[0].aborted).toBe(true)
        const second = session.load()
        const fresh = snapshot([task({ consecutive_failures: 0 })])
        current.resolve(fresh)
        await second
        if (fails) old.reject(new Error("old error"))
        else old.resolve(snapshot())
        await first
        expect(states).toEqual([
          { status: "loading" },
          { status: "loading" },
          { status: "ready", result: fresh },
        ])
        session.dispose()
      }
    )
  }

  test("session cleanup aborts a pending GET and prevents late state or later requests", async () => {
    const pending = deferred<PeriodicTaskMetricsResponse>()
    const request = mock((signal: AbortSignal) => {
      void signal // Preserve typed mock arguments for the abort assertion below.
      return pending.promise
    })
    const states: BackgroundTaskState[] = []
    const session = createBackgroundTaskRequest(request, (state) =>
      states.push(state)
    )
    const loading = session.load()
    session.dispose()
    expect(request.mock.calls[0][0].aborted).toBe(true)
    pending.resolve(snapshot())
    await loading
    await session.load()
    expect(request).toHaveBeenCalledTimes(1)
    expect(states).toEqual([{ status: "loading" }])
  })

  test("the generated GET keeps the new snapshot fields and does not invent old-server values", async () => {
    const oldTask = task()
    delete oldTask.consecutive_failures
    delete oldTask.scheduling_state
    delete oldTask.next_run_at_unix_ms
    const values = [snapshot(), snapshot([oldTask])]
    const requests: Array<{ input: RequestInfo | URL; init?: RequestInit }> = []
    const fetchMock = spyOn(globalThis, "fetch").mockImplementation(
      async (input, init) => {
        requests.push({ input, init })
        return Response.json(values[requests.length - 1])
      }
    )
    try {
      const controller = new AbortController()
      expect(await loadBackgroundTasks(controller.signal)).toEqual(values[0])
      const old = await loadBackgroundTasks(controller.signal)
      expect(old.tasks[0].consecutive_failures).toBeUndefined()
      expect(old.tasks[0].scheduling_state).toBeUndefined()
      expect(old.tasks[0].next_run_at_unix_ms).toBeUndefined()
      expect(requests).toHaveLength(2)
      for (const request of requests) {
        expect(String(request.input)).toBe("/api/diagnostics/tasks")
        expect(request.init?.method).toBe("GET")
        expect(request.init?.cache).toBe("no-store")
        expect(request.init?.signal).toBe(controller.signal)
      }
    } finally {
      fetchMock.mockRestore()
    }
  })

  test("an unavailable or malformed endpoint is not shown as an empty successful snapshot", async () => {
    for (const response of [
      Response.json({ error: "unavailable" }, { status: 503 }),
      Response.json({ tasks: null }),
    ]) {
      const fetchMock = spyOn(globalThis, "fetch").mockResolvedValue(response)
      try {
        await expect(
          loadBackgroundTasks(new AbortController().signal)
        ).rejects.toBeDefined()
        expect(fetchMock).toHaveBeenCalledTimes(1)
      } finally {
        fetchMock.mockRestore()
      }
    }
  })
})

describe("localized task snapshot presentation", () => {
  for (const language of ["ru", "en"]) {
    test(
      "finite task names and outcomes are localized in " + language,
      async () => {
        const i18n = await translations(language)
        const labels = [
          "resolver-hash-refresh",
          "keenetic-dns-refresh",
          "owned-snat-health",
          "interface-probe",
          "interface-traffic-sample",
        ]
        const outcomes = [
          "success",
          "noop",
          "failure",
          "skipped",
          "abandoned",
        ] as const
        const html = await render(
          <BackgroundTasksResult
            result={snapshot(
              labels.map((label, index) =>
                task({ label, last_outcome: outcomes[index] })
              )
            )}
          />,
          language
        )
        for (const [index, label] of labels.entries()) {
          expect(html).toContain(backgroundTaskTitle(label, i18n.t))
          expect(html).toContain(label)
          expect(html).toContain(backgroundTaskOutcome(outcomes[index], i18n.t))
          expect(html).not.toContain("<dd>" + outcomes[index] + "</dd>")
        }
        expect(html).toContain(i18n.t("backgroundTasks.nextRun"))
        expect(html).toContain(
          i18n.t("backgroundTasks.milliseconds", { value: "0" })
        )
      }
    )
  }

  test("actual scheduled time is absolute; no timer and missing metadata remain distinct", async () => {
    const i18n = await translations()
    const scheduled = backgroundTaskNextRun(task(), i18n.t, "ru", "UTC")
    expect(scheduled).toContain("08.09.2026")
    expect(scheduled).toContain("12:34:56")
    expect(
      backgroundTaskNextRun(
        task({ scheduling_state: "not_scheduled" }),
        i18n.t,
        "ru",
        "UTC"
      )
    ).toBe("Пока не назначен")
    for (const entry of [
      task({ scheduling_state: undefined }),
      task({ scheduling_state: "unknown" }),
      task({ scheduling_state: "future-state" }),
      task({ next_run_at_unix_ms: undefined }),
      task({ next_run_at_unix_ms: NaN }),
      task({ next_run_at_unix_ms: Number.MAX_SAFE_INTEGER }),
    ]) {
      expect(backgroundTaskNextRun(entry, i18n.t, "ru", "UTC")).toBe(
        "Нет данных"
      )
    }
    expect(backgroundTaskNumber(0, "ru")).toBe("0")
    for (const value of [undefined, -1, NaN, Infinity, 1.5]) {
      expect(backgroundTaskNumber(value, "ru")).toBeNull()
    }
  })

  test("in-flight work coexists with its next run and unknown fields never become zero or disabled", async () => {
    const html = await render(
      <BackgroundTasksResult
        result={snapshot([
          task({ in_flight: 3, consecutive_failures: 0 }),
          task({
            label: "future-task",
            last_outcome: undefined,
            consecutive_failures: undefined,
            scheduling_state: undefined,
            last_duration_ms: undefined,
          }),
        ])}
      />
    )
    expect(html).toContain("<dd>3</dd>")
    expect(html).toContain("Ошибок подряд</dt><dd>0</dd>")
    expect(html).toContain("Ошибок подряд</dt><dd>Нет данных</dd>")
    expect(html).toContain("Следующий плановый вызов")
    expect(html).toContain("Фоновая задача")
    expect(html).toContain("future-task")
    expect(html).not.toContain("Отключена")
    expect(html).not.toContain("Повтор через")
  })

  test("empty snapshots and escaped technical detail stay inside the detailed view", async () => {
    const empty = await render(<BackgroundTasksResult result={snapshot([])} />)
    expect(empty).toContain(
      "В этом снимке нет зарегистрированных фоновых задач."
    )
    const html = await render(
      <BackgroundTasksResult
        result={snapshot([
          task({
            label: "<script>task</script>",
            last_error: "<img src=x onerror=alert(1)>\nline two",
          }),
        ])}
      />
    )
    expect(html).not.toContain("<script>")
    expect(html).not.toContain("<img")
    expect(html).toContain("&lt;script&gt;task&lt;/script&gt;")
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;")
    expect(html).toContain("Подробности последней попытки")
  })
})
