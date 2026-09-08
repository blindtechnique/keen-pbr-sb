import { afterEach, describe, expect, test } from "bun:test"
import { QueryClient, QueryObserver } from "@tanstack/react-query"

import {
  applyRouterInfoStatusEvent,
  createRouterInfoEventRefresh,
  ROUTER_INFO_EVENT_WINDOW_MS,
  ROUTER_INFO_QUERY_KEY,
} from "../src/api/router-info-events"
import {
  routerMetadataQueryOptions,
  routerMetricsQueryOptions,
} from "../src/components/overview/router-info-model"

const cleanupTasks: Array<() => void> = []

afterEach(() => {
  while (cleanupTasks.length > 0) cleanupTasks.pop()?.()
})

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((onResolve, onReject) => {
    resolve = onResolve
    reject = onReject
  })
  return { promise, resolve, reject }
}

async function settle() {
  for (let index = 0; index < 30; index += 1) await Promise.resolve()
}

function fixture() {
  type TimerHandle = ReturnType<typeof setTimeout>
  const timers = new Map<TimerHandle, { callback: () => void; delay: number }>()
  let timerId = 0
  const client = new QueryClient({
    defaultOptions: { queries: { gcTime: Infinity, retry: false } },
  })
  const refresh = createRouterInfoEventRefresh(client, {
    schedule(callback, delay) {
      const handle = ++timerId as unknown as TimerHandle
      timers.set(handle, { callback, delay })
      return handle
    },
    cancel(handle) {
      timers.delete(handle)
    },
  })
  cleanupTasks.push(() => {
    refresh.dispose()
    client.clear()
  })
  return {
    client,
    refresh,
    timers,
    fireWindow() {
      expect(timers.size).toBe(1)
      const [handle, timer] = [...timers.entries()][0]
      expect(timer.delay).toBe(5_000)
      timers.delete(handle)
      timer.callback()
    },
    observe(initialData?: string) {
      const requests: Array<{
        signal: AbortSignal
        response: ReturnType<typeof deferred<string>>
      }> = []
      const observer = new QueryObserver(client, {
        queryKey: ROUTER_INFO_QUERY_KEY,
        staleTime: Infinity,
        initialData,
        queryFn: ({ signal }) => {
          const response = deferred<string>()
          requests.push({ signal, response })
          return response.promise
        },
      })
      cleanupTasks.push(observer.subscribe(() => {}))
      return requests
    },
  }
}

describe("router metadata event refresh", () => {
  test("accepts only the data-free router notification and retains existing query schedules", () => {
    let scheduled = 0
    const schedule = () => {
      scheduled += 1
    }
    for (const invalid of [
      "",
      "{",
      "null",
      "[]",
      "{}",
      '{"type":"interfaces"}',
    ]) {
      expect(applyRouterInfoStatusEvent(invalid, schedule)).toBe(false)
    }
    expect(scheduled).toBe(0)
    expect(applyRouterInfoStatusEvent('{"type":"router_info"}', schedule)).toBe(
      true
    )
    expect(scheduled).toBe(1)
    expect(routerMetadataQueryOptions().queryKey).toEqual(ROUTER_INFO_QUERY_KEY)
    expect(routerMetadataQueryOptions().refetchInterval).toBe(60_000)
    expect(routerMetricsQueryOptions().refetchInterval).toBe(15_000)
    expect(ROUTER_INFO_EVENT_WINDOW_MS).toBe(5_000)
  })

  test("a burst keeps its first fixed window and invalidates only exact inactive metadata", async () => {
    const f = fixture()
    f.client.setQueryData(ROUTER_INFO_QUERY_KEY, "old")
    f.client.setQueryData(["system-router", "other"], "untouched")
    f.client.setQueryData(["system-metrics"], "untouched")
    f.refresh.scheduleRefresh()
    const first = [...f.timers.keys()][0]
    for (let index = 0; index < 20; index += 1) f.refresh.scheduleRefresh()
    expect([...f.timers.keys()]).toEqual([first])
    expect(f.client.getQueryState(ROUTER_INFO_QUERY_KEY)?.isInvalidated).toBe(
      false
    )
    f.fireWindow()
    await settle()
    expect(f.client.getQueryState(ROUTER_INFO_QUERY_KEY)?.isInvalidated).toBe(
      true
    )
    expect(f.client.getQueryState(ROUTER_INFO_QUERY_KEY)?.fetchStatus).toBe(
      "idle"
    )
    expect(
      f.client.getQueryState(["system-router", "other"])?.isInvalidated
    ).toBe(false)
    expect(f.client.getQueryState(["system-metrics"])?.isInvalidated).toBe(
      false
    )
    expect(f.timers.size).toBe(0)
  })

  test("an active metadata observer refetches once at the fixed deadline", async () => {
    const f = fixture()
    const requests = f.observe("old")
    f.refresh.scheduleRefresh()
    f.refresh.scheduleRefresh()
    expect(requests).toHaveLength(0)
    f.fireWindow()
    expect(requests).toHaveLength(1)
    requests[0].response.resolve("updated")
    await settle()
    expect(f.client.getQueryData(ROUTER_INFO_QUERY_KEY)).toBe("updated")
    expect(requests).toHaveLength(1)
    expect(f.timers.size).toBe(0)
  })

  test("an event during the initial GET waits a full window after completion without cancelling it", async () => {
    const f = fixture()
    const requests = f.observe()
    expect(requests).toHaveLength(1)
    f.refresh.scheduleRefresh()
    for (let index = 0; index < 10; index += 1) f.refresh.scheduleRefresh()
    expect(f.timers.size).toBe(0)
    expect(requests).toHaveLength(1)
    expect(requests[0].signal.aborted).toBe(false)
    requests[0].response.resolve("before-event")
    await settle()
    expect(requests).toHaveLength(1)
    const completedWindow = [...f.timers.keys()][0]
    f.refresh.scheduleRefresh()
    expect([...f.timers.keys()]).toEqual([completedWindow])
    f.fireWindow()
    expect(requests).toHaveLength(2)
    requests[1].response.resolve("after-event")
    await settle()
    expect(f.client.getQueryData(ROUTER_INFO_QUERY_KEY)).toBe("after-event")
    expect(requests).toHaveLength(2)
    expect(f.timers.size).toBe(0)
  })

  test("a GET starting inside the event window shifts only to completion plus five seconds", async () => {
    const f = fixture()
    const requests = f.observe("old")
    f.refresh.scheduleRefresh()
    const original = [...f.timers.keys()][0]
    void f.client.refetchQueries({
      queryKey: ROUTER_INFO_QUERY_KEY,
      exact: true,
    })
    expect(requests).toHaveLength(1)
    expect(f.timers.size).toBe(0)
    requests[0].response.resolve("before-event")
    await settle()
    expect(requests).toHaveLength(1)
    expect([...f.timers.keys()][0]).not.toBe(original)
    f.fireWindow()
    expect(requests).toHaveLength(2)
    requests[1].response.resolve("after-event")
    await settle()
    expect(f.client.getQueryData(ROUTER_INFO_QUERY_KEY)).toBe("after-event")
    expect(f.timers.size).toBe(0)
  })

  test("events during an event-triggered GET keep one successor even when that GET fails", async () => {
    const f = fixture()
    const requests = f.observe("old")
    f.refresh.scheduleRefresh()
    f.fireWindow()
    expect(requests).toHaveLength(1)
    f.refresh.scheduleRefresh()
    f.refresh.scheduleRefresh()
    expect(f.timers.size).toBe(0)
    expect(requests).toHaveLength(1)
    expect(requests[0].signal.aborted).toBe(false)
    requests[0].response.reject(new Error("temporary metadata failure"))
    await settle()
    expect(requests).toHaveLength(1)
    const completedWindow = [...f.timers.keys()][0]
    f.refresh.scheduleRefresh()
    expect([...f.timers.keys()]).toEqual([completedWindow])
    f.fireWindow()
    expect(requests).toHaveLength(2)
    requests[1].response.resolve("recovered")
    await settle()
    expect(f.client.getQueryData(ROUTER_INFO_QUERY_KEY)).toBe("recovered")
    expect(requests).toHaveLength(2)
    expect(f.timers.size).toBe(0)
  })

  test("close cancels the window or waiting successor, while reconnect can schedule again", async () => {
    const f = fixture()
    f.refresh.scheduleRefresh()
    f.refresh.cancelPending()
    expect(f.timers.size).toBe(0)
    const requests = f.observe()
    f.refresh.scheduleRefresh()
    f.refresh.cancelPending()
    requests[0].response.resolve("old")
    await settle()
    expect(requests).toHaveLength(1)
    f.refresh.scheduleRefresh()
    f.fireWindow()
    expect(requests).toHaveLength(2)
    f.refresh.scheduleRefresh()
    f.refresh.dispose()
    requests[1].response.resolve("last")
    await settle()
    f.refresh.scheduleRefresh()
    expect(requests).toHaveLength(2)
    expect(f.timers.size).toBe(0)
  })
})
