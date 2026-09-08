import { afterEach, describe, expect, spyOn, test } from "bun:test"
import {
  QueryClient,
  QueryClientProvider,
  QueryObserver,
} from "@tanstack/react-query"
import { createInstance } from "i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { I18nextProvider } from "react-i18next"

import type { RouterMetrics } from "../src/api/generated/model"
import { RouterInfoPanel } from "../src/components/overview/router-info-card"
import {
  routerInfoView,
  routerMetadataQueryOptions,
  routerMetricsQueryOptions,
  type RouterMetadata,
} from "../src/components/overview/router-info-model"
import { enTranslation } from "../src/i18n/en"

const cleanupTasks: Array<() => void> = []
afterEach(() => {
  while (cleanupTasks.length > 0) cleanupTasks.pop()?.()
})

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

function queryFixture() {
  const requests = new Map<string, ReturnType<typeof deferred<Response>>>()
  const fetchMock = spyOn(globalThis, "fetch").mockImplementation((input) => {
    const request = deferred<Response>()
    requests.set(String(input), request)
    return request.promise
  })
  cleanupTasks.push(() => fetchMock.mockRestore())
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity } },
  })
  cleanupTasks.push(() => client.clear())
  const metadata = new QueryObserver(client, routerMetadataQueryOptions())
  const metrics = new QueryObserver(client, routerMetricsQueryOptions())
  cleanupTasks.push(metadata.subscribe(() => {}))
  cleanupTasks.push(metrics.subscribe(() => {}))
  return {
    client,
    requests,
    metadata,
    metrics,
    view: () =>
      routerInfoView(
        metadata.getCurrentResult().data,
        metrics.getCurrentResult().data
      ),
  }
}

async function renderPanel(
  metadata: RouterMetadata | undefined,
  metrics: RouterMetrics | undefined
) {
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: Infinity, staleTime: Infinity },
    },
  })
  cleanupTasks.push(() => client.clear())
  if (metadata) {
    client.setQueryData(routerMetadataQueryOptions().queryKey, metadata)
  }
  if (metrics) {
    client.setQueryData(routerMetricsQueryOptions().queryKey, metrics)
  }
  const i18n = createInstance()
  await i18n.init({
    lng: "en",
    resources: { en: { translation: enTranslation } },
    interpolation: { escapeValue: false },
  })
  return renderToStaticMarkup(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <RouterInfoPanel />
      </I18nextProvider>
    </QueryClientProvider>
  )
}

describe("independent router observations", () => {
  test("polls local metrics every 15 seconds and NDMS metadata every minute", () => {
    const metadata = routerMetadataQueryOptions()
    const metrics = routerMetricsQueryOptions()
    expect(metadata.queryKey).not.toEqual(metrics.queryKey)
    expect(metadata.refetchInterval).toBe(60_000)
    expect(metrics.refetchInterval).toBe(15_000)
    expect(metadata.refetchIntervalInBackground).toBe(false)
    expect(metrics.refetchIntervalInBackground).toBe(false)
  })

  test("never borrows legacy local fields from the metadata response", () => {
    const legacyMetrics: RouterMetrics = {
      cpu_model: "old cpu",
      cpu_load_percent: 99,
      cpu_temperature_c: 80,
      memory_total_mb: 512,
      memory_used_mb: 480,
      memory_used_percent: 94,
      disk_total_mb: 1000,
      disk_used_mb: 900,
      disk_used_percent: 90,
      uptime_seconds: 10,
      load_average: [9, 8, 7],
      conntrack_total: 16000,
      conntrack_free: 10,
    }
    for (const metrics of [undefined, {}]) {
      const view = routerInfoView(
        { available: true, model: "Router", ...legacyMetrics },
        metrics
      )
      expect(view.available).toBe(true)
      expect(view.model).toBe("Router")
      for (const key of Object.keys(legacyMetrics)) {
        expect(view[key as keyof RouterMetrics]).toBeUndefined()
      }
    }
  })

  test("parallel local query renders first and a late NDMS snapshot cannot roll it back", async () => {
    const fixture = queryFixture()
    expect([...fixture.requests.keys()]).toEqual([
      "/api/system/router",
      "/api/system/metrics",
    ])
    const localReady = fixture.client.fetchQuery(routerMetricsQueryOptions())
    fixture.requests
      .get("/api/system/metrics")!
      .resolve(
        Response.json({
          cpu_load_percent: 12,
          memory_used_mb: 64,
          uptime_seconds: 200,
        })
      )
    await localReady
    expect(fixture.metadata.getCurrentResult().isPending).toBe(true)
    expect(fixture.view()).toMatchObject({
      available: true,
      cpu_load_percent: 12,
      memory_used_mb: 64,
      uptime_seconds: 200,
    })
    const metadataReady = fixture.client.fetchQuery(
      routerMetadataQueryOptions()
    )
    fixture.requests.get("/api/system/router")!.resolve(
      Response.json({
        available: true,
        model: "Keenetic",
        clients_total: 3,
        cpu_load_percent: 99,
        memory_used_mb: 500,
        uptime_seconds: 100,
      })
    )
    await metadataReady
    expect(fixture.view()).toMatchObject({
      available: true,
      model: "Keenetic",
      clients_total: 3,
      cpu_load_percent: 12,
      memory_used_mb: 64,
      uptime_seconds: 200,
    })
  })

  test("NDMS request failure cannot hide the independent local sample", async () => {
    const fixture = queryFixture()
    const localReady = fixture.client.fetchQuery(routerMetricsQueryOptions())
    fixture.requests
      .get("/api/system/metrics")!
      .resolve(Response.json({ cpu_load_percent: 0, memory_total_mb: 512 }))
    await localReady
    const metadataReady = fixture.client.fetchQuery(
      routerMetadataQueryOptions()
    )
    fixture.requests
      .get("/api/system/router")!
      .reject(new Error("RCI unavailable"))
    await expect(metadataReady).rejects.toThrow("RCI unavailable")
    expect(fixture.metadata.getCurrentResult().isError).toBe(true)
    expect(fixture.view()).toMatchObject({
      available: true,
      cpu_load_percent: 0,
      memory_total_mb: 512,
    })
  })

  test("an unavailable NDMS response does not hide locals or invent an idle CPU", () => {
    const view = routerInfoView(
      { available: false, clients_total: 0 },
      { load_average: [0.1, 0.2, 0.3], uptime_seconds: 0 }
    )
    expect(view.available).toBe(true)
    expect(view.cpu_load_percent).toBeUndefined()
    expect(view.clients_total).toBeUndefined()
    expect(view.load_average).toEqual([0.1, 0.2, 0.3])
    expect(routerInfoView(undefined, {}).available).toBe(false)
  })

  test("the real card shows local-only data while metadata is pending", async () => {
    const html = await renderPanel(undefined, {
      cpu_model: "Local CPU",
      cpu_load_percent: 12,
      memory_total_mb: 512,
      memory_used_mb: 64,
      memory_used_percent: 13,
    })
    expect(html).toContain("Local CPU")
    expect(html).toContain("12%")
    expect(html).not.toContain(enTranslation.overview.router.unavailable)
    expect(html).not.toContain('data-slot="skeleton"')
  })

  test("the real card shows metadata-only data without stale CPU fallback", async () => {
    const html = await renderPanel(
      {
        available: true,
        model: "TEST-ROUTER",
        firmware_title: "Firmware 5.0",
        cpu_load_percent: 99,
      },
      undefined
    )
    expect(html).toContain("TEST-ROUTER")
    expect(html).toContain("Firmware 5.0")
    expect(html).not.toContain("99%")
    expect(html).not.toContain(enTranslation.overview.router.unavailable)
    expect(html).not.toContain('data-slot="skeleton"')
  })
})
