import { describe, expect, test } from "bun:test"

import {
  collectLogDiagnostics,
  LOG_DIAGNOSTICS_ENDPOINTS,
  type FetchLike,
} from "../src/components/settings/log-diagnostics-tools-model"

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === "string") {
    return input
  }
  return input instanceof URL ? input.toString() : input.url
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "Content-Type": "application/json",
    },
  })
}

describe("log diagnostics collector", () => {
  test("starts all endpoint requests in parallel and preserves every result", async () => {
    const requested: string[] = []
    let releaseRequests: (() => void) | undefined
    const gate = new Promise<void>((resolve) => {
      releaseRequests = resolve
    })
    const fetcher: FetchLike = async (input) => {
      const url = requestUrl(input)
      requested.push(url)
      await gate
      return jsonResponse({ endpoint: url })
    }

    const collecting = collectLogDiagnostics({
      fetcher,
      generatedAt: new Date("2026-07-26T10:11:12.000Z"),
    })

    await Promise.resolve()
    expect(requested).toEqual(Object.values(LOG_DIAGNOSTICS_ENDPOINTS))

    releaseRequests?.()
    const bundle = await collecting

    expect(bundle.format_version).toBe(1)
    expect(bundle.generated_at).toBe("2026-07-26T10:11:12.000Z")
    expect(bundle.privacy).toEqual({
      list_contents_redacted: true,
      contains_log_lines: true,
    })
    expect(Object.keys(bundle.sections)).toEqual(
      Object.keys(LOG_DIAGNOSTICS_ENDPOINTS)
    )
    expect(bundle.sections.router).toEqual({
      ok: true,
      endpoint: "/api/system/router",
      http_status: 200,
      data: { endpoint: "/api/system/router" },
    })
  })

  test("redacts list contents by default and includes them only after opt-in", async () => {
    const fetcher: FetchLike = async (input) => {
      const url = requestUrl(input)
      return jsonResponse(
        url === LOG_DIAGNOSTICS_ENDPOINTS.config
          ? {
              config: {
                lists: {
                  private_list: {
                    type: "remote",
                    url: "https://example.test/private.txt",
                    domains: ["private.example"],
                    ip_cidrs: ["10.0.0.0/8"],
                    refresh_interval: "1d",
                  },
                },
              },
              is_draft: false,
            }
          : { ok: true }
      )
    }

    const redacted = await collectLogDiagnostics({ fetcher })
    expect(redacted.sections.config).toMatchObject({
      ok: true,
      data: {
        config: {
          lists: {
            private_list: {
              url: "<redacted>",
              domains: ["<redacted>"],
              ip_cidrs: ["<redacted>"],
              refresh_interval: "1d",
            },
          },
        },
      },
    })

    const complete = await collectLogDiagnostics({
      fetcher,
      includeListContents: true,
    })
    expect(complete.privacy.list_contents_redacted).toBe(false)
    expect(complete.sections.config).toMatchObject({
      ok: true,
      data: {
        config: {
          lists: {
            private_list: {
              url: "https://example.test/private.txt",
              domains: ["private.example"],
              ip_cidrs: ["10.0.0.0/8"],
            },
          },
        },
      },
    })
  })

  test("times out one stalled endpoint without blocking the remaining bundle", async () => {
    const fetcher: FetchLike = async (input) => {
      const url = requestUrl(input)
      if (url === LOG_DIAGNOSTICS_ENDPOINTS.routing_health) {
        return await new Promise<Response>(() => undefined)
      }
      return jsonResponse({ ok: true })
    }

    const bundle = await collectLogDiagnostics({
      fetcher,
      requestTimeoutMs: 5,
    })

    expect(bundle.sections.routing_health).toEqual({
      ok: false,
      endpoint: "/api/health/routing",
      http_status: null,
      error: "Request timed out after 5 ms",
    })
    expect(bundle.sections.service_health).toMatchObject({ ok: true })
  })

  test("records network, HTTP and JSON errors without rejecting the bundle", async () => {
    const fetcher: FetchLike = async (input) => {
      const url = requestUrl(input)
      if (url === LOG_DIAGNOSTICS_ENDPOINTS.routing_health) {
        throw new Error("connection reset")
      }
      if (url === LOG_DIAGNOSTICS_ENDPOINTS.transports) {
        return jsonResponse({ error: "transport manager unavailable" }, 503)
      }
      if (url === LOG_DIAGNOSTICS_ENDPOINTS.logs) {
        return new Response("not-json", { status: 200 })
      }
      return jsonResponse({ ok: true })
    }

    const bundle = await collectLogDiagnostics({ fetcher })

    expect(bundle.sections.routing_health).toEqual({
      ok: false,
      endpoint: "/api/health/routing",
      http_status: null,
      error: "connection reset",
    })
    expect(bundle.sections.transports).toEqual({
      ok: false,
      endpoint: "/api/transports",
      http_status: 503,
      error: "transport manager unavailable",
      details: { error: "transport manager unavailable" },
    })
    expect(bundle.sections.logs).toMatchObject({
      ok: false,
      endpoint: "/api/logs?lines=5000",
      http_status: 200,
    })
    expect(bundle.sections.config).toEqual({
      ok: true,
      endpoint: "/api/config",
      http_status: 200,
      data: { ok: true },
    })
  })
})
