import { describe, expect, test } from "bun:test"

import {
  authCredentialsMayBeCollected,
  authEndpointModeLabelKey,
  authSettingsRestartRequired,
  confirmAuthEnabledChange,
  parseAuthStatus,
  refreshCredentialTransportStatus,
  refreshTrustedLocalCredentialTransport,
} from "../src/lib/auth-status"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

describe("authentication status contract", () => {
  test("requires an explicit warning before disabling network authentication", () => {
    let confirmations = 0
    const deny = () => {
      confirmations += 1
      return false
    }
    expect(confirmAuthEnabledChange(true, false, deny)).toBe(false)
    expect(confirmations).toBe(1)
    expect(confirmAuthEnabledChange(true, true, deny)).toBe(true)
    expect(confirmAuthEnabledChange(false, true, deny)).toBe(true)
    expect(confirmations).toBe(1)
    expect(enTranslation.pages.settings.auth.disableConfirm).toContain(
      "after the daemon restarts"
    )
    expect(ruTranslation.pages.settings.auth.disableConfirm).toContain(
      "До перезапуска"
    )
    expect(enTranslation.pages.settings.auth.disableRestartRequired).toContain(
      "still requires sign-in"
    )
    expect(ruTranslation.pages.settings.auth.disableRestartRequired).toContain(
      "текущая служба"
    )
  })

  test("treats only an explicit restart-required response as staged", () => {
    expect(authSettingsRestartRequired({ restart_required: true })).toBe(true)
    expect(authSettingsRestartRequired({ restart_required: false })).toBe(false)
    expect(authSettingsRestartRequired({ restart_required: "true" })).toBe(
      false
    )
    expect(authSettingsRestartRequired(null)).toBe(false)
  })

  test("accepts only the explicit boolean contract", () => {
    expect(
      parseAuthStatus({ enabled: true, authenticated: false }, 1_000)
    ).toEqual({
      enabled: true,
      authenticated: false,
      provider: null,
      trustedLocalConnection: false,
      trustedLocalConnectionGeneration: null,
      trustedLocalConnectionValidUntilMs: 0,
      noAuthScope: null,
      networkApiBlocked: false,
    })
    expect(
      parseAuthStatus(
        {
          enabled: true,
          authenticated: true,
          provider: "keenetic",
          trusted_local_connection: true,
          trusted_local_connection_generation: "7",
          trusted_local_connection_valid_for_seconds: 5,
        },
        1_000
      )
    ).toEqual({
      enabled: true,
      authenticated: true,
      provider: "keenetic",
      trustedLocalConnection: true,
      trustedLocalConnectionGeneration: "7",
      trustedLocalConnectionValidUntilMs: 6_000,
      noAuthScope: null,
      networkApiBlocked: false,
    })
    expect(
      parseAuthStatus(
        {
          enabled: true,
          authenticated: true,
          trusted_local_connection: "true",
        },
        1_000
      )
    ).toEqual({
      enabled: true,
      authenticated: true,
      provider: null,
      trustedLocalConnection: false,
      trustedLocalConnectionGeneration: null,
      trustedLocalConnectionValidUntilMs: 0,
      noAuthScope: null,
      networkApiBlocked: false,
    })
  })

  test("parses the explicit loopback-only recovery scope", () => {
    const status = parseAuthStatus({
      enabled: false,
      authenticated: false,
      provider: "local",
      no_auth_scope: "loopback_only",
      network_api_blocked: true,
    })
    expect(status?.noAuthScope).toBe("loopback_only")
    expect(status?.networkApiBlocked).toBe(true)
    expect(enTranslation.auth.loopbackOnlyDescription).toContain("SSH")
    expect(ruTranslation.auth.loopbackOnlyDescription).toContain("LAN")
  })

  test("requires bounded generation-bearing local evidence", () => {
    for (const evidence of [
      {},
      {
        trusted_local_connection_generation: "0",
        trusted_local_connection_valid_for_seconds: 5,
      },
      {
        trusted_local_connection_generation: "1",
        trusted_local_connection_valid_for_seconds: 0,
      },
      {
        trusted_local_connection_generation: "1",
        trusted_local_connection_valid_for_seconds: 61,
      },
      {
        trusted_local_connection_generation: 1,
        trusted_local_connection_valid_for_seconds: 5,
      },
    ]) {
      expect(
        parseAuthStatus(
          {
            enabled: true,
            authenticated: true,
            trusted_local_connection: true,
            ...evidence,
          },
          1_000
        )?.trustedLocalConnection
      ).toBe(false)
    }
  })

  test("collects Keenetic credentials only while fresh evidence is live", () => {
    const status = parseAuthStatus(
      {
        enabled: true,
        authenticated: false,
        provider: "keenetic",
        trusted_local_connection: true,
        trusted_local_connection_generation: "9",
        trusted_local_connection_valid_for_seconds: 5,
      },
      1_000
    )
    expect(authCredentialsMayBeCollected(status, 5_999)).toBe(true)
    expect(authCredentialsMayBeCollected(status, 6_000)).toBe(false)
    expect(authCredentialsMayBeCollected(null, 1_000)).toBe(false)
    expect(
      authCredentialsMayBeCollected(
        parseAuthStatus(
          { enabled: true, authenticated: false, provider: "unknown" },
          1_000
        ),
        1_000
      )
    ).toBe(false)
    expect(
      authCredentialsMayBeCollected(
        parseAuthStatus(
          {
            enabled: true,
            authenticated: false,
            provider: "local",
            error: "auth_misconfigured",
          },
          1_000
        ),
        1_000
      )
    ).toBe(false)
    expect(
      authCredentialsMayBeCollected(
        parseAuthStatus(
          {
            enabled: true,
            authenticated: true,
            provider: "local",
          },
          1_000
        ),
        99_000
      )
    ).toBe(true)
  })

  test("refreshes a credential-locality proof before password POST", async () => {
    const calls: Array<[RequestInfo | URL, RequestInit | undefined]> = []
    const fetchImpl = (async (url, init) => {
      calls.push([url, init])
      return new Response(
        JSON.stringify({
          enabled: true,
          authenticated: false,
          provider: "keenetic",
          trusted_local_connection: true,
          trusted_local_connection_generation: "12",
          trusted_local_connection_valid_for_seconds: 5,
        }),
        { status: 200 }
      )
    }) as typeof fetch

    const status = await refreshCredentialTransportStatus(
      fetchImpl,
      () => 2_000
    )
    expect(status?.trustedLocalConnectionValidUntilMs).toBe(7_000)
    expect(calls).toHaveLength(1)
    expect(calls[0]?.[0]).toBe("/api/auth/status?credential_transport=1")
    expect(calls[0]?.[1]).toMatchObject({
      cache: "no-store",
      credentials: "same-origin",
    })
  })

  test("fails credential preflight closed", async () => {
    const malformed = (async () =>
      new Response(
        JSON.stringify({
          enabled: true,
          authenticated: false,
          provider: "keenetic",
          trusted_local_connection: true,
        }),
        { status: 200 }
      )) as typeof fetch
    const unavailable = (async () =>
      new Response("", { status: 503 })) as typeof fetch
    expect(
      await refreshCredentialTransportStatus(malformed, () => 1_000)
    ).toBeNull()
    expect(
      await refreshCredentialTransportStatus(unavailable, () => 1_000)
    ).toBeNull()
  })

  test("rejects a credential proof that expired while its response was delayed", async () => {
    let nowMs = 1_000
    const calls: Array<[RequestInfo | URL, RequestInit | undefined]> = []
    const delayed = (async (url, init) => {
      calls.push([url, init])
      nowMs = 7_000
      return new Response(
        JSON.stringify({
          enabled: true,
          authenticated: true,
          provider: "keenetic",
          trusted_local_connection: true,
          trusted_local_connection_generation: "14",
          trusted_local_connection_valid_for_seconds: 5,
        }),
        { status: 200 }
      )
    }) as typeof fetch

    expect(
      await refreshCredentialTransportStatus(delayed, () => nowMs)
    ).toBeNull()
    nowMs = 1_000
    expect(
      await refreshTrustedLocalCredentialTransport(delayed, () => nowMs)
    ).toBeNull()
    expect(calls).toHaveLength(2)
    expect(calls.every(([, init]) => init?.body === undefined)).toBe(true)
  })

  test("requires locality for settings even while current provider is local", async () => {
    const untrustedLocalProvider = (async () =>
      new Response(
        JSON.stringify({
          enabled: true,
          authenticated: true,
          provider: "local",
          trusted_local_connection: false,
        }),
        { status: 200 }
      )) as typeof fetch
    const trustedLocalProvider = (async () =>
      new Response(
        JSON.stringify({
          enabled: true,
          authenticated: true,
          provider: "local",
          trusted_local_connection: true,
          trusted_local_connection_generation: "13",
          trusted_local_connection_valid_for_seconds: 5,
        }),
        { status: 200 }
      )) as typeof fetch

    expect(
      await refreshTrustedLocalCredentialTransport(
        untrustedLocalProvider,
        () => 1_000
      )
    ).toBeNull()
    expect(
      (
        await refreshTrustedLocalCredentialTransport(
          trustedLocalProvider,
          () => 1_000
        )
      )?.trustedLocalConnection
    ).toBe(true)
  })

  test("rejects malformed and truthy lookalike responses", () => {
    expect(parseAuthStatus(null)).toBeNull()
    expect(parseAuthStatus({})).toBeNull()
    expect(parseAuthStatus({ enabled: "false", authenticated: 1 })).toBeNull()
  })

  test("maps Keenetic endpoint modes to localized labels", () => {
    expect(authEndpointModeLabelKey("auto")).toBe(
      "pages.settings.auth.endpointModeAuto"
    )
    expect(authEndpointModeLabelKey("manual")).toBe(
      "pages.settings.auth.endpointModeManual"
    )
    expect(ruTranslation.pages.settings.auth.endpointModeAuto).toBe(
      "Автоматически через NDMS"
    )
    expect(ruTranslation.pages.settings.auth.endpointModeManual).toBe("Вручную")
    expect(enTranslation.pages.settings.auth.endpointModeAuto).toBe(
      "Automatically via NDMS"
    )
    expect(enTranslation.pages.settings.auth.endpointModeManual).toBe(
      "Manually"
    )
  })
})
