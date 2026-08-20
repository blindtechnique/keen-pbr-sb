import { describe, expect, mock, test } from "bun:test"

import {
  NDMS_NATIVE_IMPORT_PREFLIGHT_ENDPOINT,
  NDMS_NATIVE_IMPORT_OWNER_RISK_ACCEPTANCE,
  NDMS_NATIVE_IMPORT_OWNER_RISK_HEADER,
  NDMS_NATIVE_IMPORT_SECRET_ENDPOINT,
  NativeSecretTransportError,
  nativeSecretEndpointIsAllowed,
  preflightNdmsNativeImport,
  postNdmsNativeImportSecretOnce,
  type NdmsNativeImportPreflightBinding,
  type NativeSecretFetch,
} from "@/api/native-secret-transport"
import {
  createNativeWireGuardSecretVault,
  type NativeWireGuardSecretTicket,
  type NativeWireGuardSecretVault,
} from "@/lib/native-wireguard-secret-vault"

const selectedSecret = (): {
  vault: NativeWireGuardSecretVault
  ticket: NativeWireGuardSecretTicket
} => {
  const vault = createNativeWireGuardSecretVault()
  const ticket = vault.begin()
  expect(vault.replace(ticket, new TextEncoder().encode("private-key"))).toBe(
    true
  )
  return { vault, ticket }
}

const errorCode = async (promise: Promise<unknown>) => {
  try {
    await promise
  } catch (error) {
    expect(error).toBeInstanceOf(NativeSecretTransportError)
    return (error as NativeSecretTransportError).code
  }
  throw new Error("expected NativeSecretTransportError")
}

describe("native secret endpoint confinement", () => {
  test("accepts only the fixed native import route", () => {
    expect(
      nativeSecretEndpointIsAllowed(NDMS_NATIVE_IMPORT_SECRET_ENDPOINT)
    ).toBe(true)

    for (const endpoint of [
      "https://router.example/api/system/ndms/interfaces/import",
      "//router.example/api/system/ndms/interfaces/import",
      "/api/../auth/status",
      "/api/%2e%2e/auth/status",
      "/api/system/ndms/interfaces/import?retry=1",
      "/api/system//ndms/interfaces/import",
      "/api/auth/status",
      "/api/system/ndms/interfaces/remove",
      "/api/system/ndms/interfaces/import-preflight",
      "/other/system/ndms/interfaces/import",
    ]) {
      expect(nativeSecretEndpointIsAllowed(endpoint)).toBe(false)
    }
  })

  test("codegen keeps the secret POST out while retaining preflight and models", async () => {
    const generatedClient = await Bun.file(
      new URL("../src/api/generated/keen-api.ts", import.meta.url)
    ).text()
    const generatedModelIndex = await Bun.file(
      new URL("../src/api/generated/model/index.ts", import.meta.url)
    ).text()

    expect(generatedClient).not.toContain("postNdmsNativeImportSecret")
    expect(generatedClient).not.toContain(
      "return `/api/system/ndms/interfaces/import`"
    )
    expect(generatedClient).toContain("postNdmsNativeImportPreflight")
    expect(generatedClient).toContain(NDMS_NATIVE_IMPORT_PREFLIGHT_ENDPOINT)
    expect(generatedModelIndex).toContain("./ndmsNativeImportResponse")
    expect(generatedModelIndex).toContain("./ndmsNativeImportPreflightResponse")
  })
})

describe("one-shot native secret transport", () => {
  test("preflights its exact bodyless no-store route before vault consumption", async () => {
    const fetchImpl = mock((input: RequestInfo | URL, init?: RequestInit) => {
      expect(input).toBe(NDMS_NATIVE_IMPORT_PREFLIGHT_ENDPOINT)
      expect(init).toEqual(
        expect.objectContaining({
          method: "POST",
          credentials: "same-origin",
          mode: "same-origin",
          cache: "no-store",
          redirect: "error",
          referrerPolicy: "no-referrer",
          keepalive: false,
          headers: { Accept: "application/json" },
        })
      )
      expect(init?.body).toBeUndefined()
      return Promise.resolve(
        Response.json({
          admitted: true,
          owner_risk_acceptance_required: true,
          external_ndms_writer_race_excluded: false,
        })
      )
    }) as typeof fetch

    expect(
      await preflightNdmsNativeImport({
        binding: {
          preflightEndpoint: NDMS_NATIVE_IMPORT_PREFLIGHT_ENDPOINT,
          secretEndpoint: NDMS_NATIVE_IMPORT_SECRET_ENDPOINT,
        },
        fetchImpl,
      })
    ).toBe("admitted")
    expect(fetchImpl).toHaveBeenCalledTimes(1)
  })

  test("does not admit a false or malformed capability response", async () => {
    for (const payload of [
      null,
      { admitted: false },
      {
        admitted: true,
        owner_risk_acceptance_required: false,
        external_ndms_writer_race_excluded: false,
      },
      {
        admitted: true,
        owner_risk_acceptance_required: true,
        external_ndms_writer_race_excluded: true,
      },
    ]) {
      const fetchImpl = mock(() =>
        Promise.resolve(Response.json(payload))
      ) as unknown as typeof fetch
      expect(
        await preflightNdmsNativeImport({
          binding: {
            preflightEndpoint: NDMS_NATIVE_IMPORT_PREFLIGHT_ENDPOINT,
            secretEndpoint: NDMS_NATIVE_IMPORT_SECRET_ENDPOINT,
          },
          fetchImpl,
        })
      ).toBe("denied")
    }
  })

  test("does not consume the secret when preflight denies or fails", async () => {
    const denied = selectedSecret()
    expect(
      await errorCode(
        postNdmsNativeImportSecretOnce({
          ...denied,
          preflight: () => Promise.resolve("denied"),
        })
      )
    ).toBe("preflight_denied")
    expect(denied.vault.takeOnce(denied.ticket)).not.toBeNull()

    const failed = selectedSecret()
    expect(
      await errorCode(
        postNdmsNativeImportSecretOnce({
          ...failed,
          preflight: () => Promise.reject(new Error("offline")),
        })
      )
    ).toBe("preflight_failed")
    expect(failed.vault.takeOnce(failed.ticket)).not.toBeNull()
  })

  test("binds bodyless preflight to its exact route and secret destination", async () => {
    const { vault, ticket } = selectedSecret()
    const preflight = mock((binding: NdmsNativeImportPreflightBinding) => {
      expect(binding).toEqual({
        preflightEndpoint: NDMS_NATIVE_IMPORT_PREFLIGHT_ENDPOINT,
        secretEndpoint: NDMS_NATIVE_IMPORT_SECRET_ENDPOINT,
      })
      return Promise.resolve("denied" as const)
    })
    const fetchImpl = mock(() => Promise.resolve(new Response()))

    expect(
      await errorCode(
        postNdmsNativeImportSecretOnce({
          vault,
          ticket,
          preflight,
          fetchImpl,
        })
      )
    ).toBe("preflight_denied")
    expect(preflight).toHaveBeenCalledTimes(1)
    expect(fetchImpl).toHaveBeenCalledTimes(0)
    expect(vault.takeOnce(ticket)).not.toBeNull()
  })

  test("revocation during preflight prevents the secret request", async () => {
    const { vault, ticket } = selectedSecret()
    let admit: (() => void) | undefined
    const preflight = () =>
      new Promise<"admitted">((resolve) => {
        admit = () => resolve("admitted")
      })
    const fetchImpl = mock(() => Promise.resolve(new Response()))
    const request = postNdmsNativeImportSecretOnce({
      vault,
      ticket,
      preflight,
      fetchImpl,
    })

    vault.revoke()
    admit?.()

    expect(await errorCode(request)).toBe("secret_unavailable")
    expect(fetchImpl).toHaveBeenCalledTimes(0)
  })

  test("unmount during preflight prevents a late secret request", async () => {
    const { vault, ticket } = selectedSecret()
    let admit: (() => void) | undefined
    const preflight = () =>
      new Promise<"admitted">((resolve) => {
        admit = () => resolve("admitted")
      })
    const fetchImpl = mock(() => Promise.resolve(new Response()))
    const request = postNdmsNativeImportSecretOnce({
      vault,
      ticket,
      preflight,
      fetchImpl,
    })

    vault.dispose()
    admit?.()

    expect(await errorCode(request)).toBe("secret_unavailable")
    expect(fetchImpl).toHaveBeenCalledTimes(0)
  })

  test("performs one same-origin no-store fetch and returns HTTP errors", async () => {
    const { vault, ticket } = selectedSecret()
    let body: Uint8Array | null = null
    const response = new Response("forbidden", { status: 403 })
    const fetchImpl: NativeSecretFetch = mock((input, init) => {
      expect(input).toBe("/api/system/ndms/interfaces/import")
      expect(init?.method).toBe("POST")
      expect(init?.credentials).toBe("same-origin")
      expect(init?.mode).toBe("same-origin")
      expect(init?.cache).toBe("no-store")
      expect(init?.redirect).toBe("error")
      expect(init?.referrerPolicy).toBe("no-referrer")
      expect(init?.keepalive).toBe(false)
      expect(init?.headers).toEqual({
        Accept: "application/json",
        "Content-Type": "text/plain; charset=utf-8",
        [NDMS_NATIVE_IMPORT_OWNER_RISK_HEADER]:
          NDMS_NATIVE_IMPORT_OWNER_RISK_ACCEPTANCE,
      })
      body = init?.body as Uint8Array
      expect(new TextDecoder().decode(body)).toBe("private-key")
      return Promise.resolve(response)
    })

    expect(
      await postNdmsNativeImportSecretOnce({
        vault,
        ticket,
        preflight: () => Promise.resolve("admitted"),
        fetchImpl,
      })
    ).toBe(response)
    expect(fetchImpl).toHaveBeenCalledTimes(1)
    expect(body).not.toBeNull()
    expect(body).toEqual(new Uint8Array("private-key".length))
    expect(vault.takeOnce(ticket)).toBeNull()
  })

  test("does not retry a rejected fetch and wipes its body", async () => {
    const { vault, ticket } = selectedSecret()
    let body: Uint8Array | null = null
    const fetchImpl: NativeSecretFetch = mock((_input, init) => {
      body = init?.body as Uint8Array
      return Promise.reject(new Error("network down"))
    })

    expect(
      await errorCode(
        postNdmsNativeImportSecretOnce({
          vault,
          ticket,
          preflight: () => Promise.resolve("admitted"),
          fetchImpl,
        })
      )
    ).toBe("request_failed")
    expect(fetchImpl).toHaveBeenCalledTimes(1)
    expect(body).not.toBeNull()
    expect(body).toEqual(new Uint8Array("private-key".length))
  })

  test("two admitted calls can consume the ticket only once", async () => {
    const { vault, ticket } = selectedSecret()
    let admitFirst: (() => void) | undefined
    let admitSecond: (() => void) | undefined
    const firstPreflight = () =>
      new Promise<"admitted">((resolve) => {
        admitFirst = () => resolve("admitted")
      })
    const secondPreflight = () =>
      new Promise<"admitted">((resolve) => {
        admitSecond = () => resolve("admitted")
      })
    const fetchImpl = mock(() => Promise.resolve(new Response()))

    const first = postNdmsNativeImportSecretOnce({
      vault,
      ticket,
      preflight: firstPreflight,
      fetchImpl,
    })
    const second = postNdmsNativeImportSecretOnce({
      vault,
      ticket,
      preflight: secondPreflight,
      fetchImpl,
    })

    admitFirst?.()
    admitSecond?.()
    const settled = await Promise.allSettled([first, second])

    expect(fetchImpl).toHaveBeenCalledTimes(1)
    expect(settled.filter((item) => item.status === "fulfilled")).toHaveLength(
      1
    )
    const rejected = settled.find((item) => item.status === "rejected")
    expect(rejected?.status).toBe("rejected")
    if (rejected?.status === "rejected") {
      expect(rejected.reason).toBeInstanceOf(NativeSecretTransportError)
      expect((rejected.reason as NativeSecretTransportError).code).toBe(
        "secret_unavailable"
      )
    }
  })
})
