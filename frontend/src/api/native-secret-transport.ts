import type {
  NativeWireGuardSecretTicket,
  NativeWireGuardSecretVault,
} from "@/lib/native-wireguard-secret-vault"

export type NativeSecretPreflightVerdict = "admitted" | "denied"

export const NDMS_NATIVE_IMPORT_SECRET_ENDPOINT =
  "/api/system/ndms/interfaces/import" as const
export const NDMS_NATIVE_IMPORT_PREFLIGHT_ENDPOINT =
  "/api/system/ndms/interfaces/import/preflight" as const

export type NdmsNativeImportSecretEndpoint =
  typeof NDMS_NATIVE_IMPORT_SECRET_ENDPOINT
export type NdmsNativeImportPreflightEndpoint =
  typeof NDMS_NATIVE_IMPORT_PREFLIGHT_ENDPOINT

export type NdmsNativeImportPreflightBinding = Readonly<{
  preflightEndpoint: NdmsNativeImportPreflightEndpoint
  secretEndpoint: NdmsNativeImportSecretEndpoint
}>

export type NativeSecretBodylessPreflight = (
  binding: NdmsNativeImportPreflightBinding
) => Promise<NativeSecretPreflightVerdict>

export type NativeSecretTransportErrorCode =
  | "preflight_denied"
  | "preflight_failed"
  | "secret_unavailable"
  | "request_failed"

export class NativeSecretTransportError extends Error {
  readonly code: NativeSecretTransportErrorCode

  constructor(code: NativeSecretTransportErrorCode) {
    super(code)
    this.name = "NativeSecretTransportError"
    this.code = code
  }
}

export type NativeSecretFetch = (
  input: RequestInfo | URL,
  init?: RequestInit
) => Promise<Response>

export type PostNdmsNativeImportSecretOnceOptions = {
  vault: NativeWireGuardSecretVault
  ticket: NativeWireGuardSecretTicket
  /**
   * Must perform only the bodyless admission/step-up phase. The secret stays
   * in the vault until this callback has returned `admitted`.
   */
  preflight: NativeSecretBodylessPreflight
  fetchImpl?: NativeSecretFetch
  signal?: AbortSignal
}

// A syntactically same-origin path is not enough: handing a private key to an
// ordinary API handler or log route would still disclose it. This primitive is
// intentionally bound to the sole secret-consuming native import endpoint.
export const nativeSecretEndpointIsAllowed = (
  endpoint: string
): endpoint is NdmsNativeImportSecretEndpoint =>
  endpoint === NDMS_NATIVE_IMPORT_SECRET_ENDPOINT

/**
 * Sends one secret-bearing request after a separate bodyless preflight.
 *
 * This intentionally bypasses generated apiFetch/fetchWithStepUp: those
 * helpers may replay string bodies after a 403. Once admission succeeds, the
 * secret is consumed before exactly one same-origin fetch and wiped whether
 * that fetch returns an HTTP response or throws.
 */
export async function postNdmsNativeImportSecretOnce({
  vault,
  ticket,
  preflight,
  fetchImpl = fetch,
  signal,
}: PostNdmsNativeImportSecretOnceOptions): Promise<Response> {
  let verdict: NativeSecretPreflightVerdict
  try {
    verdict = await preflight({
      preflightEndpoint: NDMS_NATIVE_IMPORT_PREFLIGHT_ENDPOINT,
      secretEndpoint: NDMS_NATIVE_IMPORT_SECRET_ENDPOINT,
    })
  } catch {
    throw new NativeSecretTransportError("preflight_failed")
  }

  if (verdict !== "admitted") {
    throw new NativeSecretTransportError("preflight_denied")
  }

  const secret = vault.takeOnce(ticket)
  if (secret === null) {
    throw new NativeSecretTransportError("secret_unavailable")
  }

  try {
    return await fetchImpl(NDMS_NATIVE_IMPORT_SECRET_ENDPOINT, {
      method: "POST",
      credentials: "same-origin",
      mode: "same-origin",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
      keepalive: false,
      headers: {
        Accept: "application/json",
        "Content-Type": "text/plain; charset=utf-8",
      },
      body: secret,
      signal,
    })
  } catch {
    throw new NativeSecretTransportError("request_failed")
  } finally {
    secret.fill(0)
  }
}
