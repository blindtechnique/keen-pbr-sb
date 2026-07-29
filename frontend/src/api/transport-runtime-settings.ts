import { apiFetch, type ApiError } from "@/api/client"

export const SING_BOX_PROCESS_MODES = ["isolated", "shared"] as const

export type SingBoxProcessMode = (typeof SING_BOX_PROCESS_MODES)[number]

export type TransportRuntimeSettings = {
  sing_box_process_mode: SingBoxProcessMode
  running_sing_box_process_mode: SingBoxProcessMode
  restart_required: boolean
  runtime_ready: boolean
}

type ApiResponse<T> = {
  data: T
  status: number
  headers: Headers
}

export const transportRuntimeSettingsQueryKey = [
  "transport-runtime-settings",
] as const

function isSingBoxProcessMode(value: unknown): value is SingBoxProcessMode {
  return (
    typeof value === "string" &&
    SING_BOX_PROCESS_MODES.includes(value as SingBoxProcessMode)
  )
}

function isTransportRuntimeSettings(
  value: unknown
): value is TransportRuntimeSettings {
  if (!value || typeof value !== "object") return false

  const candidate = value as Record<string, unknown>
  return (
    isSingBoxProcessMode(candidate.sing_box_process_mode) &&
    isSingBoxProcessMode(candidate.running_sing_box_process_mode) &&
    typeof candidate.restart_required === "boolean" &&
    typeof candidate.runtime_ready === "boolean"
  )
}

function validateSettingsPayload(value: unknown): TransportRuntimeSettings {
  if (isTransportRuntimeSettings(value)) return value

  throw {
    status: 502,
    message: "Transport manager returned invalid runtime settings",
    details: value,
  } satisfies ApiError
}

export async function getTransportRuntimeSettings(): Promise<TransportRuntimeSettings> {
  const response = await apiFetch<ApiResponse<unknown>>(
    "/api/transports/settings",
    {
      cache: "no-store",
      method: "GET",
    }
  )
  return validateSettingsPayload(response.data)
}

export async function setTransportRuntimeSettings(
  singBoxProcessMode: SingBoxProcessMode
): Promise<TransportRuntimeSettings> {
  const response = await apiFetch<ApiResponse<unknown>>(
    "/api/transports/settings",
    {
      body: JSON.stringify({
        sing_box_process_mode: singBoxProcessMode,
      }),
      headers: {
        "Content-Type": "application/json",
      },
      method: "POST",
    }
  )
  return validateSettingsPayload(response.data)
}
