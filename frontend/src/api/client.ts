import {
  isReplayable,
  isStepUpRequired,
  requestStepUpGrant,
} from "@/lib/step-up"

export type ApiError = {
  status: number
  message: string
  details?: unknown
}

const parseResponsePayload = async (response: Response) => {
  const contentType = response.headers.get("content-type") ?? ""
  if (contentType.includes("application/json")) {
    return response.json()
  }

  return response.text()
}

const normalizeError = (status: number, payload: unknown): ApiError => {
  if (payload && typeof payload === "object") {
    const body = payload as Record<string, unknown>
    const message =
      typeof body.error === "string"
        ? body.error
        : typeof body.message === "string"
          ? body.message
          : `Request failed with status ${status}`

    return { status, message, details: payload }
  }

  if (typeof payload === "string" && payload.length > 0) {
    return { status, message: payload, details: payload }
  }

  return {
    status,
    message: `Request failed with status ${status}`,
    details: payload,
  }
}

export const apiFetch = async <T>(
  url: string,
  options: RequestInit
): Promise<T> => {
  let response = await fetch(url, options)
  let payload = await parseResponsePayload(response)

  // Handled here rather than at each privileged call site, mirroring the
  // server: it enforces the step-up in one pre-routing guard, so the client
  // answers it in one place too. Every existing caller - including the
  // generated client and the backup download - gets this without changing.
  if (
    isStepUpRequired(response.status, payload) &&
    isReplayable(options.body)
  ) {
    const granted = await requestStepUpGrant()
    if (granted) {
      // Exactly once. If the replay is refused again, that is the answer, not
      // an invitation to prompt in a loop.
      response = await fetch(url, options)
      payload = await parseResponsePayload(response)
    }
  }

  if (!response.ok) {
    throw normalizeError(response.status, payload)
  }

  return {
    data: payload,
    status: response.status,
    headers: response.headers,
  } as T
}
