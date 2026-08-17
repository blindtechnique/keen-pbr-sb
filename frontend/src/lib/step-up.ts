export type StepUpCredentials = {
  username: string
  password: string
}

// Returns credentials, or null when the user dismisses the prompt.
export type StepUpPrompt = () => Promise<StepUpCredentials | null>

let promptHandler: StepUpPrompt | null = null

// Installed by the dialog once React has mounted. Before that, and in tests,
// there is deliberately no handler: a request that needs a step-up then fails
// with the server's own error instead of hanging on a prompt nobody can see.
export const setStepUpPrompt = (handler: StepUpPrompt | null) => {
  promptHandler = handler
}

// One grant request at a time. A page that fires several privileged requests
// at once would otherwise open a stack of identical password dialogs, and the
// user answering the first would still be looking at the rest.
let pendingGrant: Promise<boolean> | null = null
let protectedTransportUnavailableHandler: (() => void) | null = null

export const setProtectedTransportUnavailableHandler = (
  handler: (() => void) | null
) => {
  protectedTransportUnavailableHandler = handler
}

export const isStepUpRequired = (status: number, payload: unknown): boolean => {
  if (status !== 403) {
    return false
  }
  if (!payload || typeof payload !== "object") {
    return false
  }

  // Matched on the machine-readable code, not on prose: the message is
  // localised and rephrased, the code is the contract.
  return (payload as Record<string, unknown>).error === "step_up_required"
}

// A request can only be replayed if its body can be sent twice. Strings and
// bodyless requests can; a stream has already been consumed by the first
// attempt, and retrying it would send an empty body that the server would
// answer with a confusing 400 rather than the real problem.
export const isReplayable = (body: BodyInit | null | undefined): boolean =>
  body === null || body === undefined || typeof body === "string"

export const requestStepUpGrant = async (
  fetchImpl: typeof fetch = fetch
): Promise<boolean> => {
  if (pendingGrant) {
    return pendingGrant
  }

  const handler = promptHandler
  if (!handler) {
    return false
  }

  pendingGrant = (async () => {
    const credentials = await handler()
    if (!credentials) {
      return false
    }

    const response = await fetchImpl("/api/auth/step-up", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(credentials),
    })

    if (!response.ok) {
      const payload = await response
        .clone()
        .json()
        .catch(() => null)
      if (
        response.status === 403 &&
        payload &&
        typeof payload === "object" &&
        (payload as Record<string, unknown>).error ===
          "protected_secret_transport_unavailable"
      ) {
        protectedTransportUnavailableHandler?.()
      }
    }
    return response.ok
  })()

  try {
    return await pendingGrant
  } finally {
    // Cleared whether the grant succeeded, was refused, or threw, so a later
    // request is never answered by a stale verdict from a previous prompt.
    pendingGrant = null
  }
}

/**
 * fetch() that answers a step-up requirement and replays the request once.
 *
 * Every caller that talks to a privileged endpoint must go through this rather
 * than through fetch() directly. There is no way to tell from a call site
 * whether the endpoint is privileged today, and a module keeping its own
 * fetch() silently opts out - which is exactly what backup.ts did until this
 * wrapper existed.
 */
export const fetchWithStepUp = async (
  url: string,
  init: RequestInit = {},
  fetchImpl: typeof fetch = fetch
): Promise<Response> => {
  const response = await fetchImpl(url, init)

  if (response.status !== 403 || !isReplayable(init.body)) {
    return response
  }

  // Peeked on a clone: the caller still has to read the body itself, and a
  // response consumed here would reach it empty.
  const payload = await response
    .clone()
    .json()
    .catch(() => null)
  if (!isStepUpRequired(response.status, payload)) {
    return response
  }

  const granted = await requestStepUpGrant(fetchImpl)
  if (!granted) {
    return response
  }

  // Exactly once. A second refusal is the answer, not an invitation to prompt
  // in a loop.
  return fetchImpl(url, init)
}

// Exported for tests: the module-level single-flight state would otherwise
// leak between cases.
export const resetStepUpState = () => {
  promptHandler = null
  pendingGrant = null
  protectedTransportUnavailableHandler = null
}
