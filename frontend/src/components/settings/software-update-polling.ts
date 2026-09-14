export class UpdateRequestTimeout extends Error {
  constructor() {
    super("update status request timed out")
  }
}

// Bound only the actual HTTP exchange, not the time a user spends answering
// a step-up prompt. Buffer the small JSON response inside the same deadline.
export async function fetchUpdateCommand(
  input: Parameters<typeof fetch>[0],
  init?: RequestInit,
  fetchImpl: typeof fetch = fetch,
  timeoutMs = 60_000
): Promise<Response> {
  const controller = new AbortController()
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([
      (async () => {
        const response = await fetchImpl(input, {
          ...init,
          signal: controller.signal,
        })
        const body = await response.arrayBuffer()
        return new Response(body.byteLength ? body : null, {
          status: response.status,
          statusText: response.statusText,
          headers: response.headers,
        })
      })(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          controller.abort()
          reject(new UpdateRequestTimeout())
        }, timeoutMs)
      }),
    ])
  } finally {
    clearTimeout(timer)
  }
}

// The caller owns response/error publication. Abort and the generation check
// below prevent a retired attempt from publishing a late response.
export function startUpdatePolling<T>({
  read,
  onValue,
  onError,
  onExpired,
  deadline,
  intervalMs = 3000,
  timeoutMs = 10_000,
  now = Date.now,
}: {
  read: (signal: AbortSignal) => Promise<T>
  onValue: (value: T) => boolean | void
  onError: (error: unknown) => void
  onExpired: () => void
  deadline: number
  intervalMs?: number
  timeoutMs?: number
  now?: () => number
}) {
  let stopped = false
  let timer: ReturnType<typeof setTimeout> | undefined
  let requestTimer: ReturnType<typeof setTimeout> | undefined
  let controller: AbortController | undefined
  const stop = () => {
    stopped = true
    clearTimeout(timer)
    clearTimeout(requestTimer)
    controller?.abort()
  }
  const poll = async () => {
    if (stopped) return
    if (now() >= deadline) {
      onExpired()
      stop()
      return
    }
    controller = new AbortController()
    try {
      const signal = controller.signal
      const value = await Promise.race([
        read(signal),
        new Promise<never>((_, reject) => {
          requestTimer = setTimeout(() => {
            controller?.abort()
            reject(new UpdateRequestTimeout())
          }, timeoutMs)
        }),
      ])
      if (!stopped && onValue(value) === false) stop()
    } catch (error) {
      if (!stopped) onError(error)
    } finally {
      clearTimeout(requestTimer)
      if (!stopped) timer = setTimeout(() => void poll(), intervalMs)
    }
  }
  void poll()
  return stop
}
