/**
 * The terminal outcome of a service control command.
 *
 * `POST /api/nfqws` answers HTTP 200 whether or not the init script succeeded -
 * the body is the only place the real outcome appears. A client that checks
 * `response.ok` alone therefore reports success for every failed restart,
 * which is the single most misleading thing a restart button can do.
 */
export type ServiceRestartResult = {
  readonly ok: boolean
  /** Combined stdout and stderr of the init script. May be empty. */
  readonly output: string
  /** Process exit status when the daemon reported one. */
  readonly exitCode: number | undefined
}

export class ServiceRestartFailure extends Error {
  readonly result: ServiceRestartResult

  constructor(result: ServiceRestartResult) {
    super(firstMeaningfulLine(result.output) || "service restart failed")
    this.name = "ServiceRestartFailure"
    this.result = result
  }
}

/**
 * Reads the `{ok, output, status}` body the nfqws service endpoint returns.
 *
 * Deliberately fail-closed: only a literal `true` counts as success. A missing
 * field, a null, a truthy string or a body that is not an object at all all
 * mean we do not know that the service came back, and claiming otherwise is
 * exactly the failure this parser exists to prevent.
 */
export function parseServiceCommandResult(
  payload: unknown
): ServiceRestartResult {
  if (typeof payload !== "object" || payload === null) {
    return { ok: false, output: "", exitCode: undefined }
  }

  const body = payload as Record<string, unknown>
  const exitCode =
    typeof body.status === "number" && Number.isFinite(body.status)
      ? body.status
      : undefined

  return {
    ok: body.ok === true,
    output: typeof body.output === "string" ? body.output : "",
    exitCode,
  }
}

/**
 * The first line worth showing a human, for a one-line failure notice.
 *
 * Init scripts pad their output with blank lines and progress dots; leading
 * with those would waste the one line a toast has.
 */
export function firstMeaningfulLine(output: string): string {
  for (const line of output.split("\n")) {
    const trimmed = line.trim()
    if (trimmed.length > 0) {
      return trimmed
    }
  }
  return ""
}
