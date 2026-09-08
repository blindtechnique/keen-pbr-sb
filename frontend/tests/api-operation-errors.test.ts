import { describe, expect, test } from "bun:test"

import {
  getApiErrorMessage,
  getApiValidationErrors,
  formatValidationErrors,
  getOperationErrorPresentation,
  type OperationErrorKind,
} from "../src/lib/api-errors"

describe("validation metadata normalization", () => {
  test("preserves only code and params alongside the existing normalized path and message", () => {
    const params = Object.freeze({ min: "1", max: "63" })
    const entry = Object.freeze({
      path: " route.rules[0].dscp ",
      message: " changed wording ",
      code: "config.value.integer_range",
      params,
      request: "DO_NOT_COPY",
    })
    const parsed = getApiValidationErrors({
      status: 400,
      message: "error",
      details: { validation_errors: [entry] },
    })
    expect(parsed).toEqual([
      {
        path: "route.rules[0].dscp",
        message: "changed wording",
        code: entry.code,
        params,
      },
    ])
    expect(parsed[0].params).toBe(params)
    expect(entry.path).toBe(" route.rules[0].dscp ")
    expect(formatValidationErrors(parsed)).toBe(
      '- route.rules[0].dscp: changed wording\n  code: config.value.integer_range\n  params: {"min":"1","max":"63"}'
    )
  })

  test("unknown and malformed codes survive normalization without serializing arbitrary nested data", () => {
    const code = { private: "DO_NOT_RENDER" }
    const params = {
      nested: { password: "DO_NOT_RENDER" },
      toJSON: () => {
        throw new Error("must not serialize original params")
      },
    }
    const parsed = getApiValidationErrors({
      status: 400,
      message: "error",
      details: {
        validation_errors: [
          { path: "field", message: "original cause", code, params },
        ],
      },
    })
    expect(parsed[0].code).toBe(code)
    expect(parsed[0].params).toBe(params)
    expect(formatValidationErrors(parsed)).toBe("- field: original cause")
    expect(
      formatValidationErrors([
        {
          path: "field",
          message: "cause",
          code: "config.future",
          params: { max: "4" },
        },
      ])
    ).toContain("code: config.future")
  })
})

const rolledBack = {
  error: "Commit/apply failed: firewall publication failed",
  saved: false,
  applied: false,
  rolled_back: true,
  runtime_unchanged: false,
  file_rolled_back: true,
  recovery_required: false,
}

function apiError(details: Record<string, unknown>, status = 500) {
  return {
    status,
    message:
      typeof details.error === "string"
        ? details.error
        : `Request failed with status ${status}`,
    details,
  }
}

describe("operation error presentation", () => {
  test("stable codes keep their meaning when backend prose changes", () => {
    const codes = [
      "busy",
      "draft_pending",
      "draft_changed",
      "recovery_required",
      "validation",
      "preview_expired",
      "service_unavailable",
      "subscription_unavailable",
      "invalid_connection",
      "name_in_use",
      "no_interface_name",
    ] as const
    for (const code of codes) {
      expect(
        getOperationErrorPresentation(
          apiError({ error: "Reworded backend explanation", code })
        )
      ).toEqual({
        kind: code,
        details: `Reworded backend explanation\ncode: ${code}`,
      })
    }
    expect(
      getOperationErrorPresentation(
        apiError({
          error: "A lifecycle operation is already active",
          code: "name_in_use",
        })
      )?.kind
    ).toBe("name_in_use")
  })

  test("unknown codes do not borrow a familiar meaning from old prose or flags", () => {
    for (const details of [
      { error: "A lifecycle operation is already active" },
      { error: "Persistent recovery required" },
      { reason: "base_revision_mismatch" },
      { validation_errors: [{ path: "name", message: "invalid" }] },
      rolledBack,
    ]) {
      expect(
        getOperationErrorPresentation(
          apiError({ ...details, code: "future_code" })
        )?.kind
      ).toBe("unknown")
    }
    for (const code of [" busy ", "constructor", {}, ["busy"], 409, false]) {
      expect(
        getOperationErrorPresentation(
          apiError({ error: "A lifecycle operation is already active", code })
        )?.kind
      ).toBe("unknown")
    }
    for (const code of [undefined, null, ""]) {
      expect(
        getOperationErrorPresentation(
          apiError({ error: "A lifecycle operation is already active", code })
        )?.kind
      ).toBe("busy")
    }
  })

  test("optimistic terminal codes still require the complete matching outcome", () => {
    for (const code of ["rolled_back", "apply_unchanged"] as const) {
      const terminal = {
        ...rolledBack,
        rolled_back: code === "rolled_back",
        runtime_unchanged: code === "apply_unchanged",
        code,
      }
      expect(getOperationErrorPresentation(apiError(terminal))?.kind).toBe(code)
      expect(getOperationErrorPresentation(apiError({ code }))?.kind).toBe(
        "unknown"
      )
      for (const field of [
        "saved",
        "applied",
        "rolled_back",
        "runtime_unchanged",
        "file_rolled_back",
        "recovery_required",
      ]) {
        const incomplete: Record<string, unknown> = { ...terminal }
        delete incomplete[field]
        expect(getOperationErrorPresentation(apiError(incomplete))?.kind).toBe(
          "unknown"
        )
      }
      expect(
        getOperationErrorPresentation(apiError({ ...terminal, applied: true }))
          ?.kind
      ).toBe("unknown")
      expect(
        getOperationErrorPresentation(
          apiError({
            ...terminal,
            code: code === "rolled_back" ? "apply_unchanged" : "rolled_back",
          })
        )?.kind
      ).toBe("unknown")
    }
  })

  test("explicit recovery failures outrank conflicting or unfamiliar codes", () => {
    for (const code of [
      "busy",
      "rolled_back",
      "apply_unchanged",
      "future_code",
    ]) {
      for (const recovery of [
        { recovery_required: true },
        { recovery_error: "file recovery failed" },
        { rollback_error: "runtime rollback failed" },
      ]) {
        expect(
          getOperationErrorPresentation(
            apiError({
              ...rolledBack,
              ...recovery,
              code,
              apply_error: "A lifecycle operation is already active",
            })
          )?.kind
        ).toBe("recovery_required")
      }
    }
  })

  test("absence stays absent and native errors and plain throws keep exact text", () => {
    for (const absent of [null, undefined, "", "   "]) {
      expect(getOperationErrorPresentation(absent)).toBeNull()
    }
    for (const value of [
      "  exact cause\nsecond line  ",
      new Error("  exact cause\nsecond line  "),
    ]) {
      expect(getOperationErrorPresentation(value)).toEqual({
        kind: "unknown",
        details: "  exact cause\nsecond line  ",
      })
    }
    for (const value of [0, false, 42]) {
      expect(getOperationErrorPresentation(value)).toEqual({
        kind: "unknown",
        details: String(value),
      })
    }
  })

  test("classifies known primary messages and retains busy labels in details", () => {
    const cases: [string, OperationErrorKind][] = [
      ["Another runtime mutation is already in progress: save-config", "busy"],
      ["A lifecycle operation is already active", "busy"],
      ["Routing runtime initialization or shutdown is in progress", "busy"],
      [
        "Save or discard the current configuration draft before creating a linked transport",
        "draft_pending",
      ],
      ["authentication required", "unauthenticated"],
      ["step_up_required", "reauthentication_required"],
      [
        "the subscription preview has expired; fetch it again",
        "preview_expired",
      ],
      ["name is already in use", "name_in_use"],
      ["no free interface name could be derived", "no_interface_name"],
      ["cannot derive link identity", "invalid_connection"],
      ["connection data was not accepted", "invalid_connection"],
      ["subscription fetch failed", "subscription_unavailable"],
      ["subscription fetch failed: HTTP 403", "subscription_unavailable"],
      [
        "subscription fetch failed: destination policy",
        "subscription_unavailable",
      ],
      ["transport manager is unavailable", "service_unavailable"],
    ]
    for (const [message, kind] of cases) {
      expect(
        getOperationErrorPresentation(apiError({ error: message }))
      ).toEqual({ kind, details: message })
    }
    for (const message of [
      "wrapped: Another runtime mutation is already in progress",
      "protected_secret_transport_unavailable",
      "authentication is disabled; no-auth API access is loopback-only",
    ]) {
      expect(getOperationErrorPresentation(message)?.kind).toBe("unknown")
    }
  })

  test("HTTP status alone never promises a particular failure cause", () => {
    for (const status of [400, 401, 403, 409, 410, 500, 503]) {
      expect(
        getOperationErrorPresentation(
          apiError({ error: "new backend failure" }, status)
        )
      ).toEqual({ kind: "unknown", details: "new backend failure" })
    }
    for (const reason of [
      "draft_base_revision_mismatch",
      "base_revision_mismatch",
    ]) {
      expect(
        getOperationErrorPresentation(apiError({ reason }, 409))?.kind
      ).toBe("draft_changed")
    }
    expect(
      getOperationErrorPresentation(apiError({ reason: "future_reason" }, 409))
        ?.kind
    ).toBe("unknown")
  })

  test("step-up requests confirmation rather than a different account or rights", () => {
    expect(
      getOperationErrorPresentation(
        apiError({ error: "step_up_required" }, 403)
      )
    ).toEqual({
      kind: "reauthentication_required",
      details: "step_up_required",
    })
    expect(
      getOperationErrorPresentation(
        apiError({ error: "authentication required" }, 401)
      )?.kind
    ).toBe("unauthenticated")
    expect(
      getOperationErrorPresentation(
        apiError({ error: "unknown access refusal" }, 403)
      )?.kind
    ).toBe("unknown")
  })

  test("unknown string reasons and codes remain available without guessing their meaning", () => {
    expect(
      getOperationErrorPresentation(
        apiError({
          error: "New backend failure",
          reason: "  future_reason  ",
          code: "future_code",
          request: { password: "not a diagnostic" },
        })
      )
    ).toEqual({
      kind: "unknown",
      details:
        "New backend failure\nreason:   future_reason  \ncode: future_code",
    })
    expect(
      getOperationErrorPresentation({
        reason: "future_reason",
        code: "future_code",
      })
    ).toEqual({
      kind: "unknown",
      details: "reason: future_reason\ncode: future_code",
    })
  })

  test("distinguishes proven rollback from an unchanged runtime", () => {
    expect(getOperationErrorPresentation(apiError(rolledBack))).toEqual({
      kind: "rolled_back",
      details: rolledBack.error,
    })
    expect(
      getOperationErrorPresentation(
        apiError({ ...rolledBack, rolled_back: false, runtime_unchanged: true })
      )?.kind
    ).toBe("apply_unchanged")

    for (const field of [
      "saved",
      "applied",
      "rolled_back",
      "runtime_unchanged",
      "file_rolled_back",
      "recovery_required",
    ]) {
      const incomplete: Record<string, unknown> = { ...rolledBack }
      delete incomplete[field]
      expect(getOperationErrorPresentation(apiError(incomplete))?.kind).toBe(
        "unknown"
      )
      expect(
        getOperationErrorPresentation(
          apiError({ ...rolledBack, [field]: "false" })
        )?.kind
      ).toBe("unknown")
    }
    for (const flags of [
      { rolled_back: true },
      { runtime_unchanged: true },
      { file_rolled_back: true },
      { ...rolledBack, applied: true },
      { ...rolledBack, runtime_unchanged: true },
    ]) {
      expect(getOperationErrorPresentation(apiError(flags))?.kind).toBe(
        "unknown"
      )
    }
  })

  test("recovery and rollback failures win over busy and restoration flags", () => {
    const busy = "Another runtime mutation is already in progress: save-config"
    for (const diagnostics of [
      { recovery_required: true },
      { recovery_error: "exact file recovery could not be proven" },
      { rollback_error: "rollback firewall publication failed" },
    ]) {
      expect(
        getOperationErrorPresentation(
          apiError({ ...rolledBack, error: busy, ...diagnostics })
        )?.kind
      ).toBe("recovery_required")
    }
    expect(
      getOperationErrorPresentation(
        apiError({ error: "Commit/apply failed", apply_error: busy })
      )?.kind
    ).toBe("unknown")
    expect(
      getOperationErrorPresentation(
        apiError({ apply_error: busy, rollback_error: "exact rollback cause" })
      )
    ).toEqual({
      kind: "recovery_required",
      details: `Request failed with status 500\napply_error: ${busy}\nrollback_error: exact rollback cause`,
    })
  })

  test("keeps original apply and recovery causes alongside validation details", () => {
    expect(
      getOperationErrorPresentation(
        apiError({
          error:
            "Runtime rolled back, but exact persistent recovery could not be proven",
          recovery_required: true,
          apply_error: "  original apply cause  ",
          recovery_error: "  directory sync failed  ",
          validation_errors: [
            {
              path: "  outbounds[0].server  ",
              message: "  exact validation cause  ",
            },
          ],
        })
      )
    ).toEqual({
      kind: "recovery_required",
      details:
        "Runtime rolled back, but exact persistent recovery could not be proven\napply_error:   original apply cause  \nrecovery_error:   directory sync failed  \n-   outbounds[0].server  :   exact validation cause  ",
    })
    expect(
      getOperationErrorPresentation(
        apiError({
          error: "Config validation failed",
          validation_errors: [{ path: "lists[0]", message: "duplicate name" }],
        })
      )
    ).toEqual({
      kind: "validation",
      details: "Config validation failed\n- lists[0]: duplicate name",
    })
  })

  test("only exact browser fetch failures are described as network errors", () => {
    for (const message of [
      "Failed to fetch",
      "NetworkError when attempting to fetch resource.",
      "Load failed",
      "fetch failed",
    ]) {
      expect(getOperationErrorPresentation(new TypeError(message))).toEqual({
        kind: "network",
        details: message,
      })
    }
    expect(
      getOperationErrorPresentation(
        new TypeError("Cannot read properties of undefined")
      )?.kind
    ).toBe("unknown")
  })

  test("malformed objects never expose arbitrary fields or stringify payloads", () => {
    const details = {
      error: "known diagnostic",
      apply_error: { nested_secret: "must not leak" },
      rollback_error: ["must not leak"],
      recovery_required: "true",
      reason: { private_reason: "must not leak" },
      code: ["must not leak"],
      validation_errors: [
        null,
        { path: "leaked", message: 7 },
        { path: 7, message: "leaked" },
      ],
      url: "https://provider.invalid/private-token",
      request: { password: "private-password", body: "private request body" },
      toString() {
        throw new Error("must not stringify payload")
      },
    }
    expect(getOperationErrorPresentation(apiError(details))).toEqual({
      kind: "unknown",
      details: "known diagnostic",
    })
    for (const value of [
      {},
      [],
      { details: [details] },
      { message: details },
      Symbol("secret"),
    ]) {
      expect(getOperationErrorPresentation(value)).toEqual({
        kind: "unknown",
        details: "",
      })
    }
    expect(
      getOperationErrorPresentation(apiError({ error: "constructor" }))?.kind
    ).toBe("unknown")
  })

  test("leaves the existing raw formatter unchanged for unrelated callers", () => {
    expect(
      getApiErrorMessage(
        apiError({
          error: "Raw server error",
          recovery_required: true,
          recovery_error: "additional cause",
          validation_errors: [{ path: " path ", message: " message " }],
        })
      )
    ).toBe("Raw server error\n- path: message")
  })
})
