import { describe, expect, test } from "bun:test"
import { FieldApi, FormApi } from "@tanstack/react-form"

import type { ApiError } from "../src/api/client"
import {
  applyFormApiErrors,
  clearFormServerErrors,
  getUnmappedFormErrors,
  isServerOperationError,
  setFormServerErrors,
  splitFormApiErrors,
  type ServerOperationError,
} from "../src/lib/form-api-errors"

function validationError(
  validationErrors: { path: string; message: string }[]
): ApiError {
  return {
    status: 400,
    message: "Config validation failed",
    details: { validation_errors: validationErrors },
  }
}

describe("server validation field mapping", () => {
  test("resolves original paths and messages before preserving ordered field entries", () => {
    const entries = [
      { path: "dns.servers.main.address", message: "Invalid server address" },
      { path: "dns.servers.main.port", message: "must be between 1 and 65535" },
      { path: "dns.servers.main.address", message: "second address error" },
    ]
    const received: [string, string][] = []
    const split = splitFormApiErrors({
      error: validationError(entries),
      fieldNames: ["address", "port"],
      resolvePath: (path, message) => {
        received.push([path, message])
        return path.endsWith(".address") ? "address" : "port"
      },
    })

    expect(received).toEqual(
      entries.map(({ path, message }) => [path, message])
    )
    expect(split).toEqual({
      fieldErrors: {
        address: {
          kind: "server-validation",
          entries: [entries[0], entries[2]],
        },
        port: { kind: "server-validation", entries: [entries[1]] },
      },
      formError: null,
      unmappedErrors: [],
    })
  })

  test("keeps unsupported paths and disallowed resolved fields unmapped", () => {
    const entries = [
      { path: "dns.future", message: "Unknown future constraint" },
      { path: "dns.servers.main.port", message: "Invalid port" },
    ]
    const split = splitFormApiErrors({
      error: validationError(entries),
      fieldNames: ["address"],
      resolvePath: (path) => (path.endsWith(".port") ? "port" : undefined),
    })
    expect(split).toEqual({
      fieldErrors: {},
      formError: null,
      unmappedErrors: entries,
    })
  })

  test("allows message-sensitive resolvers to retain their current field choice", () => {
    const message = "Outbound 'vpn-main' not found"
    const split = splitFormApiErrors({
      error: validationError([{ path: "rules[0]", message }]),
      resolvePath: (_path, rawMessage) =>
        rawMessage === message ? "outbound" : undefined,
    })
    expect(split.fieldErrors.outbound).toEqual({
      kind: "server-validation",
      entries: [{ path: "rules[0]", message }],
    })
    expect(split.unmappedErrors).toEqual([])
  })

  test("retains general operation failures as tagged originals and keeps absence empty", () => {
    const resolvePath = () => "address"
    const error: ApiError = {
      status: 500,
      message: "Exact operation failure",
      details: { code: "busy", apply_error: "original apply cause" },
    }
    expect(splitFormApiErrors({ error: null, resolvePath })).toEqual({
      fieldErrors: {},
      formError: null,
      unmappedErrors: [],
    })
    const split = splitFormApiErrors({ error, resolvePath })
    expect(split).toEqual({
      fieldErrors: {},
      formError: { kind: "server-operation", error },
      unmappedErrors: [],
    })
    expect(split.formError?.error).toBe(error)
  })

  test("keeps local validation strings and field-invalid behavior unchanged", () => {
    const form = new FormApi({ defaultValues: { address: "" } })
    const field = new FieldApi({ form, name: "address" })
    const unmountForm = form.mount()
    const unmountField = field.mount()
    try {
      setFormServerErrors(form, {
        fields: { address: "Введите адрес сервера" },
      })
      expect(field.state.meta.errors).toEqual(["Введите адрес сервера"])
      expect(field.state.meta.isValid).toBe(false)

      clearFormServerErrors(form)
      expect(field.state.meta.errors).toEqual([])
      expect(field.state.meta.isValid).toBe(true)
    } finally {
      unmountField()
      unmountForm()
    }
  })

  test("applies tagged errors to the same field and clears them through the existing API", () => {
    const form = new FormApi({ defaultValues: { address: "" } })
    const field = new FieldApi({ form, name: "address" })
    const unmountForm = form.mount()
    const unmountField = field.mount()
    const entry = {
      path: "dns.servers.main.address",
      message: "Invalid server address",
    }
    try {
      const formMessage = applyFormApiErrors({
        error: validationError([entry]),
        form,
        fieldNames: ["address"],
        resolvePath: () => "address",
      })
      expect(formMessage).toBeNull()
      expect(field.state.meta.errors).toEqual([
        { kind: "server-validation", entries: [entry] },
      ])
      expect(field.state.meta.isValid).toBe(false)

      applyFormApiErrors({ error: null, form, resolvePath: () => "address" })
      expect(field.state.meta.errors).toEqual([])
      expect(field.state.meta.isValid).toBe(true)
    } finally {
      unmountField()
      unmountForm()
    }
  })

  test("stores original operation errors through real TanStack normalization", async () => {
    const form = new FormApi({ defaultValues: { address: "old" } })
    const unmount = form.mount()
    const error: ApiError = {
      status: 503,
      message: "Exact operation failure",
      details: { code: "recovery_required", recovery_error: "exact cause" },
    }
    try {
      const operation = applyFormApiErrors({
        error,
        form,
        resolvePath: () => undefined,
      })
      expect(form.state.errorMap.onServer).toBe(operation)
      expect(isServerOperationError(form.state.errorMap.onServer)).toBe(true)
      expect(operation?.error).toBe(error)
      expect(form.state.isValid).toBe(false)

      form.setFieldValue("address", "new")
      await form.validate("change")
      expect(form.state.errorMap.onServer).toBeUndefined()
      expect(form.state.errors).toEqual([])
      expect(form.state.isValid).toBe(true)
      expect(form.state.canSubmit).toBe(true)
    } finally {
      unmount()
    }
  })

  test("preserves unmapped validation through normalization and clears without a sentinel", async () => {
    const form = new FormApi({ defaultValues: { address: "old" } })
    const unmount = form.mount()
    const entries = [
      { path: "dns.future", message: "Unknown future constraint" },
    ]
    try {
      applyFormApiErrors({
        error: validationError(entries),
        form,
        resolvePath: () => undefined,
      })
      expect(getUnmappedFormErrors(form.state.errorMap.onServer)).toEqual(
        entries
      )
      expect(form.state.isValid).toBe(false)

      form.setFieldValue("address", "new")
      await form.validate("change")
      expect(form.state.errorMap.onServer).toBeUndefined()
      expect(getUnmappedFormErrors(form.state.errorMap.onServer)).toEqual([])
      expect(form.state.isValid).toBe(true)
      expect(form.state.canSubmit).toBe(true)

      setFormServerErrors(form, { unmapped: entries })
      clearFormServerErrors(form)
      expect(form.state.errorMap.onServer).toBeUndefined()
      expect(form.state.errors).toEqual([])
      expect(form.state.isValid).toBe(true)

      setFormServerErrors(form, { unmapped: [] })
      expect(form.state.errorMap.onServer).toBeUndefined()
      expect(form.state.errors).toEqual([])
      expect(form.state.canSubmit).toBe(true)
    } finally {
      unmount()
    }
  })

  test("keeps local form messages as strings rather than server operations", () => {
    const form = new FormApi({ defaultValues: { address: "" } })
    const unmount = form.mount()
    try {
      const message = "Добавьте хотя бы одно условие"
      setFormServerErrors(form, { form: message })
      expect(form.state.errorMap.onServer).toBe(message)
      expect(isServerOperationError(form.state.errorMap.onServer)).toBe(false)
      expect(form.state.isValid).toBe(false)
      clearFormServerErrors(form)
      expect(form.state.errorMap.onServer).toBeUndefined()
      expect(form.state.isValid).toBe(true)
    } finally {
      unmount()
    }
  })

  test("recognizes only tagged operation errors and leaves technical entries unchanged", () => {
    const error: ApiError = { status: 409, message: "Exact cause" }
    expect(isServerOperationError({ kind: "server-operation", error })).toBe(
      true
    )
    expect(
      isServerOperationError({
        kind: "server-operation",
        error: new TypeError("Failed to fetch"),
      })
    ).toBe(true)
    for (const value of [
      null,
      "local error",
      {},
      error,
      { kind: "server-operation" },
    ]) {
      expect(isServerOperationError(value)).toBe(false)
      expect(getUnmappedFormErrors(value)).toEqual([])
    }
    const entries = [{ path: "raw.path", message: "Exact original cause" }]
    expect(getUnmappedFormErrors({ kind: "server-validation", entries })).toBe(
      entries
    )
    expect(
      getUnmappedFormErrors({
        kind: "server-validation",
        entries: [{ path: 42 }],
      })
    ).toEqual([])
  })

  test.each(["replace", "clear"] as const)(
    "keeps the previous async submit cause tagged while pending, then %ss it",
    async (outcome) => {
      const first: ServerOperationError = {
        kind: "server-operation",
        error: {
          status: 409,
          message: "first exact cause",
          details: { code: "busy" },
        },
      }
      const next: ServerOperationError | undefined =
        outcome === "replace"
          ? {
              kind: "server-operation",
              error: { status: 503, message: "next exact cause" },
            }
          : undefined
      let resolvePending!: (value: ServerOperationError | undefined) => void
      const pending = new Promise<ServerOperationError | undefined>(
        (resolve) => {
          resolvePending = resolve
        }
      )
      let attempts = 0
      const form = new FormApi({
        defaultValues: { address: "" },
        validators: {
          onSubmitAsync: async () => {
            clearFormServerErrors(form)
            const result = ++attempts === 1 ? first : await pending
            setFormServerErrors(form, { form: result })
            return { form: result, fields: {} }
          },
        },
      })
      const unmount = form.mount()
      try {
        await form.validate("submit")
        expect(form.state.errorMap.onSubmit).toBe(first)
        expect(form.state.errorMap.onServer).toBe(first)

        const secondValidation = form.validate("submit")
        expect(form.state.errorMap.onServer).toBeUndefined()
        expect(form.state.errorMap.onSubmit).toBe(first)
        expect(isServerOperationError(form.state.errorMap.onSubmit)).toBe(true)
        expect(form.state.isFormValidating).toBe(true)

        resolvePending(next)
        await secondValidation
        expect(attempts).toBe(2)
        expect(form.state.errorMap.onSubmit).toBe(next)
        expect(form.state.errorMap.onServer).toBe(next)
        expect(form.state.isValid).toBe(outcome === "clear")
        if (outcome === "clear") expect(form.state.canSubmit).toBe(true)
      } finally {
        resolvePending(undefined)
        unmount()
      }
    }
  )
})
