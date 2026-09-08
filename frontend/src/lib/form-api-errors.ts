import type { AnyFormApi } from "@tanstack/react-form"

import type { ApiError } from "@/api/client"
import {
  getApiValidationErrors,
  type ValidationErrorEntry,
} from "@/lib/api-errors"

export type ApiPathResolver = (
  path: string,
  message: string
) => string | undefined

export type ServerFieldValidationError = {
  kind: "server-validation"
  entries: ValidationErrorEntry[]
  // Presentation only: server paths and messages remain unchanged.
  lineNumbers?: Readonly<Record<string, number>>
}

export type ServerOperationError = {
  kind: "server-operation"
  error: ApiError
}

export function isServerOperationError(
  value: unknown
): value is ServerOperationError {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false
  }
  const candidate = value as Partial<ServerOperationError>
  return (
    candidate.kind === "server-operation" &&
    Boolean(candidate.error) &&
    typeof candidate.error === "object" &&
    !Array.isArray(candidate.error) &&
    typeof candidate.error?.message === "string"
  )
}

const EMPTY_VALIDATION_ERRORS: ValidationErrorEntry[] = []

export function getUnmappedFormErrors(value: unknown): ValidationErrorEntry[] {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return EMPTY_VALIDATION_ERRORS
  }
  const candidate = value as Partial<ServerFieldValidationError>
  if (
    candidate.kind !== "server-validation" ||
    !Array.isArray(candidate.entries) ||
    !candidate.entries.every(
      (entry) =>
        entry &&
        typeof entry === "object" &&
        typeof entry.path === "string" &&
        typeof entry.message === "string"
    )
  ) {
    return EMPTY_VALIDATION_ERRORS
  }
  return candidate.entries
}

export type FormServerErrorMap = {
  form?: string | ServerOperationError
  fields?: Record<string, string | ServerFieldValidationError>
  unmapped?: ValidationErrorEntry[]
}

type ApplyFormApiErrorsOptions = {
  error: ApiError | null
  form: AnyFormApi
  fieldNames?: readonly string[]
  resolvePath: ApiPathResolver
}

type SplitFormApiErrorsOptions = {
  error: ApiError | null
  fieldNames?: readonly string[]
  resolvePath: ApiPathResolver
}

export type SplitFormApiErrorsResult = {
  fieldErrors: Record<string, ServerFieldValidationError>
  formError: ServerOperationError | null
  unmappedErrors: ValidationErrorEntry[]
}

export function setFormServerErrors(
  form: AnyFormApi,
  options: FormServerErrorMap
) {
  // TanStack normalizes { form, fields } and stores only the form value.
  // Keep presentation data inside that value, not in discarded sibling keys.
  const formError =
    options.form !== undefined
      ? options.form
      : options.unmapped?.length
        ? {
            kind: "server-validation" as const,
            entries: options.unmapped,
          }
        : undefined
  form.setErrorMap({
    onServer: {
      form: formError,
      fields: options.fields ?? {},
    },
  })
}

export function clearFormServerErrors(form: AnyFormApi) {
  setFormServerErrors(form, {
    form: undefined,
    fields: {},
    unmapped: [],
  })
}

export function splitFormApiErrors({
  error,
  fieldNames,
  resolvePath,
}: SplitFormApiErrorsOptions): SplitFormApiErrorsResult {
  if (!error) {
    return {
      fieldErrors: {},
      formError: null,
      unmappedErrors: [],
    }
  }

  const validationErrors = getApiValidationErrors(error)
  if (validationErrors.length === 0) {
    return {
      fieldErrors: {},
      formError: { kind: "server-operation", error },
      unmappedErrors: [],
    }
  }

  const fieldErrors: Record<string, ServerFieldValidationError> = {}
  const allowedFieldNames = fieldNames ? new Set(fieldNames) : null
  const unmappedErrors: ValidationErrorEntry[] = []

  for (const item of validationErrors) {
    const fieldPath = resolvePath(item.path, item.message)
    if (
      !fieldPath ||
      (allowedFieldNames && !allowedFieldNames.has(fieldPath))
    ) {
      unmappedErrors.push(item)
      continue
    }

    const fieldError = (fieldErrors[fieldPath] ??= {
      kind: "server-validation",
      entries: [],
    })
    fieldError.entries.push(item)
  }

  return {
    fieldErrors,
    formError: null,
    unmappedErrors,
  }
}

export function applyFormApiErrors({
  error,
  form,
  fieldNames,
  resolvePath,
}: ApplyFormApiErrorsOptions): ServerOperationError | null {
  clearFormServerErrors(form)

  const { fieldErrors, formError, unmappedErrors } = splitFormApiErrors({
    error,
    fieldNames,
    resolvePath,
  })

  setFormServerErrors(form, {
    form: formError ?? undefined,
    fields: fieldErrors,
    unmapped: unmappedErrors,
  })

  return formError
}
