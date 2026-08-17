import { describe, expect, test } from "bun:test"
import { FieldApi, FormApi } from "@tanstack/react-form"

import { getGeneralConfigActionState } from "../src/pages/general-config-form-state"

type Draft = {
  internalVpnEnabled: boolean
  inboundInterfaces: string[]
}

type DraftFormApi = FormApi<
  Draft,
  never,
  never,
  never,
  never,
  never,
  never,
  never,
  never,
  never,
  never,
  never
>

function actionState(form: DraftFormApi) {
  return getGeneralConfigActionState({
    canSubmit: form.state.canSubmit,
    deferredDirty: false,
    deferredValid: true,
    isDefaultValue: form.state.isDefaultValue,
    isPending: false,
  })
}

describe("general settings semantic action state", () => {
  test("becomes clean after a toggle is restored to its baseline", () => {
    const form = new FormApi({
      defaultValues: {
        internalVpnEnabled: true,
        inboundInterfaces: ["br0", "nwg0"],
      },
    })
    const field = new FieldApi({
      form,
      name: "internalVpnEnabled",
    })
    const unmountForm = form.mount()
    const unmountField = field.mount()

    form.setFieldValue("internalVpnEnabled", false)
    expect(actionState(form).hasChanges).toBe(true)

    form.setFieldValue("internalVpnEnabled", true)
    expect(form.state.isPristine).toBe(false)
    expect(actionState(form)).toMatchObject({
      cancelDisabled: true,
      hasChanges: false,
      saveDisabled: true,
    })

    unmountField()
    unmountForm()
  })

  test("becomes clean after an ordered interface list is restored", () => {
    const form = new FormApi({
      defaultValues: {
        internalVpnEnabled: true,
        inboundInterfaces: ["br0", "nwg0"],
      },
    })
    const field = new FieldApi({
      form,
      name: "inboundInterfaces",
    })
    const unmountForm = form.mount()
    const unmountField = field.mount()

    form.setFieldValue("inboundInterfaces", ["nwg0", "br0"])
    expect(actionState(form).hasChanges).toBe(true)

    form.setFieldValue("inboundInterfaces", ["br0", "nwg0"])
    expect(form.state.isPristine).toBe(false)
    expect(actionState(form).hasChanges).toBe(false)

    unmountField()
    unmountForm()
  })

  test("keeps deferred sections independently dirty", () => {
    expect(
      getGeneralConfigActionState({
        canSubmit: true,
        deferredDirty: true,
        deferredValid: true,
        isDefaultValue: true,
        isPending: false,
      })
    ).toEqual({
      cancelDisabled: false,
      hasChanges: true,
      saveDisabled: false,
    })
  })
})
