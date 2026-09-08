import { describe, expect, test } from "bun:test"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { FieldApi, FormApi } from "@tanstack/react-form"
import { createInstance } from "i18next"
import { I18nextProvider } from "react-i18next"
import { renderToStaticMarkup } from "react-dom/server"

import type { Outbound } from "../src/api/generated/model/outbound"
import type { RouteRule } from "../src/api/generated/model/routeRule"
import { RouteFailurePolicyFields } from "../src/components/shared/route-failure-policy-fields"
import {
  getRouteFailureFallbackOutbounds,
  getRouteFailurePolicyPrimaryValidationMessage,
  getRouteFailurePolicyValidationMessage,
  normalizeRouteFailurePolicy,
  supportsRouteFailurePolicy,
  type RouteFailurePolicy,
} from "../src/lib/route-failure-policy"
import { isSemanticallyDirty } from "../src/lib/semantic-dirty"
import { semanticJsonEqual } from "../src/lib/semantic-json"
import {
  areRouteRulesSemanticallyEqual,
  createRouteRuleDraft,
  normalizeRouteRuleDraft,
  toRouteRuleDraft,
} from "../src/pages/routing-rules-utils"
import {
  buildUpdatedConfigForListUpsert,
  createListDraft,
  normalizeQuickSetupForComparison,
  type QuickSetup,
} from "../src/pages/list-upsert-utils"
import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

const outbounds: Outbound[] = [
  { tag: "primary", type: "interface", interface: "nwg0" },
  {
    tag: "backup",
    display_name: "Backup AWG",
    type: "interface",
    interface: "nwg1",
  },
  { tag: "group", display_name: "Reserve group", type: "urltest" },
  { tag: "table", type: "table", table: 500 },
  { tag: "drop", type: "blackhole" },
  { tag: "direct", type: "ignore" },
]
const keyOnly = (key: string) => key

describe("per-rule failure policy persistence", () => {
  test.each([undefined, null, "inherit"] as const)(
    "%s keeps the existing omitted policy and ignores hidden fallback values",
    (policy) => {
      expect(normalizeRouteFailurePolicy(policy, "backup")).toEqual({})
      const rule: RouteRule = {
        outbound: "primary",
        failure_policy: policy,
        fallback_outbound: "backup",
      }
      const draft = toRouteRuleDraft(rule)
      expect(draft.failurePolicy).toBe("inherit")
      expect(normalizeRouteRuleDraft(draft).failure_policy).toBeUndefined()
      expect(normalizeRouteRuleDraft(draft).fallback_outbound).toBeUndefined()
      expect(
        areRouteRulesSemanticallyEqual([rule], [{ outbound: "primary" }])
      ).toBe(true)
    }
  )

  test("new rules default to inherit and explicit fallback round-trips", () => {
    expect(createRouteRuleDraft().failurePolicy).toBe("inherit")
    const rule: RouteRule = {
      id: "sites",
      display_name: "Sites",
      list: ["sites"],
      outbound: "primary",
      failure_policy: "fallback",
      fallback_outbound: "group",
    }
    const normalized = normalizeRouteRuleDraft(toRouteRuleDraft(rule))
    expect(normalized).toMatchObject(rule)
    expect(normalizeRouteFailurePolicy("fallback", "  backup  ")).toEqual({
      failure_policy: "fallback",
      fallback_outbound: "backup",
    })
    expect(normalizeRouteFailurePolicy("block", "backup")).toEqual({
      failure_policy: "block",
    })
  })

  test("restoring inherit clears dirty state without discarding the local reserve choice", () => {
    const baseline = toRouteRuleDraft({ outbound: "primary", list: ["sites"] })
    const changed = {
      ...baseline,
      failurePolicy: "fallback" as const,
      fallbackOutbound: "backup",
    }
    const options = {
      equals: semanticJsonEqual,
      normalize: normalizeRouteRuleDraft,
    }
    expect(isSemanticallyDirty(changed, baseline, options)).toBe(true)
    expect(
      isSemanticallyDirty(
        { ...changed, failurePolicy: "inherit" },
        baseline,
        options
      )
    ).toBe(false)
    expect(changed.fallbackOutbound).toBe("backup")
  })

  test("quick setup persists traffic fallback separately from list-download fallback", () => {
    const result = buildUpdatedConfigForListUpsert(
      { outbounds },
      "create",
      {
        ...createListDraft("Sites"),
        url: "https://example.org/list.txt",
        refreshDetourMode: "override",
        detour: "download_route",
        fallbackDetours: ["download_reserve"],
      },
      undefined,
      {
        createRouteRule: true,
        routeOutbound: "primary",
        routeFailurePolicy: "fallback",
        routeFallbackOutbound: "group",
        createDnsRule: false,
        dnsServer: "",
      }
    )
    expect(result.route?.rules?.[0]).toMatchObject({
      outbound: "primary",
      failure_policy: "fallback",
      fallback_outbound: "group",
    })
    expect(result.lists?.sites).toMatchObject({
      detour: "download_route",
      fallback_detours: ["download_reserve"],
    })
  })

  test("quick-setup dirty state ignores inactive route and fallback controls", () => {
    const baseline: QuickSetup = {
      createRouteRule: true,
      routeOutbound: "primary",
      createDnsRule: false,
      dnsServer: "",
    }
    const compare = (value: QuickSetup, initial = baseline) =>
      isSemanticallyDirty(value, initial, {
        equals: semanticJsonEqual,
        normalize: normalizeQuickSetupForComparison,
      })
    expect(
      compare({
        ...baseline,
        routeFailurePolicy: "inherit",
        routeFallbackOutbound: "backup",
      })
    ).toBe(false)
    expect(
      compare({
        ...baseline,
        routeFailurePolicy: "fallback",
        routeFallbackOutbound: "backup",
      })
    ).toBe(true)
    expect(
      compare(
        {
          ...baseline,
          createRouteRule: false,
          routeFailurePolicy: "fallback",
          routeFallbackOutbound: "backup",
        },
        { ...baseline, createRouteRule: false }
      )
    ).toBe(false)
  })
})

describe("failure policy configuration choices", () => {
  test("changing policy or primary revalidates the reserve and can submit again after correction", async () => {
    const form = new FormApi({
      defaultValues: {
        outbound: "primary",
        failurePolicy: "inherit" as RouteFailurePolicy,
        fallbackOutbound: "",
      },
    })
    const primary = new FieldApi({ form, name: "outbound" })
    const policy = new FieldApi({
      form,
      name: "failurePolicy",
      validators: {
        onChangeListenTo: ["outbound"],
        onChange: ({ value, fieldApi }) =>
          getRouteFailurePolicyPrimaryValidationMessage(
            value,
            fieldApi.form.getFieldValue("outbound"),
            outbounds,
            keyOnly
          ),
      },
    })
    const reserve = new FieldApi({
      form,
      name: "fallbackOutbound",
      validators: {
        onChangeListenTo: ["failurePolicy", "outbound"],
        onChange: ({ value, fieldApi }) =>
          getRouteFailurePolicyValidationMessage(
            fieldApi.form.getFieldValue("failurePolicy"),
            value,
            fieldApi.form.getFieldValue("outbound"),
            outbounds,
            keyOnly
          ),
      },
    })
    const cleanups = [
      form.mount(),
      primary.mount(),
      policy.mount(),
      reserve.mount(),
    ]
    try {
      policy.handleChange("fallback")
      await form.validateAllFields("submit")
      expect(reserve.state.meta.errors).toContain(
        "routeFailurePolicy.fallbackRequired"
      )
      reserve.handleChange("backup")
      await form.validateAllFields("change")
      expect(reserve.state.meta.errors).toHaveLength(0)
      expect(form.state.canSubmit).toBe(true)
      primary.handleChange("backup")
      await form.validateAllFields("change")
      expect(reserve.state.meta.errors).toContain(
        "routeFailurePolicy.fallbackMustDiffer"
      )
      primary.handleChange("table")
      await form.validateAllFields("change")
      expect(policy.state.meta.errors).toContain(
        "routeFailurePolicy.unsupportedPrimary"
      )
      policy.handleChange("inherit")
      await form.validateAllFields("change")
      expect(policy.state.meta.errors).toHaveLength(0)
      expect(reserve.state.meta.errors).toHaveLength(0)
      expect(form.state.canSubmit).toBe(true)
    } finally {
      for (const cleanup of cleanups.reverse()) cleanup()
    }
  })

  test("reserves are interface or URLTEST only and differ from the primary", () => {
    expect(
      getRouteFailureFallbackOutbounds(outbounds, "primary").map(
        (outbound) => outbound.tag
      )
    ).toEqual(["backup", "group"])
    expect(supportsRouteFailurePolicy(outbounds, "primary")).toBe(true)
    expect(supportsRouteFailurePolicy(outbounds, "group")).toBe(true)
    expect(supportsRouteFailurePolicy(outbounds, "table")).toBe(false)
  })

  test("validates references without requiring current health or a measurement", () => {
    const validate = (fallback: string) =>
      getRouteFailurePolicyValidationMessage(
        "fallback",
        fallback,
        "primary",
        outbounds,
        keyOnly
      )
    expect(validate("backup")).toBeUndefined()
    expect(validate("group")).toBeUndefined()
    expect(validate("")).toBe("routeFailurePolicy.fallbackRequired")
    expect(validate("primary")).toBe("routeFailurePolicy.fallbackMustDiffer")
    for (const unavailable of ["missing", "table", "drop", "direct"]) {
      expect(validate(unavailable)).toBe(
        "routeFailurePolicy.fallbackUnavailable"
      )
    }
    expect(
      getRouteFailurePolicyValidationMessage(
        "inherit",
        "missing",
        "primary",
        outbounds,
        keyOnly
      )
    ).toBeUndefined()
    expect(
      getRouteFailurePolicyValidationMessage(
        "block",
        "missing",
        "primary",
        outbounds,
        keyOnly
      )
    ).toBeUndefined()
  })

  test("an unsupported primary requires explicit inherit rather than silently changing the form", () => {
    for (const primary of ["table", "drop", "direct"]) {
      expect(
        getRouteFailurePolicyPrimaryValidationMessage(
          "fallback",
          primary,
          outbounds,
          keyOnly
        )
      ).toBe("routeFailurePolicy.unsupportedPrimary")
      expect(
        getRouteFailurePolicyPrimaryValidationMessage(
          "inherit",
          primary,
          outbounds,
          keyOnly
        )
      ).toBeUndefined()
    }
    const draft = {
      ...createRouteRuleDraft(),
      outbound: "table",
      failurePolicy: "fallback" as const,
      fallbackOutbound: "backup",
    }
    getRouteFailurePolicyPrimaryValidationMessage(
      draft.failurePolicy,
      draft.outbound,
      outbounds,
      keyOnly
    )
    expect(draft.failurePolicy).toBe("fallback")
    expect(draft.fallbackOutbound).toBe("backup")
  })
})

async function renderPolicy(
  policy: RouteFailurePolicy,
  language: "ru" | "en",
  primaryOutbound = "primary",
  fallbackError?: string
) {
  const i18n = createInstance()
  await i18n.init({
    lng: language,
    resources: {
      ru: { translation: ruTranslation },
      en: { translation: enTranslation },
    },
    interpolation: { escapeValue: false },
  })
  const client = new QueryClient()
  try {
    return renderToStaticMarkup(
      <I18nextProvider i18n={i18n}>
        <QueryClientProvider client={client}>
          <RouteFailurePolicyFields
            fallbackError={fallbackError}
            fallbackOutbound="backup"
            onFallbackChange={() => undefined}
            onPolicyChange={() => undefined}
            outbounds={outbounds}
            policy={policy}
            primaryOutbound={primaryOutbound}
          />
        </QueryClientProvider>
      </I18nextProvider>
    )
  } finally {
    client.clear()
  }
}

describe("failure policy fields", () => {
  test.each(["ru", "en"] as const)(
    "inherit stays compact and fallback explains new connections in %s",
    async (language) => {
      const text = (language === "ru" ? ruTranslation : enTranslation)
        .routeFailurePolicy
      const inherited = await renderPolicy("inherit", language)
      expect(inherited).toContain(text.inherit)
      expect(inherited).toContain(text.inheritHint)
      expect(inherited.match(/data-slot="select-trigger"/g)).toHaveLength(1)
      const fallback = await renderPolicy("fallback", language)
      expect(fallback).toContain(text.fallbackHint)
      expect(fallback).toContain(text.fallbackBothDownHint)
      expect(fallback).toContain("Backup AWG")
      expect(fallback.match(/data-slot="select-trigger"/g)).toHaveLength(2)
      expect(fallback).not.toContain("routeFailurePolicy.")
    }
  )

  test("unsupported primary keeps an explicit noninherit selection recoverable", async () => {
    const text = ruTranslation.routeFailurePolicy
    const inherited = await renderPolicy("inherit", "ru", "table")
    expect(inherited).toContain(' disabled=""')
    const selected = await renderPolicy("fallback", "ru", "table")
    expect(selected).toContain(text.fallback)
    expect(selected).toContain(text.supportedPrimaryHint)
    expect(selected.match(/data-slot="select-trigger"/g)).toHaveLength(1)
    expect(selected).not.toContain(' disabled=""')
  })

  test("the reserve error is visible and is wired to focus the invalid selector", async () => {
    const html = await renderPolicy(
      "fallback",
      "ru",
      "primary",
      "Choose a reserve"
    )
    expect(html).toContain("Choose a reserve")
    expect(html).toContain('aria-invalid="true"')
    const source = await Bun.file(
      new URL(
        "../src/components/shared/route-failure-policy-fields.tsx",
        import.meta.url
      )
    ).text()
    expect(source).toContain(
      'fallbackRef.current?.querySelector("button")?.focus()'
    )
  })
})
