import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"

import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"
import { formatValidationErrors } from "../src/lib/api-errors"
import { getServerValidationPresentation } from "../src/lib/server-validation-presentation"

describe("complete config validation code catalog", () => {
  test.each([
    ["config.value.string_array", "stringArray"],
    ["config.value.object", "object"],
    ["config.value.object_array", "objectArray"],
    ["config.value.number", "number"],
    ["config.value.hex", "hexValue"],
    ["config.value.duplicate", "duplicateValue"],
    ["config.value.non_empty_array", "nonEmptyArray"],
    ["config.identifier.whitespace", "identifierWhitespace"],
    ["config.interface.invalid", "interfaceInvalid"],
    ["config.daemon.meta_udp443_policy", "metaUdp443Policy"],
    ["config.daemon.ppe_deoffload_mode", "ppeDeoffloadMode"],
    ["config.list.refresh_detour_mode", "refreshDetourMode"],
    ["config.route.failure_policy", "ruleFailurePolicy"],
    ["config.dns.template_duplicate", "dnsTemplateDuplicate"],
    ["config.urltest.cycle", "groupCycle"],
    ["config.vpn.service_id", "vpnServiceId"],
    ["config.cron.invalid", "cronInvalid"],
    ["config.catalog_identity.invalid", "catalogIdentity"],
    ["config.list.source_required", "listSourceRequired"],
    ["config.list.source_format", "listSourceFormat"],
    ["config.download.primary_required", "downloadPrimaryRequired"],
    ["config.outbound.routing_table_required", "routingTableRequired"],
    ["config.download.url_required", "downloadUrlRequired"],
    ["config.download.inherit_conflict", "downloadInheritConflict"],
    ["config.conntrack.urltest_only", "conntrackGroupOnly"],
    ["config.address.ipv6", "ipv6"],
    ["config.urltest.child_type", "groupChildType"],
    ["config.route.primary_exact", "primaryExact"],
    ["config.route.primary_routable", "primaryRoutable"],
    ["config.fwmark.start_invalid", "fwmarkStart"],
    ["config.fwmark.mask_invalid", "fwmarkMask"],
    ["config.fwmark.allocation", "fwmarkAllocation"],
    ["config.iproute.reserved", "reservedRoutingTable"],
    ["config.route.multiport_combo", "multiportCombination"],
    ["config.dns.keenetic_build", "keeneticDnsBuild"],
    ["config.dns.keenetic_version", "keeneticDnsVersion"],
    ["config.dns.keenetic_address", "keeneticDnsAddress"],
    ["config.dns.type", "dnsType"],
    ["config.dns.keenetic_limit", "keeneticDnsLimit"],
    ["config.dns.probe_invalid", "dnsProbeInvalid"],
    ["config.conntrack.nested", "conntrackNested"],
    ["config.conntrack.shared_child", "conntrackShared"],
    ["config.conntrack.route_child", "conntrackRoute"],
    ["config.conntrack.dns_child", "conntrackDns"],
    ["config.conntrack.list_child", "conntrackList"],
  ])("localizes %s in RU/EN independently of diagnostic text", (code, key) => {
    for (const message of [
      "route.rules[0].outbound must not be empty",
      "Changed diagnostic\r\n<script>private-input</script> ${SECRET}",
    ]) {
      const error = Object.freeze({
        path: "private-input",
        message,
        code,
        params: Object.freeze({ value: "private-input", extra: "<script>" }),
      })
      const before = JSON.stringify(error)
      const details = formatValidationErrors([error])
      expect(getServerValidationPresentation(error)).toEqual({
        key: `serverValidation.${key}`,
      })
      expect(JSON.stringify(error)).toBe(before)
      expect(formatValidationErrors([error])).toBe(details)
      expect(details).toContain(message)
      for (const locale of [ruTranslation, enTranslation]) {
        const text = (locale.serverValidation as Record<string, string>)[key]
        expect(text).toBeString()
        expect(text.length).toBeGreaterThan(0)
        expect(text).not.toContain("{{")
        expect(text).not.toContain("private-input")
      }
    }
  })

  test("new parameterized codes expose only checked numeric constants", () => {
    for (const max of ["3", "32", "128"]) {
      expect(
        getServerValidationPresentation({
          path: "private-input",
          message: "Changed diagnostic",
          code: "config.value.too_many",
          params: { max, value: "private-input" },
        })
      ).toEqual({ key: "serverValidation.tooManyEntries", values: { max } })
    }
    expect(
      getServerValidationPresentation({
        path: "schema_version",
        message: "Changed diagnostic",
        code: "config.schema_version.migration_required",
        params: { supported: "2", version: "private-input" },
      })
    ).toEqual({
      key: "serverValidation.schemaMigration",
      values: { supported: "2" },
    })
    for (const [code, parameter] of [
      ["config.value.too_many", "max"],
      ["config.schema_version.migration_required", "supported"],
    ]) {
      for (const value of [
        undefined,
        null,
        3,
        "0",
        "-1",
        "01",
        "1.5",
        "3x",
        "<script>",
      ]) {
        expect(
          getServerValidationPresentation({
            path: "daemon.port",
            message: "daemon.port must be an integer",
            code,
            params: { [parameter]: value },
          })
        ).toEqual({ key: "serverValidation.unknown" })
      }
    }
    for (const locale of [ruTranslation, enTranslation]) {
      expect(locale.serverValidation.tooManyEntries).toContain("{{max}}")
      expect(locale.serverValidation.schemaMigration).toContain("{{supported}}")
    }
  })

  test("every code emitted by the current config validator and its diagnostic helpers has RU/EN presentation", () => {
    const files = [
      "../../src/config/config.cpp",
      "../../src/config/json_validation.hpp",
      "../../src/dns/dns_server.cpp",
    ]
    const codes = new Set(
      files.flatMap((file) =>
        [
          ...readFileSync(new URL(file, import.meta.url), "utf8")
            .replace(/^\s*#include[^\r\n]*/gm, "")
            .matchAll(/"(config\.[a-z0-9_.]+)"/g),
        ].map((match) => match[1])
      )
    )
    expect(codes.size).toBeGreaterThan(45)
    const parameters: Record<string, Record<string, string>> = {
      "config.schema_version.unsupported": { version: "3", supported: "2" },
      "config.schema_version.migration_required": { supported: "2" },
      "config.value.range": { min: "1", max: "65535" },
      "config.value.integer_range": {
        min: "-9223372036854775808",
        max: "9223372036854775807",
      },
      "config.tag.too_long": { max: "24" },
      "config.name.too_long": { max: "128" },
      "config.value.too_many": { max: "128" },
    }
    for (const code of codes) {
      const presentation = getServerValidationPresentation({
        path: "reworded.path",
        message: "No English diagnostic is available\nprivate-input",
        code,
        params: parameters[code],
      })
      expect({ code, key: presentation.key }).not.toEqual({
        code,
        key: "serverValidation.unknown",
      })
      const localKey = presentation.key.slice("serverValidation.".length)
      for (const locale of [ruTranslation, enTranslation]) {
        const text = (locale.serverValidation as Record<string, string>)[
          localKey
        ]
        expect(text).toBeString()
        expect(text.length).toBeGreaterThan(0)
        const placeholders = [...text.matchAll(/\{\{(\w+)\}\}/g)]
          .map((match) => match[1])
          .sort()
        expect(placeholders).toEqual(
          Object.keys(presentation.values ?? {}).sort()
        )
        expect(text).not.toContain("private-input")
      }
    }
  })
})

describe("structured JSON validation codes", () => {
  test.each([
    ["config.json.syntax", "jsonSyntax"],
    ["config.json.number_overflow", "jsonNumberOverflow"],
    ["config.json.type", "jsonType"],
    ["config.json.missing_field", "jsonMissingField"],
    ["config.json.object", "jsonObject"],
    ["config.json.decode", "jsonDecode"],
  ])(
    "localizes %s without parsing or interpolating diagnostics",
    (code, key) => {
      for (const message of [
        "Ports must be integers between 1 and 65535.",
        "Reworded JSON error\r\n<script>private-value</script> ${SECRET}",
      ]) {
        const error = Object.freeze({
          path: "private.field",
          message,
          code,
          params: Object.freeze({ field: "private-value", value: "<script>" }),
        })
        const before = JSON.stringify(error)
        const details = formatValidationErrors([error])
        expect(getServerValidationPresentation(error)).toEqual({
          key: `serverValidation.${key}`,
        })
        expect(JSON.stringify(error)).toBe(before)
        expect(formatValidationErrors([error])).toBe(details)
        expect(details).toContain(message)
        for (const locale of [ruTranslation, enTranslation]) {
          const text = (locale.serverValidation as Record<string, string>)[key]
          expect(text).toBeString()
          expect(text.length).toBeGreaterThan(0)
          expect(text).not.toContain("{{")
          expect(text).not.toContain("private-value")
        }
      }
    }
  )

  test("unknown JSON codes do not borrow a legacy English explanation", () => {
    for (const code of ["config.json.future", " config.json.type ", 302]) {
      expect(
        getServerValidationPresentation({
          path: "daemon.port",
          message: "daemon.port must be an integer",
          code,
        })
      ).toEqual({ key: "serverValidation.unknown" })
    }
  })

  test("uncoded JSON diagnostics remain unchanged legacy details", () => {
    for (const message of [
      "Configuration root must be an object",
      "[json.exception.parse_error.101] parse error at line 1, column 2",
      "[json.exception.type_error.302] type must be number, but is string",
    ]) {
      const error = { path: "config", message }
      expect(getServerValidationPresentation(error)).toEqual({
        key: "serverValidation.unknown",
      })
      expect(formatValidationErrors([error])).toBe(`- config: ${message}`)
    }
  })
})

describe("structured nfqws validation codes", () => {
  const cases = [
    ["nfqws.shell.command_substitution", "nfqwsCommandSubstitution"],
    ["nfqws.shell.expansion_syntax", "nfqwsExpansionSyntax"],
    ["nfqws.shell.undefined_variable", "nfqwsUndefinedVariable"],
    ["nfqws.shell.assignments_only", "nfqwsAssignmentsOnly"],
    ["nfqws.shell.unsupported_assignment", "nfqwsUnsupportedAssignment"],
    ["nfqws.shell.assignment_syntax", "nfqwsAssignmentsOnly"],
    ["nfqws.shell.whitespace_after_equals", "nfqwsWhitespaceAfterEquals"],
    ["nfqws.shell.unquoted_whitespace", "nfqwsUnquotedWhitespace"],
    ["nfqws.shell.control_operator", "nfqwsControlOperator"],
    ["nfqws.shell.unterminated_quote", "nfqwsUnterminatedQuote"],
    ["nfqws.shell.literal_variable", "nfqwsLiteralVariable"],
    ["nfqws.shell.wildcard", "nfqwsWildcard"],
    ["nfqws.port.empty", "portNumber"],
    ["nfqws.port.number", "portNumber"],
    ["nfqws.port.range", "portNumber"],
    ["nfqws.port.filter_empty", "nfqwsPortFilterRequired"],
    ["nfqws.port.empty_item", "nfqwsPortEmptyItem"],
    ["nfqws.port.range_malformed", "nfqwsPortRangeSyntax"],
    ["nfqws.port.range_inverted", "portRangeOrder"],
    ["nfqws.writable.owned_only", "nfqwsWritableOwnedOnly"],
    ["nfqws.writable.duplicate", "nfqwsWritableDuplicate"],
    ["nfqws.path.empty", "nfqwsPathRequired"],
    ["nfqws.path.missing", "nfqwsPathMissing"],
    ["nfqws.profile.new_forbidden", "nfqwsProfileNewForbidden"],
    ["nfqws.profile.empty_boundary", "nfqwsProfileEmptyBoundary"],
    ["nfqws.profile.boundary_name_required", "nfqwsProfileBoundaryName"],
    [
      "nfqws.profile.consecutive_boundaries",
      "nfqwsProfileConsecutiveBoundaries",
    ],
    ["nfqws.profile.action_required", "nfqwsProfileActionRequired"],
    ["nfqws.profile.webrtc_passthrough", "nfqwsWebrtcPassthrough"],
    ["nfqws.profile.custom_action_required", "nfqwsProfileActionRequired"],
    ["nfqws.profile.required", "nfqwsProfileRequired"],
    ["nfqws.queue.range", "nfqwsQueueRange"],
    ["nfqws.user.unsafe", "nfqwsUserCharacters"],
    ["nfqws.binary.rejected", "nfqwsBinaryRejected"],
  ]

  test("covers the complete finite nfqws catalog", () => {
    expect(cases).toHaveLength(34)
    expect(new Set(cases.map(([code]) => code)).size).toBe(34)
  })

  test.each(cases)(
    "localizes %s in RU/EN without reading raw input",
    (code, key) => {
      for (const message of [
        "IPv4 addresses must not contain leading zeros",
        "Changed diagnostic\r\n<script>hostile-private-value</script> 'quotes' ${SECRET}",
      ]) {
        const error = Object.freeze({
          path: "NFQWS_ARGS_CUSTOM/<private-value>",
          message,
          code,
          params: Object.freeze({
            value: "hostile-private-value",
            min: "<script>",
          }),
        })
        const before = JSON.stringify(error)
        const rawDetails = formatValidationErrors([error])
        const presentation = getServerValidationPresentation(error)
        expect(presentation).toEqual({ key: `serverValidation.${key}` })
        expect(JSON.stringify(error)).toBe(before)
        expect(formatValidationErrors([error])).toBe(rawDetails)
        expect(rawDetails).toContain(message)
        expect(rawDetails).toContain(code)
        expect(JSON.stringify(presentation)).not.toContain("private-value")
        expect(JSON.stringify(presentation)).not.toContain("<script>")
      }
      for (const locale of [ruTranslation, enTranslation]) {
        const text = (locale.serverValidation as Record<string, string>)[key]
        expect(text).toBeString()
        expect(text.length).toBeGreaterThan(0)
        expect(text).not.toContain("{{")
        expect(text).not.toContain("private-value")
      }
    }
  )

  test("keeps original nfqws messages as details for old uncoded responses", () => {
    for (const message of [
      "empty port",
      "queue number must be an integer from 0 to 65535",
      "nfqws2 dry run failed\nunknown option: <private-value>",
    ]) {
      const error = { path: "NFQWS_ARGS", message }
      expect(getServerValidationPresentation(error)).toEqual({
        key: "serverValidation.unknown",
      })
      expect(formatValidationErrors([error])).toBe(`- NFQWS_ARGS: ${message}`)
    }
  })

  test("unknown nfqws codes never fall back to matching legacy English", () => {
    for (const code of [
      "nfqws.future",
      " nfqws.port.range ",
      "nfqws.port.range\n",
    ]) {
      const error = {
        path: "NFQWS_ARGS",
        message: "Ports must be integers between 1 and 65535.",
        code,
      }
      expect(getServerValidationPresentation(error)).toEqual({
        key: "serverValidation.unknown",
      })
      expect(formatValidationErrors([error])).toContain(error.message)
    }
  })
})

describe("structured config validation codes", () => {
  test("specialized codes reuse RU/EN copy without reading diagnostic text", () => {
    const cases = [
      ["config.port.list", "portList"],
      ["config.port.range", "portRange"],
      ["config.port.range_order", "portRangeOrder"],
      ["config.port.number", "portNumber"],
      ["config.address.list", "addressList"],
      ["config.address.invalid", "ipAddressOrCidr"],
      ["config.address.ipv4", "ipv4"],
      ["config.name.encoding", "nameEncoding"],
      ["config.name.controls", "nameControls"],
      ["config.route.condition_required", "routeCondition"],
      ["config.route.fallback_different", "fallbackDifferent"],
      ["config.route.fallback_routable", "fallbackRoutable"],
      ["config.route.fallback_mode", "fallbackMode"],
      ["config.url.scheme", "urlScheme"],
      ["config.dns.domain", "dnsDomain"],
      ["config.dns.different", "dnsDifferent"],
      ["config.dns.port_number", "dnsPort"],
      ["config.dns.port_range", "dnsPort"],
      ["config.dns.closing_bracket", "dnsIpv6Bracket"],
      ["config.dns.port_separator", "dnsIpv6Separator"],
      ["config.dns.address", "dnsAddress"],
    ]
    for (const [code, key] of cases) {
      for (const message of [
        "Изменённая формулировка\nChanged wording with 'quotes'",
        "Use comma-separated ports or ranges.",
      ]) {
        const error = { path: "changed.field", message, code }
        const original = { ...error }
        expect(getServerValidationPresentation(error)).toEqual({
          key: `serverValidation.${key}`,
        })
        expect(error).toEqual(original)
      }
      for (const locale of [ruTranslation, enTranslation]) {
        const text = (locale.serverValidation as Record<string, string>)[key]
        expect(text).toBeString()
        expect(text).not.toContain("{{")
      }
    }
  })

  test("visible-name limits are distinct from technical tags and use only max", () => {
    const base = {
      path: "outbounds.proxy.display_name",
      message: "Reworded name diagnostic",
      code: "config.name.too_long",
    }
    expect(
      getServerValidationPresentation({
        ...base,
        params: { max: "80", name: "never interpolate this value" },
      })
    ).toEqual({ key: "serverValidation.nameLength", values: { max: "80" } })
    for (const params of [
      undefined,
      { max: 80 },
      { max: "0" },
      { max: "-1" },
      { max: "80px" },
    ]) {
      expect(getServerValidationPresentation({ ...base, params })).toEqual({
        key: "serverValidation.unknown",
      })
    }
  })

  test("all 19 known codes remain independent of diagnostic wording and language", () => {
    const cases: {
      code: string
      key: string
      params?: Record<string, string>
    }[] = [
      { code: "config.ip_cidr.leading_zeros", key: "ipv4LeadingZeros" },
      { code: "config.ip_cidr.invalid_address", key: "ipAddressOrCidr" },
      { code: "config.ip_cidr.invalid_prefix", key: "ipPrefixLength" },
      { code: "config.schema_version.invalid", key: "invalidSchemaVersion" },
      {
        code: "config.schema_version.unsupported",
        key: "futureSchemaVersion",
        params: { version: "3", supported: "2" },
      },
      { code: "config.value.integer", key: "integer" },
      { code: "config.value.string", key: "text" },
      { code: "config.value.boolean", key: "boolean" },
      { code: "config.value.required", key: "required" },
      { code: "config.value.non_negative", key: "nonNegative" },
      { code: "config.value.positive", key: "positive" },
      { code: "config.value.fraction", key: "fraction" },
      {
        code: "config.value.range",
        key: "range",
        params: { min: "-2", max: "8" },
      },
      {
        code: "config.value.integer_range",
        key: "integerRange",
        params: { min: "0", max: "63" },
      },
      { code: "config.tag.invalid", key: "tagPattern" },
      { code: "config.tag.too_long", key: "tagLength", params: { max: "24" } },
      { code: "config.reference.list_missing", key: "unknownList" },
      { code: "config.reference.outbound_missing", key: "unknownOutbound" },
      { code: "config.reference.dns_server_missing", key: "unknownDns" },
    ]
    expect(cases).toHaveLength(19)
    for (const entry of cases) {
      const result = getServerValidationPresentation({
        path: "raw.path",
        message: "Изменённый текст\nChanged diagnostic prose",
        code: entry.code,
        params: entry.params,
      })
      expect(result).toEqual({
        key: `serverValidation.${entry.key}`,
        ...(entry.params ? { values: entry.params } : {}),
      })
      for (const locale of [ruTranslation, enTranslation]) {
        expect(
          (locale.serverValidation as Record<string, string>)[entry.key]
        ).toBeString()
      }
    }
  })

  test("unknown or malformed present codes never borrow a legacy message meaning", () => {
    const entry = {
      path: "lists.office.ip_cidrs[0]",
      message: "IPv4 addresses must not contain leading zeros",
    }
    for (const code of [
      "config.future",
      " config.ip_cidr.leading_zeros ",
      "constructor",
      400,
      false,
      {},
      ["config.value.required"],
    ]) {
      expect(getServerValidationPresentation({ ...entry, code })).toEqual({
        key: "serverValidation.unknown",
      })
    }
    for (const code of [undefined, null, ""]) {
      expect(getServerValidationPresentation({ ...entry, code })).toEqual({
        key: "serverValidation.ipv4LeadingZeros",
      })
    }
  })

  test("missing or invalid presentation parameters are generic, never English fallback", () => {
    const base = {
      path: "daemon.port",
      message: "daemon.port must be between 1 and 65535",
    }
    for (const params of [
      undefined,
      null,
      [],
      { min: "1" },
      { min: 1, max: "2" },
      { min: "01", max: "2" },
      { min: "1", max: "Infinity" },
      { min: "1", max: "9e18" },
      { min: "3", max: "2" },
      { min: "<script>", max: "2" },
    ]) {
      expect(
        getServerValidationPresentation({
          ...base,
          code: "config.value.range",
          params,
        })
      ).toEqual({ key: "serverValidation.unknown" })
    }
    for (const params of [
      undefined,
      { version: "2", supported: "2" },
      { version: "3", supported: "0" },
    ]) {
      expect(
        getServerValidationPresentation({
          ...base,
          code: "config.schema_version.unsupported",
          params,
        })
      ).toEqual({ key: "serverValidation.unknown" })
    }
    for (const params of [undefined, { max: "0" }, { max: "-1" }]) {
      expect(
        getServerValidationPresentation({
          ...base,
          code: "config.tag.too_long",
          params,
        })
      ).toEqual({ key: "serverValidation.unknown" })
    }
  })
  test("uint64 schema versions and int64 range limits retain their exact decimal text", () => {
    const entry = { path: "schema_version", message: "Reworded diagnostic" }
    const params = { version: "18446744073709551615", supported: "2" }
    expect(
      getServerValidationPresentation({
        ...entry,
        code: "config.schema_version.unsupported",
        params,
      })
    ).toEqual({ key: "serverValidation.futureSchemaVersion", values: params })
    const range = { min: "-9223372036854775808", max: "9223372036854775807" }
    expect(
      getServerValidationPresentation({
        ...entry,
        code: "config.value.integer_range",
        params: range,
      })
    ).toEqual({ key: "serverValidation.integerRange", values: range })
    expect(
      getServerValidationPresentation({
        ...entry,
        code: "config.value.range",
        params: { min: "9223372036854775807", max: "9223372036854775806" },
      })
    ).toEqual({ key: "serverValidation.unknown" })
  })
})

const present = (message: string, path = "route.rules[0].src_port") => {
  const result = getServerValidationPresentation({ path, message })
  // Every fixture, including the unknown fallback, must render in both locales.
  const localKey = result.key.slice("serverValidation.".length)
  for (const resource of [ruTranslation, enTranslation]) {
    const dictionary: Record<string, string> = resource.serverValidation
    const text = dictionary[localKey]
    expect(typeof text).toBe("string")
    expect(text.length).toBeGreaterThan(0)
    const placeholders = [...text.matchAll(/\{\{(\w+)\}\}/g)]
      .map((match) => match[1])
      .sort()
    expect(placeholders).toEqual(Object.keys(result.values ?? {}).sort())
  }
  return result
}

describe("server validation presentation", () => {
  test("explains an invalid configuration version only for its exact field", () => {
    expect(
      present("schema_version must be a positive integer", "schema_version")
    ).toEqual({ key: "serverValidation.invalidSchemaVersion" })
    expect(
      present("schema_version must be a positive integer", "outbounds.other")
    ).toEqual({ key: "serverValidation.unknown" })
  })
  test("explains a future config format in both languages without suggesting edits to the version", () => {
    const message =
      "Configuration schema version 3 is newer than supported version 2. Update keen-pbr-sb before loading this configuration."
    expect(present(message, "schema_version")).toEqual({
      key: "serverValidation.futureSchemaVersion",
      values: { version: "3", supported: "2" },
    })
    expect(present(message, "outbounds.schema_version")).toEqual({
      key: "serverValidation.unknown",
    })
    expect(
      present(message.replace("version 3", "version 1"), "schema_version")
    ).toEqual({ key: "serverValidation.unknown" })
  })
  test("supplies matching interpolation values for both RU and EN messages", () => {
    expect(
      present(
        "route.rules[0].dscp must be an integer between 1 and 63",
        "route.rules[0].dscp"
      )
    ).toEqual({
      key: "serverValidation.integerRange",
      values: { min: "1", max: "63" },
    })
    expect(
      present(
        "DNS server display name must not exceed 80 Unicode code points",
        "dns.servers.primary.display_name"
      )
    ).toEqual({
      key: "serverValidation.nameLength",
      values: { max: "80" },
    })
  })
  test.each([
    ["Use comma-separated ports or ranges.", "portList"],
    ["Port ranges must use valid ports such as 8000-9000.", "portRange"],
    ["Port range start must be less than or equal to end.", "portRangeOrder"],
    ["Ports must be integers between 1 and 65535.", "portNumber"],
    ["Use comma-separated IP addresses or CIDRs.", "addressList"],
    [
      "Addresses must be valid IPv4 or IPv6 hosts or CIDR ranges, for example 10.0.0.1, 10.0.0.0/8, or 2001:db8::/32.",
      "ipAddressOrCidr",
    ],
    [
      "Route rule must include at least one condition: list, dscp, src_port, dest_port, src_addr, or dest_addr.",
      "routeCondition",
    ],
    ["Urltest URL must use the http or https scheme", "urlScheme"],
    [
      "Enter a DNS domain without a URL scheme, path or IP address",
      "dnsDomain",
    ],
    [
      "Fallback outbound must differ from the primary outbound",
      "fallbackDifferent",
    ],
    [
      "Fallback outbound must be an interface or urltest outbound",
      "fallbackRoutable",
    ],
    [
      "fallback_outbound is only used when failure_policy is fallback",
      "fallbackMode",
    ],
    ["Plain DNS template primary_ipv4 must be a valid IPv4 address", "ipv4"],
    ["Plain DNS template secondary_ipv4 must be a valid IPv4 address", "ipv4"],
    [
      "Plain DNS template secondary_ipv4 must differ from primary_ipv4",
      "dnsDifferent",
    ],
    ["Invalid DNS server address: empty string", "required"],
  ])("maps exact backend text: %s", (message, key) => {
    expect(present(message)).toEqual({ key: "serverValidation." + key })
  })

  test.each([
    ["must be an integer", "integer"],
    ["must be a string", "text"],
    ["must be a boolean", "boolean"],
    ["must not be empty", "required"],
    ["must not be blank", "required"],
    ["must be >= 0", "nonNegative"],
    ["must be greater than 0", "positive"],
    ["must be a finite number between 0 and 1", "fraction"],
    ["is required when failure_policy is fallback", "required"],
    ["must include at least one list name", "unknownList"],
  ])("strips only the exact original path: %s", (suffix, key) => {
    const path = "outbounds.awg_group.interval_ms"
    expect(present(path + " " + suffix, path)).toEqual({
      key: "serverValidation." + key,
    })
    expect(present(path + " " + suffix, "outbounds.other.interval_ms")).toEqual(
      { key: "serverValidation.unknown" }
    )
    expect(present(suffix, "")).toEqual({ key: "serverValidation.unknown" })
  })

  test.each([
    [
      "outbounds.awg.interval_ms",
      "must be between 1 and 4294967295",
      "range",
      "1",
      "4294967295",
    ],
    [
      "route.rules[2].dscp",
      "must be an integer between 1 and 63",
      "integerRange",
      "1",
      "63",
    ],
    [
      "daemon.ipset_hashsize",
      "must be between 1 and 2147483648",
      "range",
      "1",
      "2147483648",
    ],
  ])(
    "retains numeric bounds supplied by the server: %s",
    (path, suffix, kind, min, max) => {
      expect(present(path + " " + suffix, path)).toEqual({
        key: "serverValidation." + kind,
        values: { min, max },
      })
    }
  )

  test.each([
    "must be between 63 and 1",
    "must be between 1 and 9999999999999999999999999",
    "must be between 1 and <script>2</script>",
    "must be between 1 and 2 and reset routing",
    "must be between 1 and 2\n",
    "must be between 01 and 2",
    "must be between 1e1 and 20",
  ])(
    "does not interpolate malformed or partial numeric bounds: %s",
    (suffix) => {
      expect(present("field " + suffix, "field")).toEqual({
        key: "serverValidation.unknown",
      })
    }
  )

  test("keeps alias and technical identifier limits distinct", () => {
    expect(
      present(
        "Outbound display name must not exceed 80 Unicode code points",
        "outbounds.awg.display_name"
      )
    ).toEqual({ key: "serverValidation.nameLength", values: { max: "80" } })
    expect(
      present(
        "Outbound tag 'abcdefghijklmnopqrstuvwxyz' is too long: 26 chars, maximum is 24",
        "outbounds.abcdefghijklmnopqrstuvwxyz.tag"
      )
    ).toEqual({ key: "serverValidation.tagLength", values: { max: "24" } })
    expect(
      present(
        "Outbound tag 'Bad-name' must match naming convention [a-z][a-z0-9_]*",
        "outbounds.Bad-name.tag"
      )
    ).toEqual({ key: "serverValidation.tagPattern" })
    expect(
      present(
        "Outbound display name 'Bad-name' must match naming convention [a-z][a-z0-9_]*",
        "outbounds.awg.display_name"
      )
    ).toEqual({ key: "serverValidation.unknown" })
  })

  test.each([
    ["must contain a non-whitespace character", "required"],
    ["must be valid UTF-8", "nameEncoding"],
    ["must not contain ASCII control characters", "nameControls"],
    ["must not contain C1 or bidirectional control characters", "nameControls"],
  ])("covers the finite display-name vocabulary: %s", (suffix, key) => {
    for (const kind of [
      "List display name",
      "Outbound display name",
      "Route rule display name",
      "DNS server display name",
      "DNS rule display name",
      "Plain DNS template name",
    ]) {
      expect(present(kind + " " + suffix)).toEqual({
        key: "serverValidation." + key,
      })
    }
  })

  test.each([
    [
      "Invalid DNS server address: '192.0.2.1:foo' (non-numeric port)",
      "dnsPort",
    ],
    [
      "Invalid DNS server address: '192.0.2.1:70000' (port out of range 1-65535)",
      "dnsPort",
    ],
    [
      "Invalid DNS server address: '[2001:db8::1' (missing closing ']')",
      "dnsIpv6Bracket",
    ],
    [
      "Invalid DNS server address: '[2001:db8::1]53' (expected ':' after ']')",
      "dnsIpv6Separator",
    ],
    [
      "Invalid DNS server address: 'private.example/token' (not a valid IPv4 or IPv6 address)",
      "dnsAddress",
    ],
  ])(
    "maps DNS parser errors without exposing the address: %s",
    (message, key) => {
      expect(present(message, "dns.servers.primary.address")).toEqual({
        key: "serverValidation." + key,
      })
    }
  )

  test.each([
    [
      "route.rules[2].list[0]",
      "route.rules[2] references unknown list 'private_list'",
      "unknownList",
    ],
    [
      "route.rules[2].outbound",
      "route.rules[2] references unknown outbound tag 'private_tunnel'",
      "unknownOutbound",
    ],
    [
      "route.rules[2].fallback_outbound",
      "route.rules[2] references unknown fallback outbound tag 'private_tunnel'",
      "unknownOutbound",
    ],
    [
      "dns.rules[2].server",
      "dns.rules[2] references unknown DNS server tag 'private_dns'",
      "unknownDns",
    ],
    [
      "dns.rules[2].list[1]",
      "dns.rules[2] references unknown list 'private_list'",
      "unknownList",
    ],
    [
      "outbounds.group.outbound_groups[0].outbounds[1]",
      "Urltest outbound 'group' references unknown outbound tag 'private_tunnel'",
      "unknownOutbound",
    ],
  ])(
    "handles references only at their exact owner path: %s",
    (path, message, key) => {
      expect(present(message, path)).toEqual({ key: "serverValidation." + key })
      expect(present(message, "outbounds.unrelated.address")).toEqual({
        key: "serverValidation.unknown",
      })
    }
  )

  test.each([
    [
      "outbounds.awg.interface",
      "Interface outbound 'awg' requires a non-empty interface name",
      "interfaceRequired",
    ],
    [
      "outbounds.awg.gateway",
      "Interface outbound 'awg' gateway must be a valid IPv4 address",
      "ipv4",
    ],
    [
      "outbounds.awg.gateway6",
      "Interface outbound 'awg' gateway6 must be a valid IPv6 address",
      "ipv6",
    ],
    [
      "outbounds.awg.outbound_groups",
      "Urltest outbound 'awg' 'outbound_groups' array must not be empty",
      "groupRequired",
    ],
    [
      "outbounds.awg.outbound_groups[0].outbounds",
      "Urltest outbound 'awg' outbound_group has empty 'outbounds' array",
      "groupRequired",
    ],
  ])("covers interface and empty group fields: %s", (path, message, key) => {
    expect(present(message, path)).toEqual({ key: "serverValidation." + key })
    expect(present(message, path + ".other")).toEqual({
      key: "serverValidation.unknown",
    })
  })

  test.each([
    "future constraint must be between 1 and 2",
    "Unexpected DNS failure",
    "prefix Ports must be integers between 1 and 65535.",
    "Ports must be integers between 1 and 65535. trailing instruction",
    "Invalid DNS server address: 'private.example' (a future parser reason)",
    "Outbound display name must not exceed infinity Unicode code points",
    "Outbound tag 'foo' is too long: 3 chars, maximum is 24",
    "empty port",
    "queue number must be an integer from 0 to 65535",
  ])(
    "keeps unfamiliar and specialized validation as details: %s",
    (message) => {
      expect(present(message)).toEqual({ key: "serverValidation.unknown" })
    }
  )

  test("does not mutate raw paths/messages or reflect raw values into display params", () => {
    const entry = Object.freeze({
      path: "dns.servers.private.address",
      message:
        "Invalid DNS server address: 'private.example/secret' (not a valid IPv4 or IPv6 address)",
    })
    const before = { ...entry }
    const result = getServerValidationPresentation(entry)
    expect(entry).toEqual(before)
    expect(result).toEqual({ key: "serverValidation.dnsAddress" })
    expect(JSON.stringify(result)).not.toContain("private")
    expect(JSON.stringify(result)).not.toContain("secret")
  })
})
