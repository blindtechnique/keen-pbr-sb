import type { ValidationErrorEntry } from "@/lib/api-errors"

export type ServerValidationPresentation = {
  key: string
  values?: Record<string, string>
}

const codeKeys = new Map<string, string>([
  ["config.ip_cidr.leading_zeros", "serverValidation.ipv4LeadingZeros"],
  ["config.ip_cidr.invalid_address", "serverValidation.ipAddressOrCidr"],
  ["config.ip_cidr.invalid_prefix", "serverValidation.ipPrefixLength"],
  ["config.schema_version.invalid", "serverValidation.invalidSchemaVersion"],
  ["config.json.syntax", "serverValidation.jsonSyntax"],
  ["config.json.number_overflow", "serverValidation.jsonNumberOverflow"],
  ["config.json.type", "serverValidation.jsonType"],
  ["config.json.missing_field", "serverValidation.jsonMissingField"],
  ["config.json.object", "serverValidation.jsonObject"],
  ["config.json.decode", "serverValidation.jsonDecode"],
  ["config.value.integer", "serverValidation.integer"],
  ["config.value.string", "serverValidation.text"],
  ["config.value.boolean", "serverValidation.boolean"],
  ["config.value.required", "serverValidation.required"],
  ["config.value.non_negative", "serverValidation.nonNegative"],
  ["config.value.positive", "serverValidation.positive"],
  ["config.value.fraction", "serverValidation.fraction"],
  ["config.tag.invalid", "serverValidation.tagPattern"],
  ["config.reference.list_missing", "serverValidation.unknownList"],
  ["config.reference.outbound_missing", "serverValidation.unknownOutbound"],
  ["config.reference.dns_server_missing", "serverValidation.unknownDns"],
  ["config.port.list", "serverValidation.portList"],
  ["config.port.range", "serverValidation.portRange"],
  ["config.port.range_order", "serverValidation.portRangeOrder"],
  ["config.port.number", "serverValidation.portNumber"],
  ["config.address.list", "serverValidation.addressList"],
  ["config.address.invalid", "serverValidation.ipAddressOrCidr"],
  ["config.address.ipv4", "serverValidation.ipv4"],
  ["config.name.encoding", "serverValidation.nameEncoding"],
  ["config.name.controls", "serverValidation.nameControls"],
  ["config.route.condition_required", "serverValidation.routeCondition"],
  ["config.route.fallback_different", "serverValidation.fallbackDifferent"],
  ["config.route.fallback_routable", "serverValidation.fallbackRoutable"],
  ["config.route.fallback_mode", "serverValidation.fallbackMode"],
  ["config.url.scheme", "serverValidation.urlScheme"],
  ["config.dns.domain", "serverValidation.dnsDomain"],
  ["config.dns.different", "serverValidation.dnsDifferent"],
  ["config.dns.port_number", "serverValidation.dnsPort"],
  ["config.dns.port_range", "serverValidation.dnsPort"],
  ["config.dns.closing_bracket", "serverValidation.dnsIpv6Bracket"],
  ["config.dns.port_separator", "serverValidation.dnsIpv6Separator"],
  ["config.dns.address", "serverValidation.dnsAddress"],
  ["config.value.string_array", "serverValidation.stringArray"],
  ["config.value.object", "serverValidation.object"],
  ["config.value.object_array", "serverValidation.objectArray"],
  ["config.value.number", "serverValidation.number"],
  ["config.value.hex", "serverValidation.hexValue"],
  ["config.value.duplicate", "serverValidation.duplicateValue"],
  ["config.value.non_empty_array", "serverValidation.nonEmptyArray"],
  ["config.identifier.whitespace", "serverValidation.identifierWhitespace"],
  ["config.interface.invalid", "serverValidation.interfaceInvalid"],
  ["config.daemon.meta_udp443_policy", "serverValidation.metaUdp443Policy"],
  ["config.daemon.ppe_deoffload_mode", "serverValidation.ppeDeoffloadMode"],
  ["config.list.refresh_detour_mode", "serverValidation.refreshDetourMode"],
  ["config.route.failure_policy", "serverValidation.ruleFailurePolicy"],
  ["config.dns.template_duplicate", "serverValidation.dnsTemplateDuplicate"],
  ["config.urltest.cycle", "serverValidation.groupCycle"],
  ["config.vpn.service_id", "serverValidation.vpnServiceId"],
  ["config.cron.invalid", "serverValidation.cronInvalid"],
  ["config.catalog_identity.invalid", "serverValidation.catalogIdentity"],
  ["config.list.source_required", "serverValidation.listSourceRequired"],
  ["config.list.source_format", "serverValidation.listSourceFormat"],
  [
    "config.download.primary_required",
    "serverValidation.downloadPrimaryRequired",
  ],
  [
    "config.outbound.routing_table_required",
    "serverValidation.routingTableRequired",
  ],
  ["config.download.url_required", "serverValidation.downloadUrlRequired"],
  [
    "config.download.inherit_conflict",
    "serverValidation.downloadInheritConflict",
  ],
  ["config.conntrack.urltest_only", "serverValidation.conntrackGroupOnly"],
  ["config.address.ipv6", "serverValidation.ipv6"],
  ["config.urltest.child_type", "serverValidation.groupChildType"],
  ["config.route.primary_exact", "serverValidation.primaryExact"],
  ["config.route.primary_routable", "serverValidation.primaryRoutable"],
  ["config.fwmark.start_invalid", "serverValidation.fwmarkStart"],
  ["config.fwmark.mask_invalid", "serverValidation.fwmarkMask"],
  ["config.fwmark.allocation", "serverValidation.fwmarkAllocation"],
  ["config.iproute.reserved", "serverValidation.reservedRoutingTable"],
  ["config.route.multiport_combo", "serverValidation.multiportCombination"],
  ["config.dns.keenetic_build", "serverValidation.keeneticDnsBuild"],
  ["config.dns.keenetic_version", "serverValidation.keeneticDnsVersion"],
  ["config.dns.keenetic_address", "serverValidation.keeneticDnsAddress"],
  ["config.dns.type", "serverValidation.dnsType"],
  ["config.dns.keenetic_limit", "serverValidation.keeneticDnsLimit"],
  ["config.dns.probe_invalid", "serverValidation.dnsProbeInvalid"],
  ["config.conntrack.nested", "serverValidation.conntrackNested"],
  ["config.conntrack.shared_child", "serverValidation.conntrackShared"],
  ["config.conntrack.route_child", "serverValidation.conntrackRoute"],
  ["config.conntrack.dns_child", "serverValidation.conntrackDns"],
  ["config.conntrack.list_child", "serverValidation.conntrackList"],
  [
    "nfqws.shell.command_substitution",
    "serverValidation.nfqwsCommandSubstitution",
  ],
  ["nfqws.shell.expansion_syntax", "serverValidation.nfqwsExpansionSyntax"],
  ["nfqws.shell.undefined_variable", "serverValidation.nfqwsUndefinedVariable"],
  ["nfqws.shell.assignments_only", "serverValidation.nfqwsAssignmentsOnly"],
  [
    "nfqws.shell.unsupported_assignment",
    "serverValidation.nfqwsUnsupportedAssignment",
  ],
  ["nfqws.shell.assignment_syntax", "serverValidation.nfqwsAssignmentsOnly"],
  [
    "nfqws.shell.whitespace_after_equals",
    "serverValidation.nfqwsWhitespaceAfterEquals",
  ],
  [
    "nfqws.shell.unquoted_whitespace",
    "serverValidation.nfqwsUnquotedWhitespace",
  ],
  ["nfqws.shell.control_operator", "serverValidation.nfqwsControlOperator"],
  ["nfqws.shell.unterminated_quote", "serverValidation.nfqwsUnterminatedQuote"],
  ["nfqws.shell.literal_variable", "serverValidation.nfqwsLiteralVariable"],
  ["nfqws.shell.wildcard", "serverValidation.nfqwsWildcard"],
  ["nfqws.port.empty", "serverValidation.portNumber"],
  ["nfqws.port.number", "serverValidation.portNumber"],
  ["nfqws.port.range", "serverValidation.portNumber"],
  ["nfqws.port.filter_empty", "serverValidation.nfqwsPortFilterRequired"],
  ["nfqws.port.empty_item", "serverValidation.nfqwsPortEmptyItem"],
  ["nfqws.port.range_malformed", "serverValidation.nfqwsPortRangeSyntax"],
  ["nfqws.port.range_inverted", "serverValidation.portRangeOrder"],
  ["nfqws.writable.owned_only", "serverValidation.nfqwsWritableOwnedOnly"],
  ["nfqws.writable.duplicate", "serverValidation.nfqwsWritableDuplicate"],
  ["nfqws.path.empty", "serverValidation.nfqwsPathRequired"],
  ["nfqws.path.missing", "serverValidation.nfqwsPathMissing"],
  ["nfqws.profile.new_forbidden", "serverValidation.nfqwsProfileNewForbidden"],
  [
    "nfqws.profile.empty_boundary",
    "serverValidation.nfqwsProfileEmptyBoundary",
  ],
  [
    "nfqws.profile.boundary_name_required",
    "serverValidation.nfqwsProfileBoundaryName",
  ],
  [
    "nfqws.profile.consecutive_boundaries",
    "serverValidation.nfqwsProfileConsecutiveBoundaries",
  ],
  [
    "nfqws.profile.action_required",
    "serverValidation.nfqwsProfileActionRequired",
  ],
  [
    "nfqws.profile.webrtc_passthrough",
    "serverValidation.nfqwsWebrtcPassthrough",
  ],
  [
    "nfqws.profile.custom_action_required",
    "serverValidation.nfqwsProfileActionRequired",
  ],
  ["nfqws.profile.required", "serverValidation.nfqwsProfileRequired"],
  ["nfqws.queue.range", "serverValidation.nfqwsQueueRange"],
  ["nfqws.user.unsafe", "serverValidation.nfqwsUserCharacters"],
  ["nfqws.binary.rejected", "serverValidation.nfqwsBinaryRejected"],
])

function integerParameter(params: unknown, name: string): string | null {
  if (!params || typeof params !== "object" || Array.isArray(params))
    return null
  const value = (params as Record<string, unknown>)[name]
  return typeof value === "string" && /^(?:0|-?[1-9]\d*)$/.test(value)
    ? value
    : null
}

// Constraints arrive as decimal strings, including uint64 schema versions.
// Compare exactly; converting to Number would round the displayed boundary.
function compareIntegerParameters(left: string, right: string): number {
  const first = BigInt(left)
  const second = BigInt(right)
  return first < second ? -1 : first > second ? 1 : 0
}

function presentCode(
  error: ValidationErrorEntry
): ServerValidationPresentation {
  const unknown = { key: "serverValidation.unknown" }
  if (typeof error.code !== "string") return unknown
  const key = codeKeys.get(error.code)
  if (key) return { key }

  switch (error.code) {
    case "config.schema_version.migration_required": {
      const supported = integerParameter(error.params, "supported")
      return supported !== null && compareIntegerParameters(supported, "0") > 0
        ? { key: "serverValidation.schemaMigration", values: { supported } }
        : unknown
    }
    case "config.schema_version.unsupported": {
      const version = integerParameter(error.params, "version")
      const supported = integerParameter(error.params, "supported")
      return version !== null &&
        supported !== null &&
        compareIntegerParameters(supported, "0") > 0 &&
        compareIntegerParameters(version, supported) > 0
        ? {
            key: "serverValidation.futureSchemaVersion",
            values: { version, supported },
          }
        : unknown
    }
    case "config.value.range":
    case "config.value.integer_range": {
      const min = integerParameter(error.params, "min")
      const max = integerParameter(error.params, "max")
      return min !== null &&
        max !== null &&
        compareIntegerParameters(min, max) <= 0
        ? {
            key:
              error.code === "config.value.integer_range"
                ? "serverValidation.integerRange"
                : "serverValidation.range",
            values: { min, max },
          }
        : unknown
    }
    case "config.tag.too_long":
    case "config.name.too_long":
    case "config.value.too_many": {
      const max = integerParameter(error.params, "max")
      return max !== null && compareIntegerParameters(max, "0") > 0
        ? {
            key:
              error.code === "config.value.too_many"
                ? "serverValidation.tooManyEntries"
                : error.code === "config.name.too_long"
                  ? "serverValidation.nameLength"
                  : "serverValidation.tagLength",
            values: { max },
          }
        : unknown
    }
    default:
      return unknown
  }
}

const exactMessages = new Map<string, string>([
  [
    "IPv4 addresses must not contain leading zeros",
    "serverValidation.ipv4LeadingZeros",
  ],
  ["IP/CIDR address is invalid", "serverValidation.ipAddressOrCidr"],
  ["IP/CIDR prefix length is invalid", "serverValidation.ipPrefixLength"],
  ["Use comma-separated ports or ranges.", "serverValidation.portList"],
  [
    "Port ranges must use valid ports such as 8000-9000.",
    "serverValidation.portRange",
  ],
  [
    "Port range start must be less than or equal to end.",
    "serverValidation.portRangeOrder",
  ],
  [
    "Ports must be integers between 1 and 65535.",
    "serverValidation.portNumber",
  ],
  [
    "Use comma-separated IP addresses or CIDRs.",
    "serverValidation.addressList",
  ],
  [
    "Addresses must be valid IPv4 or IPv6 hosts or CIDR ranges, for example 10.0.0.1, 10.0.0.0/8, or 2001:db8::/32.",
    "serverValidation.ipAddressOrCidr",
  ],
  [
    "Route rule must include at least one condition: list, dscp, src_port, dest_port, src_addr, or dest_addr.",
    "serverValidation.routeCondition",
  ],
  [
    "Urltest URL must use the http or https scheme",
    "serverValidation.urlScheme",
  ],
  [
    "Enter a DNS domain without a URL scheme, path or IP address",
    "serverValidation.dnsDomain",
  ],
  [
    "Fallback outbound must differ from the primary outbound",
    "serverValidation.fallbackDifferent",
  ],
  [
    "Fallback outbound must be an interface or urltest outbound",
    "serverValidation.fallbackRoutable",
  ],
  [
    "fallback_outbound is only used when failure_policy is fallback",
    "serverValidation.fallbackMode",
  ],
  [
    "Plain DNS template primary_ipv4 must be a valid IPv4 address",
    "serverValidation.ipv4",
  ],
  [
    "Plain DNS template secondary_ipv4 must be a valid IPv4 address",
    "serverValidation.ipv4",
  ],
  [
    "Plain DNS template secondary_ipv4 must differ from primary_ipv4",
    "serverValidation.dnsDifferent",
  ],
  ["Invalid DNS server address: empty string", "serverValidation.required"],
])

const pathSuffixes = new Map<string, string>([
  ["must be an integer", "serverValidation.integer"],
  ["must be a string", "serverValidation.text"],
  ["must be a boolean", "serverValidation.boolean"],
  ["must not be empty", "serverValidation.required"],
  ["must not be blank", "serverValidation.required"],
  ["must be >= 0", "serverValidation.nonNegative"],
  ["must be greater than 0", "serverValidation.positive"],
  ["must be a finite number between 0 and 1", "serverValidation.fraction"],
  ["is required when failure_policy is fallback", "serverValidation.required"],
  ["must include at least one list name", "serverValidation.unknownList"],
])

const nameKinds = [
  "List display name",
  "Outbound display name",
  "Route rule display name",
  "DNS server display name",
  "DNS rule display name",
  "Plain DNS template name",
]

const nameSuffixes = new Map<string, string>([
  ["must contain a non-whitespace character", "serverValidation.required"],
  ["must be valid UTF-8", "serverValidation.nameEncoding"],
  [
    "must not contain ASCII control characters",
    "serverValidation.nameControls",
  ],
  [
    "must not contain C1 or bidirectional control characters",
    "serverValidation.nameControls",
  ],
])

function boundedInteger(raw: string): boolean {
  return /^-?(?:0|[1-9]\d*)$/.test(raw) && Number.isSafeInteger(Number(raw))
}

// This is a finite presenter for backend validation codes and legacy config/DNS
// messages, not a second validator. It never changes the raw entry or
// guesses constraints from a field name; unrecognized messages keep details.
export function getServerValidationPresentation(
  error: ValidationErrorEntry
): ServerValidationPresentation {
  // Stable codes own the meaning, even if the diagnostic wording changes or
  // contains line breaks. Legacy English parsing applies only without a code.
  if (error.code !== undefined && error.code !== null && error.code !== "") {
    return presentCode(error)
  }
  const { path, message } = error
  if (/[\r\n]/.test(message)) return { key: "serverValidation.unknown" }
  const exactKey = exactMessages.get(message)
  if (exactKey) return { key: exactKey }

  if (path === "schema_version") {
    if (message === "schema_version must be a positive integer") {
      return { key: "serverValidation.invalidSchemaVersion" }
    }
    const future =
      /^Configuration schema version ([1-9]\d*) is newer than supported version ([1-9]\d*)\. Update keen-pbr-sb before loading this configuration\.$/.exec(
        message
      )
    if (
      future &&
      boundedInteger(future[1]) &&
      boundedInteger(future[2]) &&
      Number(future[1]) > Number(future[2])
    ) {
      return {
        key: "serverValidation.futureSchemaVersion",
        values: { version: future[1], supported: future[2] },
      }
    }
  }

  const prefix = path ? `${path} ` : null
  if (prefix && message.startsWith(prefix)) {
    const suffix = message.slice(prefix.length)
    const pathKey = pathSuffixes.get(suffix)
    if (pathKey) return { key: pathKey }
    const range =
      /^must be (an integer )?between (-?(?:0|[1-9]\d*)) and (-?(?:0|[1-9]\d*))$/.exec(
        suffix
      )
    if (
      range &&
      boundedInteger(range[2]) &&
      boundedInteger(range[3]) &&
      Number(range[2]) <= Number(range[3])
    ) {
      return {
        key: range[1]
          ? "serverValidation.integerRange"
          : "serverValidation.range",
        values: { min: range[2], max: range[3] },
      }
    }
  }

  for (const kind of nameKinds) {
    if (!message.startsWith(`${kind} `)) continue
    const suffix = message.slice(kind.length + 1)
    const nameKey = nameSuffixes.get(suffix)
    if (nameKey) return { key: nameKey }
    const length = /^must not exceed ([1-9]\d*) Unicode code points$/.exec(
      suffix
    )
    if (length && boundedInteger(length[1])) {
      return { key: "serverValidation.nameLength", values: { max: length[1] } }
    }
  }

  // Technical IDs have different constraints from visible aliases.
  const tagKind =
    /^(List name|Outbound tag|Route rule id|DNS server tag|DNS rule id) (.+)$/.exec(
      message
    )
  if (tagKind) {
    if (tagKind[2] === "must not be empty")
      return { key: "serverValidation.required" }
    if (
      /^'[^'\r\n]+' must match naming convention \[a-z\]\[a-z0-9_\]\*$/.test(
        tagKind[2]
      )
    ) {
      return { key: "serverValidation.tagPattern" }
    }
    const length =
      /^'[^'\r\n]+' is too long: ([1-9]\d*) chars, maximum is ([1-9]\d*)$/.exec(
        tagKind[2]
      )
    if (
      length &&
      boundedInteger(length[1]) &&
      boundedInteger(length[2]) &&
      Number(length[1]) > Number(length[2])
    ) {
      return { key: "serverValidation.tagLength", values: { max: length[2] } }
    }
  }

  const dnsAddress =
    /^Invalid DNS server address: '[^'\r\n]*' \((non-numeric port|port out of range 1-65535|missing closing '\]'|expected ':' after '\]'|not a valid IPv4 or IPv6 address)\)$/.exec(
      message
    )
  if (dnsAddress) {
    switch (dnsAddress[1]) {
      case "non-numeric port":
      case "port out of range 1-65535":
        return { key: "serverValidation.dnsPort" }
      case "missing closing ']'":
        return { key: "serverValidation.dnsIpv6Bracket" }
      case "expected ':' after ']'":
        return { key: "serverValidation.dnsIpv6Separator" }
      case "not a valid IPv4 or IPv6 address":
        return { key: "serverValidation.dnsAddress" }
    }
  }

  const reference =
    /^(route\.rules\[\d+\]|dns\.rules\[\d+\]) references unknown (list|outbound tag|fallback outbound tag|DNS server tag) '[^'\r\n]+'$/.exec(
      message
    )
  if (reference) {
    const owner = reference[1]
    switch (reference[2]) {
      case "list":
        if (
          path.startsWith(`${owner}.list`) &&
          /^\[\d+\]$/.test(path.slice(`${owner}.list`.length))
        ) {
          return { key: "serverValidation.unknownList" }
        }
        break
      case "outbound tag":
        if (path === `${owner}.outbound`)
          return { key: "serverValidation.unknownOutbound" }
        break
      case "fallback outbound tag":
        if (path === `${owner}.fallback_outbound`)
          return { key: "serverValidation.unknownOutbound" }
        break
      case "DNS server tag":
        if (path === `${owner}.server`)
          return { key: "serverValidation.unknownDns" }
        break
    }
  }

  const interfaceMessage =
    /^Interface outbound '([a-z][a-z0-9_]*)' (requires a non-empty interface name|gateway must be a valid IPv4 address|gateway6 must be a valid IPv6 address)$/.exec(
      message
    )
  if (interfaceMessage) {
    const owner = `outbounds.${interfaceMessage[1]}`
    if (
      interfaceMessage[2] === "requires a non-empty interface name" &&
      path === `${owner}.interface`
    )
      return { key: "serverValidation.interfaceRequired" }
    if (
      interfaceMessage[2] === "gateway must be a valid IPv4 address" &&
      path === `${owner}.gateway`
    )
      return { key: "serverValidation.ipv4" }
    if (
      interfaceMessage[2] === "gateway6 must be a valid IPv6 address" &&
      path === `${owner}.gateway6`
    )
      return { key: "serverValidation.ipv6" }
  }

  const groupMessage =
    /^Urltest outbound '([a-z][a-z0-9_]*)' ('outbound_groups' array must not be empty|outbound_group has empty 'outbounds' array|references unknown outbound tag '[^'\r\n]+')$/.exec(
      message
    )
  if (groupMessage) {
    const owner = `outbounds.${groupMessage[1]}.outbound_groups`
    if (
      groupMessage[2] === "'outbound_groups' array must not be empty" &&
      path === owner
    )
      return { key: "serverValidation.groupRequired" }
    const suffix = path.startsWith(`${owner}[`) ? path.slice(owner.length) : ""
    if (
      groupMessage[2] === "outbound_group has empty 'outbounds' array" &&
      /^\[\d+\]\.outbounds$/.test(suffix)
    )
      return { key: "serverValidation.groupRequired" }
    if (
      groupMessage[2].startsWith("references unknown outbound tag '") &&
      /^\[\d+\]\.outbounds\[\d+\]$/.test(suffix)
    )
      return { key: "serverValidation.unknownOutbound" }
  }

  return { key: "serverValidation.unknown" }
}
