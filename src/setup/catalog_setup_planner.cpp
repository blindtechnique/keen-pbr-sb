#include "catalog_setup_planner.hpp"

#include "../crypto/sha256.hpp"
#include "../util/display_name.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <sstream>
#include <utility>

namespace keen_pbr3::setup {

namespace {

constexpr std::size_t kMaxTechnicalIdLength = 24U;

struct ParsedPreset {
    std::string id;
    std::string name;
    std::optional<std::string> url;
    std::vector<std::string> domains;
    std::vector<std::string> ip_cidrs;
    bool rejects{false};
};

[[noreturn]] void fail(CatalogSetupErrorCode code,
                       std::string path,
                       std::string message) {
    throw CatalogSetupPlanError(
        code, std::move(path), std::move(message));
}

std::string trim_ascii(std::string value) {
    const auto first = value.find_first_not_of(" \t\n\r\f\v");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\n\r\f\v");
    return value.substr(first, last - first + 1U);
}

std::string lower_ascii(std::string value) {
    std::transform(
        value.begin(), value.end(), value.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return value;
}

std::string validate_catalog_url(std::string url,
                                 const std::string& path) {
    url = trim_ascii(std::move(url));
    for (const unsigned char character : url) {
        if (character <= 0x20U || character == 0x7fU ||
            character == '\\') {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                path,
                "Catalogue URL contains an unsafe character");
        }
    }

    const auto scheme_end = url.find("://");
    if (scheme_end == std::string::npos ||
        lower_ascii(url.substr(0, scheme_end)) != "https") {
        fail(
            CatalogSetupErrorCode::malformed_preset,
            path,
            "Catalogue URL must use HTTPS");
    }

    const auto authority_start = scheme_end + 3U;
    const auto authority_end = url.find_first_of("/?#", authority_start);
    const auto authority = url.substr(
        authority_start,
        authority_end == std::string::npos
            ? std::string::npos
            : authority_end - authority_start);
    if (authority.empty()) {
        fail(
            CatalogSetupErrorCode::malformed_preset,
            path,
            "Catalogue URL must include a trusted host");
    }
    if (authority.find('@') != std::string::npos) {
        fail(
            CatalogSetupErrorCode::malformed_preset,
            path,
            "Catalogue URL must not include userinfo");
    }

    const auto port_separator = authority.find(':');
    std::string host = authority.substr(0, port_separator);
    if (port_separator != std::string::npos) {
        const auto port = authority.substr(port_separator + 1U);
        if (port.empty() ||
            !std::all_of(
                port.begin(), port.end(),
                [](unsigned char character) {
                    return std::isdigit(character) != 0;
                })) {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                path,
                "Catalogue URL has an invalid authority");
        }
        try {
            const auto numeric_port = std::stoul(port);
            if (numeric_port == 0U || numeric_port > 65535U) {
                fail(
                    CatalogSetupErrorCode::malformed_preset,
                    path,
                    "Catalogue URL has an invalid authority");
            }
        } catch (const CatalogSetupPlanError&) {
            throw;
        } catch (const std::exception&) {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                path,
                "Catalogue URL has an invalid authority");
        }
    }

    host = lower_ascii(std::move(host));
    if (!host.empty() && host.back() == '.') host.pop_back();
    if (host.empty() || host.back() == '.' ||
        (host != "repo.hoaxisr.ru" &&
         host != "raw.githubusercontent.com")) {
        fail(
            CatalogSetupErrorCode::malformed_preset,
            path,
            "Catalogue URL host is not trusted");
    }

    return url;
}

bool is_routable(OutboundType type) {
    return type == OutboundType::INTERFACE ||
           type == OutboundType::TABLE ||
           type == OutboundType::URLTEST;
}

const Outbound* find_outbound(const Config& config, const std::string& tag) {
    if (!config.outbounds.has_value()) return nullptr;
    const auto& outbounds = *config.outbounds;
    const auto found = std::find_if(
        outbounds.begin(), outbounds.end(),
        [&](const Outbound& outbound) { return outbound.tag == tag; });
    return found == outbounds.end() ? nullptr : &*found;
}

const DnsServer* find_dns_server(const Config& config,
                                 const std::string& tag) {
    if (!config.dns.has_value() || !config.dns->servers.has_value()) {
        return nullptr;
    }
    const auto& servers = *config.dns->servers;
    const auto found = std::find_if(
        servers.begin(), servers.end(),
        [&](const DnsServer& server) { return server.tag == tag; });
    return found == servers.end() ? nullptr : &*found;
}

const nlohmann::json& preset_array(const nlohmann::json& snapshot) {
    if (snapshot.is_array()) return snapshot;
    if (snapshot.is_object()) {
        const auto presets = snapshot.find("presets");
        if (presets != snapshot.end() && presets->is_array()) {
            return *presets;
        }
    }
    fail(
        CatalogSetupErrorCode::invalid_catalog_snapshot,
        "catalog",
        "Catalogue snapshot must be an array or contain a presets array");
}

std::vector<std::string> parse_domains(const nlohmann::json& preset,
                                       const std::string& path) {
    const auto engines = preset.find("engines");
    if (engines == preset.end() || engines->is_null()) return {};
    if (!engines->is_object()) {
        fail(
            CatalogSetupErrorCode::malformed_preset,
            path + ".engines",
            "Catalogue preset engines must be an object");
    }

    const auto dns = engines->find("dns");
    if (dns == engines->end() || dns->is_null()) return {};
    if (!dns->is_object()) {
        fail(
            CatalogSetupErrorCode::malformed_preset,
            path + ".engines.dns",
            "Catalogue preset DNS engine must be an object");
    }

    const auto domains = dns->find("domains");
    if (domains == dns->end() || domains->is_null()) return {};
    if (!domains->is_array()) {
        fail(
            CatalogSetupErrorCode::malformed_preset,
            path + ".engines.dns.domains",
            "Catalogue preset domains must be an array");
    }

    std::vector<std::string> result;
    result.reserve(domains->size());
    for (std::size_t index = 0; index < domains->size(); ++index) {
        const auto& domain = domains->at(index);
        if (!domain.is_string() ||
            trim_ascii(domain.get<std::string>()).empty()) {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                path + ".engines.dns.domains[" +
                    std::to_string(index) + "]",
                "Catalogue preset domain must be a non-empty string");
        }
        result.push_back(domain.get<std::string>());
    }
    return result;
}

std::vector<std::string> parse_subnets(const nlohmann::json& preset,
                                       const std::string& path) {
    const auto engines = preset.find("engines");
    if (engines == preset.end() || engines->is_null()) return {};
    if (!engines->is_object()) {
        fail(
            CatalogSetupErrorCode::malformed_preset,
            path + ".engines",
            "Catalogue preset engines must be an object");
    }

    const auto dns = engines->find("dns");
    if (dns == engines->end() || dns->is_null()) return {};
    if (!dns->is_object()) {
        fail(
            CatalogSetupErrorCode::malformed_preset,
            path + ".engines.dns",
            "Catalogue preset DNS engine must be an object");
    }

    const auto subnets = dns->find("subnets");
    if (subnets == dns->end() || subnets->is_null()) return {};
    if (!subnets->is_array()) {
        fail(
            CatalogSetupErrorCode::malformed_preset,
            path + ".engines.dns.subnets",
            "Catalogue preset subnets must be an array");
    }

    std::vector<std::string> result;
    result.reserve(subnets->size());
    for (std::size_t index = 0; index < subnets->size(); ++index) {
        const auto& subnet = subnets->at(index);
        if (!subnet.is_string() ||
            trim_ascii(subnet.get<std::string>()).empty()) {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                path + ".engines.dns.subnets[" +
                    std::to_string(index) + "]",
                "Catalogue preset subnet must be a non-empty string");
        }
        // Address/CIDR syntax is intentionally left to validate_config(), the
        // single authoritative validator for both manual and planned edits.
        result.push_back(subnet.get<std::string>());
    }
    return result;
}

std::optional<std::string> parse_url(const nlohmann::json& preset,
                                     const std::string& path) {
    const auto engines = preset.find("engines");
    if (engines == preset.end() || engines->is_null()) return std::nullopt;
    if (!engines->is_object()) {
        fail(
            CatalogSetupErrorCode::malformed_preset,
            path + ".engines",
            "Catalogue preset engines must be an object");
    }

    std::optional<std::string> ruleset_url;
    const auto singbox = engines->find("singbox");
    if (singbox != engines->end() && !singbox->is_null()) {
        if (!singbox->is_object()) {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                path + ".engines.singbox",
                "Catalogue preset sing-box engine must be an object");
        }
        const auto rule_sets = singbox->find("ruleSets");
        if (rule_sets != singbox->end() && !rule_sets->is_null()) {
            if (!rule_sets->is_array()) {
                fail(
                    CatalogSetupErrorCode::malformed_preset,
                    path + ".engines.singbox.ruleSets",
                    "Catalogue preset ruleSets must be an array");
            }
            if (rule_sets->size() > 1U) {
                fail(
                    CatalogSetupErrorCode::malformed_preset,
                    path + ".engines.singbox.ruleSets",
                    "A catalogue preset with multiple rule-set URLs cannot "
                    "be represented by one list");
            }
            if (!rule_sets->empty()) {
                const auto& rule_set = rule_sets->front();
                if (!rule_set.is_object() ||
                    !rule_set.contains("url") ||
                    !rule_set.at("url").is_string() ||
                    trim_ascii(rule_set.at("url").get<std::string>()).empty()) {
                    fail(
                        CatalogSetupErrorCode::malformed_preset,
                        path + ".engines.singbox.ruleSets[0].url",
                        "Catalogue rule-set URL must be a non-empty string");
                }
                ruleset_url = validate_catalog_url(
                    rule_set.at("url").get<std::string>(),
                    path + ".engines.singbox.ruleSets[0].url");
            }
        }
    }

    std::optional<std::string> subscription_url;
    const auto dns = engines->find("dns");
    if (dns != engines->end() && !dns->is_null()) {
        if (!dns->is_object()) {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                path + ".engines.dns",
                "Catalogue preset DNS engine must be an object");
        }
        const auto subscription = dns->find("subscriptionUrl");
        if (subscription != dns->end() && !subscription->is_null()) {
            if (!subscription->is_string() ||
                trim_ascii(subscription->get<std::string>()).empty()) {
                fail(
                    CatalogSetupErrorCode::malformed_preset,
                    path + ".engines.dns.subscriptionUrl",
                    "Catalogue subscription URL must be a non-empty string");
            }
            subscription_url = validate_catalog_url(
                subscription->get<std::string>(),
                path + ".engines.dns.subscriptionUrl");
        }
    }

    // Some authoritative presets deliberately publish both a compiled
    // sing-box ruleset and the raw DNS subscription from which it was built.
    // ListConfig has one URL slot. Prefer the compiled ruleset used for
    // routing, and only fall back to subscriptionUrl when no ruleset exists.
    return ruleset_url ? ruleset_url : subscription_url;
}

bool parse_reject_action(const nlohmann::json& preset,
                         const std::string& path) {
    const auto engines = preset.find("engines");
    if (engines == preset.end() || !engines->is_object()) return false;
    const auto singbox = engines->find("singbox");
    if (singbox == engines->end() || !singbox->is_object()) return false;
    const auto action = singbox->find("action");
    if (action == singbox->end() || action->is_null()) return false;
    if (!action->is_string()) {
        fail(
            CatalogSetupErrorCode::malformed_preset,
            path + ".engines.singbox.action",
            "Catalogue action must be a string");
    }
    const auto value = action->get<std::string>();
    if (value == "reject") return true;
    if (value.empty() || value == "tunnel") return false;
    fail(
        CatalogSetupErrorCode::malformed_preset,
        path + ".engines.singbox.action",
        "Unsupported catalogue action '" + value + "'");
}

ParsedPreset parse_preset(const nlohmann::json& preset,
                          const std::string& expected_id,
                          std::size_t index) {
    const std::string path = "catalog.presets[" + std::to_string(index) + "]";
    if (!preset.is_object() || !preset.contains("id") ||
        !preset.at("id").is_string()) {
        fail(
            CatalogSetupErrorCode::malformed_preset,
            path + ".id",
            "Selected catalogue preset must contain a string id");
    }
    if (preset.at("id").get_ref<const std::string&>() != expected_id) {
        fail(
            CatalogSetupErrorCode::malformed_preset,
            path + ".id",
            "Selected catalogue preset id changed while planning");
    }
    if (!preset.contains("name") || !preset.at("name").is_string()) {
        fail(
            CatalogSetupErrorCode::malformed_preset,
            path + ".name",
            "Selected catalogue preset must contain a string name");
    }

    ParsedPreset result;
    result.id = expected_id;
    result.name = preset.at("name").get<std::string>();
    if (!display_name::is_valid(result.name)) {
        fail(
            CatalogSetupErrorCode::malformed_preset,
            path + ".name",
            "Catalogue preset name is not a valid display name");
    }
    result.url = parse_url(preset, path);
    result.domains = parse_domains(preset, path);
    result.ip_cidrs = parse_subnets(preset, path);
    result.rejects = parse_reject_action(preset, path);
    if (!result.url && result.domains.empty() && result.ip_cidrs.empty()) {
        fail(
            CatalogSetupErrorCode::malformed_preset,
            path + ".engines",
            "Selected catalogue preset has no usable URL, inline domains, "
            "or inline CIDRs");
    }
    return result;
}

std::vector<ParsedPreset> select_presets(
    const CatalogSetupIntent& intent,
    const nlohmann::json& snapshot) {
    if (intent.selections.empty()) {
        fail(
            CatalogSetupErrorCode::empty_selection,
            "intent.selections",
            "At least one catalogue preset must be selected");
    }

    std::set<std::string> requested;
    for (std::size_t index = 0; index < intent.selections.size(); ++index) {
        const auto& selection = intent.selections[index];
        const auto& id = selection.preset_id;
        if (trim_ascii(id).empty()) {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                "intent.selections[" + std::to_string(index) +
                    "].preset_id",
                "Selected catalogue preset id must not be empty");
        }
        if (!requested.insert(id).second) {
            fail(
                CatalogSetupErrorCode::duplicate_selection,
                "intent.selections[" + std::to_string(index) +
                    "].preset_id",
                "Catalogue preset '" + id + "' is selected more than once");
        }
        if (selection.display_name.has_value() &&
            !display_name::is_valid(*selection.display_name)) {
            fail(
                CatalogSetupErrorCode::incompatible_intent,
                "intent.selections[" + std::to_string(index) +
                    "].display_name",
                "Catalogue list display name is invalid");
        }
    }

    const auto& presets = preset_array(snapshot);
    std::map<std::string, std::pair<const nlohmann::json*, std::size_t>>
        selected_entries;
    for (std::size_t index = 0; index < presets.size(); ++index) {
        const auto& entry = presets.at(index);
        if (!entry.is_object()) continue;
        const auto id = entry.find("id");
        if (id == entry.end() || !id->is_string()) continue;
        const auto& value = id->get_ref<const std::string&>();
        if (requested.find(value) == requested.end()) continue;
        if (!selected_entries.emplace(
                value, std::make_pair(&entry, index)).second) {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                "catalog.presets[" + std::to_string(index) + "].id",
                "Authoritative catalogue contains duplicate selected id '" +
                    value + "'");
        }
    }

    std::vector<ParsedPreset> result;
    result.reserve(intent.selections.size());
    for (const auto& selection : intent.selections) {
        const auto& id = selection.preset_id;
        const auto found = selected_entries.find(id);
        if (found == selected_entries.end()) {
            fail(
                CatalogSetupErrorCode::preset_not_found,
                "intent.selections",
                "Catalogue preset '" + id +
                    "' is absent from the authoritative snapshot");
        }
        auto parsed =
            parse_preset(*found->second.first, id, found->second.second);
        if (selection.display_name.has_value()) {
            parsed.name = *selection.display_name;
        }
        result.push_back(std::move(parsed));
    }
    return result;
}

std::string sanitize_technical_id(const std::string& value,
                                  const std::string& fallback_prefix) {
    std::string result;
    result.reserve(value.size());
    bool pending_separator = false;
    for (const unsigned char character : value) {
        const bool letter = character >= 'a' && character <= 'z';
        const bool uppercase = character >= 'A' && character <= 'Z';
        const bool digit = character >= '0' && character <= '9';
        if (letter || uppercase || digit) {
            if (pending_separator && !result.empty()) result.push_back('_');
            result.push_back(
                uppercase
                    ? static_cast<char>(std::tolower(character))
                    : static_cast<char>(character));
            pending_separator = false;
        } else {
            pending_separator = true;
        }
    }
    while (!result.empty() && result.back() == '_') result.pop_back();
    if (result.empty()) result = fallback_prefix;
    if (result.front() < 'a' || result.front() > 'z') {
        result = fallback_prefix + "_" + result;
    }
    if (result.size() > kMaxTechnicalIdLength) {
        result.resize(kMaxTechnicalIdLength);
    }
    return result;
}

std::string unique_technical_id(const std::string& seed,
                                const std::string& fallback_prefix,
                                std::set<std::string>& occupied) {
    const auto base = sanitize_technical_id(seed, fallback_prefix);
    if (occupied.insert(base).second) return base;

    for (std::size_t suffix = 2U;; ++suffix) {
        const auto suffix_text = "_" + std::to_string(suffix);
        const auto prefix_length =
            suffix_text.size() < kMaxTechnicalIdLength
                ? kMaxTechnicalIdLength - suffix_text.size()
                : 1U;
        const auto candidate =
            base.substr(0, std::min(base.size(), prefix_length)) +
            suffix_text.substr(
                suffix_text.size() >= kMaxTechnicalIdLength
                    ? suffix_text.size() - (kMaxTechnicalIdLength - 1U)
                    : 0U);
        if (occupied.insert(candidate).second) return candidate;
    }
}

std::string generated_display_name(
    const std::optional<std::string>& requested_name,
    const std::vector<ParsedPreset>& presets) {
    if (requested_name.has_value()) return *requested_name;
    if (presets.size() == 1U) return presets.front().name;

    std::string combined = presets.front().name;
    for (std::size_t index = 1; index < presets.size(); ++index) {
        const auto candidate = combined + " + " + presets[index].name;
        if (!display_name::is_valid(candidate)) break;
        combined = candidate;
    }
    if (display_name::is_valid(combined)) return combined;

    // Every individual catalogue name was validated. Falling back to the
    // first one is preferable to truncating a UTF-8 code point or inventing a
    // locale-dependent backend label.
    return presets.front().name;
}

void validate_intent_shape(const CatalogSetupIntent& intent) {
    if (intent.route_display_name.has_value() &&
        !display_name::is_valid(*intent.route_display_name)) {
        fail(
            CatalogSetupErrorCode::incompatible_intent,
            "intent.route_display_name",
            "Route rule display name is invalid");
    }
    if (intent.dns_display_name.has_value() &&
        !display_name::is_valid(*intent.dns_display_name)) {
        fail(
            CatalogSetupErrorCode::incompatible_intent,
            "intent.dns_display_name",
            "DNS rule display name is invalid");
    }

    if (intent.mode == CatalogSetupMode::outbound) {
        if (!intent.outbound_tag.has_value() ||
            trim_ascii(*intent.outbound_tag).empty()) {
            fail(
                CatalogSetupErrorCode::outbound_required,
                "intent.outbound_tag",
                "Outbound mode requires an outbound tag");
        }
    } else if (intent.outbound_tag.has_value()) {
        fail(
            CatalogSetupErrorCode::incompatible_intent,
            "intent.outbound_tag",
            "outbound_tag is only valid in outbound mode");
    }

    if (intent.dns_mode == CatalogDnsMode::explicit_server) {
        if (!intent.dns_server_tag.has_value() ||
            trim_ascii(*intent.dns_server_tag).empty()) {
            fail(
                CatalogSetupErrorCode::dns_server_required,
                "intent.dns_server_tag",
                "Explicit DNS mode requires a DNS server tag");
        }
    } else if (intent.dns_server_tag.has_value()) {
        fail(
            CatalogSetupErrorCode::incompatible_intent,
            "intent.dns_server_tag",
            "dns_server_tag is only valid in explicit DNS mode");
    }
}

std::set<std::string> occupied_route_ids(const Config& config) {
    std::set<std::string> result;
    for (const auto& rule :
         config.route.value_or(RouteConfig{}).rules.value_or(
             std::vector<RouteRule>{})) {
        if (rule.id.has_value()) result.insert(*rule.id);
    }
    return result;
}

std::set<std::string> occupied_dns_rule_ids(const Config& config) {
    std::set<std::string> result;
    for (const auto& rule :
         config.dns.value_or(DnsConfig{}).rules.value_or(
             std::vector<DnsRule>{})) {
        if (rule.id.has_value()) result.insert(*rule.id);
    }
    return result;
}

std::optional<std::string> usable_source_detour(
    const CatalogSetupIntent& intent,
    const Config& config,
    bool has_url_backed_list,
    std::vector<CatalogSetupWarning>& warnings) {
    if (!intent.source_detour_tag.has_value() ||
        trim_ascii(*intent.source_detour_tag).empty()) {
        return std::nullopt;
    }
    const auto& tag = *intent.source_detour_tag;
    if (!has_url_backed_list) {
        warnings.push_back({
            CatalogSetupWarningCode::source_detour_not_applicable,
            "intent.source_detour_tag",
            "Source detour '" + tag +
                "' was not used because the selection has no URL-backed list",
        });
        return std::nullopt;
    }
    const auto* outbound = find_outbound(config, tag);
    if (outbound == nullptr) {
        warnings.push_back({
            CatalogSetupWarningCode::source_detour_not_found,
            "intent.source_detour_tag",
            "Source detour '" + tag +
                "' was not used because the outbound does not exist",
        });
        return std::nullopt;
    }
    if (!is_routable(outbound->type)) {
        warnings.push_back({
            CatalogSetupWarningCode::source_detour_not_routable,
            "intent.source_detour_tag",
            "Source detour '" + tag +
                "' was not used because the outbound has no routing table",
        });
        return std::nullopt;
    }
    return tag;
}

std::optional<std::string> select_dns_server(
    const CatalogSetupIntent& intent,
    const Config& config,
    const std::optional<std::string>& route_outbound,
    std::vector<CatalogSetupWarning>& warnings) {
    if (intent.dns_mode == CatalogDnsMode::none) return std::nullopt;
    if (intent.mode == CatalogSetupMode::block) {
        warnings.push_back({
            CatalogSetupWarningCode::dns_ignored_for_block,
            "intent.dns_mode",
            "DNS rule was not created for a blocking catalogue selection",
        });
        return std::nullopt;
    }

    if (intent.dns_mode == CatalogDnsMode::automatic) {
        if (!route_outbound.has_value()) {
            warnings.push_back({
                CatalogSetupWarningCode::dns_automatic_unavailable,
                "intent.dns_mode",
                "Automatic DNS selection needs an outbound route",
            });
            return std::nullopt;
        }
        for (const auto& server :
             config.dns.value_or(DnsConfig{}).servers.value_or(
                 std::vector<DnsServer>{})) {
            if (server.detour == route_outbound) return server.tag;
        }
        warnings.push_back({
            CatalogSetupWarningCode::dns_automatic_unavailable,
            "intent.dns_mode",
            "No DNS server is detoured through outbound '" +
                *route_outbound + "'",
        });
        return std::nullopt;
    }

    const auto& tag = *intent.dns_server_tag;
    const auto* server = find_dns_server(config, tag);
    if (server == nullptr) {
        fail(
            CatalogSetupErrorCode::dns_server_not_found,
            "intent.dns_server_tag",
            "DNS server '" + tag + "' does not exist");
    }
    if (route_outbound.has_value()) {
        if (!server->detour.has_value()) {
            warnings.push_back({
                CatalogSetupWarningCode::dns_detour_missing,
                "intent.dns_server_tag",
                "DNS server '" + tag +
                    "' has no detour while the route uses outbound '" +
                    *route_outbound + "'",
            });
        } else if (*server->detour != *route_outbound) {
            warnings.push_back({
                CatalogSetupWarningCode::dns_detour_mismatch,
                "intent.dns_server_tag",
                "DNS server '" + tag + "' uses detour '" +
                    *server->detour + "' instead of route outbound '" +
                    *route_outbound + "'",
            });
        }
    }
    return tag;
}

} // namespace

CatalogSetupPlanError::CatalogSetupPlanError(
    CatalogSetupErrorCode code,
    std::string path,
    std::string message)
    : std::runtime_error(std::move(message)),
      code_(code),
      path_(std::move(path)) {}

CatalogSetupPlan plan_catalog_setup(
    const CatalogSetupIntent& intent,
    const nlohmann::json& catalog_snapshot,
    const Config& active_config) {
    // The planner never repairs or normalizes an invalid active snapshot.
    // Existing validation remains the single source of truth.
    validate_config(active_config);
    validate_intent_shape(intent);
    const auto presets = select_presets(intent, catalog_snapshot);

    const bool has_reject = std::any_of(
        presets.begin(), presets.end(),
        [](const ParsedPreset& preset) { return preset.rejects; });
    const bool has_tunnel = std::any_of(
        presets.begin(), presets.end(),
        [](const ParsedPreset& preset) { return !preset.rejects; });
    if (has_reject && has_tunnel) {
        fail(
            CatalogSetupErrorCode::mixed_catalog_actions,
            "intent.selections",
            "Reject and tunnel catalogue presets must be planned separately");
    }
    if (has_reject && intent.mode != CatalogSetupMode::block) {
        fail(
            CatalogSetupErrorCode::incompatible_intent,
            "intent.mode",
            "A reject catalogue preset must use block mode");
    }

    Config candidate = active_config;
    CatalogSetupPlan plan;
    plan.summary.mode = intent.mode;

    std::optional<std::string> route_outbound;
    if (intent.mode == CatalogSetupMode::outbound) {
        const auto* outbound =
            find_outbound(active_config, *intent.outbound_tag);
        if (outbound == nullptr) {
            fail(
                CatalogSetupErrorCode::outbound_not_found,
                "intent.outbound_tag",
                "Outbound '" + *intent.outbound_tag + "' does not exist");
        }
        if (!is_routable(outbound->type)) {
            fail(
                CatalogSetupErrorCode::outbound_not_routable,
                "intent.outbound_tag",
                "Outbound '" + *intent.outbound_tag +
                    "' has no routable table");
        }
        route_outbound = outbound->tag;
    } else if (intent.mode == CatalogSetupMode::block) {
        auto outbounds =
            candidate.outbounds.value_or(std::vector<Outbound>{});
        const auto existing = std::find_if(
            outbounds.begin(), outbounds.end(),
            [](const Outbound& outbound) {
                return outbound.type == OutboundType::BLACKHOLE;
            });
        if (existing != outbounds.end()) {
            route_outbound = existing->tag;
            plan.summary.blackhole =
                CatalogBlackholePlanSummary{existing->tag, false};
        } else {
            std::set<std::string> occupied;
            for (const auto& outbound : outbounds) {
                occupied.insert(outbound.tag);
            }
            const auto tag =
                unique_technical_id("block", "block", occupied);
            Outbound blackhole;
            blackhole.tag = tag;
            blackhole.type = OutboundType::BLACKHOLE;
            outbounds.push_back(std::move(blackhole));
            candidate.outbounds = std::move(outbounds);
            route_outbound = tag;
            plan.summary.blackhole =
                CatalogBlackholePlanSummary{tag, true};
        }
    }

    const bool has_url_backed_list = std::any_of(
        presets.begin(), presets.end(),
        [](const ParsedPreset& preset) { return preset.url.has_value(); });
    const auto source_detour = usable_source_detour(
        intent,
        active_config,
        has_url_backed_list,
        plan.warnings);

    auto lists =
        candidate.lists.value_or(std::map<std::string, ListConfig>{});
    std::set<std::string> occupied_list_ids;
    for (const auto& [id, _] : lists) occupied_list_ids.insert(id);

    std::vector<std::string> list_ids;
    list_ids.reserve(presets.size());
    for (const auto& preset : presets) {
        const auto technical_id = unique_technical_id(
            preset.id, "list", occupied_list_ids);
        ListConfig list;
        list.display_name = preset.name;
        list.url = preset.url;
        if (!preset.domains.empty()) list.domains = preset.domains;
        if (!preset.ip_cidrs.empty()) list.ip_cidrs = preset.ip_cidrs;
        if (preset.url && source_detour) list.detour = source_detour;
        lists.emplace(technical_id, std::move(list));
        list_ids.push_back(technical_id);
        plan.summary.lists.push_back({
            preset.id,
            technical_id,
            preset.name,
            preset.url.has_value(),
            !preset.domains.empty(),
            !preset.ip_cidrs.empty(),
            preset.url ? source_detour : std::nullopt,
        });
    }
    candidate.lists = std::move(lists);

    const auto route_display_name =
        generated_display_name(intent.route_display_name, presets);
    const auto dns_display_name =
        generated_display_name(intent.dns_display_name, presets);
    const auto rule_seed = [&]() {
        std::ostringstream value;
        value << "catalog";
        for (const auto& id : list_ids) value << "_" << id;
        return value.str();
    }();

    if (route_outbound.has_value()) {
        auto route = candidate.route.value_or(RouteConfig{});
        auto rules = route.rules.value_or(std::vector<RouteRule>{});
        auto ids = occupied_route_ids(active_config);

        RouteRule rule;
        rule.id =
            unique_technical_id(rule_seed, "rule", ids);
        rule.display_name = route_display_name;
        rule.enabled = true;
        rule.list = list_ids;
        rule.outbound = *route_outbound;

        std::size_t insertion_index = rules.size();
        if (intent.mode == CatalogSetupMode::block) {
            insertion_index = 0U;
        } else {
            std::set<std::string> blackhole_tags;
            for (const auto& outbound :
                 candidate.outbounds.value_or(std::vector<Outbound>{})) {
                if (outbound.type == OutboundType::BLACKHOLE) {
                    blackhole_tags.insert(outbound.tag);
                }
            }
            for (std::size_t index = 0; index < rules.size(); ++index) {
                if (route_rule_enabled(rules[index]) &&
                    blackhole_tags.count(rules[index].outbound) != 0U) {
                    insertion_index = index;
                    break;
                }
            }
        }

        rules.insert(
            rules.begin() + static_cast<std::ptrdiff_t>(insertion_index),
            rule);
        route.rules = std::move(rules);
        candidate.route = std::move(route);
        plan.summary.route_rule = CatalogRouteRulePlanSummary{
            *rule.id,
            route_display_name,
            *route_outbound,
            insertion_index,
            intent.mode == CatalogSetupMode::block,
        };
    }

    const auto dns_server = select_dns_server(
        intent, active_config, route_outbound, plan.warnings);
    if (dns_server.has_value()) {
        auto dns = candidate.dns.value_or(DnsConfig{});
        auto rules = dns.rules.value_or(std::vector<DnsRule>{});
        auto ids = occupied_dns_rule_ids(active_config);

        DnsRule rule;
        rule.id =
            unique_technical_id(rule_seed, "dns_rule", ids);
        rule.display_name = dns_display_name;
        rule.enabled = true;
        rule.list = list_ids;
        rule.server = *dns_server;
        rule.allow_domain_rebinding = false;
        const auto insertion_index = rules.size();
        rules.push_back(rule);
        dns.rules = std::move(rules);
        candidate.dns = std::move(dns);
        plan.summary.dns_rule = CatalogDnsRulePlanSummary{
            *rule.id,
            dns_display_name,
            *dns_server,
            insertion_index,
        };
    }

    // This is deliberately the last planner step: the same authoritative
    // validator used by manual edits must approve the full candidate.
    validate_config(candidate);
    plan.candidate_revision =
        Sha256::hex(nlohmann::json(candidate).dump());
    plan.candidate = std::move(candidate);
    return plan;
}

} // namespace keen_pbr3::setup
