#include "catalog_setup_planner.hpp"

#include "../crypto/sha256.hpp"
#include "../dns/dns_server.hpp"
#include "../util/display_name.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <functional>
#include <iterator>
#include <map>
#include <set>
#include <sstream>
#include <utility>

namespace keen_pbr3::setup {

namespace {

constexpr std::size_t kMaxTechnicalIdLength = 24U;

struct AutomaticDnsEndpoint {
    const char* technical_name;
    const char* display_name;
    const char* address;
};

constexpr std::array<AutomaticDnsEndpoint, 10U>
    kAutomaticDnsEndpoints{{
        {"cloudflare", "Cloudflare", "1.1.1.1"},
        {"cloudflare", "Cloudflare", "1.0.0.1"},
        {"google", "Google", "8.8.8.8"},
        {"google", "Google", "8.8.4.4"},
        {"quad9", "Quad9", "9.9.9.9"},
        {"quad9", "Quad9", "149.112.112.112"},
        {"opendns", "OpenDNS", "208.67.222.222"},
        {"opendns", "OpenDNS", "208.67.220.220"},
        {"yandex", "Yandex", "77.88.8.8"},
        {"yandex", "Yandex", "77.88.8.1"},
    }};

struct ManagedCatalogUrlMigration {
    const char* preset_id;
    const char* previous_rule_set;
    const char* current_geosite;
};

// These are the package-owned URL moves shipped in sb.12. Provenance alone is
// not permission to replace a source: an operator may have edited that list
// after installing it. Only the exact old managed URL is eligible, and the
// exact new packaged URL must still be present in the authoritative snapshot.
constexpr std::array<ManagedCatalogUrlMigration, 16U>
    kManagedCatalogUrlMigrations{{
        {"anthropic", "claude", "anthropic"},
        {"copilot", "copilot", "github-copilot"},
        {"gemini", "gemini", "google-gemini"},
        {"grok", "grok", "xai"},
        {"openai", "openai", "openai"},
        {"linkedin", "linkedin", "linkedin"},
        {"nintendo", "nintendo", "nintendo"},
        {"roblox", "roblox", "roblox"},
        {"netflix", "netflix", "netflix"},
        {"discord", "discord-full", "discord"},
        {"instagram", "instagram", "instagram"},
        {"telegram", "telegram", "telegram"},
        {"tiktok", "tiktok", "tiktok"},
        {"whatsapp", "whatsapp", "whatsapp"},
        {"x", "x", "x"},
        {"youtube", "youtube", "youtube"},
    }};

// What a catalogue preset says should happen to the traffic it matches. Three
// destinations, and each decides the plan's shape: `tunnel` needs an outbound
// from the operator, `reject` needs a blackhole, `direct` needs the main
// routing table. A preset that mixes them with another in one plan is refused
// rather than silently resolved.
enum class CatalogAction {
    tunnel,
    reject,
    direct,
};

struct ParsedPreset {
    std::string id;
    std::string name;
    std::string catalog_identity_id;
    std::optional<std::string> url;
    std::vector<std::string> domains;
    std::vector<std::string> ip_cidrs;
    CatalogAction action{CatalogAction::tunnel};
    bool dns_eligible{true};
    bool allow_legacy_adoption{true};
    bool reconcile_managed_sources{false};
    bool broad_traffic_scope_warning{false};
};

struct ResolvedPreset {
    ParsedPreset preset;
    std::string catalog_identity;
    std::optional<std::string> existing_technical_id;
};

struct CatalogPresetEntry {
    const nlohmann::json* preset;
    std::size_t index;
};

using CatalogPresetIndex =
    std::map<std::string, std::vector<CatalogPresetEntry>>;
using CatalogCoverGraph =
    std::map<std::string, std::vector<std::string>>;

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

bool is_known_managed_catalog_url_migration(
    const ParsedPreset& preset,
    const ListConfig& installed) {
    if (!preset.url.has_value() || !installed.url.has_value()) return false;

    constexpr const char* previous_prefix =
        "https://repo.hoaxisr.ru/rulesets/srs/";
    constexpr const char* current_prefix =
        "https://raw.githubusercontent.com/SagerNet/sing-geosite/"
        "rule-set/geosite-";
    for (const auto& migration : kManagedCatalogUrlMigrations) {
        if (preset.catalog_identity_id != migration.preset_id) continue;
        const auto previous = std::string(previous_prefix) +
                              migration.previous_rule_set + ".srs";
        const auto current = std::string(current_prefix) +
                             migration.current_geosite + ".srs";
        return trim_ascii(*installed.url) == previous &&
               trim_ascii(*preset.url) == current;
    }
    return false;
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

// Linux calls table 254 `main`; it is where an unmarked packet goes. Routing a
// list here is what "always direct" means on this router.
constexpr int64_t kMainRoutingTable = 254;

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

CatalogPresetIndex index_catalog_presets(
    const nlohmann::json& presets) {
    CatalogPresetIndex result;
    for (std::size_t index = 0; index < presets.size(); ++index) {
        const auto& entry = presets.at(index);
        if (!entry.is_object()) continue;
        const auto id = entry.find("id");
        if (id == entry.end() || !id->is_string()) {
            if (entry.contains("covers") ||
                entry.contains("routingCompanions") ||
                entry.contains("warnings") ||
                entry.contains("hidden")) {
                fail(
                    CatalogSetupErrorCode::malformed_preset,
                    "catalog.presets[" + std::to_string(index) + "].id",
                    "Catalogue metadata owner must contain a string id");
            }
            continue;
        }
        const auto value = trim_ascii(id->get<std::string>());
        if (value.empty()) {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                "catalog.presets[" + std::to_string(index) + "].id",
                "Catalogue preset id must not be empty");
        }
        auto& entries = result[value];
        entries.push_back({&entry, index});
        if (entries.size() > 1U) {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                "catalog.presets[" + std::to_string(index) + "].id",
                "Authoritative catalogue contains duplicate id '" +
                    value + "'");
        }
    }
    return result;
}

CatalogCoverGraph parse_cover_graph(
    const CatalogPresetIndex& catalog) {
    CatalogCoverGraph graph;
    for (const auto& [id, entries] : catalog) {
        const auto& entry = entries.front();
        const auto path =
            "catalog.presets[" + std::to_string(entry.index) + "].covers";
        const auto covers = entry.preset->find("covers");
        if (covers == entry.preset->end() || covers->is_null()) {
            graph.emplace(id, std::vector<std::string>{});
            continue;
        }
        if (!covers->is_array()) {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                path,
                "Catalogue covers must be an array");
        }

        std::vector<std::string> children;
        children.reserve(covers->size());
        std::set<std::string> unique;
        for (std::size_t index = 0; index < covers->size(); ++index) {
            const auto& child = covers->at(index);
            if (!child.is_string() ||
                trim_ascii(child.get<std::string>()).empty()) {
                fail(
                    CatalogSetupErrorCode::malformed_preset,
                    path + "[" + std::to_string(index) + "]",
                    "Catalogue cover id must be a non-empty string");
            }
            const auto child_id =
                trim_ascii(child.get<std::string>());
            if (child_id == id) {
                fail(
                    CatalogSetupErrorCode::malformed_preset,
                    path + "[" + std::to_string(index) + "]",
                    "Catalogue preset '" + id +
                        "' must not cover itself");
            }
            if (catalog.count(child_id) == 0U) {
                fail(
                    CatalogSetupErrorCode::malformed_preset,
                    path + "[" + std::to_string(index) + "]",
                    "Catalogue preset '" + id +
                        "' covers unknown preset '" + child_id + "'");
            }
            if (!unique.insert(child_id).second) {
                fail(
                    CatalogSetupErrorCode::malformed_preset,
                    path + "[" + std::to_string(index) + "]",
                    "Catalogue preset '" + id +
                        "' covers '" + child_id + "' more than once");
            }
            children.push_back(std::move(child_id));
        }
        graph.emplace(id, std::move(children));
    }

    enum class VisitState {
        unseen,
        visiting,
        done,
    };
    std::map<std::string, VisitState> states;
    std::function<void(const std::string&)> visit =
        [&](const std::string& id) {
            const auto state = states[id];
            if (state == VisitState::done) return;
            if (state == VisitState::visiting) {
                fail(
                    CatalogSetupErrorCode::malformed_preset,
                    "catalog.presets",
                    "Catalogue covers contain a cycle at preset '" +
                        id + "'");
            }
            states[id] = VisitState::visiting;
            for (const auto& child : graph.at(id)) {
                visit(child);
            }
            states[id] = VisitState::done;
        };
    for (const auto& [id, _] : graph) visit(id);
    return graph;
}

bool catalog_transitively_covers(
    const CatalogCoverGraph& graph,
    const std::string& parent,
    const std::string& candidate) {
    std::vector<std::string> pending{parent};
    std::set<std::string> visited;
    while (!pending.empty()) {
        auto current = std::move(pending.back());
        pending.pop_back();
        if (!visited.insert(current).second) continue;
        const auto found = graph.find(current);
        if (found == graph.end()) continue;
        for (const auto& child : found->second) {
            if (child == candidate) return true;
            pending.push_back(child);
        }
    }
    return false;
}

std::string catalog_source_identity(const nlohmann::json& snapshot) {
    if (snapshot.is_object()) {
        const auto catalog_id = snapshot.find("catalog_id");
        if (catalog_id != snapshot.end() && catalog_id->is_string()) {
            const auto value =
                trim_ascii(catalog_id->get<std::string>());
            if (!value.empty()) return value;
        }
        // Compatibility for external/test providers predating catalog_id.
        // The URL describes the logical source better than cache/bundled,
        // which only describes how the same catalogue reached the router.
        const auto url = snapshot.find("url");
        if (url != snapshot.end() && url->is_string()) {
            const auto value = trim_ascii(url->get<std::string>());
            if (!value.empty()) return "url:" + value;
        }
    }
    // Pure planner tests and embedded callers may supply the preset array
    // directly. Production snapshots always carry catalog_id.
    return "catalog:inline";
}

std::string catalog_preset_identity_for_source(
    const std::string& catalog_source,
    const std::string& preset_id) {
    return Sha256::hex(
        nlohmann::json{
            {"catalog_source", catalog_source},
            {"preset_id", preset_id},
        }
            .dump());
}

std::vector<std::string> normalized_values(
    std::vector<std::string> values) {
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
    return values;
}

bool legacy_list_matches_preset(const ListConfig& list,
                                const ParsedPreset& preset) {
    if (preset.url.has_value()) {
        return list.url.has_value() &&
               trim_ascii(*list.url) == trim_ascii(*preset.url);
    }
    if (list.url.has_value() || list.file.has_value()) return false;
    return normalized_values(
               list.domains.value_or(std::vector<std::string>{})) ==
               normalized_values(preset.domains) &&
           normalized_values(
               list.ip_cidrs.value_or(std::vector<std::string>{})) ==
               normalized_values(preset.ip_cidrs);
}

std::optional<std::string> find_installed_preset_list(
    const std::map<std::string, ListConfig>& lists,
    const ParsedPreset& preset,
    const std::string& catalog_identity) {
    for (const auto& [technical_id, list] : lists) {
        if (list.catalog_identity == catalog_identity) {
            return technical_id;
        }
    }
    // Lists created by the first sb.12 alpha did not persist provenance.
    // Adopt only an exact source/content match; aliases and technical IDs are
    // deliberately ignored because users may rename them.
    if (preset.allow_legacy_adoption) {
        for (const auto& [technical_id, list] : lists) {
            if (!list.catalog_identity.has_value() &&
                legacy_list_matches_preset(list, preset)) {
                return technical_id;
            }
        }
    }
    return std::nullopt;
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

// An absent engine, an absent action and an empty action all mean `tunnel`:
// most of the catalogue predates the field, and a list with no sing-box engine
// at all - one built purely from a DNS subscription - still routes somewhere.
// An unrecognised value is refused rather than defaulted, because guessing
// would route traffic somewhere the catalogue did not ask for.
CatalogAction parse_catalog_action(const nlohmann::json& preset,
                                   const std::string& path) {
    const auto engines = preset.find("engines");
    if (engines == preset.end() || !engines->is_object()) {
        return CatalogAction::tunnel;
    }
    const auto singbox = engines->find("singbox");
    if (singbox == engines->end() || !singbox->is_object()) {
        return CatalogAction::tunnel;
    }
    const auto action = singbox->find("action");
    if (action == singbox->end() || action->is_null()) {
        return CatalogAction::tunnel;
    }
    if (!action->is_string()) {
        fail(
            CatalogSetupErrorCode::malformed_preset,
            path + ".engines.singbox.action",
            "Catalogue action must be a string");
    }
    const auto value = action->get<std::string>();
    if (value == "reject") return CatalogAction::reject;
    if (value == "direct") return CatalogAction::direct;
    if (value.empty() || value == "tunnel") return CatalogAction::tunnel;
    fail(
        CatalogSetupErrorCode::malformed_preset,
        path + ".engines.singbox.action",
        "Unsupported catalogue action '" + value + "'");
}

bool parse_broad_traffic_scope_warning(
    const nlohmann::json& preset,
    const std::string& path) {
    const auto warnings = preset.find("warnings");
    if (warnings == preset.end() || warnings->is_null()) return false;
    if (!warnings->is_array()) {
        fail(
            CatalogSetupErrorCode::malformed_preset,
            path + ".warnings",
            "Catalogue warnings must be an array");
    }

    bool broad_scope = false;
    for (std::size_t index = 0; index < warnings->size(); ++index) {
        const auto warning_path =
            path + ".warnings[" + std::to_string(index) + "]";
        const auto& warning = warnings->at(index);
        if (!warning.is_object()) {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                warning_path,
                "Catalogue warning must be an object");
        }
        const auto code = warning.find("code");
        if (code == warning.end() || !code->is_string() ||
            trim_ascii(code->get<std::string>()).empty()) {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                warning_path + ".code",
                "Catalogue warning code must be a non-empty string");
        }
        if (code->get_ref<const std::string&>() !=
            "broad_traffic_scope") {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                warning_path + ".code",
                "Unsupported catalogue warning code '" +
                    code->get<std::string>() + "'");
        }
        const auto requires_acceptance =
            warning.find("requiresAcceptance");
        if (requires_acceptance == warning.end() ||
            !requires_acceptance->is_boolean() ||
            !requires_acceptance->get<bool>()) {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                warning_path + ".requiresAcceptance",
                "Broad traffic scope warning must require explicit "
                "acceptance");
        }
        if (broad_scope) {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                warning_path + ".code",
                "Broad traffic scope warning is duplicated");
        }
        broad_scope = true;
    }
    return broad_scope;
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
    result.catalog_identity_id = expected_id;
    if (!display_name::is_valid(result.name)) {
        fail(
            CatalogSetupErrorCode::malformed_preset,
            path + ".name",
            "Catalogue preset name is not a valid display name");
    }
    result.url = parse_url(preset, path);
    result.domains = parse_domains(preset, path);
    result.ip_cidrs = parse_subnets(preset, path);
    // Pure IP lists are matched by the routing firewall and do not need a
    // parallel DNS rule. URL-backed rule sets remain DNS-eligible because
    // their decoded contents can include domains even when the catalogue
    // snapshot has no inline domain preview.
    result.dns_eligible =
        !result.domains.empty() || result.url.has_value();
    result.action = parse_catalog_action(preset, path);
    result.broad_traffic_scope_warning =
        parse_broad_traffic_scope_warning(preset, path);
    return result;
}

std::vector<ParsedPreset> parse_routing_companions(
    const nlohmann::json& parent,
    const ParsedPreset& parsed_parent,
    std::size_t parent_index,
    const CatalogPresetIndex& catalog) {
    const std::string parent_path =
        "catalog.presets[" + std::to_string(parent_index) + "]";
    const auto companions = parent.find("routingCompanions");
    if (companions == parent.end() || companions->is_null()) return {};
    if (!companions->is_array()) {
        fail(
            CatalogSetupErrorCode::malformed_preset,
            parent_path + ".routingCompanions",
            "Catalogue routing companions must be an array");
    }

    std::vector<ParsedPreset> result;
    result.reserve(companions->size());
    std::set<std::string> companion_ids;
    for (std::size_t index = 0; index < companions->size(); ++index) {
        const auto path =
            parent_path + ".routingCompanions[" +
            std::to_string(index) + "]";
        const auto& definition = companions->at(index);
        if (!definition.is_object()) {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                path,
                "Catalogue routing companion must be an object");
        }

        const auto required_string =
            [&](const char* key) {
                const auto value = definition.find(key);
                if (value == definition.end() || !value->is_string() ||
                    trim_ascii(value->get<std::string>()).empty()) {
                    fail(
                        CatalogSetupErrorCode::malformed_preset,
                        path + "." + key,
                        "Catalogue routing companion " +
                            std::string(key) +
                            " must be a non-empty string");
                }
                return value->get<std::string>();
            };

        ParsedPreset companion;
        companion.id = required_string("id");
        companion.name = required_string("name");
        if (!companion_ids.insert(companion.id).second) {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                path + ".id",
                "Catalogue routing companion id '" + companion.id +
                    "' is duplicated");
        }
        if (!display_name::is_valid(companion.name)) {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                path + ".name",
                "Catalogue routing companion name is not a valid display "
                "name");
        }

        companion.catalog_identity_id =
            parsed_parent.id + "#routing-companion:" + companion.id;
        const auto explicit_identity =
            definition.find("catalogIdentityId");
        if (explicit_identity != definition.end()) {
            if (!explicit_identity->is_string() ||
                trim_ascii(
                    explicit_identity->get<std::string>()).empty()) {
                fail(
                    CatalogSetupErrorCode::malformed_preset,
                    path + ".catalogIdentityId",
                    "Catalogue routing companion catalogIdentityId must be "
                    "a non-empty string");
            }
            const auto identity_id =
                trim_ascii(explicit_identity->get<std::string>());
            if (identity_id.find("#routing-companion:") ==
                std::string::npos) {
                fail(
                    CatalogSetupErrorCode::malformed_preset,
                    path + ".catalogIdentityId",
                    "Catalogue routing companion catalogIdentityId must "
                    "identify a routing companion");
            }
            companion.catalog_identity_id = identity_id;
        }
        companion.action = parsed_parent.action;
        companion.dns_eligible = false;
        companion.reconcile_managed_sources = true;
        // Companions did not exist in older packages. Do not silently adopt
        // an unrelated manual list merely because its URL/content happens to
        // match the companion source.
        companion.allow_legacy_adoption = false;

        const auto url = definition.find("url");
        const auto source_preset_id =
            definition.find("sourcePresetId");
        const bool has_url =
            url != definition.end() && !url->is_null();
        const bool has_source =
            source_preset_id != definition.end() &&
            !source_preset_id->is_null();
        if (has_url == has_source) {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                path,
                "Catalogue routing companion must define exactly one of "
                "url or sourcePresetId");
        }
        const auto suppress_direct =
            definition.find("suppressDirectSelection");
        if (suppress_direct != definition.end() &&
            !suppress_direct->is_boolean()) {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                path + ".suppressDirectSelection",
                "Catalogue routing companion suppressDirectSelection must "
                "be a boolean");
        }

        if (has_url) {
            if (!url->is_string() ||
                trim_ascii(url->get<std::string>()).empty()) {
                fail(
                    CatalogSetupErrorCode::malformed_preset,
                    path + ".url",
                    "Catalogue routing companion URL must be a non-empty "
                    "string");
            }
            companion.url = validate_catalog_url(
                url->get<std::string>(), path + ".url");
            if (definition.contains("include")) {
                fail(
                    CatalogSetupErrorCode::malformed_preset,
                    path + ".include",
                    "Catalogue routing companion include is only valid with "
                    "sourcePresetId");
            }
        } else {
            const auto source_id = required_string("sourcePresetId");
            const auto include = required_string("include");
            if (include != "ip_cidrs") {
                fail(
                    CatalogSetupErrorCode::malformed_preset,
                    path + ".include",
                    "Catalogue routing companion currently supports only "
                    "ip_cidrs");
            }
            const auto source = catalog.find(source_id);
            if (source == catalog.end()) {
                fail(
                    CatalogSetupErrorCode::malformed_preset,
                    path + ".sourcePresetId",
                    "Catalogue routing companion references unknown preset '" +
                        source_id + "'");
            }
            if (source->second.size() > 1U) {
                fail(
                    CatalogSetupErrorCode::malformed_preset,
                    "catalog.presets[" +
                        std::to_string(source->second[1].index) + "].id",
                    "Authoritative catalogue contains duplicate routing "
                    "companion source id '" + source_id + "'");
            }
            const auto& source_entry = source->second.front();
            const auto source_path =
                "catalog.presets[" +
                std::to_string(source_entry.index) + "]";
            companion.ip_cidrs =
                parse_subnets(*source_entry.preset, source_path);
            if (companion.ip_cidrs.empty()) {
                fail(
                    CatalogSetupErrorCode::malformed_preset,
                    path + ".sourcePresetId",
                    "Catalogue routing companion source preset '" +
                        source_id + "' has no inline CIDRs");
            }
        }

        result.push_back(std::move(companion));
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
    const auto catalog_entries =
        index_catalog_presets(presets);
    const auto cover_graph =
        parse_cover_graph(catalog_entries);

    std::set<std::string> suppressed_selections;
    for (const auto& selection : intent.selections) {
        for (const auto& candidate : intent.selections) {
            if (selection.preset_id != candidate.preset_id &&
                catalog_transitively_covers(
                    cover_graph,
                    selection.preset_id,
                    candidate.preset_id)) {
                suppressed_selections.insert(candidate.preset_id);
            }
        }
        const auto parent = catalog_entries.find(selection.preset_id);
        if (parent == catalog_entries.end() ||
            parent->second.empty()) {
            continue;
        }
        const auto companions =
            parent->second.front().preset->find("routingCompanions");
        if (companions == parent->second.front().preset->end() ||
            !companions->is_array()) {
            continue;
        }
        for (const auto& companion : *companions) {
            if (!companion.is_object()) {
                continue;
            }
            const auto suppress =
                companion.find("suppressDirectSelection");
            if (suppress == companion.end() ||
                !suppress->is_boolean() ||
                !suppress->get<bool>()) {
                continue;
            }
            const auto source = companion.find("sourcePresetId");
            if (source != companion.end() && source->is_string() &&
                requested.count(source->get<std::string>()) != 0U) {
                suppressed_selections.insert(
                    source->get<std::string>());
            }
        }
    }

    std::vector<ParsedPreset> result;
    result.reserve(intent.selections.size() * 2U);
    for (const auto& selection : intent.selections) {
        const auto& id = selection.preset_id;
        if (suppressed_selections.count(id) != 0U) continue;
        const auto found = catalog_entries.find(id);
        if (found == catalog_entries.end()) {
            fail(
                CatalogSetupErrorCode::preset_not_found,
                "intent.selections",
                "Catalogue preset '" + id +
                    "' is absent from the authoritative snapshot");
        }
        const auto& entry = found->second.front();
        const auto hidden = entry.preset->find("hidden");
        if (hidden != entry.preset->end()) {
            if (!hidden->is_boolean()) {
                fail(
                    CatalogSetupErrorCode::malformed_preset,
                    "catalog.presets[" + std::to_string(entry.index) +
                        "].hidden",
                    "Catalogue preset hidden must be a boolean");
            }
            if (hidden->get<bool>()) {
                fail(
                    CatalogSetupErrorCode::preset_not_found,
                    "intent.selections",
                    "Catalogue preset '" + id +
                        "' is an internal source and cannot be selected");
            }
        }
        auto parsed =
            parse_preset(*entry.preset, id, entry.index);
        if (!parsed.url && parsed.domains.empty() &&
            parsed.ip_cidrs.empty()) {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                "catalog.presets[" + std::to_string(entry.index) +
                    "].engines",
                "Selected catalogue preset has no usable URL, inline domains, "
                "or inline CIDRs");
        }
        if (selection.display_name.has_value()) {
            parsed.name = *selection.display_name;
        }
        auto companions = parse_routing_companions(
            *entry.preset, parsed, entry.index, catalog_entries);
        parsed.reconcile_managed_sources = !companions.empty();
        result.push_back(std::move(parsed));
        result.insert(
            result.end(),
            std::make_move_iterator(companions.begin()),
            std::make_move_iterator(companions.end()));
    }

    // Multiple visible presets may intentionally share one package-managed
    // routing companion. Resolve it once, but reject identity collisions that
    // would otherwise alias different source content to one list.
    std::vector<ParsedPreset> unique_result;
    unique_result.reserve(result.size());
    std::map<std::string, std::size_t> identity_positions;
    for (auto& preset : result) {
        const auto existing =
            identity_positions.find(preset.catalog_identity_id);
        if (existing == identity_positions.end()) {
            identity_positions.emplace(
                preset.catalog_identity_id,
                unique_result.size());
            unique_result.push_back(std::move(preset));
            continue;
        }
        const auto& previous = unique_result[existing->second];
        if (previous.url != preset.url ||
            normalized_values(previous.domains) !=
                normalized_values(preset.domains) ||
            normalized_values(previous.ip_cidrs) !=
                normalized_values(preset.ip_cidrs) ||
            previous.action != preset.action ||
            previous.dns_eligible != preset.dns_eligible) {
            fail(
                CatalogSetupErrorCode::malformed_preset,
                "catalog.presets",
                "Catalogue routing companion identity '" +
                    preset.catalog_identity_id +
                    "' resolves to conflicting content");
        }
    }
    return unique_result;
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

bool route_rule_matches_whole_list(const RouteRule& rule,
                                   const std::string& list_id) {
    if (!route_rule_enabled(rule) || !rule.list.has_value()) {
        return false;
    }
    // Other route conditions are combined with the list condition, so such a
    // rule covers only a subset of the catalogue list and cannot satisfy the
    // one-click setup contract on its own.
    if (rule.dscp.has_value() || rule.src_port.has_value() ||
        rule.dest_port.has_value() || rule.src_addr.has_value() ||
        rule.dest_addr.has_value() || rule.proto.has_value()) {
        return false;
    }
    return std::find(rule.list->begin(), rule.list->end(), list_id) !=
           rule.list->end();
}

bool route_policy_covers_list(const Config& config,
                              const std::string& list_id,
                              const std::string& outbound) {
    const auto rules =
        config.route.value_or(RouteConfig{}).rules.value_or(
            std::vector<RouteRule>{});
    for (const auto& rule : rules) {
        if (!route_rule_matches_whole_list(rule, list_id)) continue;
        // Route rules are evaluated top to bottom. A later matching rule does
        // not provide coverage when an earlier whole-list rule already sends
        // the same traffic somewhere else (including blackhole).
        return rule.outbound == outbound;
    }
    return false;
}

bool dns_policy_covers_list(const Config& config,
                            const std::string& list_id,
                            const std::string& server) {
    const auto rules =
        config.dns.value_or(DnsConfig{}).rules.value_or(
            std::vector<DnsRule>{});
    for (const auto& rule : rules) {
        if (!dns_rule_enabled(rule) ||
            std::find(rule.list.begin(), rule.list.end(), list_id) ==
                rule.list.end()) {
            continue;
        }
        return rule.server == server;
    }
    return false;
}

bool dns_policy_covers_list_on_detour(
    const Config& config,
    const std::string& list_id,
    const std::string& detour) {
    const auto rules =
        config.dns.value_or(DnsConfig{}).rules.value_or(
            std::vector<DnsRule>{});
    for (const auto& rule : rules) {
        if (!dns_rule_enabled(rule) ||
            std::find(rule.list.begin(), rule.list.end(), list_id) ==
                rule.list.end()) {
            continue;
        }
        const auto* server = find_dns_server(config, rule.server);
        return server != nullptr && server->detour.has_value() &&
               *server->detour == detour;
    }
    return false;
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
    Config& config,
    const std::optional<std::string>& route_outbound,
    const std::vector<std::string>& dns_eligible_list_ids,
    CatalogSetupSummary& summary,
    std::vector<CatalogSetupWarning>& warnings) {
    if (intent.dns_mode == CatalogDnsMode::none) return std::nullopt;
    if (dns_eligible_list_ids.empty()) return std::nullopt;
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
            fail(
                CatalogSetupErrorCode::dns_automatic_unavailable,
                "intent.dns_mode",
                "Automatic DNS requires an outbound route; choose an "
                "outbound or disable automatic DNS");
        }

        // Server vector order is editable in the advanced UI. Select by tag
        // so the same valid config always produces the same quick-setup plan.
        const auto existing_servers =
            config.dns.value_or(DnsConfig{}).servers.value_or(
                std::vector<DnsServer>{});
        const DnsServer* selected = nullptr;
        std::size_t selected_coverage = 0U;
        for (const auto& server : existing_servers) {
            if (server.detour != route_outbound) continue;
            const auto coverage = static_cast<std::size_t>(std::count_if(
                dns_eligible_list_ids.begin(),
                dns_eligible_list_ids.end(),
                [&](const std::string& list_id) {
                    return dns_policy_covers_list(
                        config, list_id, server.tag);
                }));
            if (selected == nullptr ||
                coverage > selected_coverage ||
                (coverage == selected_coverage &&
                 server.tag < selected->tag)) {
                selected = &server;
                selected_coverage = coverage;
            }
        }
        if (selected != nullptr) {
            summary.dns_server = CatalogDnsServerPlanSummary{
                selected->tag,
                selected->display_name.value_or(selected->tag),
                selected->address.value_or(""),
                *route_outbound,
                false,
            };
            return selected->tag;
        }

        auto dns = config.dns.value_or(DnsConfig{});
        if (!dns.system_resolver.has_value()) {
            api::SystemResolver resolver;
            resolver.address = "127.0.0.1";
            dns.system_resolver = std::move(resolver);
        }
        auto servers =
            dns.servers.value_or(std::vector<DnsServer>{});
        std::set<std::pair<std::string, std::uint16_t>>
            occupied_endpoints;
        std::set<std::string> occupied;
        for (const auto& server : servers) {
            occupied.insert(server.tag);
            if (server.type.value_or(api::DnsServerType::STATIC) !=
                    api::DnsServerType::STATIC ||
                !server.address.has_value()) {
                continue;
            }
            try {
                const auto parsed =
                    parse_dns_address_str(*server.address);
                occupied_endpoints.emplace(parsed.ip, parsed.port);
            } catch (const DnsError&) {
                // The authoritative validator/runtime owns malformed-address
                // reporting. An invalid endpoint cannot reserve a valid
                // automatic endpoint.
            }
        }

        const AutomaticDnsEndpoint* endpoint = nullptr;
        for (const auto& candidate : kAutomaticDnsEndpoints) {
            const auto parsed =
                parse_dns_address_str(candidate.address);
            if (occupied_endpoints.count(
                    {parsed.ip, parsed.port}) == 0U) {
                endpoint = &candidate;
                break;
            }
        }
        if (endpoint == nullptr) {
            fail(
                CatalogSetupErrorCode::dns_automatic_unavailable,
                "intent.dns_mode",
                "No unused built-in DNS endpoint is available for outbound '" +
                    *route_outbound + "'");
        }

        DnsServer created;
        created.tag = unique_technical_id(
            std::string(endpoint->technical_name) + "_" +
                *route_outbound,
            "dns",
            occupied);
        const auto* outbound = find_outbound(config, *route_outbound);
        const auto outbound_name =
            outbound == nullptr
                ? *route_outbound
                : outbound->display_name.value_or(*route_outbound);
        auto generated_name =
            std::string(endpoint->display_name) + " · " + outbound_name;
        if (!display_name::is_valid(generated_name)) {
            generated_name =
                std::string(endpoint->display_name) + " · " +
                *route_outbound;
        }
        created.display_name = std::move(generated_name);
        created.address = endpoint->address;
        created.detour = *route_outbound;
        created.type = api::DnsServerType::STATIC;
        servers.push_back(created);
        dns.servers = std::move(servers);
        config.dns = std::move(dns);
        summary.dns_server = CatalogDnsServerPlanSummary{
            created.tag,
            *created.display_name,
            *created.address,
            *created.detour,
            true,
        };
        return created.tag;
    }

    const auto& tag = *intent.dns_server_tag;
    const auto* server = find_dns_server(config, tag);
    if (server == nullptr) {
        fail(
            CatalogSetupErrorCode::dns_server_not_found,
            "intent.dns_server_tag",
            "DNS server '" + tag + "' does not exist");
    }
    summary.dns_server = CatalogDnsServerPlanSummary{
        server->tag,
        server->display_name.value_or(server->tag),
        server->address.value_or(""),
        server->detour.value_or(""),
        false,
    };
    if (route_outbound.has_value()) {
        if (!server->detour.has_value()) {
            fail(
                CatalogSetupErrorCode::dns_detour_mismatch,
                "intent.dns_server_tag",
                "DNS server '" + tag +
                    "' has no detour while the route uses outbound '" +
                    *route_outbound + "'");
        } else if (*server->detour != *route_outbound) {
            fail(
                CatalogSetupErrorCode::dns_detour_mismatch,
                "intent.dns_server_tag",
                "DNS server '" + tag + "' uses detour '" +
                    *server->detour + "' instead of route outbound '" +
                    *route_outbound + "'");
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

std::string catalog_preset_identity(
    const nlohmann::json& catalog_snapshot,
    const std::string& preset_id) {
    return catalog_preset_identity_for_source(
        catalog_source_identity(catalog_snapshot), preset_id);
}

CatalogSetupPlan plan_catalog_setup(
    const CatalogSetupIntent& intent,
    const nlohmann::json& catalog_snapshot,
    const Config& active_config) {
    // The planner never repairs or normalizes an invalid active snapshot.
    // Existing validation remains the single source of truth.
    validate_config(active_config);
    validate_intent_shape(intent);
    const auto presets = select_presets(intent, catalog_snapshot);

    // Each action needs a different destination - an operator-chosen outbound,
    // a blackhole, the main table - and one plan emits one route rule. Two
    // actions in one selection have no single answer, so the mix is refused
    // instead of resolved by precedence nobody asked for.
    const auto action_name = [](CatalogAction action) -> const char* {
        switch (action) {
            case CatalogAction::reject: return "reject";
            case CatalogAction::direct: return "direct";
            case CatalogAction::tunnel: break;
        }
        return "tunnel";
    };
    std::set<CatalogAction> selected_actions;
    for (const auto& preset : presets) selected_actions.insert(preset.action);
    if (selected_actions.size() > 1U) {
        std::string names;
        for (const auto action : selected_actions) {
            if (!names.empty()) names += ", ";
            names += action_name(action);
        }
        fail(
            CatalogSetupErrorCode::mixed_catalog_actions,
            "intent.selections",
            "Catalogue presets with different actions (" + names +
                ") must be planned separately");
    }

    const auto selected_action = selected_actions.empty()
                                     ? CatalogAction::tunnel
                                     : *selected_actions.begin();
    // A `reject` or `direct` preset names its own destination, so a mode that
    // would send it anywhere else is a contradiction. A `tunnel` preset names
    // none, and blocking or installing one without a route stays the
    // operator's call - the same latitude these presets have always had.
    if (selected_action == CatalogAction::reject &&
        intent.mode != CatalogSetupMode::block) {
        fail(
            CatalogSetupErrorCode::incompatible_intent,
            "intent.mode",
            "A reject catalogue preset must use block mode");
    }
    if (selected_action == CatalogAction::direct &&
        intent.mode != CatalogSetupMode::direct) {
        fail(
            CatalogSetupErrorCode::incompatible_intent,
            "intent.mode",
            "A direct catalogue preset must use direct mode");
    }
    if (selected_action != CatalogAction::direct &&
        intent.mode == CatalogSetupMode::direct) {
        fail(
            CatalogSetupErrorCode::incompatible_intent,
            "intent.mode",
            "Direct mode is only for catalogue presets that ask for it");
    }

    Config candidate = active_config;
    CatalogSetupPlan plan;
    plan.summary.mode = intent.mode;
    std::set<std::string> emitted_catalog_warnings;
    for (const auto& preset : presets) {
        if (preset.broad_traffic_scope_warning &&
            emitted_catalog_warnings.insert(preset.id).second) {
            plan.warnings.push_back({
                CatalogSetupWarningCode::broad_traffic_scope,
                "catalog.presets." + preset.id,
                "Catalogue preset '" + preset.name +
                    "' covers a very large share of Internet traffic; all "
                    "matching traffic will use the selected route",
            });
        }
    }

    const auto active_lists =
        active_config.lists.value_or(
            std::map<std::string, ListConfig>{});
    std::vector<ResolvedPreset> resolved;
    resolved.reserve(presets.size());
    std::vector<ParsedPreset> pending_presets;
    pending_presets.reserve(presets.size());
    for (const auto& preset : presets) {
        const auto identity = catalog_preset_identity_for_source(
            catalog_source_identity(catalog_snapshot),
            preset.catalog_identity_id);
        const auto existing = find_installed_preset_list(
            active_lists, preset, identity);
        resolved.push_back({preset, identity, existing});
        if (!existing.has_value()) pending_presets.push_back(preset);
    }

    std::optional<std::string> route_outbound;
    bool create_blackhole_if_needed = false;
    bool create_direct_outbound_if_needed = false;
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
        } else {
            std::set<std::string> occupied;
            for (const auto& outbound : outbounds) {
                occupied.insert(outbound.tag);
            }
            const auto tag =
                unique_technical_id("block", "block", occupied);
            route_outbound = tag;
            create_blackhole_if_needed = true;
        }
    } else if (intent.mode == CatalogSetupMode::direct) {
        // "Direct" is the main routing table, so any outbound already pointed
        // at it is the same destination and is reused rather than duplicated -
        // the same reasoning that makes block reuse an existing blackhole.
        // Only when the router has none does the plan add one, named `wan`
        // after the example configuration this project ships.
        auto outbounds =
            candidate.outbounds.value_or(std::vector<Outbound>{});
        const auto existing = std::find_if(
            outbounds.begin(), outbounds.end(),
            [](const Outbound& outbound) {
                return outbound.type == OutboundType::TABLE &&
                       outbound.table.has_value() &&
                       *outbound.table == kMainRoutingTable;
            });
        if (existing != outbounds.end()) {
            route_outbound = existing->tag;
        } else {
            std::set<std::string> occupied;
            for (const auto& outbound : outbounds) {
                occupied.insert(outbound.tag);
            }
            route_outbound =
                unique_technical_id("wan", "outbound", occupied);
            create_direct_outbound_if_needed = true;
        }
    }

    const bool has_url_backed_list = std::any_of(
        pending_presets.begin(), pending_presets.end(),
        [](const ParsedPreset& preset) { return preset.url.has_value(); });
    const auto source_detour =
        pending_presets.empty()
            ? std::optional<std::string>{}
            : usable_source_detour(
                  intent,
                  active_config,
                  has_url_backed_list,
                  plan.warnings);

    auto lists =
        candidate.lists.value_or(std::map<std::string, ListConfig>{});
    std::set<std::string> occupied_list_ids;
    for (const auto& [id, _] : lists) occupied_list_ids.insert(id);

    std::vector<std::pair<std::string, ParsedPreset>> selected_lists;
    selected_lists.reserve(resolved.size());
    const auto effective_source_detour =
        [&](const ListConfig& list, bool url_backed)
        -> std::optional<std::string> {
        if (!url_backed) return std::nullopt;
        const auto chain = effective_list_refresh_detours(candidate, list);
        return chain.empty()
                   ? std::nullopt
                   : std::optional<std::string>{chain.front()};
    };
    for (const auto& item : resolved) {
        const auto& preset = item.preset;
        if (item.existing_technical_id.has_value()) {
            const auto& active_list =
                active_lists.at(*item.existing_technical_id);
            if (preset.reconcile_managed_sources &&
                (!active_list.catalog_identity.has_value() ||
                 active_list.catalog_identity ==
                     item.catalog_identity)) {
                auto& managed =
                    lists.at(*item.existing_technical_id);
                // Exact legacy source adoption remains supported, but once a
                // parent gains package-owned companions it must be upgraded
                // atomically. Otherwise old inline CIDRs would be routed both
                // by the parent and by its new shared IP companion.
                managed.catalog_identity = item.catalog_identity;
                const bool managed_url_is_unchanged =
                    active_list.url.has_value() ==
                        preset.url.has_value() &&
                    (!active_list.url.has_value() ||
                     trim_ascii(*active_list.url) ==
                         trim_ascii(*preset.url));
                if (!active_list.catalog_identity.has_value() ||
                    managed_url_is_unchanged ||
                    is_known_managed_catalog_url_migration(
                        preset, active_list)) {
                    managed.url = preset.url;
                }
                managed.domains =
                    preset.domains.empty()
                        ? std::optional<std::vector<std::string>>{}
                        : std::optional<std::vector<std::string>>{
                              preset.domains};
                managed.ip_cidrs =
                    preset.ip_cidrs.empty()
                        ? std::optional<std::vector<std::string>>{}
                        : std::optional<std::vector<std::string>>{
                              preset.ip_cidrs};
            } else if (
                active_list.catalog_identity == item.catalog_identity &&
                is_known_managed_catalog_url_migration(
                    preset, active_list)) {
                // Preserve aliases, refresh routing and every other source
                // field. The allowlist above proves only this URL transition.
                lists.at(*item.existing_technical_id).url = preset.url;
            }
            const auto& list =
                lists.at(*item.existing_technical_id);
            plan.summary.lists.push_back({
                preset.id,
                *item.existing_technical_id,
                list.display_name.value_or(preset.name),
                true,
                preset.url.has_value(),
                !preset.domains.empty(),
                !preset.ip_cidrs.empty(),
                effective_source_detour(list, preset.url.has_value()),
            });
            selected_lists.emplace_back(
                *item.existing_technical_id, preset);
            continue;
        }
        const auto technical_id = unique_technical_id(
            preset.id, "list", occupied_list_ids);
        ListConfig list;
        list.display_name = preset.name;
        list.catalog_identity = item.catalog_identity;
        list.url = preset.url;
        if (!preset.domains.empty()) list.domains = preset.domains;
        if (!preset.ip_cidrs.empty()) list.ip_cidrs = preset.ip_cidrs;
        if (preset.url && source_detour) {
            list.refresh_detour_mode = ListRefreshDetourMode::OVERRIDE;
            list.detour = source_detour;
        }
        const auto summary_source_detour =
            effective_source_detour(list, preset.url.has_value());
        lists.emplace(technical_id, std::move(list));
        selected_lists.emplace_back(technical_id, preset);
        plan.summary.lists.push_back({
            preset.id,
            technical_id,
            preset.name,
            false,
            preset.url.has_value(),
            !preset.domains.empty(),
            !preset.ip_cidrs.empty(),
            summary_source_detour,
        });
    }
    candidate.lists = std::move(lists);

    const auto unique_selected_ids = [&]() {
        std::vector<std::string> result;
        std::set<std::string> seen;
        for (const auto& [list_id, _] : selected_lists) {
            if (seen.insert(list_id).second) result.push_back(list_id);
        }
        return result;
    }();
    const auto missing_route_list_ids = [&]() {
        std::vector<std::string> result;
        if (!route_outbound.has_value()) return result;
        for (const auto& list_id : unique_selected_ids) {
            if (!route_policy_covers_list(
                    active_config, list_id, *route_outbound)) {
                result.push_back(list_id);
            }
        }
        return result;
    }();

    std::vector<std::string> dns_eligible_list_ids;
    {
        std::set<std::string> seen;
        for (const auto& [list_id, preset] : selected_lists) {
            if (preset.dns_eligible && seen.insert(list_id).second) {
                dns_eligible_list_ids.push_back(list_id);
            }
        }
    }
    const auto dns_server = select_dns_server(
        intent,
        candidate,
        route_outbound,
        dns_eligible_list_ids,
        plan.summary,
        plan.warnings);
    const auto missing_dns_list_ids = [&]() {
        std::vector<std::string> result;
        if (!dns_server.has_value()) return result;
        std::set<std::string> seen;
        for (const auto& [list_id, preset] : selected_lists) {
            if (!preset.dns_eligible ||
                !seen.insert(list_id).second) {
                continue;
            }
            const bool covered =
                intent.dns_mode == CatalogDnsMode::automatic &&
                        route_outbound.has_value()
                    ? dns_policy_covers_list_on_detour(
                          active_config, list_id, *route_outbound)
                    : dns_policy_covers_list(
                          active_config, list_id, *dns_server);
            if (!covered) {
                result.push_back(list_id);
            }
        }
        return result;
    }();

    const auto preset_for_list_id =
        [&](const std::string& list_id) -> const ParsedPreset& {
            const auto found = std::find_if(
                selected_lists.begin(),
                selected_lists.end(),
                [&](const auto& selected) {
                    return selected.first == list_id;
                });
            if (found == selected_lists.end()) {
                fail(
                    CatalogSetupErrorCode::malformed_preset,
                    "intent.selections",
                    "Resolved catalogue list has no source preset");
            }
            return found->second;
        };
    const auto rule_seed =
        [](const std::vector<std::string>& list_ids) {
        std::ostringstream value;
        value << "catalog";
        for (const auto& id : list_ids) value << "_" << id;
        return value.str();
    };

    if (!missing_route_list_ids.empty() &&
        intent.mode == CatalogSetupMode::block) {
        if (create_blackhole_if_needed) {
            auto outbounds =
                candidate.outbounds.value_or(std::vector<Outbound>{});
            Outbound blackhole;
            blackhole.tag = *route_outbound;
            blackhole.type = OutboundType::BLACKHOLE;
            outbounds.push_back(std::move(blackhole));
            candidate.outbounds = std::move(outbounds);
        }
        plan.summary.blackhole = CatalogBlackholePlanSummary{
            *route_outbound, create_blackhole_if_needed};
    }

    if (!missing_route_list_ids.empty() &&
        intent.mode == CatalogSetupMode::direct) {
        if (create_direct_outbound_if_needed) {
            auto outbounds =
                candidate.outbounds.value_or(std::vector<Outbound>{});
            Outbound wan;
            wan.tag = *route_outbound;
            wan.type = OutboundType::TABLE;
            wan.table = kMainRoutingTable;
            outbounds.push_back(std::move(wan));
            candidate.outbounds = std::move(outbounds);
        }
        plan.summary.direct_outbound = CatalogDirectOutboundPlanSummary{
            *route_outbound, create_direct_outbound_if_needed};
    }

    if (route_outbound.has_value() &&
        !missing_route_list_ids.empty()) {
        auto route = candidate.route.value_or(RouteConfig{});
        auto rules = route.rules.value_or(std::vector<RouteRule>{});
        auto ids = occupied_route_ids(active_config);
        std::size_t base_insertion_index = rules.size();
        // Both of these go to the top, and for the same reason: they are
        // exceptions. A blocked domain must not be rescued by a broader tunnel
        // rule below it, and a domain kept direct must not be swept into a
        // tunnel by one either - "always direct" that loses to the next rule
        // is not always.
        if (intent.mode == CatalogSetupMode::block ||
            intent.mode == CatalogSetupMode::direct) {
            base_insertion_index = 0U;
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
                    base_insertion_index = index;
                    break;
                }
            }
        }

        std::vector<ParsedPreset> route_presets;
        route_presets.reserve(missing_route_list_ids.size());
        for (const auto& list_id : missing_route_list_ids) {
            route_presets.push_back(preset_for_list_id(list_id));
        }
        const auto route_display_name = generated_display_name(
            intent.route_display_name, route_presets);

        RouteRule rule;
        rule.id = unique_technical_id(
            rule_seed(missing_route_list_ids), "rule", ids);
        rule.display_name = route_display_name;
        rule.enabled = true;
        rule.list = missing_route_list_ids;
        rule.outbound = *route_outbound;

        rules.insert(
            rules.begin() +
                static_cast<std::ptrdiff_t>(base_insertion_index),
            rule);
        plan.summary.route_rules.push_back(
            CatalogRouteRulePlanSummary{
                *rule.id,
                route_display_name,
                *route_outbound,
                base_insertion_index,
                intent.mode == CatalogSetupMode::block,
            });
        route.rules = std::move(rules);
        candidate.route = std::move(route);
        plan.summary.route_rule =
            plan.summary.route_rules.front();
    }

    if (dns_server.has_value() && !missing_dns_list_ids.empty()) {
        auto dns = candidate.dns.value_or(DnsConfig{});
        auto rules = dns.rules.value_or(std::vector<DnsRule>{});
        auto ids = occupied_dns_rule_ids(active_config);
        std::vector<ParsedPreset> dns_presets;
        dns_presets.reserve(missing_dns_list_ids.size());
        for (const auto& list_id : missing_dns_list_ids) {
            dns_presets.push_back(preset_for_list_id(list_id));
        }
        const auto dns_display_name = generated_display_name(
            intent.dns_display_name, dns_presets);

        DnsRule rule;
        rule.id = unique_technical_id(
            rule_seed(missing_dns_list_ids), "dns_rule", ids);
        rule.display_name = dns_display_name;
        rule.enabled = true;
        rule.list = missing_dns_list_ids;
        rule.server = *dns_server;
        rule.allow_domain_rebinding = false;
        const auto insertion_index = rules.size();
        rules.push_back(rule);
        plan.summary.dns_rules.push_back(
            CatalogDnsRulePlanSummary{
                *rule.id,
                dns_display_name,
                *dns_server,
                insertion_index,
            });
        dns.rules = std::move(rules);
        candidate.dns = std::move(dns);
        plan.summary.dns_rule =
            plan.summary.dns_rules.front();
    }

    // This is deliberately the last planner step: the same authoritative
    // validator used by manual edits must approve the full candidate.
    validate_config(candidate);
    plan.candidate_revision =
        Sha256::hex(nlohmann::json(candidate).dump());
    plan.candidate = std::move(candidate);
    return plan;
}

void validate_recommended_list_setup(
    const Config& candidate,
    const std::string& list_id) {
    validate_config(candidate);

    const auto normalized_list_id = trim_ascii(list_id);
    if (normalized_list_id.empty() ||
        !candidate.lists.has_value() ||
        candidate.lists->find(normalized_list_id) ==
            candidate.lists->end()) {
        throw std::invalid_argument(
            "The beginner setup list does not exist in the candidate");
    }

    const auto route_rules =
        candidate.route.value_or(RouteConfig{}).rules.value_or(
            std::vector<RouteRule>{});
    std::vector<const RouteRule*> route_matches;
    for (const auto& rule : route_rules) {
        const auto& lists = route_rule_lists(rule);
        if (route_rule_enabled(rule) &&
            std::find(
                lists.begin(), lists.end(), normalized_list_id) !=
                lists.end()) {
            route_matches.push_back(&rule);
        }
    }
    const auto dedicated_route =
        route_matches.size() == 1U
            ? route_matches.front()
            : nullptr;
    if (dedicated_route == nullptr ||
        route_rule_lists(*dedicated_route) !=
            std::vector<std::string>{normalized_list_id} ||
        dedicated_route->dscp.has_value() ||
        dedicated_route->proto.has_value() ||
        dedicated_route->src_port.has_value() ||
        dedicated_route->dest_port.has_value() ||
        dedicated_route->src_addr.has_value() ||
        dedicated_route->dest_addr.has_value()) {
        throw std::invalid_argument(
            "Beginner setup requires one dedicated route rule for the list");
    }

    const auto* outbound =
        find_outbound(candidate, dedicated_route->outbound);
    if (outbound == nullptr || !is_routable(outbound->type)) {
        throw std::invalid_argument(
            "Beginner setup route must use a routable outbound");
    }

    const auto dns_rules =
        candidate.dns.value_or(DnsConfig{}).rules.value_or(
            std::vector<DnsRule>{});
    std::vector<const DnsRule*> dns_matches;
    for (const auto& rule : dns_rules) {
        if (dns_rule_enabled(rule) &&
            std::find(
                rule.list.begin(),
                rule.list.end(),
                normalized_list_id) != rule.list.end()) {
            dns_matches.push_back(&rule);
        }
    }
    if (dns_matches.size() != 1U ||
        dns_matches.front()->list !=
            std::vector<std::string>{normalized_list_id}) {
        throw std::invalid_argument(
            "Beginner setup requires one dedicated DNS rule for the list");
    }

    const auto* dns_server =
        find_dns_server(candidate, dns_matches.front()->server);
    if (dns_server == nullptr) {
        throw std::invalid_argument(
            "Beginner setup DNS server does not exist");
    }
    if (!dns_server->detour.has_value() ||
        *dns_server->detour != outbound->tag) {
        throw std::invalid_argument(
            "Beginner setup DNS server must use the same outbound as the "
            "route; create or select a compatible DNS server");
    }
}

} // namespace keen_pbr3::setup
