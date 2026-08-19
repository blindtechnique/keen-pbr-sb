#ifdef WITH_API

#include "handler_test_routing.hpp"
#include "../cmd/test_routing.hpp"
#include "../nfqws/list_match.hpp"
#include "generated/api_types.hpp"

#include <fstream>
#include <nlohmann/json.hpp>
#include <sstream>

namespace keen_pbr3 {

namespace {

api::Evaluation to_api_evaluation(RoutingMatchEvaluation evaluation) {
    switch (evaluation) {
        case RoutingMatchEvaluation::Matched:
            return api::Evaluation::MATCHED;
        case RoutingMatchEvaluation::NotMatched:
            return api::Evaluation::NOT_MATCHED;
        case RoutingMatchEvaluation::InsufficientContext:
            return api::Evaluation::INSUFFICIENT_CONTEXT;
    }
    return api::Evaluation::INSUFFICIENT_CONTEXT;
}

std::vector<api::RoutingTestUnknownConditionElement>
to_api_unknown_conditions(const std::vector<std::string>& conditions) {
    std::vector<api::RoutingTestUnknownConditionElement> converted;
    converted.reserve(conditions.size());
    for (const auto& condition : conditions) {
        nlohmann::json value = condition;
        converted.push_back(
            value.get<api::RoutingTestUnknownConditionElement>());
    }
    return converted;
}

constexpr const char* kNfqwsConfigPath = "/opt/etc/nfqws2/nfqws2.conf";

std::string read_text_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return {};
    std::ostringstream out;
    out << file.rdbuf();
    return out.str();
}

api::RoutingTestNfqwsMatchRole to_api_role(nfqws::ListRole role) {
    switch (role) {
        case nfqws::ListRole::hostlist:
            return api::RoutingTestNfqwsMatchRole::HOSTLIST;
        case nfqws::ListRole::hostlist_auto:
            return api::RoutingTestNfqwsMatchRole::HOSTLIST_AUTO;
        case nfqws::ListRole::hostlist_exclude:
            return api::RoutingTestNfqwsMatchRole::HOSTLIST_EXCLUDE;
        case nfqws::ListRole::ipset:
            return api::RoutingTestNfqwsMatchRole::IPSET;
        case nfqws::ListRole::ipset_exclude:
            return api::RoutingTestNfqwsMatchRole::IPSET_EXCLUDE;
    }
    return api::RoutingTestNfqwsMatchRole::HOSTLIST;
}

// Which nfqws lists cover this target, taken from the lists nfqws2.conf
// actually names rather than from a fixed pair of filenames: an operator may
// add lists of their own, and address lists are matched by prefix while
// hostlists are matched by domain.
//
// Exclude lists are reported too, and reported as themselves. They are not
// coverage - they are the reason coverage does not apply - and folding the two
// into one answer would invert the meaning for every domain on them.
api::RoutingTestNfqws nfqws_coverage(const TestRoutingResult& result) {
    api::RoutingTestNfqws coverage;
    const auto config = read_text_file(kNfqwsConfigPath);
    coverage.available = !config.empty();
    if (config.empty()) return coverage;

    // The target itself when it is an address, plus everything it resolved to:
    // a domain is handled by nfqws through its hostlists, but its addresses can
    // still sit in an ipset.
    std::vector<std::string> addresses;
    if (!result.is_domain) addresses.push_back(result.target);
    addresses.insert(addresses.end(),
                     result.resolved_ips.begin(),
                     result.resolved_ips.end());

    for (const auto& reference : nfqws::parse_list_references(config)) {
        const auto contents = read_text_file(reference.path);
        if (contents.empty()) continue;
        const auto entries = nfqws::parse_hostlist(contents);

        const auto append = [&](const nfqws::HostlistMatch& hit,
                                const std::string& matched) {
            api::RoutingTestNfqwsMatchElement element;
            element.list = reference.path;
            element.role = to_api_role(reference.role);
            element.includes = nfqws::role_includes(reference.role);
            element.entry = hit.entry;
            element.matched = matched;
            element.exact = hit.exact;
            coverage.matches.push_back(std::move(element));
        };

        if (nfqws::role_is_hostlist(reference.role)) {
            if (!result.is_domain) continue;
            if (const auto hit = nfqws::match_hostlist(entries, result.target)) {
                append(*hit, result.target);
            }
            continue;
        }
        for (const auto& address : addresses) {
            if (const auto hit = nfqws::match_ipset(entries, address)) {
                append(*hit, address);
                break;
            }
        }
    }
    return coverage;
}

api::ListMatch to_api_list_match(const ListMatchInfo& match) {
    api::ListMatch converted;
    converted.list = match.list_name;
    converted.via = match.via;
    return converted;
}

} // namespace

void register_test_routing_handler(ApiServer& server, ApiContext& ctx) {
    server.post("/api/routing/test", [&ctx](const std::string& body) -> std::string {
        nlohmann::json j;
        try {
            j = nlohmann::json::parse(body);
        } catch (const nlohmann::json::exception&) {
            nlohmann::json payload = {{"error", "Invalid request body"}};
            throw ApiError("Invalid request body", 400, payload.dump());
        }

        api::RoutingTestRequest req;
        try {
            api::from_json(j, req);
        } catch (const std::exception&) {
            nlohmann::json payload = {{"error", "Invalid request body"}};
            throw ApiError("Invalid request body", 400, payload.dump());
        }

        if (req.target.empty()) {
            nlohmann::json payload = {{"error", "Field 'target' must not be empty"}};
            throw ApiError("Field 'target' must not be empty", 400, payload.dump());
        }

        auto result = ctx.compute_test_routing(req.target);

        api::RoutingTestResponse resp;
        resp.target       = result.target;
        resp.is_domain    = result.is_domain;
        resp.config_scope = api::ConfigScope::ACTIVE;
        resp.unapplied_draft = result.unapplied_draft;
        resp.dns_error    = result.dns_error;
        resp.no_matching_rule = result.no_matching_rule;
        resp.resolved_ips = result.resolved_ips;
        resp.warnings     = result.warnings;
        // A separate question with a separate answer: nfqws can be handling a
        // target the routing rules never touch, and the reverse.
        resp.nfqws        = nfqws_coverage(result);

        for (const auto& entry : result.entries) {
            api::RoutingTestEntry e;
            e.ip                = entry.ip;
            e.expected_outbound = entry.expected_outbound;
            e.actual_outbound   = entry.actual_outbound;
            e.ok                = entry.ok;
            e.evaluation = to_api_evaluation(entry.evaluation);
            e.unknown_conditions =
                to_api_unknown_conditions(entry.unknown_conditions);
            if (entry.list_match) {
                e.list_match = to_api_list_match(*entry.list_match);
            }
            resp.results.push_back(std::move(e));
        }

        for (const auto& rule_diag : result.rule_diagnostics) {
            api::RoutingTestRuleDiagnosticElement rd;
            rd.rule_index = rule_diag.rule_index;
            rd.rule = rule_diag.rule;
            rd.outbound = rule_diag.outbound;
            rd.interface_name = rule_diag.interface_name;
            rd.target_in_lists = rule_diag.target_in_lists;
            if (rule_diag.target_match) {
                api::ListMatch lm;
                lm.list = rule_diag.target_match->list_name;
                lm.via  = rule_diag.target_match->via;
                rd.target_match = std::move(lm);
            }
            for (const auto& ip_diag : rule_diag.ip_rows) {
                api::RoutingTestRuleIpDiagnosticElement ipd;
                ipd.ip = ip_diag.ip;
                ipd.in_ipset = ip_diag.in_ipset;
                ipd.in_lists = ip_diag.in_lists;
                ipd.evaluation =
                    to_api_evaluation(ip_diag.evaluation);
                ipd.unknown_conditions =
                    to_api_unknown_conditions(
                        ip_diag.unknown_conditions);
                if (ip_diag.list_match) {
                    ipd.list_match =
                        to_api_list_match(*ip_diag.list_match);
                }
                rd.ip_rows.push_back(std::move(ipd));
            }
            resp.rule_diagnostics.push_back(std::move(rd));
        }

        nlohmann::json out;
        api::to_json(out, resp);
        return out.dump();
    });
}

} // namespace keen_pbr3

#endif // WITH_API
