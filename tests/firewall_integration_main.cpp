#include "../src/cache/cache_manager.hpp"
#include "../src/config/config.hpp"
#include "../src/config/routing_state.hpp"
#include "../src/firewall/firewall.hpp"
#include "../src/firewall/firewall_runtime.hpp"
#include "../src/health/routing_health_checker.hpp"
#include "../src/health/url_tester.hpp"
#include "../src/http/curl_runtime.hpp"
#include "../src/log/logger.hpp"
#include "../src/routing/firewall_state.hpp"
#include "../src/routing/netlink.hpp"
#include "../src/routing/policy_rule.hpp"
#include "../src/routing/route_table.hpp"
#include "../src/util/format_compat.hpp"
#include "../src/util/safe_exec.hpp"

#include <algorithm>
#include <array>
#include <functional>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace keen_pbr3 {

namespace {

struct CliOptions {
    std::string config_path;
    std::string backend{"iptables"};
    std::string mode{"destructive"};
    std::string log_level{"info"};
    bool run_urltest_probes{false};
    bool repeat_preserve_apply{false};
    bool drop_iptables_dispatchers_before_repeat{false};
    bool use_raw_prerouting{false};
    bool exercise_iptables_convergence{false};
};

struct RuntimeCleanup {
    RouteTable& route_table;
    PolicyRuleManager& policy_rules;
    Firewall& firewall;

    ~RuntimeCleanup() {
        try {
            firewall.cleanup();
        } catch (...) {
        }
        try {
            policy_rules.clear();
        } catch (...) {
        }
        try {
            route_table.clear();
        } catch (...) {
        }
    }
};

void verify_metric_scoped_route_delete(NetlinkManager& netlink) {
    constexpr uint32_t kTable = 249;

    RouteSpec primary;
    primary.destination = "default";
    primary.table = kTable;
    primary.interface = "lo";
    primary.family = AF_INET;

    RouteSpec fallback = primary;
    fallback.metric = 1;

    auto cleanup = [&]() {
        try {
            netlink.delete_route(primary);
        } catch (...) {
        }
        try {
            netlink.delete_route(fallback);
        } catch (...) {
        }
    };

    try {
        netlink.add_route(primary);
        netlink.add_route(fallback);
        netlink.delete_route(primary);

        const auto routes = netlink.dump_routes_in_table(kTable, AF_INET);
        const bool primary_present = std::any_of(
            routes.begin(), routes.end(), [](const DumpedRoute& route) {
                return route.destination == "default" &&
                       route.interface == std::optional<std::string>{"lo"} &&
                       route.metric == 0;
            });
        const bool fallback_present = std::any_of(
            routes.begin(), routes.end(), [](const DumpedRoute& route) {
                return route.destination == "default" &&
                       route.interface == std::optional<std::string>{"lo"} &&
                       route.metric == 1;
            });
        if (primary_present || !fallback_present) {
            throw std::runtime_error(
                "Deleting a metric-zero route removed or damaged its weighted fallback");
        }
    } catch (...) {
        cleanup();
        throw;
    }

    cleanup();
}

void verify_route_reconcile_restores_vanished_route(NetlinkManager& netlink) {
    constexpr uint32_t kTable = 248;

    RouteSpec selected;
    selected.destination = "default";
    selected.table = kTable;
    selected.interface = "lo";
    selected.family = AF_INET;

    RouteSpec fallback = selected;
    fallback.metric = 1;

    RouteTable routes(netlink);
    routes.add(selected);
    routes.add(fallback);

    // Simulate a firmware interface refresh removing one of the routes behind
    // the daemon's back while its owned-state inventory still contains it.
    netlink.delete_route(fallback);
    routes.add_missing({selected, fallback});

    const auto live = netlink.dump_routes_in_table(kTable, AF_INET);
    const bool restored = std::any_of(
        live.begin(), live.end(), [&](const DumpedRoute& route) {
            return route_table_detail::route_matches_live(fallback, route);
        });
    if (!restored) {
        throw std::runtime_error(
            "Route reconciler did not restore a vanished weighted fallback");
    }
}

std::string read_file(const std::string& path) {
    std::ifstream input(path);
    if (!input.is_open()) {
        throw std::runtime_error("Cannot open config file: " + path);
    }

    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

void print_usage(const char* argv0) {
    std::cerr
        << "Usage: " << argv0 << " --config <path> --backend <iptables|nftables> "
        << "--mode <destructive|preserve-sets> [--run-urltest-probes] "
        << "[--repeat-preserve-apply] "
        << "[--drop-iptables-dispatchers-before-repeat] "
        << "[--exercise-iptables-convergence] "
        << "[--use-raw-prerouting] [--log-level <lvl>]\n";
}

CliOptions parse_args(int argc, char* argv[]) {
    CliOptions options;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--config") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--config requires a value");
            }
            options.config_path = argv[++i];
        } else if (arg == "--backend") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--backend requires a value");
            }
            options.backend = argv[++i];
        } else if (arg == "--mode") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--mode requires a value");
            }
            options.mode = argv[++i];
        } else if (arg == "--log-level") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--log-level requires a value");
            }
            options.log_level = argv[++i];
        } else if (arg == "--run-urltest-probes") {
            options.run_urltest_probes = true;
        } else if (arg == "--repeat-preserve-apply") {
            options.repeat_preserve_apply = true;
        } else if (arg == "--drop-iptables-dispatchers-before-repeat") {
            options.drop_iptables_dispatchers_before_repeat = true;
        } else if (arg == "--use-raw-prerouting") {
            options.use_raw_prerouting = true;
        } else if (arg == "--exercise-iptables-convergence") {
            options.exercise_iptables_convergence = true;
        } else if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            std::exit(0);
        } else {
            throw std::runtime_error("Unknown option: " + arg);
        }
    }

    if (options.config_path.empty()) {
        throw std::runtime_error("--config is required");
    }

    return options;
}

FirewallBackendPreference parse_backend_preference(const std::string& value) {
    if (value == "iptables") {
        return FirewallBackendPreference::iptables;
    }
    if (value == "nftables") {
        return FirewallBackendPreference::nftables;
    }
    throw std::runtime_error("Unsupported backend: " + value);
}

FirewallApplyMode parse_apply_mode(const std::string& value) {
    if (value == "destructive") {
        return FirewallApplyMode::Destructive;
    }
    if (value == "preserve-sets") {
        return FirewallApplyMode::PreserveSets;
    }
    throw std::runtime_error("Unsupported mode: " + value);
}

api::DaemonConfigFirewallBackend parse_backend_config_value(const std::string& value) {
    if (value == "iptables") {
        return api::DaemonConfigFirewallBackend::IPTABLES;
    }
    if (value == "nftables") {
        return api::DaemonConfigFirewallBackend::NFTABLES;
    }
    throw std::runtime_error("Unsupported backend: " + value);
}

std::vector<const Outbound*> find_urltest_children(const std::vector<Outbound>& outbounds,
                                                   const Outbound& urltest) {
    struct GroupRef {
        size_t index;
        uint32_t weight;
    };

    std::vector<GroupRef> groups;
    const auto& outbound_groups = urltest.outbound_groups.value_or(std::vector<OutboundGroup>{});
    groups.reserve(outbound_groups.size());
    for (size_t i = 0; i < outbound_groups.size(); ++i) {
        groups.push_back(GroupRef{
            .index = i,
            .weight = static_cast<uint32_t>(outbound_groups[i].weight.value_or(1)),
        });
    }

    std::stable_sort(groups.begin(), groups.end(), [](const GroupRef& lhs, const GroupRef& rhs) {
        return lhs.weight < rhs.weight;
    });

    std::vector<const Outbound*> ordered_children;
    for (const auto& group_ref : groups) {
        for (const auto& child_tag : outbound_groups[group_ref.index].outbounds) {
            for (const auto& outbound : outbounds) {
                if (outbound.tag == child_tag) {
                    ordered_children.push_back(&outbound);
                    break;
                }
            }
        }
    }
    return ordered_children;
}

std::optional<std::string> select_urltest_child(const Outbound& urltest,
                                                const std::vector<const Outbound*>& ordered_children,
                                                const OutboundMarkMap& marks,
                                                URLTester& tester) {
    struct CandidateResult {
        std::string child_tag;
        uint32_t latency_ms{0};
        uint32_t group_weight{0};
    };

    std::vector<CandidateResult> successful_results;
    const auto& groups = urltest.outbound_groups.value_or(std::vector<OutboundGroup>{});
    const uint32_t timeout_ms = static_cast<uint32_t>(
        urltest.probe_timeout_ms.value_or(kDefaultUrltestProbeTimeoutMs));
    const RetryConfig retry = urltest.retry.value_or(RetryConfig{});

    for (const auto& group : groups) {
        for (const auto& child_tag : group.outbounds) {
            auto mark_it = marks.find(child_tag);
            if (mark_it == marks.end()) {
                continue;
            }

            URLTestResult result =
                tester.test(urltest.url.value_or(""), mark_it->second, timeout_ms, retry);
            if (result.success) {
                successful_results.push_back(CandidateResult{
                    .child_tag = child_tag,
                    .latency_ms = result.latency_ms,
                    .group_weight = static_cast<uint32_t>(group.weight.value_or(1)),
                });
            }
        }
    }

    if (successful_results.empty()) {
        return std::nullopt;
    }

    const uint32_t best_weight = std::min_element(
        successful_results.begin(),
        successful_results.end(),
        [](const CandidateResult& lhs, const CandidateResult& rhs) {
            return lhs.group_weight < rhs.group_weight;
        })->group_weight;

    if (urltest.selection_mode.value_or(UrltestSelectionMode::LATENCY) ==
        UrltestSelectionMode::PRIORITY) {
        for (const auto* child : ordered_children) {
            const auto result_it = std::find_if(
                successful_results.begin(),
                successful_results.end(),
                [best_weight, child](const CandidateResult& result) {
                    return result.group_weight == best_weight &&
                           result.child_tag == child->tag;
                });
            if (result_it != successful_results.end()) {
                return result_it->child_tag;
            }
        }
        return std::nullopt;
    }

    uint32_t min_latency = std::numeric_limits<uint32_t>::max();
    for (const auto& result : successful_results) {
        if (result.group_weight == best_weight) {
            min_latency = std::min(min_latency, result.latency_ms);
        }
    }

    const uint32_t tolerance = static_cast<uint32_t>(urltest.tolerance_ms.value_or(100));
    for (const auto* child : ordered_children) {
        for (const auto& result : successful_results) {
            if (result.group_weight != best_weight || result.child_tag != child->tag) {
                continue;
            }
            if (result.latency_ms <= min_latency + tolerance) {
                return result.child_tag;
            }
        }
    }

    return std::nullopt;
}

std::map<std::string, std::string> probe_urltests(const Config& config,
                                                  const OutboundMarkMap& marks) {
    std::map<std::string, std::string> selections;
    URLTester tester;
    const auto& outbounds = config.outbounds.value_or(std::vector<Outbound>{});

    for (const auto& outbound : outbounds) {
        if (outbound.type != OutboundType::URLTEST) {
            continue;
        }

        const auto ordered_children = find_urltest_children(outbounds, outbound);
        auto selection = select_urltest_child(outbound, ordered_children, marks, tester);
        if (selection.has_value()) {
            selections[outbound.tag] = *selection;
        }
    }

    return selections;
}

bool report_has_failures(const RoutingHealthReport& report) {
    if (!report.error.empty()) {
        return true;
    }
    if (!report.overall_ok) {
        return true;
    }
    if (!report.firewall_chain.chain_present || !report.firewall_chain.prerouting_hook_present) {
        return true;
    }

    for (const auto& check : report.firewall_rules) {
        if (check.status != CheckStatus::ok) {
            return true;
        }
    }
    for (const auto& check : report.route_tables) {
        if (check.status != CheckStatus::ok) {
            return true;
        }
    }
    for (const auto& check : report.policy_rules) {
        if (check.status != CheckStatus::ok) {
            return true;
        }
    }
    return false;
}

void print_command_dump(const std::string& label,
                        const std::vector<std::string>& command) {
    const auto result = safe_exec_capture(command, /*suppress_stderr=*/false, 1024 * 1024);
    std::cerr << "===== " << label << " =====\n";
    std::cerr << "command: " << safe_exec_command_string(command) << "\n";
    std::cerr << "exit_code: " << result.exit_code << "\n";
    if (result.truncated) {
        std::cerr << "output: [truncated]\n";
    }
    if (result.stdout_output.empty()) {
        std::cerr << "(no output)\n";
    } else {
        std::cerr << result.stdout_output;
        if (result.stdout_output.back() != '\n') {
            std::cerr << "\n";
        }
    }
}

void dump_firewall_state(FirewallBackend backend) {
    if (backend == FirewallBackend::iptables) {
        print_command_dump("iptables-save", {"iptables-save", "-t", "mangle"});
        print_command_dump("iptables-save-raw", {"iptables-save", "-t", "raw"});
        print_command_dump("ip6tables-save", {"ip6tables-save", "-t", "mangle"});
        print_command_dump("ipset-list", {"ipset", "list"});
        return;
    }

    print_command_dump("nft-list-ruleset", {"nft", "list", "ruleset"});
}

void dump_routing_state(const RoutingHealthReport& report) {
    print_command_dump("ip-rule-show", {"ip", "rule", "show"});

    std::set<uint32_t> tables;
    for (const auto& check : report.route_tables) {
        if (check.status == CheckStatus::ok) {
            continue;
        }
        tables.insert(check.table_id);
    }

    for (uint32_t table_id : tables) {
        print_command_dump("ip-route-show-table-" + std::to_string(table_id),
                           {"ip", "route", "show", "table", std::to_string(table_id)});
        print_command_dump("ip-6-route-show-table-" + std::to_string(table_id),
                           {"ip", "-6", "route", "show", "table", std::to_string(table_id)});
    }
}

void print_report(const RoutingHealthReport& report) {
    if (!report.error.empty()) {
        std::cerr << "health-check error: " << report.error << "\n";
        return;
    }

    if (!report.firewall_chain.chain_present || !report.firewall_chain.prerouting_hook_present) {
        std::cerr << "firewall chain check failed: chain_present="
                  << (report.firewall_chain.chain_present ? "true" : "false")
                  << " prerouting_hook_present="
                  << (report.firewall_chain.prerouting_hook_present ? "true" : "false");
        if (!report.firewall_chain.detail.empty()) {
            std::cerr << " detail=" << report.firewall_chain.detail;
        }
        std::cerr << "\n";
    }

    for (const auto& check : report.firewall_rules) {
        if (check.status == CheckStatus::ok) {
            continue;
        }
        std::cerr << "firewall rule failed: set=" << check.set_name
                  << " action=" << check.action
                  << " status=" << static_cast<int>(check.status);
        if (!check.detail.empty()) {
            std::cerr << " detail=" << check.detail;
        }
        std::cerr << "\n";
    }

    for (const auto& check : report.route_tables) {
        if (check.status == CheckStatus::ok) {
            continue;
        }
        std::cerr << "route check failed: table=" << check.table_id
                  << " outbound=" << check.outbound_tag;
        if (!check.detail.empty()) {
            std::cerr << " detail=" << check.detail;
        }
        std::cerr << "\n";
    }

    for (const auto& check : report.policy_rules) {
        if (check.status == CheckStatus::ok) {
            continue;
        }
        std::cerr << "policy rule failed: fwmark=" << check.fwmark
                  << " table=" << check.expected_table;
        if (!check.detail.empty()) {
            std::cerr << " detail=" << check.detail;
        }
        std::cerr << "\n";
    }
}

struct IptablesConvergenceTopology {
    explicit IptablesConvergenceTopology(bool raw)
        : raw_prerouting(raw),
          prerouting_table(raw ? "raw" : "mangle"),
          prerouting_dispatcher(raw ? "KeenPbrRaw" : "KeenPbrTable"),
          prerouting_generations(raw
              ? std::array<std::string, 2>{"KeenPbrRaw_A", "KeenPbrRaw_B"}
              : std::array<std::string, 2>{"KeenPbrTable_A", "KeenPbrTable_B"}) {}

    bool raw_prerouting;
    std::string prerouting_table;
    std::string prerouting_dispatcher;
    std::array<std::string, 2> prerouting_generations;
    const std::string output_dispatcher{"KeenPbrOutput"};
    const std::array<std::string, 2> output_generations{
        "KeenPbrOutput_A", "KeenPbrOutput_B"};
    const std::string raw_conntrack_chain{"KeenPbrRawCt"};
    const std::string foreign_chain{"KpbrForeignGuard"};
};

ExecCaptureResult capture_command(const std::vector<std::string>& command) {
    auto result = safe_exec_capture(
        command,
        /*suppress_stderr=*/false,
        /*max_bytes=*/1024U * 1024U,
        /*capture_stderr=*/true);
    if (result.exit_code != 0 || result.truncated || result.timed_out) {
        throw std::runtime_error(
            "Command failed during iptables convergence test: " +
            safe_exec_command_string(command) + "\n" + result.stdout_output);
    }
    return result;
}

void run_command(const std::vector<std::string>& command) {
    (void)capture_command(command);
}

void verify_restart_adopts_and_replaces_generated_default_route(
    NetlinkManager& netlink) {
    constexpr uint32_t kTable = 247;
    const std::string replacement_interface{"kpbr_rt_new"};

    RouteSpec stale_primary;
    stale_primary.destination = "default";
    stale_primary.table = kTable;
    stale_primary.interface = "lo";
    stale_primary.family = AF_INET;

    RouteSpec replacement_primary = stale_primary;
    replacement_primary.interface = replacement_interface;

    RouteSpec fallback = stale_primary;
    fallback.metric = 1;

    RouteSpec fail_closed = stale_primary;
    fail_closed.interface.reset();
    fail_closed.unreachable = true;
    fail_closed.metric = 65535;

    auto cleanup = [&]() {
        for (const auto& route : std::array<RouteSpec, 4>{
                 replacement_primary, stale_primary, fallback, fail_closed}) {
            try {
                netlink.delete_route(route);
            } catch (...) {
            }
        }
        (void)safe_exec(
            {"ip", "link", "del", replacement_interface},
            /*suppress_output=*/true);
    };

    cleanup();
    try {
        run_command({"ip", "link", "add", replacement_interface,
                     "type", "dummy"});
        run_command({"ip", "link", "set", replacement_interface, "up"});

        // Simulate state that survived a daemon restart: the previous active
        // child still owns metric 0, while the weighted fallback and
        // fail-closed route are already correct. All three are explicitly
        // tagged with keen-pbr's reserved protocol by RouteSpec.
        netlink.add_route(stale_primary);
        netlink.add_route(fallback);
        netlink.add_route(fail_closed);

        RouteTable restarted(netlink);
        const std::vector<RouteSpec> desired{
            replacement_primary, fallback, fail_closed};
        restarted.reconcile(desired);

        const auto live = netlink.dump_routes_in_table(kTable, AF_INET);
        auto contains = [&](const RouteSpec& expected) {
            return std::any_of(
                live.begin(), live.end(), [&](const DumpedRoute& actual) {
                    return route_table_detail::route_matches_live(
                        expected, actual);
                });
        };

        if (!contains(replacement_primary)) {
            throw std::runtime_error(
                "Restart reconciliation did not atomically replace the stale "
                "protocol-186 primary route");
        }
        if (contains(stale_primary)) {
            throw std::runtime_error(
                "Restart reconciliation left the stale protocol-186 primary "
                "route installed");
        }
        if (!contains(fallback) || !contains(fail_closed)) {
            throw std::runtime_error(
                "Replacing the stale primary route damaged its weighted "
                "fallback or fail-closed route");
        }

        const size_t primary_count = std::count_if(
            live.begin(), live.end(), [&](const DumpedRoute& route) {
                return route.table == kTable &&
                       route.destination == "default" &&
                       route.metric == 0 &&
                       route.protocol ==
                           KEEN_PBR_GENERATED_ROUTE_PROTOCOL;
            });
        if (primary_count != 1) {
            throw std::runtime_error(
                "Restart reconciliation left an ambiguous protocol-186 "
                "metric-zero route generation");
        }

        // Already-present protocol-186 objects are adopted by the restarted
        // manager, so its ordinary exact cleanup must retire all three without
        // flushing or touching foreign state in the table.
        restarted.clear();
        const auto after_clear =
            netlink.dump_routes_in_table(kTable, AF_INET);
        const bool generated_left = std::any_of(
            after_clear.begin(), after_clear.end(), [](const DumpedRoute& route) {
                return route.protocol ==
                       KEEN_PBR_GENERATED_ROUTE_PROTOCOL;
            });
        if (generated_left) {
            throw std::runtime_error(
                "Restarted route manager did not adopt protocol-186 routes "
                "for exact cleanup");
        }
    } catch (...) {
        cleanup();
        throw;
    }

    cleanup();
}

size_t count_exact_line(const std::string& text, const std::string& expected) {
    size_t count = 0;
    std::istringstream lines(text);
    std::string line;
    while (std::getline(lines, line)) {
        if (line == expected) {
            ++count;
        }
    }
    return count;
}

size_t count_substring(const std::string& text, const std::string& needle) {
    size_t count = 0;
    size_t offset = 0;
    while ((offset = text.find(needle, offset)) != std::string::npos) {
        ++count;
        offset += needle.size();
    }
    return count;
}

std::string dispatcher_target(
    const std::string& rules,
    const std::string& dispatcher,
    const std::array<std::string, 2>& generations) {
    std::vector<std::string> targets;
    const std::string prefix = "-A " + dispatcher + " -j ";
    std::istringstream lines(rules);
    std::string line;
    while (std::getline(lines, line)) {
        if (line.rfind(prefix, 0) == 0) {
            targets.push_back(line.substr(prefix.size()));
        }
    }
    if (targets.size() != 1 ||
        (targets.front() != generations[0] &&
         targets.front() != generations[1])) {
        throw std::runtime_error(
            "Dispatcher " + dispatcher +
            " does not contain exactly one valid generation jump\n" + rules);
    }
    return targets.front();
}

size_t generation_index(
    const std::string& target,
    const std::array<std::string, 2>& generations) {
    if (target == generations[0]) {
        return 0;
    }
    if (target == generations[1]) {
        return 1;
    }
    throw std::runtime_error("Unknown iptables generation target: " + target);
}

std::string normalize_iptables_save(std::string_view output) {
    std::istringstream lines{std::string(output)};
    std::ostringstream normalized;
    std::string line;
    while (std::getline(lines, line)) {
        // iptables-save adds wall-clock metadata around an otherwise identical
        // ruleset. Comparing it verbatim makes fail-closed assertions flaky
        // whenever two snapshots cross a one-second boundary.
        if (line.rfind("# Generated by iptables-save", 0) == 0 ||
            line.rfind("# Completed on", 0) == 0) {
            continue;
        }
        normalized << line << '\n';
    }
    return normalized.str();
}

std::string iptables_save(const std::string& table) {
    return normalize_iptables_save(
        capture_command({"iptables-save", "-t", table}).stdout_output);
}

size_t count_chain_declaration(
    const std::string& rules,
    const std::string& chain) {
    size_t count = 0;
    const std::string prefix = ":" + chain + " ";
    std::istringstream lines(rules);
    std::string line;
    while (std::getline(lines, line)) {
        if (line.rfind(prefix, 0) == 0) {
            ++count;
        }
    }
    return count;
}

void assert_foreign_firewall_state(
    const IptablesConvergenceTopology& topology) {
    run_command({
        "iptables", "-t", "mangle", "-C", "PREROUTING",
        "-j", topology.foreign_chain});
    run_command({
        "iptables", "-t", "mangle", "-C", topology.foreign_chain,
        "-j", "MARK", "--set-xmark", "0x40000000/0x40000000"});
}

void install_foreign_firewall_state(
    const IptablesConvergenceTopology& topology) {
    run_command({
        "iptables", "-t", "mangle", "-N", topology.foreign_chain});
    run_command({
        "iptables", "-t", "mangle", "-A", topology.foreign_chain,
        "-j", "MARK", "--set-xmark", "0x40000000/0x40000000"});
    run_command({
        "iptables", "-t", "mangle", "-A", "PREROUTING",
        "-j", topology.foreign_chain});
    assert_foreign_firewall_state(topology);
}

void assert_referenced_ipsets_exist(
    const std::string& prerouting_state,
    const std::string& mangle_state) {
    std::set<std::string> referenced_sets;
    std::istringstream rules(prerouting_state + "\n" + mangle_state);
    std::string token;
    while (rules >> token) {
        if (token == "--match-set" && rules >> token) {
            referenced_sets.insert(token);
        }
    }

    std::set<std::string> existing_sets;
    std::istringstream sets(
        capture_command({"ipset", "save"}).stdout_output);
    std::string line;
    while (std::getline(sets, line)) {
        std::istringstream fields(line);
        std::string operation;
        std::string name;
        if (fields >> operation >> name && operation == "create") {
            existing_sets.insert(name);
        }
    }

    for (const auto& set_name : referenced_sets) {
        if (existing_sets.find(set_name) == existing_sets.end()) {
            throw std::runtime_error(
                "iptables generation references missing ipset " + set_name);
        }
    }
}

size_t assert_iptables_converged(
    const IptablesConvergenceTopology& topology,
    bool require_both_generations = true) {
    const std::string prerouting_state =
        iptables_save(topology.prerouting_table);
    const std::string mangle_state =
        topology.prerouting_table == "mangle"
            ? prerouting_state
            : iptables_save("mangle");

    if (count_chain_declaration(
            prerouting_state, topology.prerouting_dispatcher) != 1 ||
        count_chain_declaration(
            mangle_state, topology.output_dispatcher) != 1) {
        throw std::runtime_error(
            "Missing or duplicate stable iptables dispatcher");
    }

    const std::string prerouting_target = dispatcher_target(
        prerouting_state,
        topology.prerouting_dispatcher,
        topology.prerouting_generations);
    const std::string output_target = dispatcher_target(
        mangle_state,
        topology.output_dispatcher,
        topology.output_generations);
    const size_t active =
        generation_index(prerouting_target, topology.prerouting_generations);
    if (generation_index(output_target, topology.output_generations) != active) {
        throw std::runtime_error(
            "PREROUTING and OUTPUT dispatchers publish different generations");
    }
    for (size_t index = 0;
         index < topology.prerouting_generations.size();
         ++index) {
        const size_t prerouting_count = count_chain_declaration(
            prerouting_state, topology.prerouting_generations[index]);
        const size_t output_count = count_chain_declaration(
            mangle_state, topology.output_generations[index]);
        const bool required = require_both_generations || index == active;
        if ((required && prerouting_count != 1) ||
            (!required && prerouting_count > 1)) {
            throw std::runtime_error(
                "Missing or duplicate iptables generation chain " +
                topology.prerouting_generations[index] + "\n" +
                prerouting_state);
        }
        if ((required && output_count != 1) ||
            (!required && output_count > 1)) {
            throw std::runtime_error(
                "Missing or duplicate iptables OUTPUT generation chain " +
                topology.output_generations[index] + "\n" + mangle_state);
        }
    }

    if (count_exact_line(
            prerouting_state,
            "-A PREROUTING -j " + topology.prerouting_dispatcher) != 1 ||
        count_exact_line(
            mangle_state,
            "-A OUTPUT -j " + topology.output_dispatcher) != 1) {
        throw std::runtime_error(
            "Builtin iptables hooks did not converge to exactly one jump");
    }
    if (topology.raw_prerouting) {
        if (count_chain_declaration(
                mangle_state, topology.raw_conntrack_chain) != 1 ||
            count_exact_line(
                mangle_state,
                "-A PREROUTING -j " + topology.raw_conntrack_chain) != 1) {
            throw std::runtime_error(
                "Raw PREROUTING companion hook did not converge");
        }
    }
    if (count_substring(
            prerouting_state + mangle_state,
            "kpbr-integration-garbage") != 0) {
        throw std::runtime_error(
            "Garbage rule survived iptables reconciliation");
    }

    assert_referenced_ipsets_exist(prerouting_state, mangle_state);
    assert_foreign_firewall_state(topology);
    return active;
}

void delete_all_exact_hooks(
    const std::string& table,
    const std::string& builtin,
    const std::string& target) {
    while (safe_exec(
               {"iptables", "-t", table, "-D", builtin, "-j", target},
               /*suppress_output=*/true) == 0) {
    }
}

void delete_chain_if_present(
    const std::string& table,
    const std::string& chain) {
    (void)safe_exec(
        {"iptables", "-t", table, "-F", chain},
        /*suppress_output=*/true);
    (void)safe_exec(
        {"iptables", "-t", table, "-X", chain},
        /*suppress_output=*/true);
}

void delete_dispatchers(
    const IptablesConvergenceTopology& topology) {
    delete_all_exact_hooks(
        topology.prerouting_table,
        "PREROUTING",
        topology.prerouting_dispatcher);
    delete_all_exact_hooks(
        "mangle", "OUTPUT", topology.output_dispatcher);
    delete_chain_if_present(
        topology.prerouting_table, topology.prerouting_dispatcher);
    delete_chain_if_present("mangle", topology.output_dispatcher);
}

void delete_all_owned_scaffold(
    const IptablesConvergenceTopology& topology) {
    delete_dispatchers(topology);
    for (const auto& chain : topology.prerouting_generations) {
        delete_chain_if_present(topology.prerouting_table, chain);
    }
    for (const auto& chain : topology.output_generations) {
        delete_chain_if_present("mangle", chain);
    }
    if (topology.raw_prerouting) {
        delete_all_exact_hooks(
            "mangle", "PREROUTING", topology.raw_conntrack_chain);
        delete_chain_if_present("mangle", topology.raw_conntrack_chain);
    }
}

void expect_pipe_failure(
    const std::vector<std::string>& command,
    const std::string& input) {
    std::string error;
    if (safe_exec_pipe_stdin(
            command,
            input,
            &error,
            SafeExecFailureLog::Suppressed) == 0) {
        throw std::runtime_error(
            "Expected command failure during convergence test: " +
            safe_exec_command_string(command));
    }
}

void expect_apply_failure(const std::function<void()>& reapply) {
    try {
        reapply();
    } catch (const std::exception&) {
        return;
    }
    throw std::runtime_error(
        "Expected invalid live iptables state to fail closed");
}

void exercise_iptables_convergence(
    const IptablesConvergenceTopology& topology,
    const std::function<void()>& reapply) {
    // Repeated publication must only toggle the inactive slot. It must never
    // accumulate hooks or leave either dispatcher malformed.
    assert_iptables_converged(
        topology, /*require_both_generations=*/false);
    reapply();
    for (size_t index = 0; index < 6; ++index) {
        assert_iptables_converged(topology);
        reapply();
    }
    assert_iptables_converged(topology);

    delete_dispatchers(topology);
    reapply();
    assert_iptables_converged(topology);

    size_t active = assert_iptables_converged(topology);
    size_t inactive = 1U - active;
    delete_chain_if_present(
        topology.prerouting_table,
        topology.prerouting_generations[inactive]);
    delete_chain_if_present(
        "mangle", topology.output_generations[inactive]);
    reapply();
    assert_iptables_converged(topology);

    // A valid forwarded-traffic dispatcher remains the authority when the
    // OUTPUT dispatcher is missing. The repair is staged in the opposite slot.
    active = assert_iptables_converged(topology);
    run_command({
        "iptables", "-t", "mangle",
        "-F", topology.output_dispatcher});
    reapply();
    if (assert_iptables_converged(topology) == active) {
        throw std::runtime_error(
            "Valid plus missing dispatcher did not stage the opposite generation");
    }

    // The same authority rule applies when OUTPUT is malformed rather than
    // absent. Repair it to the forwarded generation before staging the next
    // inactive slot.
    active = assert_iptables_converged(topology);
    run_command({
        "iptables", "-t", "mangle",
        "-A", topology.output_dispatcher,
        "-m", "comment", "--comment", "kpbr-integration-garbage",
        "-j", "RETURN"});
    reapply();
    if (assert_iptables_converged(topology) == active) {
        throw std::runtime_error(
            "Valid plus invalid dispatcher did not stage the opposite generation");
    }

    // With no valid authority, dual A/B dispatchers are ambiguous. Applying
    // must fail before mutating live state instead of guessing a generation.
    active = assert_iptables_converged(topology);
    run_command({
        "iptables", "-t", topology.prerouting_table,
        "-F", topology.prerouting_dispatcher});
    for (const auto& generation : topology.prerouting_generations) {
        run_command({
            "iptables", "-t", topology.prerouting_table,
            "-A", topology.prerouting_dispatcher,
            "-j", generation});
    }
    run_command({
        "iptables", "-t", "mangle",
        "-F", topology.output_dispatcher});
    for (const auto& generation : topology.output_generations) {
        run_command({
            "iptables", "-t", "mangle",
            "-A", topology.output_dispatcher,
            "-j", generation});
    }
    const std::string invalid_prerouting =
        iptables_save(topology.prerouting_table);
    const std::string invalid_mangle =
        topology.prerouting_table == "mangle"
            ? invalid_prerouting
            : iptables_save("mangle");
    expect_apply_failure(reapply);
    if (iptables_save(topology.prerouting_table) != invalid_prerouting ||
        (topology.prerouting_table != "mangle" &&
         iptables_save("mangle") != invalid_mangle)) {
        throw std::runtime_error(
            "Fail-closed apply mutated ambiguous live iptables state");
    }
    run_command({
        "iptables", "-t", topology.prerouting_table,
        "-F", topology.prerouting_dispatcher});
    run_command({
        "iptables", "-t", topology.prerouting_table,
        "-A", topology.prerouting_dispatcher,
        "-j", topology.prerouting_generations[active]});
    run_command({
        "iptables", "-t", "mangle",
        "-F", topology.output_dispatcher});
    run_command({
        "iptables", "-t", "mangle",
        "-A", topology.output_dispatcher,
        "-j", topology.output_generations[active]});
    assert_iptables_converged(topology);

    // Missing plus missing has no contradictory authority and is the supported
    // bootstrap/recovery case.
    delete_all_owned_scaffold(topology);
    reapply();
    assert_iptables_converged(
        topology, /*require_both_generations=*/false);
    reapply();
    assert_iptables_converged(topology);

    // Out-of-band duplication is common after interrupted init scripts.
    run_command({
        "iptables", "-t", topology.prerouting_table,
        "-A", "PREROUTING", "-j", topology.prerouting_dispatcher});
    run_command({
        "iptables", "-t", "mangle",
        "-A", "OUTPUT", "-j", topology.output_dispatcher});
    if (topology.raw_prerouting) {
        run_command({
            "iptables", "-t", "mangle",
            "-A", "PREROUTING", "-j", topology.raw_conntrack_chain});
    }
    reapply();
    active = assert_iptables_converged(topology);

    // iptables-restore is table-transactional: a missing set in the staged
    // slot must not switch or damage the active dispatcher.
    inactive = 1U - active;
    const std::string failed_restore =
        "*" + topology.prerouting_table + "\n" +
        ":" + topology.prerouting_dispatcher + " - [0:0]\n" +
        ":" + topology.prerouting_generations[0] + " - [0:0]\n" +
        ":" + topology.prerouting_generations[1] + " - [0:0]\n" +
        "-F " + topology.prerouting_generations[inactive] + "\n" +
        "-F " + topology.prerouting_dispatcher + "\n" +
        "-A " + topology.prerouting_generations[inactive] +
        " -m set --match-set kpbr4_missing_integration dst -j RETURN\n" +
        "-A " + topology.prerouting_dispatcher + " -j " +
        topology.prerouting_generations[inactive] + "\n" +
        "COMMIT\n";
    expect_pipe_failure(
        {"iptables-restore", "--noflush", "--counters"},
        failed_restore);
    if (assert_iptables_converged(topology) != active) {
        throw std::runtime_error(
            "Failed iptables restore changed the active generation");
    }

    // ipset restore is not transactional, but it must never publish its
    // partially changed inactive set. The next normal apply repairs that slot.
    const std::string inactive_set =
        inactive == 0 ? "kpbr4s_local" : "kpbr4S_local";
    const std::string failed_ipset =
        "flush " + inactive_set + "\n" +
        "add " + inactive_set + " 203.0.113.77 -exist\n" +
        "add kpbr4_missing_integration 203.0.113.78 -exist\n";
    expect_pipe_failure(
        {"ipset", "restore", "-exist"},
        failed_ipset);
    if (assert_iptables_converged(topology) != active) {
        throw std::runtime_error(
            "Failed ipset restore changed the active generation");
    }
    reapply();
    assert_iptables_converged(topology);
    run_command({"ipset", "test", inactive_set, "10.10.0.1"});
    if (safe_exec(
            {"ipset", "test", inactive_set, "203.0.113.77"},
            /*suppress_output=*/true) == 0) {
        throw std::runtime_error(
            "Normal apply did not repair partially changed inactive ipset");
    }
}

} // namespace

int run_firewall_integration(int argc, char* argv[]) {
    CliOptions options = parse_args(argc, argv);

    auto& logger = Logger::instance();
    logger.set_level(parse_log_level(options.log_level));

    Config config = parse_config(read_file(options.config_path));
    if (!config.daemon.has_value()) {
        config.daemon = DaemonConfig{};
    }
    config.daemon->firewall_backend = parse_backend_config_value(options.backend);
    validate_config(config);

    const auto mode = parse_apply_mode(options.mode);
    const auto marks = allocate_outbound_marks(
        config.fwmark.value_or(FwmarkConfig{}),
        config.outbounds.value_or(std::vector<Outbound>{}));

    CacheManager cache_manager(
        config.daemon.value_or(DaemonConfig{}).cache_dir.value_or("/var/cache/keen-pbr"),
        max_file_size_bytes(config));
    cache_manager.ensure_dir();

    const auto urltest_selections =
        options.run_urltest_probes ? probe_urltests(config, marks) : std::map<std::string, std::string>{};

    NetlinkManager netlink;
    verify_metric_scoped_route_delete(netlink);
    verify_route_reconcile_restores_vanished_route(netlink);
    verify_restart_adopts_and_replaces_generated_default_route(netlink);
    RouteTable route_table(netlink);
    PolicyRuleManager policy_rules(netlink);
    auto firewall = create_firewall(
        parse_backend_preference(options.backend),
        options.use_raw_prerouting);
    RuntimeCleanup cleanup{route_table, policy_rules, *firewall};
    const std::optional<IptablesConvergenceTopology> convergence_topology =
        options.exercise_iptables_convergence
            ? std::optional<IptablesConvergenceTopology>{
                  options.use_raw_prerouting}
            : std::nullopt;
    if (convergence_topology.has_value()) {
        if (firewall->backend() != FirewallBackend::iptables) {
            throw std::runtime_error(
                "--exercise-iptables-convergence requires the iptables backend");
        }
        install_foreign_firewall_state(*convergence_topology);
    }

    FirewallState firewall_state;
    firewall_state.set_outbound_marks(marks);
    firewall_state.set_fwmark_mask(fwmark_mask_value(config.fwmark.value_or(FwmarkConfig{})));
    for (const auto& [tag, child] : urltest_selections) {
        firewall_state.set_urltest_selection(tag, child);
    }

    populate_routing_state(
        config,
        marks,
        route_table,
        policy_rules,
        [&netlink](const Outbound& outbound) {
            return is_interface_outbound_reachable(outbound, netlink);
        },
        &urltest_selections);

    auto apply_firewall = [&](FirewallApplyMode apply_mode) {
        firewall_state.set_rules(apply_runtime_firewall(
            config,
            marks,
            urltest_selections,
            cache_manager,
            *firewall,
            apply_mode));
    };
    apply_firewall(mode);
    if (options.repeat_preserve_apply) {
        if (options.drop_iptables_dispatchers_before_repeat) {
            if (firewall->backend() != FirewallBackend::iptables) {
                throw std::runtime_error(
                    "--drop-iptables-dispatchers-before-repeat requires the iptables backend");
            }
            const char* prerouting_table =
                options.use_raw_prerouting ? "raw" : "mangle";
            const char* prerouting_chain =
                options.use_raw_prerouting ? "KeenPbrRaw" : "KeenPbrTable";
            for (const auto& command : std::vector<std::vector<std::string>>{
                     {"iptables", "-t", prerouting_table, "-D", "PREROUTING", "-j",
                      prerouting_chain},
                     {"iptables", "-t", "mangle", "-D", "OUTPUT", "-j",
                      "KeenPbrOutput"},
                     {"iptables", "-t", prerouting_table, "-F", prerouting_chain},
                     {"iptables", "-t", prerouting_table, "-X", prerouting_chain},
                     {"iptables", "-t", "mangle", "-F", "KeenPbrOutput"},
                     {"iptables", "-t", "mangle", "-X", "KeenPbrOutput"},
                 }) {
                if (safe_exec(command, /*suppress_output=*/true) != 0) {
                    throw std::runtime_error(
                        "Failed to simulate externally removed iptables dispatchers");
                }
            }
        }
        apply_firewall(FirewallApplyMode::PreserveSets);
    }
    if (convergence_topology.has_value()) {
        exercise_iptables_convergence(
            *convergence_topology,
            [&]() {
                apply_firewall(FirewallApplyMode::PreserveSets);
            });
    }

    const RoutingHealthReport report = build_routing_health_report(
        firewall->backend(),
        firewall->uses_raw_prerouting(),
        firewall_state,
        route_table.get_routes(),
        policy_rules.get_rules(),
        netlink);

    if (report_has_failures(report)) {
        print_report(report);
        dump_routing_state(report);
        dump_firewall_state(firewall->backend());
        return 1;
    }

    if (convergence_topology.has_value()) {
        // Explicit cleanup is part of the ownership contract too: only
        // keen-pbr state may disappear.
        firewall->cleanup();
        assert_foreign_firewall_state(*convergence_topology);
    }

    std::cout << "ok backend=" << options.backend
              << " mode=" << options.mode
              << " raw_prerouting="
              << (options.use_raw_prerouting ? "true" : "false")
              << " config=" << options.config_path << "\n";
    return 0;
}

} // namespace keen_pbr3

int main(int argc, char* argv[]) {
    keen_pbr3::CurlRuntime curl_runtime;

    try {
        return keen_pbr3::run_firewall_integration(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }
}
