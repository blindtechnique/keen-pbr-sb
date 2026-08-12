#include <doctest/doctest.h>

#include "firewall/ppe_deoffload.hpp"

#include <algorithm>
#include <stdexcept>
#include <string>

namespace keen_pbr3 {

namespace {

PpeDeoffloadInputs measured_router() {
    PpeDeoffloadInputs inputs;
    inputs.desired.mode = PpeDeoffloadMode::automatic;
    inputs.desired.nfqueue_active = true;
    inputs.desired.strategy_ports_available = true;
    inputs.desired.tcp_ports = {"80", "443", "1984", "5222"};
    inputs.desired.quic_enabled = true;
    inputs.desired.quic_443_active = true;
    inputs.backend_compatible = true;
    inputs.ppe_target = PpeCapabilityState::available;
    inputs.connskip_match = PpeCapabilityState::available;
    inputs.conntrack_accounting = PpeCapabilityState::available;
    inputs.ppe_enabled = PpeCapabilityState::available;
    inputs.userspace = PpeCapabilityState::available;
    return inputs;
}

std::string active_graph(bool explicit_tcp_module = false,
                         bool save_chain_definition = false) {
    std::string rules;
    rules += save_chain_definition
        ? ":KeenPbrPpe4 - [0:0]\n"
        : "-N KeenPbrPpe4\n";
    rules +=
        "-A PREROUTING -m comment --comment \"keen-pbr-sb:ppe:prerouting\" "
        "-j KeenPbrPpe4\n";
    rules +=
        "-A FORWARD -m comment --comment \"keen-pbr-sb:ppe:forward\" "
        "-j KeenPbrPpe4\n";
    rules += "-A KeenPbrPpe4 -p tcp ";
    if (explicit_tcp_module) rules += "-m tcp ";
    rules +=
        "-m multiport --dports 80,443,1984,5222 "
        "-m connskip --connskip 30 -m comment --comment "
        "\"keen-pbr-sb:ppe:tcp:0\" -j PPE\n";
    rules +=
        "-A KeenPbrPpe4 -p udp -m udp --dport 443 "
        "-m connskip --connskip 30 -m comment --comment "
        "\"keen-pbr-sb:ppe:quic\" -j PPE\n";
    rules +=
        "-A KeenPbrPpe4 -m comment --comment "
        "\"keen-pbr-sb:ppe:return\" -j RETURN\n";
    return rules;
}

PpeDeoffloadGraphSpec measured_spec() {
    return build_ppe_deoffload_graph_spec(measured_router().desired);
}

} // namespace

TEST_CASE("PPE stays off unless auto is explicitly requested") {
    PpeDeoffloadInputs inputs;
    const auto assessment = evaluate_ppe_deoffload(inputs);
    CHECK(assessment.state == PpeDeoffloadState::disabled);
    CHECK_FALSE(assessment.supported);
    CHECK_FALSE(assessment.degraded);
}

TEST_CASE("the measured live PPE contract is admissible") {
    const auto assessment = evaluate_ppe_deoffload(measured_router());
    CHECK(assessment.state == PpeDeoffloadState::admissible);
    CHECK(assessment.supported);
    CHECK(assessment.tcp_eligible);
    CHECK(assessment.quic_eligible);
}

TEST_CASE("PPE capability states distinguish absence from uncertainty") {
    SUBCASE("target absence is a clean unsupported no-op") {
        auto inputs = measured_router();
        inputs.ppe_target = PpeCapabilityState::unavailable;
        const auto result = evaluate_ppe_deoffload(inputs);
        CHECK(result.state == PpeDeoffloadState::ppe_target_missing);
        CHECK_FALSE(result.degraded);
    }
    SUBCASE("an unreadable target inventory is degraded unknown") {
        auto inputs = measured_router();
        inputs.ppe_target = PpeCapabilityState::unknown;
        const auto result = evaluate_ppe_deoffload(inputs);
        CHECK(result.state == PpeDeoffloadState::unknown);
        CHECK(result.degraded);
    }
    SUBCASE("partial capability is degraded") {
        auto inputs = measured_router();
        inputs.connskip_match = PpeCapabilityState::unavailable;
        const auto result = evaluate_ppe_deoffload(inputs);
        CHECK(result.state == PpeDeoffloadState::connskip_match_missing);
        CHECK_FALSE(result.supported);
        CHECK(result.degraded);
    }
    SUBCASE("conntrack accounting must be one") {
        auto inputs = measured_router();
        inputs.conntrack_accounting = PpeCapabilityState::unavailable;
        const auto result = evaluate_ppe_deoffload(inputs);
        CHECK(result.state ==
              PpeDeoffloadState::conntrack_accounting_disabled);
        CHECK_FALSE(result.supported);
    }
    SUBCASE("the read-only PPE sysctl must already be one") {
        auto inputs = measured_router();
        inputs.ppe_enabled = PpeCapabilityState::unavailable;
        const auto result = evaluate_ppe_deoffload(inputs);
        CHECK(result.state == PpeDeoffloadState::ppe_already_disabled);
        CHECK_FALSE(result.supported);
    }
}

TEST_CASE("runtime inactivity retains proven PPE capability") {
    auto inputs = measured_router();
    inputs.desired.nfqueue_active = false;
    const auto inactive = evaluate_ppe_deoffload(inputs);
    CHECK(inactive.state == PpeDeoffloadState::nfqueue_inactive);
    CHECK(inactive.supported);

    inputs.desired.nfqueue_active = true;
    inputs.desired.strategy_ports_available = false;
    const auto unavailable_ports = evaluate_ppe_deoffload(inputs);
    CHECK(unavailable_ports.state ==
          PpeDeoffloadState::strategy_ports_unavailable);
    CHECK(unavailable_ports.supported);
}

TEST_CASE("desired liveness comparison ignores diagnostics but tracks queue") {
    PpeDeoffloadDesired desired;
    desired.mode = PpeDeoffloadMode::automatic;
    desired.nfqueue_active = true;
    desired.strategy_ports_available = true;
    desired.nfqueue_number = 301;
    desired.tcp_ports = {"80:90", "443"};
    desired.quic_enabled = true;
    desired.quic_443_active = true;
    desired.runtime_contract_detail = "first wording";

    auto same = desired;
    same.runtime_contract_detail = "different wording";
    CHECK(ppe_deoffload_desired_semantically_equal(desired, same));

    same.nfqueue_number = 302;
    CHECK_FALSE(ppe_deoffload_desired_semantically_equal(desired, same));
    same = desired;
    same.nfqueue_active = false;
    same.strategy_ports_available = false;
    same.nfqueue_number = -1;
    same.tcp_ports.clear();
    same.quic_443_active = false;
    CHECK_FALSE(ppe_deoffload_desired_semantically_equal(desired, same));
}

TEST_CASE("late dead or queue-changed tuple cannot reuse staged graph") {
    PpeDeoffloadDesired staged;
    staged.mode = PpeDeoffloadMode::automatic;
    staged.nfqueue_active = true;
    staged.strategy_ports_available = true;
    staged.nfqueue_number = 300;
    staged.tcp_ports = {"443"};
    staged.quic_enabled = true;
    staged.quic_443_active = true;
    const auto staged_graph = build_ppe_deoffload_graph_spec(staged);

    PpeDeoffloadDesired late_dead;
    late_dead.mode = PpeDeoffloadMode::automatic;
    late_dead.quic_enabled = true;
    late_dead.runtime_contract_detail = "nfqws process is not running";
    CHECK_FALSE(ppe_deoffload_desired_semantically_equal(
        staged, late_dead));
    CHECK(build_ppe_deoffload_graph_spec(late_dead).empty());

    auto queue_changed = staged;
    queue_changed.nfqueue_number = 301;
    queue_changed.tcp_ports = {"80"};
    queue_changed.quic_443_active = false;
    CHECK_FALSE(ppe_deoffload_desired_semantically_equal(
        staged, queue_changed));
    const auto changed_graph = build_ppe_deoffload_graph_spec(queue_changed);
    CHECK(changed_graph != staged_graph);
    REQUIRE(changed_graph.tcp_chunks.size() == 1U);
    CHECK(changed_graph.tcp_chunks[0] == "80");
    CHECK_FALSE(changed_graph.quic);
}

TEST_CASE("missing PPE owner marker requests one coalesced repair") {
    CHECK(classify_ppe_deoffload_observation(
              PpeGraphState::exact,
              /*owner_marker_valid=*/false,
              /*stored_snapshot_active=*/true) ==
          PpeObservationRefreshResult::semantic_drift);
    CHECK(classify_ppe_deoffload_observation(
              PpeGraphState::exact,
              /*owner_marker_valid=*/true,
              /*stored_snapshot_active=*/true) ==
          PpeObservationRefreshResult::refreshed);
    CHECK(classify_ppe_deoffload_observation(
              PpeGraphState::ambiguous,
              /*owner_marker_valid=*/true,
              /*stored_snapshot_active=*/true) ==
          PpeObservationRefreshResult::unavailable);
}

TEST_CASE("TCP and QUIC eligibility remain independent") {
    auto inputs = measured_router();
    inputs.desired.quic_enabled = false;
    auto assessment = evaluate_ppe_deoffload(inputs);
    CHECK(assessment.tcp_eligible);
    CHECK_FALSE(assessment.quic_eligible);

    inputs.desired.tcp_ports.clear();
    inputs.desired.quic_enabled = true;
    assessment = evaluate_ppe_deoffload(inputs);
    CHECK_FALSE(assessment.tcp_eligible);
    CHECK(assessment.quic_eligible);
}

TEST_CASE("ports are canonical, merged and chunked to the xtables ABI") {
    PpeDeoffloadDesired desired;
    desired.tcp_ports = {
        "443,80", "81-82", "82:90", "443",
        "1000", "1002", "1001", "2000", "3000", "4000",
        "5000", "6000", "7000", "8000", "9000", "10000",
        "11000", "12000", "13000", "14000", "15000", "16000"};
    const auto spec = build_ppe_deoffload_graph_spec(desired);
    REQUIRE(spec.tcp_chunks.size() == 2U);
    // Adjacent and overlapping public selectors describe the same set and
    // collapse before the 15-entry multiport limit is applied.
    CHECK(spec.tcp_chunks[0].rfind("80:90,443,1000:1002", 0U) == 0U);
    CHECK(std::count(spec.tcp_chunks[0].begin(),
                     spec.tcp_chunks[0].end(), ',') <= 14);
    CHECK(std::count(spec.tcp_chunks[1].begin(),
                     spec.tcp_chunks[1].end(), ',') <= 14);
}

TEST_CASE("invalid strategy ports fail before any graph can be built") {
    PpeDeoffloadDesired desired;
    desired.tcp_ports = {"443,$(reboot)"};
    CHECK_THROWS_AS(build_ppe_deoffload_graph_spec(desired),
                    std::invalid_argument);
}

TEST_CASE("typed desired input cannot exceed the bounded TCP graph") {
    PpeDeoffloadDesired desired;
    for (unsigned int port = 1U; port <= 481U; port += 2U) {
        desired.tcp_ports.push_back(std::to_string(port));
    }
    CHECK_THROWS_AS(build_ppe_deoffload_graph_spec(desired),
                    std::invalid_argument);

    auto rules = active_graph();
    const auto tag = rules.find("keen-pbr-sb:ppe:tcp:0");
    REQUIRE(tag != std::string::npos);
    rules.replace(tag, std::string("keen-pbr-sb:ppe:tcp:0").size(),
                  "keen-pbr-sb:ppe:tcp:16");
    CHECK(inspect_ppe_deoffload_graph(rules).state ==
          PpeGraphState::ambiguous);
}

TEST_CASE("multiport chunking counts a range as two ABI slots") {
    PpeDeoffloadDesired desired;
    desired.tcp_ports = {
        "1-2", "4-5", "7-8", "10-11", "13-14", "16-17",
        "19-20", "22-23"};
    const auto spec = build_ppe_deoffload_graph_spec(desired);
    REQUIRE(spec.tcp_chunks.size() == 2U);
    CHECK(spec.tcp_chunks[0] ==
          "1:2,4:5,7:8,10:11,13:14,16:17,19:20");
    CHECK(spec.tcp_chunks[1] == "22:23");
}

TEST_CASE("exact graph accepts iptables optional implicit TCP module") {
    const auto spec = measured_spec();
    CHECK(inspect_ppe_deoffload_graph(active_graph(false), &spec).state ==
          PpeGraphState::exact);
    CHECK(inspect_ppe_deoffload_graph(active_graph(true), &spec).state ==
          PpeGraphState::exact);
}

TEST_CASE("same desired graph is a semantic no-op contract") {
    const auto spec = measured_spec();
    const auto observed = inspect_ppe_deoffload_graph(active_graph(), &spec);
    REQUIRE(observed.state == PpeGraphState::exact);
    CHECK(observed.observed == spec);
}

TEST_CASE("duplicate owned hooks are repairable but foreign references are not") {
    const auto spec = measured_spec();
    SUBCASE("owned duplicate") {
        auto rules = active_graph();
        rules +=
            "-A FORWARD -m comment --comment keen-pbr-sb:ppe:forward "
            "-j KeenPbrPpe4\n";
        const auto observed = inspect_ppe_deoffload_graph(rules, &spec);
        CHECK(observed.state == PpeGraphState::owned_drift);
        CHECK(observed.forward_hook_count == 2U);
    }
    SUBCASE("untagged lookalike is foreign") {
        auto rules = active_graph();
        rules += "-A OUTPUT -j KeenPbrPpe4\n";
        CHECK(inspect_ppe_deoffload_graph(rules, &spec).state ==
              PpeGraphState::ambiguous);
    }
    SUBCASE("owned tag on the wrong parent is ambiguous") {
        auto rules = active_graph();
        rules +=
            "-A OUTPUT -m comment --comment keen-pbr-sb:ppe:forward "
            "-j ACCEPT\n";
        CHECK(inspect_ppe_deoffload_graph(rules, &spec).state ==
              PpeGraphState::ambiguous);
    }
}

TEST_CASE("owned TCP chunks must already be merged canonical selectors") {
    auto duplicate = active_graph();
    const auto ports = duplicate.find("80,443,1984,5222");
    REQUIRE(ports != std::string::npos);
    duplicate.replace(ports, std::string("80,443,1984,5222").size(),
                      "80,80,443,1984,5222");
    CHECK(inspect_ppe_deoffload_graph(duplicate).state ==
          PpeGraphState::ambiguous);

    auto adjacent = active_graph();
    const auto adjacent_ports = adjacent.find("80,443,1984,5222");
    REQUIRE(adjacent_ports != std::string::npos);
    adjacent.replace(adjacent_ports,
                     std::string("80,443,1984,5222").size(),
                     "80,81,443,1984,5222");
    CHECK(inspect_ppe_deoffload_graph(adjacent).state ==
          PpeGraphState::ambiguous);
}

TEST_CASE("empty unreferenced chain requires durable ownership evidence") {
    CHECK(inspect_ppe_deoffload_graph("-N KeenPbrPpe4\n").state ==
          PpeGraphState::ambiguous);
    CHECK(inspect_ppe_deoffload_graph(
              "-N KeenPbrPpe4\n", nullptr, true).state ==
          PpeGraphState::owned_drift);
}

TEST_CASE("apply transaction owns exact tagged hooks and rules") {
    const PpeGraphInspection absent;
    const auto script = build_ppe_deoffload_apply_script(
        absent, measured_spec());
    CHECK(script.find("*mangle\n") == 0U);
    CHECK(script.find("-N KeenPbrPpe4\n") != std::string::npos);
    CHECK(script.find("-F KeenPbrPpe4") == std::string::npos);
    CHECK(script.find("--connskip 30") != std::string::npos);
    CHECK(script.find("keen-pbr-sb:ppe:tcp:0") != std::string::npos);
    CHECK(script.find("-I PREROUTING 1 -m comment --comment "
                      "keen-pbr-sb:ppe:prerouting -j KeenPbrPpe4") !=
          std::string::npos);
    CHECK(script.find("-I FORWARD 1 -m comment --comment "
                      "keen-pbr-sb:ppe:forward -j KeenPbrPpe4") !=
          std::string::npos);
    CHECK(script.rfind("COMMIT\n") == script.size() - 7U);
    // The selective implementation must never write either required sysctl.
    CHECK(script.find("ppe_enabled") == std::string::npos);
    CHECK(script.find("nf_conntrack_acct") == std::string::npos);
}

TEST_CASE("cleanup deletes only exact tagged ownership in one transaction") {
    const auto before = inspect_ppe_deoffload_graph(active_graph());
    REQUIRE(before.state == PpeGraphState::exact);
    const auto script = build_ppe_deoffload_cleanup_script(before);
    CHECK(script.find("-D PREROUTING -m comment --comment "
                      "keen-pbr-sb:ppe:prerouting -j KeenPbrPpe4") !=
          std::string::npos);
    CHECK(script.find("-D FORWARD -m comment --comment "
                      "keen-pbr-sb:ppe:forward -j KeenPbrPpe4") !=
          std::string::npos);
    CHECK(script.find("-F KeenPbrPpe4") == std::string::npos);
    CHECK(script.find("-D KeenPbrPpe4 -m comment --comment "
                      "\"keen-pbr-sb:ppe:return\" -j RETURN") !=
          std::string::npos);
    CHECK(script.find("-X KeenPbrPpe4\nCOMMIT\n") !=
          std::string::npos);
    PpeGraphInspection ambiguous;
    ambiguous.state = PpeGraphState::ambiguous;
    CHECK_THROWS_AS(build_ppe_deoffload_cleanup_script(ambiguous),
                    std::invalid_argument);
}

TEST_CASE("live graph replacement fences a post-inspection foreign append") {
    const auto before = inspect_ppe_deoffload_graph(
        active_graph(/*explicit_tcp_module=*/true));
    REQUIRE(before.state == PpeGraphState::exact);
    REQUIRE(before.owned_chain_rules.size() == 3U);

    auto raced = active_graph(/*explicit_tcp_module=*/true);
    raced += "-A KeenPbrPpe4 -m comment --comment foreign -j ACCEPT\n";
    REQUIRE(inspect_ppe_deoffload_graph(raced).state ==
            PpeGraphState::ambiguous);

    const auto replacement = build_ppe_deoffload_apply_script(
        before, measured_spec());
    CHECK(replacement.find("-F KeenPbrPpe4") == std::string::npos);
    CHECK(replacement.find("--comment foreign") == std::string::npos);
    CHECK(replacement.find(
              "-D KeenPbrPpe4 -p tcp -m tcp -m multiport") !=
          std::string::npos);
    for (const auto& observed_rule : before.owned_chain_rules) {
        auto exact_deletion = observed_rule;
        exact_deletion[1] = 'D';
        CHECK(replacement.find(exact_deletion + "\n") !=
              std::string::npos);
    }
    const auto delete_chain = replacement.find("-X KeenPbrPpe4\n");
    const auto recreate_chain = replacement.find("-N KeenPbrPpe4\n");
    REQUIRE(delete_chain != std::string::npos);
    REQUIRE(recreate_chain != std::string::npos);
    CHECK(delete_chain < recreate_chain);

    // The exact deletes do not name the raced-in foreign rule. It therefore
    // remains when -X is evaluated, aborting the atomic restore before -N or
    // any desired rule can be committed.
    const auto cleanup = build_ppe_deoffload_cleanup_script(before);
    CHECK(cleanup.find("-F KeenPbrPpe4") == std::string::npos);
    CHECK(cleanup.find("--comment foreign") == std::string::npos);
    CHECK(cleanup.find("-X KeenPbrPpe4\nCOMMIT\n") !=
          std::string::npos);
    for (const auto& observed_rule : before.owned_chain_rules) {
        auto exact_deletion = observed_rule;
        exact_deletion[1] = 'D';
        CHECK(cleanup.find(exact_deletion + "\n") !=
              std::string::npos);
    }
}

TEST_CASE("legacy validation cleanup requires exact rule semantics") {
    const auto spec = measured_spec();
    const std::string chain = "KpPpeV123";
    std::string inventory = "-N " + chain + "\n";
    auto transaction = build_ppe_deoffload_validation_script(spec, chain);
    const auto table_header = transaction.find('\n');
    REQUIRE(table_header != std::string::npos);
    transaction.erase(0U, table_header + 1U);
    const auto commit = transaction.rfind("COMMIT\n");
    REQUIRE(commit != std::string::npos);
    transaction.erase(commit);
    inventory += transaction;

    CHECK(ppe_deoffload_validation_chain_is_exact(
        inventory, spec, chain));

    auto implicit_tcp_module = inventory;
    const auto tcp = implicit_tcp_module.find("-p tcp ");
    REQUIRE(tcp != std::string::npos);
    implicit_tcp_module.insert(tcp + 7U, "-m tcp ");
    CHECK(ppe_deoffload_validation_chain_is_exact(
        implicit_tcp_module, spec, chain));

    auto same_tags_foreign_semantics = inventory;
    const auto connskip = same_tags_foreign_semantics.find("--connskip 30");
    REQUIRE(connskip != std::string::npos);
    same_tags_foreign_semantics.replace(
        connskip, std::string("--connskip 30").size(), "--connskip 31");
    CHECK_FALSE(ppe_deoffload_validation_chain_is_exact(
        same_tags_foreign_semantics, spec, chain));

    auto extra_owned_tag = inventory;
    extra_owned_tag +=
        "-A " + chain +
        " -m comment --comment keen-pbr-sb:ppe:return -j ACCEPT\n";
    CHECK_FALSE(ppe_deoffload_validation_chain_is_exact(
        extra_owned_tag, spec, chain));
}

TEST_CASE("legacy validation cleanup preserves a post-inspection foreign append") {
    const auto spec = measured_spec();
    const std::string chain = "KpPpeV456";
    std::string inspected = "-N " + chain + "\n";
    auto rendered = build_ppe_deoffload_validation_script(spec, chain);
    rendered.erase(0U, rendered.find('\n') + 1U);
    rendered.erase(rendered.rfind("COMMIT\n"));
    inspected += rendered;
    REQUIRE(ppe_deoffload_validation_chain_is_exact(
        inspected, spec, chain));

    // Model the concrete TOCTOU: inspection succeeded, then a foreign writer
    // appended a rule before cleanup acquired the restore transaction lock.
    const std::string foreign_rule =
        "-A " + chain + " -m comment --comment foreign -j ACCEPT\n";
    const auto raced_inventory = inspected + foreign_rule;
    REQUIRE_FALSE(ppe_deoffload_validation_chain_is_exact(
        raced_inventory, spec, chain));

    const auto cleanup = build_ppe_deoffload_validation_cleanup_script(
        spec, chain, /*complete_graph=*/true);
    CHECK(cleanup.find("-F ") == std::string::npos);
    CHECK(cleanup.find("--comment foreign") == std::string::npos);
    CHECK(cleanup.find("-D " + chain + " ") != std::string::npos);
    CHECK(cleanup.find("-X " + chain + "\nCOMMIT\n") !=
          std::string::npos);

    // Exact deletions leave the raced-in rule present, so -X fails and the
    // atomic transaction cannot commit. The empty-chain recovery path likewise
    // has no command capable of erasing a concurrent append.
    const auto empty_cleanup = build_ppe_deoffload_validation_cleanup_script(
        spec, chain, /*complete_graph=*/false);
    CHECK(empty_cleanup ==
          "*mangle\n-X " + chain + "\nCOMMIT\n");
}

TEST_CASE("iptables-save counters validate save syntax and stay non-overclaimed") {
    std::string save = active_graph(
        /*explicit_tcp_module=*/true,
        /*save_chain_definition=*/true);
    const auto add_counter = [&save](const std::string& needle,
                                     const std::string& counter) {
        const auto at = save.find(needle);
        REQUIRE(at != std::string::npos);
        save.insert(at, counter);
    };
    // Insert from bottom to top so earlier offsets remain valid.
    add_counter("-A KeenPbrPpe4 -p udp", "[7:700] ");
    add_counter("-A KeenPbrPpe4 -p tcp", "[11:1100] ");
    add_counter("-A FORWARD", "[13:1300] ");
    add_counter("-A PREROUTING", "[17:1700] ");

    const auto counters = parse_ppe_deoffload_counters(
        save, measured_spec(), 123456U);
    REQUIRE(counters.available);
    CHECK(counters.prerouting_packets == 17U);
    CHECK(counters.prerouting_bytes == 1700U);
    CHECK(counters.forward_packets == 13U);
    CHECK(counters.forward_bytes == 1300U);
    CHECK(counters.tcp_packets == 11U);
    CHECK(counters.tcp_bytes == 1100U);
    CHECK(counters.quic_packets == 7U);
    CHECK(counters.quic_bytes == 700U);
    CHECK(counters.observed_at_unix_seconds == 123456U);
}

TEST_CASE("drifted graph never fabricates zero counters") {
    auto save = active_graph(true, true);
    const auto tag = save.find("keen-pbr-sb:ppe:tcp:0");
    REQUIRE(tag != std::string::npos);
    save.replace(tag, std::string("keen-pbr-sb:ppe:tcp:0").size(),
                 "keen-pbr-sb:ppe:tcp:9");
    CHECK_FALSE(parse_ppe_deoffload_counters(
                    save, measured_spec(), 1U).available);
}

TEST_CASE("public names remain stable for health and lifecycle cleanup") {
    CHECK(std::string(ppe_deoffload_mode_name(
              PpeDeoffloadMode::automatic)) == "auto");
    CHECK(std::string(ppe_deoffload_state_name(
              PpeDeoffloadState::active)) == "active");
    CHECK(std::string(ppe_graph_state_name(PpeGraphState::ambiguous)) ==
          "ambiguous");
    CHECK(std::string(kPpeDeoffloadChain) == "KeenPbrPpe4");
    CHECK(std::string(kPpeDeoffloadOwnerMarker) ==
          "/opt/var/run/keen-pbr.ppe-backend");
}

} // namespace keen_pbr3
