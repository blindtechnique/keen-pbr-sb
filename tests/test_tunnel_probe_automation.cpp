#include "../src/health/tunnel_probe_automation.hpp"

#include <doctest/doctest.h>

#include <map>
#include <string>
#include <vector>

namespace keen_pbr3 {

namespace {

Outbound tunnel_outbound(const std::string& tag,
                         std::optional<std::string> iface) {
    Outbound outbound;
    outbound.tag = tag;
    outbound.type = OutboundType::INTERFACE;
    outbound.interface = std::move(iface);
    return outbound;
}

ListConfig list_with_file(std::optional<std::string> file) {
    ListConfig list;
    list.file = std::move(file);
    return list;
}

// A configuration where everything is in place, so each test can spoil exactly
// one thing and see that refusal alone.
Config workable_config() {
    Config config;
    config.outbounds =
        std::vector<Outbound>{tunnel_outbound("tr_9786265a", "kpbr9786265a")};
    config.lists = std::map<std::string, ListConfig>{
        {"found_blocked", list_with_file("/opt/etc/keen-pbr/found.lst")}};

    TunnelProbeConfig probe;
    probe.enabled = true;
    probe.outbound = std::string{"tr_9786265a"};
    probe.list = std::string{"found_blocked"};
    config.tunnel_probe = probe;
    return config;
}

TunnelCandidateProposal proposal(const std::string& host,
                                 std::optional<bool> registry_blocked) {
    TunnelCandidateProposal candidate;
    candidate.host = host;
    candidate.registry_blocked = registry_blocked;
    return candidate;
}

}  // namespace

TEST_CASE("setup: absent configuration is off, not broken") {
    Config config;

    const auto result = resolve_tunnel_probe_setup(config);

    CHECK_FALSE(result.setup.has_value());
    CHECK(result.refusal == TunnelProbeRefusal::disabled);
}

TEST_CASE("setup: present but switched off is still off") {
    auto config = workable_config();
    config.tunnel_probe->enabled = false;

    CHECK(resolve_tunnel_probe_setup(config).refusal ==
          TunnelProbeRefusal::disabled);
}

TEST_CASE("setup: a complete configuration resolves to what a pass needs") {
    const auto result = resolve_tunnel_probe_setup(workable_config());

    REQUIRE(result.setup.has_value());
    CHECK(result.refusal == TunnelProbeRefusal::none);
    CHECK(result.setup->outbound_tag == "tr_9786265a");
    CHECK(result.setup->interface == "kpbr9786265a");
    CHECK(result.setup->list_name == "found_blocked");
    CHECK(result.setup->list_file == "/opt/etc/keen-pbr/found.lst");
    // The schema's defaults, applied where the operator said nothing.
    CHECK(result.setup->max_probes_per_pass == 8);
    CHECK(result.setup->interval_ms == 3600000);
    CHECK(result.setup->require_registry_confirmation);
}

TEST_CASE("setup: an outbound without an interface is refused, not guessed at") {
    // A probe leg is pinned to a device. With only a mark the direct leg would
    // measure whatever routing happened to pick, and the comparison - the
    // whole point - would prove nothing.
    auto config = workable_config();
    config.outbounds =
        std::vector<Outbound>{tunnel_outbound("tr_9786265a", std::nullopt)};

    CHECK(resolve_tunnel_probe_setup(config).refusal ==
          TunnelProbeRefusal::outbound_has_no_interface);
}

TEST_CASE("setup: an unknown outbound or list is named as missing") {
    auto missing_outbound = workable_config();
    missing_outbound.tunnel_probe->outbound = std::string{"nothing_like_it"};
    CHECK(resolve_tunnel_probe_setup(missing_outbound).refusal ==
          TunnelProbeRefusal::outbound_not_configured);

    auto missing_list = workable_config();
    missing_list.tunnel_probe->list = std::string{"no_such_list"};
    CHECK(resolve_tunnel_probe_setup(missing_list).refusal ==
          TunnelProbeRefusal::list_not_configured);
}

TEST_CASE("setup: a list with no file is refused rather than rewriting config") {
    // This automation appends to a file it owns. A list that keeps its hosts
    // inline would mean editing the operator's configuration underneath them.
    auto config = workable_config();
    config.lists = std::map<std::string, ListConfig>{
        {"found_blocked", list_with_file(std::nullopt)}};

    CHECK(resolve_tunnel_probe_setup(config).refusal ==
          TunnelProbeRefusal::list_has_no_file);
}

TEST_CASE("setup: an unnamed outbound or list is refused before lookup") {
    auto no_outbound = workable_config();
    no_outbound.tunnel_probe->outbound = std::string{};
    CHECK(resolve_tunnel_probe_setup(no_outbound).refusal ==
          TunnelProbeRefusal::no_outbound_named);

    auto no_list = workable_config();
    no_list.tunnel_probe->list = std::string{};
    CHECK(resolve_tunnel_probe_setup(no_list).refusal ==
          TunnelProbeRefusal::no_list_named);
}

TEST_CASE("setup: values outside the schema's range fall back to the default") {
    // A pass every second would be a way to hurt the router rather than a
    // configuration, so an out-of-range number is treated as unsaid.
    auto config = workable_config();
    config.tunnel_probe->interval_ms = 1000;
    config.tunnel_probe->max_probes_per_pass = 100000;

    const auto result = resolve_tunnel_probe_setup(config);

    REQUIRE(result.setup.has_value());
    CHECK(result.setup->interval_ms == 3600000);
    CHECK(result.setup->max_probes_per_pass == 8);
}

TEST_CASE("append: the registry gate holds back what it cannot confirm") {
    const std::vector<TunnelCandidateProposal> proposals{
        proposal("blocked.example", true),
        proposal("ads.example", false),
        // Nobody asked, or nobody answered. Never read as a clean bill.
        proposal("unknown.example", std::nullopt),
    };

    const auto plan = plan_host_append("", proposals,
                                       /*require_registry_confirmation=*/true);

    REQUIRE(plan.to_append.size() == 1);
    CHECK(plan.to_append[0] == "blocked.example");
    CHECK(plan.unconfirmed.size() == 2);
    CHECK(plan.already_present.empty());
}

TEST_CASE("append: without the gate every proposal is acted on") {
    const std::vector<TunnelCandidateProposal> proposals{
        proposal("blocked.example", true),
        proposal("ads.example", false),
        proposal("unknown.example", std::nullopt),
    };

    const auto plan = plan_host_append("", proposals,
                                       /*require_registry_confirmation=*/false);

    CHECK(plan.to_append.size() == 3);
    CHECK(plan.unconfirmed.empty());
}

TEST_CASE("append: a host the file already names is not written twice") {
    // Expected while the routing change has not taken effect: nfqws2 goes on
    // failing on the host, so the scan goes on proposing it.
    const std::string existing = "blocked.example\nother.example\n";

    const auto plan = plan_host_append(
        existing, {proposal("blocked.example", true), proposal("new.example", true)},
        true);

    REQUIRE(plan.to_append.size() == 1);
    CHECK(plan.to_append[0] == "new.example");
    REQUIRE(plan.already_present.size() == 1);
    CHECK(plan.already_present[0] == "blocked.example");
}

TEST_CASE("append: one pass proposing a host twice still writes it once") {
    const auto plan = plan_host_append(
        "", {proposal("same.example", true), proposal("same.example", true)},
        true);

    CHECK(plan.to_append.size() == 1);
    CHECK(plan.already_present.size() == 1);
}

TEST_CASE("host list file: blanks, comments and stray carriage returns") {
    const auto hosts = parse_host_list_file(
        "# added by hand\n"
        "\n"
        "  spaced.example  \n"
        "windows.example\r\n"
        "   \n"
        "last.example");

    REQUIRE(hosts.size() == 3);
    CHECK(hosts[0] == "spaced.example");
    // A trailing CR would make this host match nothing, so it is trimmed.
    CHECK(hosts[1] == "windows.example");
    CHECK(hosts[2] == "last.example");
}

TEST_CASE("render: appending to a file that does not end in a newline") {
    const auto rendered = render_appended_list("first.example", {"second.example"});

    CHECK(rendered == "first.example\nsecond.example\n");
}

TEST_CASE("render: appending nothing leaves the text as it was") {
    CHECK(render_appended_list("a.example\n", {}) == "a.example\n");
    CHECK(render_appended_list("", {}).empty());
}

TEST_CASE("render: an empty file gains no leading blank line") {
    CHECK(render_appended_list("", {"only.example"}) == "only.example\n");
}

}  // namespace keen_pbr3
