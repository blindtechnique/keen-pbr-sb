#include "../src/update/download_transport.hpp"
#include "../src/daemon/runtime_state_store.hpp"
#include <doctest/doctest.h>
#include <filesystem>
#include <fstream>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace keen_pbr3;
namespace {
struct UpdateFixture {
    Config config;
    OutboundMarkMap marks{{"vpn", 0x200}};
    RuntimeStateSnapshot runtime;
    UpdateFixture() {
        Outbound vpn{}; vpn.tag = "vpn"; vpn.type = OutboundType::INTERFACE;
        vpn.interface = "nwg0"; vpn.display_name = "My VPN";
        Outbound group{}; group.tag = "group"; group.type = OutboundType::URLTEST;
        group.outbound_groups = std::vector<OutboundGroup>{{{"vpn"}, {}}};
        config.outbounds = std::vector<Outbound>{vpn, group};
        runtime.runtime_state = RuntimeState::running;
        runtime.urltest_states["group"].selected_outbound = "vpn";
        RouteSpec route; route.destination = "default"; route.table = 100;
        route.interface = "nwg0"; route.family = AF_INET;
        runtime.route_specs.push_back(route);
        RuleSpec rule; rule.fwmark = 0x200; rule.fwmask = 0xff00;
        rule.table = 100; rule.family = AF_INET;
        runtime.policy_rule_specs.push_back(rule);
    }
    UpdateDownloadBinding plan(const std::string& tag = "group") const {
        return plan_update_download_binding(tag, config, marks, runtime);
    }
};
struct TempUpdateDirectory {
    std::filesystem::path path;
    TempUpdateDirectory() {
        char pattern[] = "/tmp/kpbr-update-unit.XXXXXX";
        const char* made = ::mkdtemp(pattern); REQUIRE(made != nullptr); path = made;
    }
    ~TempUpdateDirectory() { std::error_code ec; std::filesystem::remove_all(path, ec); }
};
std::string read_bytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
class StreamTransport : public HttpTransport {
public:
    int calls = 0;
    bool fail = false;
    long status = 200;
    HttpTransportResponse perform(const HttpTransportRequest& request) override {
        ++calls;
        CHECK(request.https_only);
        CHECK(request.fwmark == 0x200);
        CHECK(request.bind_interface == "nwg0");
        REQUIRE(static_cast<bool>(request.body_sink));
        request.body_sink("one", 3);
        if (fail) throw HttpTransportError("interrupted");
        request.body_sink("two", 3);
        HttpTransportResponse response; response.status_code = status; return response;
    }
};
}

TEST_CASE("update download selects applied group leaf and binds its mark and interface") {
    UpdateFixture fixture;
    const auto binding = fixture.plan();
    CHECK(binding.outbound == "group");
    CHECK(binding.selected_outbound == "vpn");
    CHECK(binding.interface == "nwg0");
    CHECK(binding.fwmark == 0x200);
    CHECK(fixture.plan("vpn").selected_outbound == "vpn");
    CHECK(update_download_options(fixture.config).at(0).at("name") == "My VPN");
    const auto request = make_update_download_request("https://example.com/file", binding, 64);
    CHECK(request.max_response_size == 64);
    CHECK(request.https_only);
    REQUIRE(static_cast<bool>(request.destination_filter));
    CHECK_THROWS(make_update_download_request("http://example.com/file", binding, 64));
}

TEST_CASE("update download never substitutes ordinary routing for an unavailable selection") {
    UpdateFixture fixture;
    SUBCASE("pending selection") { fixture.runtime.urltest_states["group"].selection_pending = true; }
    SUBCASE("removed member") { fixture.runtime.urltest_states["group"].selected_outbound = "deleted"; }
    SUBCASE("cycle") { fixture.runtime.urltest_states["group"].selected_outbound = "group"; fixture.config.outbounds->at(1).outbound_groups->at(0).outbounds = {"group"}; }
    SUBCASE("stopped") { fixture.runtime.runtime_state = RuntimeState::stopped; }
    SUBCASE("runtime disabled") { fixture.runtime.routing_runtime_active = false; }
    SUBCASE("unknown kernel") { fixture.runtime.routing_kernel_state_known = false; }
    SUBCASE("incomplete inventory") { fixture.runtime.routing_inventory_complete = false; }
    SUBCASE("no mark") { fixture.marks.clear(); }
    SUBCASE("no route") { fixture.runtime.route_specs.clear(); }
    SUBCASE("wrong interface") { fixture.runtime.route_specs[0].interface = "eth3"; }
    SUBCASE("wrong family") { fixture.runtime.policy_rule_specs[0].family = AF_INET6; }
    SUBCASE("wrong table") { fixture.runtime.policy_rule_specs[0].table = 101; }
    SUBCASE("wrong mark") { fixture.runtime.policy_rule_specs[0].fwmark = 0x300; }
    SUBCASE("catch-all rule") { fixture.runtime.policy_rule_specs[0].fwmask = 0; }
    SUBCASE("blackhole") { fixture.runtime.route_specs[0].blackhole = true; }
    SUBCASE("unreachable") { fixture.runtime.route_specs[0].unreachable = true; }
    CHECK_THROWS(fixture.plan());
    CHECK(fixture.plan("").outbound.empty());
}

TEST_CASE("update download follows nested applied groups to their selected leaf") {
    UpdateFixture fixture;
    auto nested = fixture.config.outbounds->at(1);
    nested.tag = "nested";
    fixture.config.outbounds->push_back(nested);
    fixture.config.outbounds->at(1).outbound_groups->at(0).outbounds = {"nested"};
    fixture.runtime.urltest_states["group"].selected_outbound = "nested";
    fixture.runtime.urltest_states["nested"].selected_outbound = "vpn";
    const auto binding = fixture.plan();
    CHECK(binding.outbound == "group");
    CHECK(binding.selected_outbound == "vpn");
    CHECK(binding.interface == "nwg0");
    fixture.runtime.urltest_states["nested"].selection_pending = true;
    CHECK_THROWS(fixture.plan());
}

TEST_CASE("update download preference is atomic, bounded and rejects symlinks") {
    TempUpdateDirectory directory;
    const auto path = directory.path / "preference";
    CHECK(read_update_outbound(path).empty());
    save_update_outbound(path, "group");
    CHECK(read_update_outbound(path) == "group");
    CHECK_THROWS(save_update_outbound(path, "group;echo"));
    CHECK(read_update_outbound(path) == "group");
    CHECK_FALSE(valid_update_outbound(std::string(25, 'a')));
    save_update_outbound(path, "");
    CHECK(read_update_outbound(path).empty());
    struct stat info{}; REQUIRE(::stat(path.c_str(), &info) == 0);
    CHECK((info.st_mode & 0777) == 0600);
    const auto link = directory.path / "link";
    std::filesystem::create_symlink(path, link);
    CHECK_THROWS(read_update_outbound(link));
    CHECK_THROWS(save_update_outbound(link, "vpn"));
}

TEST_CASE("update download resolves the current group member for each new file") {
    UpdateFixture fixture;
    auto backup = fixture.config.outbounds->at(0);
    backup.tag = "backup"; backup.interface = "vless1";
    fixture.config.outbounds->push_back(backup);
    fixture.config.outbounds->at(1).outbound_groups->at(0).outbounds.push_back("backup");
    fixture.marks["backup"] = 0x300;
    auto route = fixture.runtime.route_specs[0];
    route.interface = "vless1"; route.table = 101;
    fixture.runtime.route_specs.push_back(route);
    auto rule = fixture.runtime.policy_rule_specs[0];
    rule.fwmark = 0x300; rule.table = 101;
    fixture.runtime.policy_rule_specs.push_back(rule);
    const auto first = make_update_download_request("https://example.com/first", fixture.plan(), 64);
    fixture.runtime.urltest_states["group"].selected_outbound = "backup";
    const auto second = make_update_download_request("https://example.com/second", fixture.plan(), 64);
    CHECK(first.bind_interface == "nwg0");
    CHECK(first.fwmark == 0x200);
    CHECK(second.bind_interface == "vless1");
    CHECK(second.fwmark == 0x300);
    fixture.runtime.urltest_states["group"].selection_pending = true;
    CHECK_THROWS(fixture.plan());
}

TEST_CASE("update settings retain the saved path when active VPN discovery is unavailable") {
    TempUpdateDirectory directory;
    const auto path = directory.path / "preference";
    save_update_outbound(path, "group");
    int reads = 0;
    const auto failed_discovery = [&]() -> nlohmann::json {
        ++reads;
        throw std::runtime_error("daemon unavailable");
    };
    const auto unavailable = read_update_download_settings(path, failed_discovery);
    CHECK(reads == 1);
    CHECK(unavailable.at("outbound") == "group");
    CHECK(unavailable.at("options_available") == false);
    CHECK(unavailable.at("options").empty());
    CHECK(read_bytes(path) == "group\n");
    CHECK_THROWS(UpdateFixture{}.plan("removed"));
    // Returning to the ordinary path requires an explicit save, not a failed GET.
    save_update_outbound(path, "");
    CHECK(read_update_download_settings(path, failed_discovery).at("outbound") == "");
    const auto available = read_update_download_settings(path, [] {
        return update_download_options(UpdateFixture{}.config);
    });
    CHECK(available.at("options_available") == true);
    CHECK(available.at("options").size() == 2);
    const auto empty = read_update_download_settings(path, [] { return nlohmann::json::array(); });
    CHECK(empty.at("options_available") == true);
    const auto malformed = read_update_download_settings(path, [] { return nlohmann::json{}; });
    CHECK(malformed.at("options_available") == false);
}

TEST_CASE("update settings never hide an invalid saved preference as an ordinary path") {
    TempUpdateDirectory directory;
    const auto path = directory.path / "preference";
    { std::ofstream output(path); output << "not a valid outbound\n"; }
    int reads = 0;
    CHECK_THROWS(read_update_download_settings(path, [&] {
        ++reads;
        return nlohmann::json::array();
    }));
    CHECK(reads == 0);
    CHECK(read_bytes(path) == "not a valid outbound\n");
}

TEST_CASE("update download streams atomically and retains previous output on any failure") {
    TempUpdateDirectory directory;
    const auto path = directory.path / "candidate.ipk";
    { std::ofstream output(path); output << "original"; }
    StreamTransport transport;
    bool succeeds = true;
    SUBCASE("successful chunks") {}
    SUBCASE("connection interrupted") { transport.fail = true; succeeds = false; }
    SUBCASE("HTTP error") { transport.status = 404; succeeds = false; }
    const auto binding = UpdateFixture{}.plan();
    if (succeeds) {
        download_update_to_file("https://example.com/file", path, binding, transport);
        CHECK(read_bytes(path) == "onetwo");
    } else {
        CHECK_THROWS(download_update_to_file("https://example.com/file", path, binding, transport));
        CHECK(read_bytes(path) == "original");
    }
    CHECK(transport.calls == 1);
    CHECK(std::distance(std::filesystem::directory_iterator(directory.path), std::filesystem::directory_iterator{}) == 1);
}
