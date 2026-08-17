#include <doctest/doctest.h>

#include "../src/cmd/status.hpp"

#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>

namespace {

class CoutCapture {
public:
    CoutCapture() : previous_(std::cout.rdbuf(output_.rdbuf())) {}

    ~CoutCapture() { std::cout.rdbuf(previous_); }

    std::string str() const { return output_.str(); }

private:
    std::ostringstream output_;
    std::streambuf* previous_;
};

class CerrCapture {
public:
    CerrCapture() : previous_(std::cerr.rdbuf(output_.rdbuf())) {}

    ~CerrCapture() { std::cerr.rdbuf(previous_); }

    std::string str() const { return output_.str(); }

private:
    std::ostringstream output_;
    std::streambuf* previous_;
};

nlohmann::json healthy_status_response() {
    // This is the live daemon-control payload consumed by
    // run_status_command(response). It deliberately includes active config
    // and realized health snapshots instead of a path to on-disk desired
    // state.
    return {
        {"ok", true},
        {"result",
         {
             {"config_path", "/opt/etc/keen-pbr/config.json"},
             {"runtime_state", "running"},
             {"routing_runtime_active", true},
             {"config",
              {{"outbounds",
                {{{"tag", "vpn"},
                  {"type", "interface"},
                  {"interface", "tun0"}}}}}},
             {"routing_health",
              {
                  {"overall", "ok"},
                  {"firewall_backend", "iptables"},
                  {"firewall",
                   {{"chain_present", true},
                    {"prerouting_hook_present", true}}},
                  {"firewall_rules", nlohmann::json::array()},
                  {"route_tables",
                   {{{"table_id", 150},
                     {"outbound_tag", "vpn"},
                     {"expected_destination", "default"},
                     {"expected_interface", "tun0"},
                     {"expected_metric", 1},
                     {"expected_route_type", "unicast"},
                     {"table_exists", true},
                     {"default_route_present", true},
                     {"interface_matches", true},
                     {"gateway_matches", true},
                     {"status", "ok"}}}},
                  {"policy_rules",
                   {{{"fwmark", "0x00010000"},
                     {"fwmask", "0x00ff0000"},
                     {"expected_table", 150},
                     {"priority", 150},
                     {"rule_present_v4", true},
                     {"rule_present_v6", true},
                     {"status", "ok"}}}},
              }},
         }},
    };
}

} // namespace

TEST_CASE("status command renders live daemon response and exits zero") {
    CoutCapture capture;

    CHECK(keen_pbr3::run_status_command(healthy_status_response()) == 0);

    const auto output = capture.str();
    CHECK(output.find(
              "keen-pbr status - config: /opt/etc/keen-pbr/config.json") !=
          std::string::npos);
    CHECK(output.find("Outbounds:") != std::string::npos);
    CHECK(output.find("vpn [interface]") != std::string::npos);
    CHECK(output.find("Overall: OK") != std::string::npos);
}

TEST_CASE("status command renders realized table and priority from daemon") {
    auto response = healthy_status_response();
    auto& health = response["result"]["routing_health"];
    health["route_tables"][0]["table_id"] = 777;
    health["policy_rules"][0]["expected_table"] = 777;
    health["policy_rules"][0]["priority"] = 404;

    CoutCapture capture;
    CHECK(keen_pbr3::run_status_command(response) == 0);

    const auto output = capture.str();
    CHECK(output.find("table=777") != std::string::npos);
    CHECK(output.find("pri=404") != std::string::npos);
}

TEST_CASE("status command preserves and renders PPE health") {
    auto response = healthy_status_response();
    response["result"]["routing_health"]["ppe_deoffload"] = {
        {"mode", "auto"},
        {"capability", "supported"},
        {"state", "active"},
        {"connskip_packets", 30},
        {"last_reconcile_ts", 1000},
        {"observed_at", 1001},
        {"prerouting", {{"packets", 11}, {"bytes", 1100}}},
        {"forward", {{"packets", 7}, {"bytes", 700}}},
        {"tcp",
         {{"desired_ports", {"80,443"}},
          {"applied_ports", {"80,443"}},
          {"active", true},
          {"counters", {{"packets", 5}, {"bytes", 500}}}}},
        {"quic",
         {{"desired_ports", {"443"}},
          {"applied_ports", {"443"}},
          {"active", true},
          {"counters", {{"packets", 3}, {"bytes", 300}}}}},
    };

    CoutCapture capture;
    CHECK(keen_pbr3::run_status_command(response) == 0);
    const auto output = capture.str();
    CHECK(output.find("PPE de-offload:") != std::string::npos);
    CHECK(output.find("mode=auto state=active") != std::string::npos);
    CHECK(output.find("packets prerouting=11 forward=7 tcp=5 quic=3") !=
          std::string::npos);
    CHECK(output.find("observed_at=1001") != std::string::npos);
}

TEST_CASE("status command returns nonzero for degraded live health") {
    auto response = healthy_status_response();
    auto& health = response["result"]["routing_health"];
    health["overall"] = "degraded";
    health["route_tables"][0]["status"] = "mismatch";
    health["route_tables"][0]["detail"] = "interface mismatch";

    CoutCapture capture;
    CHECK(keen_pbr3::run_status_command(response) == 1);

    const auto output = capture.str();
    CHECK(output.find("MISMATCH") != std::string::npos);
    CHECK(output.find("interface mismatch") != std::string::npos);
    CHECK(output.find("Overall: DEGRADED") != std::string::npos);
}

TEST_CASE("status command fails closed when routing runtime is inactive") {
    auto response = healthy_status_response();
    auto& result = response["result"];
    result["runtime_state"] = "stopped";
    result["routing_runtime_active"] = false;

    CoutCapture capture;
    CHECK(keen_pbr3::run_status_command(response) == 1);

    const auto output = capture.str();
    CHECK(output.find("Runtime: stopped (routing inactive)") !=
          std::string::npos);
    CHECK(output.find("Overall: DEGRADED") != std::string::npos);
}

TEST_CASE("status command fails closed for inconsistent degraded summary") {
    auto response = healthy_status_response();
    auto& health = response["result"]["routing_health"];
    health["overall"] = "degraded";

    CoutCapture capture;
    CHECK(keen_pbr3::run_status_command(response) == 1);
    CHECK(capture.str().find("Overall: DEGRADED") != std::string::npos);
}

TEST_CASE("status command renders daemon health errors") {
    auto response = healthy_status_response();
    response["result"]["routing_health"] = {
        {"overall", "error"},
        {"error", "firewall verifier unavailable"},
    };

    CoutCapture capture;
    CHECK(keen_pbr3::run_status_command(response) == 1);

    const auto output = capture.str();
    CHECK(output.find(
              "Health check error: firewall verifier unavailable") !=
          std::string::npos);
    CHECK(output.find("Overall: ERROR") != std::string::npos);
}

TEST_CASE("status command rejects malformed hexadecimal marks") {
    auto response = healthy_status_response();
    response["result"]["routing_health"]["policy_rules"][0]["fwmark"] =
        "0xnot-a-mark";

    CHECK_THROWS_WITH_AS(
        keen_pbr3::run_status_command(response),
        "invalid hexadecimal value in status response: 0xnot-a-mark",
        std::runtime_error);
}

TEST_CASE("status command rejects uint32 overflow from daemon payload") {
    auto response = healthy_status_response();
    response["result"]["routing_health"]["route_tables"][0]["table_id"] =
        static_cast<std::int64_t>(UINT32_MAX) + 1;

    CHECK_THROWS_WITH_AS(
        keen_pbr3::run_status_command(response),
        "invalid value for route table_id in status response",
        std::runtime_error);
}

TEST_CASE("status command returns nonzero for control errors") {
    CHECK(keen_pbr3::run_status_command(
              {{"ok", false},
               {"error",
                {{"code", "daemon_error"},
                 {"message", "status unavailable"}}}}) == 1);
}

TEST_CASE("status command reports an incompatible daemon response") {
    auto response = healthy_status_response();
    response["result"].erase("routing_runtime_active");

    CerrCapture capture;
    CHECK(keen_pbr3::run_status_command(response) == 1);
    CHECK(capture.str().find("incompatible daemon response") !=
          std::string::npos);
}
