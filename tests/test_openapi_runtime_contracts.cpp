#include <doctest/doctest.h>

#include "../src/api/generated/api_types.hpp"

#include <nlohmann/json.hpp>

#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>

namespace keen_pbr3 {
namespace {

std::string openapi_document() {
    std::ifstream input(KEEN_PBR_OPENAPI_PATH, std::ios::binary);
    if (!input.good()) {
        throw std::runtime_error("cannot open docs/openapi.yaml");
    }
    return {std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
}

std::string_view yaml_block(const std::string& document,
                            std::string_view heading,
                            std::string_view next_heading_prefix) {
    const auto begin = document.find(heading);
    if (begin == std::string::npos) {
        throw std::runtime_error("OpenAPI heading not found");
    }
    const auto next = document.find(next_heading_prefix, begin + heading.size());
    return std::string_view(document).substr(
        begin, next == std::string::npos ? std::string::npos : next - begin);
}

void check_status(const std::string& document,
                  std::string_view path,
                  std::string_view status) {
    const auto block = yaml_block(document, path, "\n  /api/");
    CHECK(block.find(status) != std::string_view::npos);
}

}  // namespace

TEST_CASE("OpenAPI advertises runtime auth and exit-check statuses") {
    const auto document = openapi_document();
    check_status(document, "  /api/auth/login:\n", "\n        \"429\":");
    check_status(document, "  /api/auth/step-up:\n", "\n        \"429\":");
    check_status(document, "  /api/auth/step-up:\n", "\n        \"503\":");
    check_status(document, "  /api/auth/settings:\n", "\n        \"500\":");
    check_status(document, "  /api/transports/exit-check:\n", "\n        \"503\":");
}

TEST_CASE("OpenAPI response schemas match runtime body shapes") {
    const auto document = openapi_document();

    const auto auth = yaml_block(
        document, "    AuthSettingsResponse:\n", "\n    OkResponse:");
    CHECK(auth.find("required: [saved, durable]") != std::string_view::npos);
    CHECK(auth.find("remote_access_pending:") != std::string_view::npos);
    CHECK(auth.find("restart_required:") != std::string_view::npos);

    const auto granted = yaml_block(
        document, "    GrantedResponse:\n", "\n    AuthCredentials:");
    CHECK(granted.find("expires_in_seconds:") != std::string_view::npos);

    const auto backup = yaml_block(
        document, "    BackupDocument:\n", "\n    BackupRollbackAvailability:");
    CHECK(backup.find("created_at:") != std::string_view::npos);
    CHECK(backup.find("groups:") != std::string_view::npos);
    const auto outbounds = backup.find("outbounds:");
    REQUIRE(outbounds != std::string_view::npos);
    CHECK(backup.find("type: array", outbounds) != std::string_view::npos);

    const auto sing_box_install = yaml_block(
        document, "    SingBoxInstallResult:\n", "\n    SingBoxProcessMode:");
    CHECK(sing_box_install.find("durable:") != std::string_view::npos);
    CHECK(sing_box_install.find("Present only after the binary replacement committed") !=
          std::string_view::npos);
}

TEST_CASE("generated auth settings response accepts the runtime body") {
    const nlohmann::json runtime_body{
        {"saved", true},
        {"durable", false},
        {"remote_access_pending", true},
        {"remote_access_generation", 17},
        {"restart_required", true},
        {"runtime_auth_enabled", true},
        {"restart_detail", "authentication remains enabled until restart"},
        {"warning", "authentication remains enabled until restart"},
    };

    const auto response = runtime_body.get<api::AuthSettingsResponse>();
    CHECK(response.saved);
    CHECK_FALSE(response.durable);
    REQUIRE(response.remote_access_pending.has_value());
    CHECK(*response.remote_access_pending);
    REQUIRE(response.remote_access_generation.has_value());
    CHECK(*response.remote_access_generation == 17);
    REQUIRE(response.restart_required.has_value());
    CHECK(*response.restart_required);
    REQUIRE(response.runtime_auth_enabled.has_value());
    CHECK(*response.runtime_auth_enabled);
    REQUIRE(response.restart_detail.has_value());
    CHECK_FALSE(response.restart_detail->empty());
}

TEST_CASE("generated step-up response keeps the runtime grant TTL") {
    const nlohmann::json runtime_body{
        {"granted", true},
        {"expires_in_seconds", 300},
    };

    const auto response = runtime_body.get<api::GrantedResponse>();
    CHECK(response.granted);
    REQUIRE(response.expires_in_seconds.has_value());
    CHECK(*response.expires_in_seconds == 300);
}

TEST_CASE("generated sing-box install result keeps a non-durable commit") {
    const nlohmann::json runtime_body{
        {"install_outcome", "installed"},
        {"pinned_version", "1.13.14"},
        {"durable", false},
    };

    const auto response = runtime_body.get<api::SingBoxInstallResult>();
    CHECK(response.install_outcome == api::InstallOutcome::INSTALLED);
    REQUIRE(response.durable.has_value());
    CHECK_FALSE(*response.durable);

    const nlohmann::json round_trip = response;
    REQUIRE(round_trip.contains("durable"));
    CHECK_FALSE(round_trip.at("durable").get<bool>());
}

TEST_CASE("generated backup response accepts runtime outbound arrays") {
    const nlohmann::json runtime_body{
        {"format", "keen-pbr-sb-backup"},
        {"schema", 1},
        {"created_at", 1776632400},
        {"groups", {{"outbounds", true}}},
        {"data",
         {{"outbounds",
           nlohmann::json::array({
               {{"type", "table"},
                {"tag", "wan"},
                {"table", 254}},
           })}}},
    };

    const auto response = runtime_body.get<api::BackupDocument>();
    REQUIRE(response.created_at.has_value());
    CHECK(*response.created_at == 1776632400);
    REQUIRE(response.data.outbounds.has_value());
    REQUIRE(response.data.outbounds->size() == 1U);
    const auto& outbound = response.data.outbounds->front();
    CHECK(outbound.at("tag").get<std::string>() == "wan");
    CHECK(outbound.at("table").get<int>() == 254);
}

}  // namespace keen_pbr3
