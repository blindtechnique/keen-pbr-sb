#include <doctest/doctest.h>
#include <nlohmann/json.hpp>

#include "api/update_version.hpp"

using keen_pbr3::format_fork_version;
using keen_pbr3::is_newer_fork_version;
using keen_pbr3::safe_github_tag;
using keen_pbr3::published_fork_version;

TEST_CASE("fork release comparison does not offer downgrades") {
    CHECK(is_newer_fork_version("v3.0.7-sb.4", "v3.0.7-sb.3"));
    CHECK_FALSE(is_newer_fork_version("v3.0.7-sb.3", "v3.0.7-sb.4"));
    CHECK_FALSE(is_newer_fork_version("v3.0.7-sb.4", "v3.0.7-sb.4"));
}

TEST_CASE("fork release comparison supports historical and future tags") {
    CHECK(is_newer_fork_version("v3.0.7-sb.3", "3.0.7-sb1"));
    CHECK(is_newer_fork_version("v3.0.8-sb.1", "v3.0.7-sb.99"));
    CHECK(is_newer_fork_version("v4.0-sb.1", "v3.99.99-sb.99"));
    CHECK_FALSE(is_newer_fork_version("not-a-version", "v3.0.7-sb.4"));
}

TEST_CASE("fork release comparison supports timestamp identities") {
    CHECK(format_fork_version("3.3.0", "20260827010101") ==
          "v3.3.0-20260827010101");
    CHECK(is_newer_fork_version("v3.3.0-20260827020202",
                                "v3.3.0-20260827010101"));
    CHECK_FALSE(is_newer_fork_version("v3.3.0-20260827010101",
                                      "v3.3.0-20260827020202"));
    CHECK(is_newer_fork_version("v3.3.0-20260827010101",
                                "v3.3.0-sb.12"));
    CHECK(is_newer_fork_version("v3.3.1-sb.1",
                                "v3.3.0-20260827010101"));
}

TEST_CASE("stable compatibility tags use the actual IPK build for discovery") {
    const nlohmann::json release = {
        {"tag_name", "v3.3.0-sb.13"},
        {"assets", {{{"name", "keen-pbr_3.3.0-20260910123456_keenetic_aarch64-3.10.ipk"}},
                    {{"name", "keen-pbr_3.3.0-20260910123456_keenetic_mips-3.4.ipk"}},
                    {{"name", "keen-pbr_3.3.0-20260910123456_keenetic_mipsel-3.4.ipk"}},
                    {{"name", "install.sh"}}, {{"name", "release-manifest.tsv"}}}}};
    const auto latest = published_fork_version(release);
    CHECK(latest == "v3.3.0-20260910123456");
    CHECK(is_newer_fork_version(latest, "v3.0.7-sb.11"));
    CHECK(is_newer_fork_version(latest, "v3.3.0-20260909133844"));
    CHECK_FALSE(is_newer_fork_version(latest, latest));
    CHECK_FALSE(is_newer_fork_version(latest, "v3.3.0-20260911123456"));
    CHECK(release["tag_name"] == "v3.3.0-sb.13");
}

TEST_CASE("timestamp releases offer newer builds without changing the base version") {
    const nlohmann::json release = {
        {"tag_name", "v3.3.2-20260910120000"},
        {"assets", {{{"name", "keen-pbr_3.3.2-20260910120000_keenetic_aarch64-3.10.ipk"}},
                    {{"name", "keen-pbr_3.3.2-20260910120000_keenetic_mips-3.4.ipk"}},
                    {{"name", "keen-pbr_3.3.2-20260910120000_keenetic_mipsel-3.4.ipk"}}}}};
    const auto latest = published_fork_version(release);
    CHECK(latest == "v3.3.2-20260910120000");
    // Previously published intermediate release and locally accepted fix.
    CHECK(is_newer_fork_version(latest, "v3.3.2-20260909233706"));
    CHECK(is_newer_fork_version(latest, "v3.3.2-20260910095526"));
    CHECK_FALSE(is_newer_fork_version(latest, latest));
    CHECK_FALSE(is_newer_fork_version(latest, "v3.3.2-20260911120000"));
    CHECK_FALSE(is_newer_fork_version(latest, "v3.3.3-20260910090000"));
}

TEST_CASE("legacy releases and metadata without package names remain readable") {
    CHECK(published_fork_version({{"tag_name", "v3.0.7-sb.11"},
                                  {"assets", {{{"name", "keen-pbr_3.0.7-11_keenetic_mips-3.4.ipk"}}}}})
          == "v3.0.7-11");
    CHECK(published_fork_version({{"tag_name", "v3.0.7-sb.11"}})
          == "v3.0.7-sb.11");
    CHECK(published_fork_version({{"tag_name", "v3.3.0-20260910123456"}})
          == "v3.3.0-20260910123456");
}

TEST_CASE("update discovery ignores unrelated assets and malformed metadata") {
    CHECK(published_fork_version(nullptr).empty());
    CHECK(published_fork_version(nlohmann::json::array()).empty());
    CHECK(published_fork_version({{"tag_name", 42}, {"assets", "invalid"}}).empty());
    CHECK(published_fork_version({{"tag_name", "not-a-version"}}).empty());
    CHECK(published_fork_version({{"tag_name", "v3.3.0-sb.12"},
        {"assets", {nullptr, 42, {{"name", false}},
            {{"name", "keen-pbr-headless_9.0.0-99_keenetic_mips-3.4.ipk"}},
            {{"name", "keen-pbr_9.0.0-99_openwrt_mips.ipk"}},
            {{"name", "keen-pbr_invalid_keenetic_mips-3.4.ipk"}},
            {{"name", "keen-pbr_3.3.0-20260909133844_keenetic_mips-3.4.ipk.debug"}}}}})
        == "v3.3.0-sb.12");
}

TEST_CASE("mixed architecture versions cannot produce an arbitrary update offer") {
    nlohmann::json release = {{"tag_name", "v3.3.0-sb.12"},
        {"assets", {{{"name", "keen-pbr_3.3.0-20260909133844_keenetic_mips-3.4.ipk"}},
                    {{"name", "keen-pbr_3.3.0-20260910123456_keenetic_aarch64-3.10.ipk"}}}}};
    CHECK(published_fork_version(release).empty());
    std::swap(release["assets"][0], release["assets"][1]);
    CHECK(published_fork_version(release).empty());
}

TEST_CASE("only path-safe GitHub tags are accepted for changelog links") {
    CHECK(safe_github_tag("v3.0.7-sb.4"));
    CHECK(safe_github_tag("3.0.7-sb1"));
    CHECK(safe_github_tag("v3.3.0-20260827010101"));
    CHECK_FALSE(safe_github_tag("v3.0.7/../../main"));
    CHECK_FALSE(safe_github_tag(""));
}
