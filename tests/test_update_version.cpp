#include <doctest/doctest.h>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <sys/stat.h>

#include "api/update_version.hpp"

using keen_pbr3::format_fork_version;
using keen_pbr3::is_newer_fork_version;
using keen_pbr3::safe_github_tag;
using keen_pbr3::published_fork_version;
using keen_pbr3::release_matches_channel;
using keen_pbr3::select_channel_release;
using keen_pbr3::release_cache_matches_channel;

TEST_CASE("update channel preference is durable and independent of the package marker") {
    char pattern[] = "/tmp/kpbr-update-channel-XXXXXX";
    const char* created = ::mkdtemp(pattern);
    REQUIRE(created != nullptr);
    const std::filesystem::path root(created);
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() { std::filesystem::remove_all(path); }
    } cleanup{root};
    const auto preference = root / "etc/update-channel";
    CHECK_FALSE(keen_pbr3::read_update_channel(preference).has_value());
    keen_pbr3::save_update_channel(preference, "alpha");
    CHECK(keen_pbr3::read_update_channel(preference) == "alpha");
    keen_pbr3::save_update_channel(preference, "stable");
    CHECK(keen_pbr3::read_update_channel(preference) == "stable");
    CHECK_THROWS(keen_pbr3::save_update_channel(preference, "next"));
    CHECK(keen_pbr3::read_update_channel(preference) == "stable");
    struct stat st {};
    REQUIRE(::stat(preference.c_str(), &st) == 0);
    CHECK((st.st_mode & 0777) == 0600);
    for (const auto value : {"", "beta\n", "stable\nalpha", "stable\n\n"}) {
        { std::ofstream output(preference); output << value; }
        CHECK_THROWS(keen_pbr3::read_update_channel(preference));
    }
    const auto link = root / "symlink";
    std::filesystem::create_symlink(preference, link);
    CHECK_THROWS(keen_pbr3::save_update_channel(link, "alpha"));
    CHECK_THROWS(keen_pbr3::read_update_channel(root));
}

TEST_CASE("channel changes never authorize a downgrade or hide timestamp updates") {
    using keen_pbr3::channel_release_installable;
    const std::string current = "v3.3.2-20260918174010";
    CHECK(channel_release_installable(current, "v3.3.2-20260918174022", "alpha", "alpha"));
    CHECK(channel_release_installable(current, "v3.3.2-20260918174022", "alpha", "stable"));
    CHECK(channel_release_installable(current, current, "alpha", "stable"));
    CHECK_FALSE(channel_release_installable(current, current, "alpha", "alpha"));
    CHECK_FALSE(channel_release_installable(current, "v3.3.2-20260918093748", "alpha", "stable"));
    CHECK_FALSE(channel_release_installable(current, "", "alpha", "alpha"));
    CHECK_FALSE(channel_release_installable("broken", current, "alpha", "stable"));
    CHECK_FALSE(channel_release_installable(current, current, "", "stable"));
    CHECK_FALSE(channel_release_installable(current, current, "alpha", "next"));
}

namespace {
nlohmann::json published_release(const std::string& tag) {
    return {{"tag_name", tag}, {"draft", false},
            {"prerelease", tag.compare(0, 6, "alpha-") == 0},
            {"assets", {{{"name",
                "keen-pbr_3.3.2-20260918174010_keenetic_aarch64-3.10.ipk"}}}}};
}
}

TEST_CASE("Alpha discovery selects numeric run and attempt, never main Latest") {
    const auto stable = published_release("v3.3.2-20260918174022");
    const auto older = published_release("alpha-99-9");
    const auto latest = published_release("alpha-100-10");
    auto draft = published_release("alpha-101-1");
    draft["draft"] = true;
    const auto selected = select_channel_release(
        nlohmann::json::array({stable, draft, published_release("alpha-100-2"),
                               older, latest}), "alpha");
    CHECK(selected == latest);
    CHECK_FALSE(is_newer_fork_version(published_fork_version(selected),
                                     "v3.3.2-20260918174010"));
    CHECK(select_channel_release(nlohmann::json::array({stable}), "alpha").empty());
    CHECK(select_channel_release(stable, "alpha").empty());
    CHECK(select_channel_release(latest, "stable").empty());
    CHECK(select_channel_release(stable, "stable") == stable);
}

TEST_CASE("release channel validation fails closed on missing or malformed metadata") {
    for (const auto tag : {"alpha-", "alpha-12-", "alpha-x-1", "alpha-1-2-extra",
                          "alpha-18446744073709551616-1", "next-100-1"}) {
        CHECK_FALSE(release_matches_channel(published_release(tag), "alpha"));
    }
    auto release = published_release("alpha-100-1");
    CHECK_FALSE(release_matches_channel(release, ""));
    release["draft"] = "false";
    CHECK_FALSE(release_matches_channel(release, "alpha"));
    release.erase("draft");
    CHECK_FALSE(release_matches_channel(release, "alpha"));
    CHECK_FALSE(release_matches_channel(nullptr, "alpha"));
}

TEST_CASE("release cache cannot cross channels even on a network failure") {
    nlohmann::json cache = {{"release", published_release("v3.3.2-20260918174022")},
                            {"cached_at", 12345}};
    CHECK_FALSE(release_cache_matches_channel(cache, "alpha"));
    cache["channel"] = "stable";
    CHECK_FALSE(release_cache_matches_channel(cache, "alpha"));
    cache["channel"] = "alpha";
    CHECK_FALSE(release_cache_matches_channel(cache, "alpha"));
    cache["release"] = published_release("alpha-100-1");
    CHECK(release_cache_matches_channel(cache, "alpha"));
    CHECK_FALSE(release_cache_matches_channel(cache, "stable"));
    cache["release"]["assets"] = nlohmann::json::array();
    CHECK_FALSE(release_cache_matches_channel(cache, "alpha"));
    CHECK_FALSE(release_cache_matches_channel(nullptr, "alpha"));
}

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
