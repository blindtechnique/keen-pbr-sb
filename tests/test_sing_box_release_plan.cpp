#include <doctest/doctest.h>

#include "../src/update/sing_box_release_plan.hpp"

#include <string>

#include <nlohmann/json.hpp>

namespace keen_pbr3 {

namespace {

using Verdict = SingBoxReleaseVerdict;

constexpr const char* kVersion = "1.13.14";
constexpr const char* kArch = "arm64";
constexpr const char* kDigest =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

std::string release_with(const std::vector<std::string>& asset_names) {
    nlohmann::json assets = nlohmann::json::array();
    for (const auto& name : asset_names) {
        assets.push_back(
            {{"browser_download_url",
              "https://github.com/SagerNet/sing-box/releases/download/"
              "v1.13.14/" +
                  name}});
    }
    return nlohmann::json{{"assets", assets}}.dump();
}

// What the release actually carries: one archive per architecture plus one
// checksums file for all of them.
std::string real_release() {
    return release_with({
        "sing-box-1.13.14-linux-amd64.tar.gz",
        "sing-box-1.13.14-linux-arm64.tar.gz",
        "sing-box-1.13.14-linux-armv7.tar.gz",
        "sing-box-1.13.14-linux-mipsle.tar.gz",
        "sing-box-1.13.14-checksums.txt",
    });
}

} // namespace

TEST_CASE("the archive is named, not pattern-matched") {
    CHECK(sing_box_archive_name(kVersion, kArch) ==
          "sing-box-1.13.14-linux-arm64.tar.gz");
    CHECK(sing_box_archive_name("", kArch).empty());
    CHECK(sing_box_archive_name(kVersion, "").empty());
}

TEST_CASE("a real release yields both URLs") {
    const auto plan =
        plan_sing_box_release(real_release(), kVersion, kArch);
    CHECK(plan.verdict == Verdict::ready);
    CHECK(plan.archive_name == "sing-box-1.13.14-linux-arm64.tar.gz");
    CHECK(plan.archive_url.rfind("https://github.com/", 0U) == 0U);
    CHECK(plan.archive_url.find("linux-arm64.tar.gz") !=
          std::string::npos);
    CHECK(plan.checksums_url.find("checksums.txt") != std::string::npos);
}

TEST_CASE("the archive must match exactly, not by substring") {
    // A release carrying a neighbouring variant must not satisfy a request
    // for arm64. Installing the wrong architecture is the failure this whole
    // path exists to avoid, and it fails at runtime rather than at install.
    const auto plan = plan_sing_box_release(
        release_with({"sing-box-1.13.14-linux-arm64v8.tar.gz",
                      "sing-box-1.13.14-linux-arm64.tar.gz.sig",
                      "sing-box-1.13.14-checksums.txt"}),
        kVersion, kArch);
    CHECK(plan.verdict == Verdict::archive_missing);
    CHECK(plan.archive_url.empty());
}

TEST_CASE("a release with no checksums file is refused, not downgraded") {
    // The rule install.sh does not have. It verifies only when a checksums
    // file exists, so a release without one installs unverified - defensible
    // for a command an operator typed, not for a button in a browser.
    const auto plan = plan_sing_box_release(
        release_with({"sing-box-1.13.14-linux-arm64.tar.gz"}), kVersion,
        kArch);
    CHECK(plan.verdict == Verdict::checksums_missing);
    CHECK_FALSE(plan.archive_url.empty());
    CHECK(plan.checksums_url.empty());
}

TEST_CASE("a release document that is not one is unreadable") {
    for (const char* body :
         {"", "not json", "[]", "null", R"({"assets": {}})",
          R"({"assets": []})", R"({})"}) {
        const auto plan = plan_sing_box_release(body, kVersion, kArch);
        CHECK((plan.verdict == Verdict::release_unreadable ||
               plan.verdict == Verdict::archive_missing));
        CHECK(plan.archive_url.empty());
    }
}

TEST_CASE("the digest is read for our archive and no other") {
    const std::string checksums =
        std::string(kDigest) + "  sing-box-1.13.14-linux-amd64.tar.gz\n" +
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "  sing-box-1.13.14-linux-arm64.tar.gz\n";
    CHECK(published_archive_digest(
              checksums, "sing-box-1.13.14-linux-arm64.tar.gz") ==
          "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
          "ff");
    CHECK(published_archive_digest(
              checksums, "sing-box-1.13.14-linux-mipsle.tar.gz")
              .empty());
}

TEST_CASE("the binary-mode star sha256sum writes is accepted") {
    const std::string checksums =
        std::string(kDigest) + " *sing-box-1.13.14-linux-arm64.tar.gz\n";
    CHECK(published_archive_digest(
              checksums, "sing-box-1.13.14-linux-arm64.tar.gz") == kDigest);
}

TEST_CASE("a checksums line that is not one yields nothing") {
    const std::string name = "sing-box-1.13.14-linux-arm64.tar.gz";
    for (const std::string& text :
         {std::string{}, std::string("garbage\n"),
          // Digest that is not SHA-256.
          std::string("abc  ") + name + "\n",
          std::string(64U, 'A') + "  " + name + "\n",
          // A third column: not the format it looks like, and choosing which
          // two of three to believe is not a decision to make about a
          // checksum.
          std::string(kDigest) + "  " + name + "  extra\n",
          // The name only.
          name + "\n"}) {
        CHECK(published_archive_digest(text, name).empty());
    }
}

TEST_CASE("verification approves only bytes that match the published digest") {
    const std::string name = "sing-box-1.13.14-linux-arm64.tar.gz";
    const std::string checksums = std::string(kDigest) + "  " + name + "\n";

    CHECK(verify_sing_box_archive(checksums, name, kDigest) ==
          Verdict::ready);
    CHECK(verify_sing_box_archive(checksums, name, std::string(64U, 'f')) ==
          Verdict::checksum_mismatch);
    // No published digest at all: unusable, and unusable is not a pass.
    CHECK(verify_sing_box_archive("", name, kDigest) ==
          Verdict::checksum_unusable);
    // The one thing this must never do is approve bytes nobody hashed.
    for (const char* unhashed : {"", "not-a-digest", "0123456789abcdef"}) {
        CHECK(verify_sing_box_archive(checksums, name, unhashed) ==
              Verdict::checksum_mismatch);
    }
}

TEST_CASE("every verdict has a name") {
    for (const auto verdict :
         {Verdict::ready, Verdict::release_unreadable,
          Verdict::archive_missing, Verdict::checksums_missing,
          Verdict::checksum_unusable, Verdict::checksum_mismatch}) {
        CHECK(std::string(sing_box_release_verdict_name(verdict)).size() >
              0U);
    }
}

} // namespace keen_pbr3
