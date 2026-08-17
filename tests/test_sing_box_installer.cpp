#include <doctest/doctest.h>

#include "../src/update/sing_box_installer.hpp"

#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace keen_pbr3 {

namespace {

using Outcome = SingBoxInstallOutcome;
using Verdict = SingBoxReleaseVerdict;

constexpr const char* kVersion = "1.13.14";
constexpr const char* kArch = "arm64";
constexpr const char* kReleaseUrl = "https://api.example/releases/v1.13.14";
constexpr const char* kArchiveUrl =
    "https://dl.example/sing-box-1.13.14-linux-arm64.tar.gz";
constexpr const char* kChecksumsUrl =
    "https://dl.example/sing-box-1.13.14-checksums.txt";
constexpr const char* kArchiveBytes = "ARCHIVE";
constexpr const char* kArchiveDigest =
    "1111111111111111111111111111111111111111111111111111111111111111";

std::string release_json() {
    return nlohmann::json{
        {"assets",
         nlohmann::json::array(
             {{{"browser_download_url", kArchiveUrl}},
              {{"browser_download_url", kChecksumsUrl}}})}}
        .dump();
}

std::string checksums_text() {
    return std::string(kArchiveDigest) +
           "  sing-box-1.13.14-linux-arm64.tar.gz\n";
}

// A router where every step works. Individual tests break exactly one.
struct Harness {
    std::map<std::string, std::string> responses{
        {kReleaseUrl, release_json()},
        {kArchiveUrl, kArchiveBytes},
        {kChecksumsUrl, checksums_text()},
    };
    std::vector<std::string> performed;
    bool install_succeeds{true};
    bool marker_succeeds{true};
    std::string staged_version{kVersion};
    std::string staged_path{"/tmp/staged/sing-box"};

    SingBoxInstallSteps steps() {
        SingBoxInstallSteps steps;
        steps.fetch =
            [this](const std::string& url) -> std::optional<std::string> {
            performed.push_back("fetch:" + url);
            const auto found = responses.find(url);
            if (found == responses.end()) return std::nullopt;
            return found->second;
        };
        steps.digest = [](const std::string& bytes) {
            return bytes == kArchiveBytes ? std::string(kArchiveDigest)
                                          : std::string(64U, '0');
        };
        steps.stage_archive = [this](const std::string&) {
            performed.push_back("stage");
            return staged_path;
        };
        steps.read_staged_version = [this](const std::string&) {
            performed.push_back("read_version");
            return staged_version;
        };
        steps.install_atomically = [this](const std::string&) {
            performed.push_back("install");
            return install_succeeds;
        };
        steps.write_managed_marker = [this]() {
            performed.push_back("marker");
            return marker_succeeds;
        };
        return steps;
    }

    SingBoxInstallReport run() {
        return install_pinned_sing_box(steps(), kReleaseUrl, kVersion,
                                       kArch);
    }

    bool did(const std::string& step) const {
        for (const auto& performed_step : performed) {
            if (performed_step.rfind(step, 0U) == 0U) return true;
        }
        return false;
    }
};

} // namespace

TEST_CASE("a good release installs and records itself as ours") {
    Harness harness;
    const auto report = harness.run();
    CHECK(report.outcome == Outcome::installed);
    CHECK(report.staged_version == kVersion);
    CHECK(harness.did("install"));
    CHECK(harness.did("marker"));
}

TEST_CASE("nothing is unpacked until the digest matches") {
    // The whole point of the order: a release that fails verification never
    // reaches the filesystem, so a hostile or corrupt archive is never
    // unpacked at all.
    Harness harness;
    harness.responses[kChecksumsUrl] =
        std::string(64U, 'f') + "  sing-box-1.13.14-linux-arm64.tar.gz\n";
    const auto report = harness.run();

    CHECK(report.outcome == Outcome::checksum_mismatch);
    CHECK(report.release_verdict == Verdict::checksum_mismatch);
    CHECK_FALSE(harness.did("stage"));
    CHECK_FALSE(harness.did("install"));
}

TEST_CASE("a release with no checksums file installs nothing") {
    // The refusal that separates this path from install.sh, carried all the
    // way through the executor rather than only decided in the planner.
    Harness harness;
    harness.responses[kReleaseUrl] =
        nlohmann::json{
            {"assets",
             nlohmann::json::array(
                 {{{"browser_download_url", kArchiveUrl}}})}}
            .dump();
    const auto report = harness.run();

    CHECK(report.outcome == Outcome::release_refused);
    CHECK(report.release_verdict == Verdict::checksums_missing);
    CHECK_FALSE(harness.did("fetch:" + std::string(kArchiveUrl)));
    CHECK_FALSE(harness.did("stage"));
}

TEST_CASE("an unreachable checksums file is the same refusal as an absent one") {
    // Fetching the archive and failing to fetch its digest must not become a
    // reason to proceed. The archive is already in memory at that point,
    // which is exactly when the temptation exists.
    Harness harness;
    harness.responses.erase(kChecksumsUrl);
    const auto report = harness.run();

    CHECK(report.outcome == Outcome::download_failed);
    CHECK_FALSE(harness.did("stage"));
    CHECK_FALSE(harness.did("install"));
}

TEST_CASE("a verified archive that is not the pinned release is not installed") {
    // The archive matched its published digest and still contains the wrong
    // build. Upstream's problem; catching it before the swap is ours, and the
    // check runs on the staged copy so the running binary is still the old one
    // when it fails.
    Harness harness;
    harness.staged_version = "1.12.0";
    const auto report = harness.run();

    CHECK(report.outcome == Outcome::staged_version_mismatch);
    CHECK(report.staged_version == "1.12.0");
    CHECK(harness.did("stage"));
    CHECK_FALSE(harness.did("install"));
}

TEST_CASE("a binary that will not say its version is not installed either") {
    Harness harness;
    harness.staged_version.clear();
    const auto report = harness.run();
    CHECK(report.outcome == Outcome::staged_version_mismatch);
    CHECK_FALSE(harness.did("install"));
}

TEST_CASE("an archive that yields no binary stops before the swap") {
    Harness harness;
    harness.staged_path.clear();
    const auto report = harness.run();
    CHECK(report.outcome == Outcome::archive_unusable);
    CHECK_FALSE(harness.did("read_version"));
    CHECK_FALSE(harness.did("install"));
}

TEST_CASE("a failed install leaves the marker unwritten") {
    // The marker says "this binary is ours". Writing it for a binary that was
    // never put in place would make the next capability read offer to replace
    // a file this daemon does not own.
    Harness harness;
    harness.install_succeeds = false;
    const auto report = harness.run();
    CHECK(report.outcome == Outcome::install_failed);
    CHECK_FALSE(harness.did("marker"));
}

TEST_CASE("an installed binary without its marker is neither success nor failure") {
    // The binary is in place and correct; only its provenance record is
    // missing. Calling that success hides that the next capability read will
    // treat this binary as the operator's and refuse to touch it.
    Harness harness;
    harness.marker_succeeds = false;
    const auto report = harness.run();
    CHECK(report.outcome == Outcome::marker_not_written);
    CHECK(harness.did("install"));
}

TEST_CASE("an installer assembled without its steps installs nothing") {
    SingBoxInstallSteps incomplete;
    incomplete.fetch = [](const std::string&) {
        return std::optional<std::string>{release_json()};
    };
    const auto report = install_pinned_sing_box(incomplete, kReleaseUrl,
                                                kVersion, kArch);
    CHECK(report.outcome == Outcome::install_failed);
}

TEST_CASE("every outcome has a name") {
    for (const auto outcome :
         {Outcome::installed, Outcome::release_refused,
          Outcome::download_failed, Outcome::checksum_mismatch,
          Outcome::archive_unusable, Outcome::staged_version_mismatch,
          Outcome::install_failed, Outcome::marker_not_written}) {
        CHECK(std::string(sing_box_install_outcome_name(outcome)).size() >
              0U);
    }
}

} // namespace keen_pbr3
