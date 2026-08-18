#include "sing_box_release_plan.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>

#include <nlohmann/json.hpp>

namespace keen_pbr3 {

namespace {

bool lowercase_sha256(const std::string& value) {
    if (value.size() != 64U) return false;
    return std::all_of(value.begin(), value.end(), [](const char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}

// The last path segment of an asset URL. Matching on the whole URL would let
// a query string or a mirror prefix decide which asset was chosen.
std::string url_file_name(const std::string& url) {
    const auto slash = url.find_last_of('/');
    if (slash == std::string::npos) return url;
    return url.substr(slash + 1U);
}

} // namespace

const char* sing_box_release_verdict_name(
    const SingBoxReleaseVerdict verdict) noexcept {
    switch (verdict) {
    case SingBoxReleaseVerdict::ready:
        return "ready";
    case SingBoxReleaseVerdict::release_unreadable:
        return "release_unreadable";
    case SingBoxReleaseVerdict::archive_missing:
        return "archive_missing";
    case SingBoxReleaseVerdict::checksums_missing:
        return "checksums_missing";
    case SingBoxReleaseVerdict::checksum_unusable:
        return "checksum_unusable";
    case SingBoxReleaseVerdict::checksum_mismatch:
        return "checksum_mismatch";
    }
    return "release_unreadable";
}

std::string sing_box_archive_name(const std::string& version,
                                  const std::string& asset_architecture) {
    if (version.empty() || asset_architecture.empty()) return {};
    return "sing-box-" + version + "-linux-" + asset_architecture +
           ".tar.gz";
}

SingBoxReleasePlan plan_sing_box_release(
    const std::string& release_json,
    const std::string& version,
    const std::string& asset_architecture) {
    SingBoxReleasePlan plan;
    plan.archive_name = sing_box_archive_name(version, asset_architecture);
    if (plan.archive_name.empty()) return plan;

    const auto document =
        nlohmann::json::parse(release_json, nullptr, false);
    if (document.is_discarded() || !document.is_object()) return plan;
    const auto assets = document.find("assets");
    if (assets == document.end() || !assets->is_array()) return plan;

    // The checksums file carries the release version in its name, which the
    // caller has no reason to know; it is recognised by suffix instead. The
    // archive is matched by its EXACT name, because a substring match on
    // "linux-arm64" would also accept an asset for a different variant, and
    // installing the wrong architecture is the failure this whole path exists
    // to avoid.
    for (const auto& asset : *assets) {
        if (!asset.is_object()) continue;
        const auto url = asset.value("browser_download_url", std::string{});
        if (url.empty()) continue;
        const auto name = url_file_name(url);
        if (name == plan.archive_name) {
            plan.archive_url = url;
            // GitHub publishes "sha256:<hex>" here. Any other algorithm is
            // ignored rather than guessed at: this planner compares SHA-256,
            // and treating an unknown prefix as one would compare a digest
            // against a different function's output and call the mismatch a
            // corrupt download.
            const auto digest =
                asset.value("digest", std::string{});
            constexpr const char* kPrefix = "sha256:";
            if (digest.rfind(kPrefix, 0U) == 0U) {
                auto hex = digest.substr(std::strlen(kPrefix));
                if (lowercase_sha256(hex)) plan.asset_digest = std::move(hex);
            }
        } else if (name.size() > 14U &&
                   name.compare(name.size() - 14U, 14U,
                                "-checksums.txt") == 0 &&
                   name.rfind("sing-box-", 0U) == 0U) {
            plan.checksums_url = url;
        }
    }

    if (plan.archive_url.empty()) {
        plan.verdict = SingBoxReleaseVerdict::archive_missing;
        return plan;
    }
    if (plan.checksums_url.empty() && plan.asset_digest.empty()) {
        // Refused, not downgraded. A browser button must not be softer than
        // the command an operator types - and with neither source there is
        // nothing to compare the download against at all.
        plan.verdict = SingBoxReleaseVerdict::checksums_missing;
        return plan;
    }
    plan.verdict = SingBoxReleaseVerdict::ready;
    return plan;
}

std::string published_archive_digest(const std::string& checksums_text,
                                     const std::string& archive_name) {
    if (archive_name.empty()) return {};
    std::istringstream lines(checksums_text);
    std::string line;
    while (std::getline(lines, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::istringstream fields(line);
        std::string digest;
        std::string name;
        if (!(fields >> digest >> name)) continue;
        std::string extra;
        // A third field means this is not the format it looks like, and
        // guessing which two of three columns to believe is not a decision
        // worth making about a checksum.
        if (fields >> extra) continue;
        // sha256sum writes '*' before the name in binary mode.
        if (!name.empty() && name.front() == '*') name.erase(0U, 1U);
        if (name != archive_name) continue;
        return lowercase_sha256(digest) ? digest : std::string{};
    }
    return {};
}

SingBoxReleaseVerdict verify_sing_box_archive(
    const std::string& checksums_text,
    const std::string& archive_name,
    const std::string& actual_digest) {
    const auto expected =
        published_archive_digest(checksums_text, archive_name);
    if (expected.empty()) return SingBoxReleaseVerdict::checksum_unusable;
    // No guard on the shape of `actual_digest`: `expected` is already a
    // validated 64-character lowercase digest, so anything that is not one
    // cannot equal it. A check that cannot fail would imply a protection this
    // comparison does not need, and the test below pins the property instead.
    return expected == actual_digest
               ? SingBoxReleaseVerdict::ready
               : SingBoxReleaseVerdict::checksum_mismatch;
}

} // namespace keen_pbr3
