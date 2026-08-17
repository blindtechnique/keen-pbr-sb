#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace keen_pbr3 {

struct NfqwsStrategyAssetSync {
    std::vector<std::string> installed;
    std::vector<std::string> preserved;
};

struct NfqwsStrategyAssetVerificationPath {
    std::string name;
    std::filesystem::path source;
    std::filesystem::path destination;
    // Existing live files win because sync preserves them.  Otherwise the
    // packaged source is safe for a read-only engine dry-run before install.
    std::filesystem::path verification_path;
};

// Resolves the exact files a strategy sync would use without creating or
// changing anything.  This lets candidate validation finish before the first
// live write.
std::vector<NfqwsStrategyAssetVerificationPath>
inspect_nfqws_strategy_assets(
    const std::filesystem::path& manifest,
    const std::filesystem::path& source_directory,
    const std::filesystem::path& destination_directory);

// Installs only assets named by the manifest. Existing regular files are
// preserved verbatim so package updates never overwrite nfqws2 or user data.
NfqwsStrategyAssetSync sync_nfqws_strategy_assets(
    const std::filesystem::path& manifest,
    const std::filesystem::path& source_directory,
    const std::filesystem::path& destination_directory);

} // namespace keen_pbr3
