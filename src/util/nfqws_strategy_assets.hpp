#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace keen_pbr3 {

struct NfqwsStrategyAssetSync {
    std::vector<std::string> installed;
    std::vector<std::string> preserved;
};

// Installs only assets named by the manifest. Existing regular files are
// preserved verbatim so package updates never overwrite nfqws2 or user data.
NfqwsStrategyAssetSync sync_nfqws_strategy_assets(
    const std::filesystem::path& manifest,
    const std::filesystem::path& source_directory,
    const std::filesystem::path& destination_directory);

} // namespace keen_pbr3
