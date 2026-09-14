#pragma once

#include "../config/config.hpp"

#include <chrono>
#include <cstddef>

namespace keen_pbr3 {

class CacheManager;

// Budgets for this optional read-only report, never for apply or routing.
struct ListHintsLimits {
    std::size_t entries{100000};
    std::size_t index_owners{100000};
    std::size_t input_bytes{8U * 1024U * 1024U};
    std::size_t file_bytes{2U * 1024U * 1024U};
    std::size_t hints{100};
    std::chrono::milliseconds elapsed{2000};
};

api::ListHintsResponse build_list_hints(const Config& config,
                                      const CacheManager* cache = nullptr,
                                      ListHintsLimits limits = {});

} // namespace keen_pbr3
