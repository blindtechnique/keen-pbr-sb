#pragma once

#include <cstdint>

namespace keen_pbr3 {

enum class NdmsCatalogCacheStatus : std::uint8_t {
    fresh,
    stale,
    unavailable,
};

} // namespace keen_pbr3
