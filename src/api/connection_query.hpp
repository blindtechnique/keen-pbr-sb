#pragma once

#ifdef WITH_API

#include "generated/api_types.hpp"

#include <vector>

namespace keen_pbr3 {

std::vector<api::ConnectionRecord> filter_and_sort_connections(
    std::vector<api::ConnectionRecord> records,
    const api::ConnectionQueryRequest& request);

} // namespace keen_pbr3

#endif // WITH_API
