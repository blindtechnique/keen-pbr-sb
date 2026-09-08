#pragma once

#ifdef WITH_API

#include "handlers.hpp"

namespace keen_pbr3 {

struct ListQueryOptions {
    std::int64_t offset{0};
    std::int64_t limit{50};
    std::string search;
    std::string sort{"id"};
    std::string order{"asc"};
};

ListQueryOptions parse_list_query_request(const std::string& body);
api::ListPage build_list_page(const VisibleConfigSnapshot& visible,
                             const ListQueryOptions& request);
// One existing atomic snapshot read, with no mutation admission or new owner.
api::ListPage query_lists(const ApiContext& ctx, const ListQueryOptions& request);
void register_lists_query_handler(ApiServer& server, ApiContext& ctx);

} // namespace keen_pbr3

#endif // WITH_API
