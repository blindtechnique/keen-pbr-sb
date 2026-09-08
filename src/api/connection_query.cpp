#ifdef WITH_API

#include "connection_query.hpp"
#include "query_text.hpp"

#include <algorithm>
#include <string>

namespace keen_pbr3 {
namespace {

using query_text::lower_search_text;

bool equals_ci(const std::string& left, const std::string& right) {
    return lower_search_text(left) == lower_search_text(right);
}

bool contains_ci(const std::string& value, const std::string& needle) {
    return lower_search_text(value).find(lower_search_text(needle)) !=
           std::string::npos;
}

bool matches_search(const api::ConnectionRecord& record,
                    const std::string& search) {
    if (search.empty()) return true;
    if (contains_ci(record.source, search) ||
        contains_ci(record.destination, search) ||
        contains_ci(record.device, search) ||
        contains_ci(record.state, search) ||
        contains_ci(record.protocol, search) ||
        contains_ci(record.route, search)) {
        return true;
    }
    return std::any_of(
        record.destination_domains.begin(),
        record.destination_domains.end(),
        [&](const std::string& domain) {
            return contains_ci(domain, search);
        });
}

int compare_records(const api::ConnectionRecord& left,
                    const api::ConnectionRecord& right,
                    api::ConnectionSort sort) {
    switch (sort) {
    case api::ConnectionSort::FIRST_SEEN:
        if (left.first_seen != right.first_seen) {
            return left.first_seen < right.first_seen ? -1 : 1;
        }
        break;
    case api::ConnectionSort::SOURCE:
        if (left.source != right.source) {
            return left.source < right.source ? -1 : 1;
        }
        break;
    case api::ConnectionSort::DESTINATION:
        if (left.destination != right.destination) {
            return left.destination < right.destination ? -1 : 1;
        }
        break;
    case api::ConnectionSort::LAST_SEEN:
        if (left.last_seen != right.last_seen) {
            return left.last_seen < right.last_seen ? -1 : 1;
        }
        break;
    }
    if (left.id == right.id) return 0;
    return left.id < right.id ? -1 : 1;
}

} // namespace

std::vector<api::ConnectionRecord> filter_and_sort_connections(
    std::vector<api::ConnectionRecord> records,
    const api::ConnectionQueryRequest& request) {
    const bool active_only = request.active_only.value_or(true);
    const std::string search = request.search.value_or("");
    const std::string state = request.state.value_or("");
    const std::string route = request.route.value_or("");
    const std::string device = request.device.value_or("");

    records.erase(
        std::remove_if(
            records.begin(),
            records.end(),
            [&](const api::ConnectionRecord& record) {
                return (active_only && !record.active) ||
                       (!search.empty() && !matches_search(record, search)) ||
                       (!state.empty() && !equals_ci(record.state, state)) ||
                       (!route.empty() && !equals_ci(record.route, route)) ||
                       (!device.empty() &&
                        !contains_ci(record.device, device) &&
                        !contains_ci(record.source, device));
            }),
        records.end());

    const auto sort =
        request.sort.value_or(api::ConnectionSort::LAST_SEEN);
    const bool descending =
        request.order.value_or(api::SortOrder::DESC) == api::SortOrder::DESC;
    std::sort(
        records.begin(),
        records.end(),
        [&](const api::ConnectionRecord& left,
            const api::ConnectionRecord& right) {
            const int comparison = compare_records(left, right, sort);
            return descending ? comparison > 0 : comparison < 0;
        });
    return records;
}

} // namespace keen_pbr3

#endif // WITH_API
