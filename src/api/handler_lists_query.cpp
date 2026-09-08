#ifdef WITH_API

#include "handler_lists_query.hpp"
#include "query_text.hpp"

#include <algorithm>
#include <limits>
#include <map>
#include <sstream>
#include <string_view>

namespace keen_pbr3 {
namespace {

using query_text::lower_search_text;

void validate_query(const ListQueryOptions& request) {
    if (request.offset < 0 || request.limit < 1 || request.limit > 200) {
        throw ApiError("Invalid list query page bounds", 400);
    }
    const auto characters = std::count_if(
        request.search.begin(), request.search.end(), [](unsigned char ch) {
            return (ch & 0xC0U) != 0x80U;
        });
    if (characters > 256) {
        throw ApiError("List query search is too long", 400);
    }
    if (request.sort != "id" && request.sort != "name" && request.sort != "source") {
        throw ApiError("Invalid list query sort", 400);
    }
    if (request.order != "asc" && request.order != "desc") {
        throw ApiError("Invalid list query order", 400);
    }
}

std::string trimmed_name(const std::optional<std::string>& name,
                         const std::string& fallback) {
    if (!name) return fallback;
    const auto first = name->find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return fallback;
    const auto last = name->find_last_not_of(" \t\r\n");
    return name->substr(first, last - first + 1);
}

// Compare digit runs without conversion, so long numbers cannot overflow.
int natural_compare(std::string_view left, std::string_view right) {
    std::size_t l = 0, r = 0;
    const auto digit = [](char ch) { return ch >= '0' && ch <= '9'; };
    while (l < left.size() && r < right.size()) {
        if (digit(left[l]) && digit(right[r])) {
            auto le = l, re = r;
            while (le < left.size() && digit(left[le])) ++le;
            while (re < right.size() && digit(right[re])) ++re;
            auto ln = l, rn = r;
            while (ln < le && left[ln] == '0') ++ln;
            while (rn < re && right[rn] == '0') ++rn;
            if (le - ln != re - rn) return le - ln < re - rn ? -1 : 1;
            const auto comparison = left.substr(ln, le - ln).compare(
                right.substr(rn, re - rn));
            if (comparison != 0) return comparison < 0 ? -1 : 1;
            l = le;
            r = re;
            continue;
        }
        const auto lc = static_cast<unsigned char>(left[l]);
        const auto rc = static_cast<unsigned char>(right[r]);
        if (lc != rc) return lc < rc ? -1 : 1;
        ++l;
        ++r;
    }
    if (l == left.size() && r == right.size()) return 0;
    return l == left.size() ? -1 : 1;
}

using SearchFields = std::map<std::string, std::vector<std::string>>;

SearchFields dependency_search_fields(const Config& config) {
    std::map<std::string, std::string> outbounds, servers;
    if (config.outbounds) {
        for (const auto& outbound : *config.outbounds) {
            outbounds.emplace(outbound.tag,
                              trimmed_name(outbound.display_name, outbound.tag));
        }
    }
    if (config.dns && config.dns->servers) {
        for (const auto& server : *config.dns->servers) {
            servers.emplace(server.tag, trimmed_name(server.display_name, server.tag));
        }
    }
    SearchFields fields;
    if (config.route && config.route->rules) {
        std::size_t index = 0;
        for (const auto& rule : *config.route->rules) {
            const auto rule_name = trimmed_name(rule.display_name,
                                                "#" + std::to_string(++index));
            const auto outbound = outbounds.find(rule.outbound);
            const auto label = lower_search_text(rule_name + " → " +
                (outbound == outbounds.end() ? rule.outbound : outbound->second));
            for (const auto& list : route_rule_lists(rule)) {
                auto& labels = fields[list];
                labels.push_back(label);
                labels.push_back(lower_search_text(rule_name));
                if (rule_name == "#" + std::to_string(index)) {
                    labels.push_back("правило №" + std::to_string(index));
                    labels.push_back("rule #" + std::to_string(index));
                }
                if (rule.id) labels.push_back(lower_search_text(*rule.id));
                labels.push_back(lower_search_text(rule.outbound));
                if (outbound != outbounds.end()) {
                    labels.push_back(lower_search_text(outbound->second));
                }
            }
        }
    }
    if (config.dns && config.dns->rules) {
        for (const auto& rule : *config.dns->rules) {
            const auto server = servers.find(rule.server);
            for (const auto& list : rule.list) {
                auto& labels = fields[list];
                labels.push_back(lower_search_text(rule.server));
                if (server != servers.end()) {
                    labels.push_back(lower_search_text(server->second));
                }
            }
        }
    }
    return fields;
}

struct QueryRow {
    const std::string* id;
    const ListConfig* list;
    std::string sort_key;
};

} // namespace

ListQueryOptions parse_list_query_request(const std::string& body) {
    try {
        const auto document = nlohmann::json::parse(body);
        if (!document.is_object()) throw ApiError("Invalid list query body", 400);
        ListQueryOptions request;
        const auto integer = [&document](const char* key, std::int64_t fallback) {
            const auto value = document.find(key);
            if (value == document.end()) return fallback;
            if (!value->is_number_integer() ||
                (value->is_number_unsigned() &&
                 value->get<std::uint64_t>() >
                     static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))) {
                throw ApiError("List query page bounds must be integers", 400);
            }
            return value->get<std::int64_t>();
        };
        request.offset = integer("offset", request.offset);
        request.limit = integer("limit", request.limit);
        const auto text = [&document](const char* key, const std::string& fallback) {
            const auto value = document.find(key);
            if (value == document.end()) return fallback;
            if (!value->is_string()) throw ApiError("Invalid list query text field", 400);
            return value->get<std::string>();
        };
        request.search = text("search", request.search);
        request.sort = text("sort", request.sort);
        request.order = text("order", request.order);
        validate_query(request);
        return request;
    } catch (const nlohmann::json::exception&) {
        throw ApiError("Invalid list query body", 400);
    }
}

api::ListPage build_list_page(const VisibleConfigSnapshot& visible,
                             const ListQueryOptions& request) {
    validate_query(request);
    api::ListPage page{};
    page.is_draft = visible.is_draft;
    page.revision = visible.revision;
    page.limit = request.limit;
    if (!visible.config.lists || visible.config.lists->empty()) return page;
    const auto& lists = *visible.config.lists;
    page.total = static_cast<std::int64_t>(lists.size());
    std::vector<std::string> words;
    std::istringstream search(lower_search_text(request.search));
    for (std::string word; search >> word;) words.push_back(std::move(word));
    const auto dependencies = words.empty()
        ? SearchFields{} : dependency_search_fields(visible.config);
    std::vector<QueryRow> rows;
    rows.reserve(lists.size());
    for (const auto& [id, list] : lists) {
        page.has_refreshable_lists = page.has_refreshable_lists ||
            (list.url && !list.url->empty());
        const auto name = trimmed_name(list.display_name, id);
        const auto source = list.url && !list.url->empty()
            ? *list.url : list.file.value_or("");
        if (!words.empty()) {
            std::vector<std::string> fields{
                lower_search_text(id), lower_search_text(name),
                lower_search_text(list.url.value_or("")),
                lower_search_text(list.file.value_or(""))};
            if (source.empty()) {
                fields.push_back("встроенный");
                fields.push_back("inline");
            }
            const auto dependent = dependencies.find(id);
            if (dependent != dependencies.end()) {
                fields.insert(fields.end(), dependent->second.begin(), dependent->second.end());
            }
            if (!std::all_of(words.begin(), words.end(), [&](const std::string& word) {
                    return std::any_of(fields.begin(), fields.end(), [&](const std::string& field) {
                        return field.find(word) != std::string::npos;
                    });
                })) continue;
        }
        rows.push_back({&id, &list, request.sort == "id" ? id :
            lower_search_text(request.sort == "name" ? name : source)});
    }
    std::sort(rows.begin(), rows.end(), [&](const QueryRow& left, const QueryRow& right) {
        const auto comparison = request.sort == "id"
            ? left.sort_key.compare(right.sort_key)
            : natural_compare(left.sort_key, right.sort_key);
        if (comparison == 0) return *left.id < *right.id;
        return request.order == "desc" ? comparison > 0 : comparison < 0;
    });
    page.filtered_total = static_cast<std::int64_t>(rows.size());
    if (rows.empty()) return page;
    page.offset = request.offset >= page.filtered_total
        ? ((page.filtered_total - 1) / request.limit) * request.limit
        : request.offset;
    const auto begin = static_cast<std::size_t>(page.offset);
    const auto count = std::min(rows.size() - begin,
                                static_cast<std::size_t>(request.limit));
    page.items.reserve(count);
    for (std::size_t index = begin; index < begin + count; ++index) {
        const auto& list = *rows[index].list;
        api::ListPageItem item{};
        item.id = *rows[index].id;
        item.display_name = list.display_name;
        item.url = list.url;
        item.file = list.file;
        item.domain_count = list.domains
            ? static_cast<std::int64_t>(list.domains->size()) : 0;
        if (list.ip_cidrs) {
            for (const auto& address : *list.ip_cidrs) {
                if (address.find(':') == std::string::npos) ++item.ipv4_count;
                else ++item.ipv6_count;
            }
        }
        page.items.push_back(std::move(item));
    }
    return page;
}

api::ListPage query_lists(const ApiContext& ctx, const ListQueryOptions& request) {
    return build_list_page(ctx.get_visible_config_state(), request);
}

void register_lists_query_handler(ApiServer& server, ApiContext& ctx) {
    server.post("/api/lists/query", [&ctx](const std::string& body) {
        return nlohmann::json(query_lists(ctx, parse_list_query_request(body))).dump();
    });
}

} // namespace keen_pbr3

#endif // WITH_API
