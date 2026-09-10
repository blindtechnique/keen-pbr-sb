#ifdef WITH_API

#include "handler_lists_refresh.hpp"
#include "generated/api_types.hpp"

#include <nlohmann/json.hpp>
#include <algorithm>

namespace keen_pbr3 {

api::ListRefreshRequest parse_list_refresh_request(const std::string& body) {
    if (body.empty()) {
        return {};
    }

    nlohmann::json payload;
    try {
        payload = nlohmann::json::parse(body);
    } catch (const nlohmann::json::exception&) {
        throw ApiError("Invalid request body", 400);
    }
    if (payload.is_null()) {
        return {};
    }
    if (!payload.is_object()) {
        throw ApiError("Invalid request body", 400);
    }

    api::ListRefreshRequest request;
    const auto name = payload.find("name");
    if (name != payload.end() && !name->is_null()) {
        if (!name->is_string()) {
            throw ApiError("Field 'name' must be a string", 400);
        }
        request.name = name->get<std::string>();
    }
    const auto force = payload.find("force_refresh");
    if (force != payload.end()) {
        if (!force->is_boolean()) {
            throw ApiError("Field 'force_refresh' must be a boolean", 400);
        }
        request.force_refresh = force->get<bool>();
    }
    const auto acceptance = payload.find("accept_shrink");
    if (acceptance != payload.end()) {
        if (!acceptance->is_object() || !request.name || request.name->empty()) {
            throw ApiError("Accepting a smaller list requires one named list", 400);
        }
        const auto digest = [&acceptance](const char* field) {
            const auto value = acceptance->find(field);
            if (value == acceptance->end() || !value->is_string()) {
                throw ApiError("Shrink acceptance requires both list digests", 400);
            }
            const auto text = value->get<std::string>();
            if (text.size() != 64 || !std::all_of(text.begin(), text.end(), [](char ch) {
                    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
                })) {
                throw ApiError("Shrink acceptance contains an invalid digest", 400);
            }
            return text;
        };
        api::AcceptShrink accepted;
        accepted.previous_sha256 = digest("previous_sha256");
        accepted.candidate_sha256 = digest("candidate_sha256");
        request.accept_shrink = std::move(accepted);
        request.force_refresh = true;
    }
    return request;
}

ApiError make_list_refresh_apply_error(
    const ListRefreshOperationResult& partial,
    const char* stage,
    const std::string& detail,
    const char* runtime_result) {
    std::string message =
        "Lists were refreshed, but routing changes were not applied";
    if (!detail.empty()) {
        message += ": ";
        message += detail;
    }
    return ApiError(message, 503, nlohmann::json{
        {"error", message},
        {"code", "list_refresh_apply_failed"},
        {"params", {{"stage", stage}, {"runtime_result", runtime_result}}},
        {"refreshed_lists", partial.refreshed_lists},
        {"changed_lists", partial.changed_lists},
        {"failed_lists", partial.failed_lists},
        {"reloaded", false},
    }.dump());
}

void register_lists_refresh_handler(ApiServer& server, ApiContext& ctx) {
    server.post("/api/lists/refresh", [&ctx](const std::string& body) -> std::string {
        const auto request = parse_list_refresh_request(body);
        const auto result = ctx.refresh_lists(request);

        api::ListRefreshResponse response;
        response.status = api::ConfigUpdateResponseStatus::OK;
        response.message = result.message;
        response.refreshed_lists = result.refreshed_lists;
        response.changed_lists = result.changed_lists;
        response.failed_lists = result.failed_lists;
        response.reloaded = result.reloaded;
        return nlohmann::json(response).dump();
    });
}

} // namespace keen_pbr3

#endif // WITH_API
