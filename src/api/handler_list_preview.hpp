#pragma once

#ifdef WITH_API

#include "../config/config.hpp"
#include "../http/http_transport.hpp"
#include "../lists/list_preview.hpp"

#include <memory>
#include <optional>
#include <string>

namespace keen_pbr3 {
class ApiServer;
struct ApiContext;

struct ListPreviewRequest {
    std::optional<std::string> url;
    std::optional<std::string> text;
    std::string format{"text"};
    ListConfig route;
};

ListPreviewRequest parse_list_preview_request(const std::string& body);
std::string serialize_list_preview_result(const ListPreviewResult& result);
// Complete normalized content for a local editor; never writes a draft.
std::string import_list_content_request(const std::string& body);

// The caller supplies one active config/mark snapshot; no disk, draft,
// cache, resolver or runtime writes occur. Tests inject only the HTTP transport.
ListPreviewResult preview_list_request(
    const std::string& body, const Config& active_config,
    const OutboundMarkMap& active_marks,
    std::shared_ptr<HttpTransport> transport = {});

void register_list_preview_handler(ApiServer& server, ApiContext& ctx);

} // namespace keen_pbr3
#endif
