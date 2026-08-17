#pragma once

#ifdef WITH_API

#include "generated/api_types.hpp"
#include "handlers.hpp"
#include "server.hpp"

namespace keen_pbr3 {

api::DependencyAnalysisResponse build_dependency_analysis_response(
    const Config& config,
    const api::DependencyAnalysisRequest& request);

void register_dependency_analysis_handler(ApiServer& server, ApiContext& ctx);

} // namespace keen_pbr3

#endif // WITH_API
