#pragma once

#ifdef WITH_API

#include "../keenetic/ndms_native_tombstone_forget.hpp"

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <string_view>

namespace keen_pbr3 {

class ApiServer;
struct ApiContext;

inline constexpr std::string_view kNdmsNativeTombstoneForgetApiPath{
    "/api/system/ndms/interfaces/retained-deletions/forget"};
inline constexpr std::size_t
    kNdmsNativeTombstoneForgetRequestMaximumBytes = 1024U;

nlohmann::json ndms_native_tombstone_forget_api_response(
    const NdmsNativeTombstoneForgetResult& result);

void register_ndms_native_tombstone_forget_handler(
    ApiServer& server,
    ApiContext& context);

} // namespace keen_pbr3

#endif // WITH_API
