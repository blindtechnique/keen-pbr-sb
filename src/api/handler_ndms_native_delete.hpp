#pragma once

#ifdef WITH_API

#include "../keenetic/ndms_native_cooperative_delete.hpp"

#include <nlohmann/json_fwd.hpp>

#include <cstddef>
#include <string_view>

namespace keen_pbr3 {

class ApiServer;
struct ApiContext;

inline constexpr std::string_view kNdmsNativeDeleteApiPath{
    "/api/system/ndms/interfaces/remove"};
inline constexpr std::string_view kNdmsNativeDeleteRecoveryApiPath{
    "/api/system/ndms/interfaces/remove/recovery/retry"};

inline constexpr std::string_view kNdmsNativeDeleteRaceAcceptanceHeader{
    "X-Keen-Pbr-External-Ndms-Writer-Race-Acceptance"};
inline constexpr std::string_view kNdmsNativeDeleteRaceAcceptanceValue{
    "owner-accepted"};
inline constexpr std::string_view kNdmsNativeDeleteGlobalSaveHeader{
    "X-Keen-Pbr-Global-Save-Acknowledgement"};
inline constexpr std::string_view kNdmsNativeDeleteGlobalSaveValue{
    "owner-acknowledges-save-persists-all-pending-keenetic-changes"};

inline constexpr std::size_t kNdmsNativeDeleteRequestMaximumBytes = 1024U;

// Maps the coordinator's already-redacted result into the public envelope.
// It validates every enum and cross-field claim before serializing anything;
// a faulty embedder callback therefore becomes a generic HTTP failure instead
// of a false safety statement or a covert revision channel.
nlohmann::json ndms_native_delete_api_response(
    const NdmsNativeCooperativeDeleteResult& result);

void register_ndms_native_delete_handler(ApiServer& server,
                                         ApiContext& context);

} // namespace keen_pbr3

#endif // WITH_API
