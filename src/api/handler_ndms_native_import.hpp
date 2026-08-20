#pragma once

#ifdef WITH_API

#include "../keenetic/ndms_native_cooperative_import.hpp"

#include <nlohmann/json_fwd.hpp>

#include <string_view>

namespace keen_pbr3 {

class ApiServer;
struct ApiContext;

inline constexpr std::string_view kNdmsNativeImportApiPath{
    "/api/system/ndms/interfaces/import"};
inline constexpr std::string_view kNdmsNativeImportPreflightApiPath{
    "/api/system/ndms/interfaces/import/preflight"};
inline constexpr std::string_view kNdmsNativeImportRecoveryApiPath{
    "/api/system/ndms/interfaces/import/recovery/retry"};
inline constexpr std::string_view
    kNdmsNativeImportRaceAcceptanceHeader{
        "X-Keen-Pbr-External-Ndms-Writer-Race-Acceptance"};
inline constexpr std::string_view
    kNdmsNativeImportRaceAcceptanceValue{"owner-accepted"};

// Maps the coordinator's already-redacted result into the public envelope.
// Optional identifiers are independently syntax-checked before exposure so a
// faulty embedder callback cannot use them as an accidental secret channel.
nlohmann::json ndms_native_import_api_response(
    const NdmsNativeCooperativeImportResult& result);

// Recovery is intentionally bodyless. It can finish already-durable forward
// bookkeeping, retire a stable-absence transaction without a router write, or
// perform one exact rollback delete only after fresh owner acceptance. The
// transaction id and all raw observation/revision material remain private.
nlohmann::json ndms_native_import_recovery_api_response(
    const NdmsNativeCooperativeImportResumeResult& result);

void register_ndms_native_import_handler(ApiServer& server,
                                         ApiContext& ctx);

} // namespace keen_pbr3

#endif // WITH_API
