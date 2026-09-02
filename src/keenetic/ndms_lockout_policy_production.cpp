#include "ndms_lockout_policy.hpp"

#include "ndms_http_config_projection.hpp"

#include <exception>
#include <string>

namespace keen_pbr3 {

std::optional<NdmsLockoutPolicy> fetch_ndms_lockout_policy(
    std::string* error) {
    try {
        const auto snapshot = shared_ndms_lockout_policy_cache().get();
        if (snapshot.status != NdmsCatalogCacheStatus::fresh) {
            if (error) {
                *error = "NDMS HTTP lockout policy snapshot is not fresh";
            }
            return std::nullopt;
        }
        if (!snapshot.policy) {
            if (error) {
                *error = "NDMS reported no usable HTTP lockout policy";
            }
            return std::nullopt;
        }
        if (error) error->clear();
        return snapshot.policy;
    } catch (const std::exception& exception) {
        if (error) {
            *error = std::string{"NDMS lockout policy read failed: "} +
                     exception.what();
        }
        return std::nullopt;
    }
}

} // namespace keen_pbr3
