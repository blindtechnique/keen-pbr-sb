#include "../../src/keenetic/ndms_native_exact_mutation_transport.hpp"

#include <utility>

using namespace keen_pbr3;

using ForbiddenDirectBackendCall = decltype(
    std::declval<NdmsNativeLibcurlExactMutationBackend&>()
        .post_fixed_loopback_once(
            std::declval<NdmsNativeExactMutationDispatchCapability&&>(),
            std::declval<NdmsNativeSecretBuffer&&>(),
            std::declval<
                NdmsNativeExactMutationPreDispatchGuard&>(),
            std::declval<NdmsNativeExactMutationBackendTrace&>()));
