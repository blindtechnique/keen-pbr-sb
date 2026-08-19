#pragma once

#include "ndms_native_interface_read.hpp"

#include <string_view>

namespace keen_pbr3 {

// Bounded loopback RCI reads for daemon-startup ownership reconciliation.
// This factory intentionally exposes no command runner and cannot authorize a
// router mutation.
NdmsNativeInterfaceReadDependencies
ndms_native_interface_read_production_dependencies();

inline bool ndms_native_interface_read_loopback_destination_permitted(
    const std::string_view address) noexcept {
    // The production URL is the literal IPv4 endpoint below. Requiring the
    // actual peer to be the same literal also disables proxy use in
    // HttpTransport and applies to every redirect hop.
    return address == "127.0.0.1";
}

} // namespace keen_pbr3
