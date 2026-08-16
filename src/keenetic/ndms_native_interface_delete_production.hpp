#pragma once

#include "ndms_native_interface_delete.hpp"

namespace keen_pbr3 {

// Production dependencies for the exact-owned interface delete: bounded
// loopback RCI reads and one `ndmc -c` command.
//
// Deliberately a separate translation unit from the decision it feeds. The
// decision must stay linkable into the narrow native-import test target,
// which is independent of the daemon, the API and the router by design -
// pulling HttpClient into it breaks that, and the narrow targets exist
// precisely so these invariants stay checkable when the monolith is broken.
NdmsNativeInterfaceDeleteDependencies
ndms_native_interface_delete_production_dependencies();

} // namespace keen_pbr3
