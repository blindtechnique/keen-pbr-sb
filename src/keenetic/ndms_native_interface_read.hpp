#pragma once

#include <nlohmann/json.hpp>

#include <functional>
#include <optional>
#include <string>

namespace keen_pbr3 {

// Read-only view of the two bounded RCI documents used by ownership
// reconciliation.  Keeping this separate from the mutation dependency type is
// a capability boundary: daemon startup can prove that a stale claim is safe
// to retire, but it cannot issue an interface-delete command.
struct NdmsNativeInterfaceReadDependencies final {
    // Returns the parsed document for an RCI path, or nullopt when the read
    // itself failed.  The firmware represents an absent interface as an empty
    // body; production wiring converts that to a null json value.
    std::function<std::optional<nlohmann::json>(const std::string& rci_path)>
        read_document;
};

} // namespace keen_pbr3
