#pragma once

#include "config.hpp"

#include <cstdint>
#include <nlohmann/json.hpp>

namespace keen_pbr3 {

// Keep the current version aligned with ConfigObject.schema_version's schema
// default. Unversioned released configurations are version 1.
inline constexpr std::uint64_t kCurrentConfigSchemaVersion = 2;

class ConfigSchemaVersionError : public ConfigValidationError {
public:
    explicit ConfigSchemaVersionError(std::uint64_t source_version);

    std::uint64_t source_version() const noexcept { return source_version_; }
    std::uint64_t supported_version() const noexcept {
        return kCurrentConfigSchemaVersion;
    }

private:
    std::uint64_t source_version_;
};

// Operates on a copy/moved raw document before DTO projection or validation.
// Unknown fields survive this boundary and the config-object typed serializers.
// Preservation does not activate runtime semantics for unrecognized settings.
nlohmann::json migrate_config_json(nlohmann::json document);

} // namespace keen_pbr3
