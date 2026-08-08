#pragma once

#include <optional>
#include <string>

namespace keen_pbr3 {

// Immutable catalogue provenance for the official Instagram and aggregate
// Meta presets. Display names, technical IDs and source URLs are deliberately
// not authority boundaries: they are editable and can be copied by a user.
inline constexpr const char* kInstagramCatalogIdentity =
    "b66e64bf217b449cc21289f1efc727da26ac957f7e235073a603687e2fc4469f";
inline constexpr const char* kMetaCatalogIdentity =
    "24da8a1062a6c4c131b61366efda6b25a2b37b5afa202ad6f395441dbb2f7f96";

inline bool is_official_instagram_or_meta_catalog_identity(
    const std::optional<std::string>& identity) noexcept {
    return identity.has_value() &&
           (*identity == kInstagramCatalogIdentity ||
            *identity == kMetaCatalogIdentity);
}

} // namespace keen_pbr3
