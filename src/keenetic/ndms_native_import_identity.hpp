#pragma once

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>

namespace keen_pbr3 {

inline constexpr std::string_view kNdmsNativeImportMarkerPrefix{
    "kpbr-ni-v1-"};
inline constexpr std::size_t kNdmsNativeImportTransactionIdHexBytes = 32U;

inline bool valid_ndms_native_import_transaction_id(
    const std::string_view value) noexcept {
    return value.size() == kNdmsNativeImportTransactionIdHexBytes &&
           std::all_of(
               value.begin(), value.end(),
               [](const unsigned char character) {
                   return (character >= '0' && character <= '9') ||
                          (character >= 'a' && character <= 'f');
               });
}

inline bool valid_ndms_native_import_marker(
    const std::string_view marker,
    const std::string_view transaction_id) noexcept {
    return valid_ndms_native_import_transaction_id(transaction_id) &&
           marker.size() ==
               kNdmsNativeImportMarkerPrefix.size() +
                   transaction_id.size() &&
           marker.compare(0U, kNdmsNativeImportMarkerPrefix.size(),
                          kNdmsNativeImportMarkerPrefix) == 0 &&
           marker.substr(kNdmsNativeImportMarkerPrefix.size()) ==
               transaction_id;
}

inline std::optional<std::string_view>
ndms_native_import_transaction_id_from_marker(
    const std::string_view marker) noexcept {
    if (marker.size() !=
            kNdmsNativeImportMarkerPrefix.size() +
                kNdmsNativeImportTransactionIdHexBytes ||
        marker.compare(0U, kNdmsNativeImportMarkerPrefix.size(),
                       kNdmsNativeImportMarkerPrefix) != 0) {
        return std::nullopt;
    }
    const auto transaction_id =
        marker.substr(kNdmsNativeImportMarkerPrefix.size());
    if (!valid_ndms_native_import_transaction_id(transaction_id)) {
        return std::nullopt;
    }
    return transaction_id;
}

} // namespace keen_pbr3
