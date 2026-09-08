#pragma once

#include <nlohmann/json.hpp>

namespace keen_pbr3 {

// subscriptions.json is an unversioned array, not a public source projection.
// Full private records (including URLs) belong only in the secret backup.
// These functions perform no I/O and reject with a fixed, secret-free message.
nlohmann::json validated_subscription_backup(const nlohmann::json& records);

// Transports may use the current object or the legacy array. Null means the
// persisted transports.json file is absent. Only a saved
// sing-box link proves identity; never trust a supplied link_fingerprint.
// Keep sources and schedules even if every VPN disappears. Legacy unbound tags
// need a unique private inventory match. The caller chooses archive records,
// or current records for an old archive with no subscription section; explicit
// [] is therefore distinct from an absent section. Validate before any writes.
nlohmann::json reconcile_subscription_backup(
    const nlohmann::json& records,
    const nlohmann::json& transports_config);

} // namespace keen_pbr3
