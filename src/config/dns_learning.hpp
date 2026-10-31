#pragma once

#include "config.hpp"

namespace keen_pbr3 {
inline std::pair<bool, bool> dns_learning_enabled(const std::optional<DnsConfig>& dns) {
    if (!dns) return {false, false};
    const bool legacy = dns->passive_learning.value_or(false);
    if (!dns->learning) return {legacy, legacy};
    return {dns->learning->dns.value_or(legacy), dns->learning->l7.value_or(legacy)};
}
} // namespace keen_pbr3
