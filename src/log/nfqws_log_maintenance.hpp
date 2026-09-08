#pragma once

#include "log_tail.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace keen_pbr3 {

void set_nfqws_log_max_bytes(std::size_t max_bytes);
std::size_t nfqws_log_max_bytes();
void set_nfqws_log_retention(bool size_enabled, bool age_enabled, unsigned max_age_days);
bool nfqws_log_size_limit_enabled();
bool nfqws_log_age_limit_enabled();
unsigned nfqws_log_max_age_days();

// Exact conventional and configured nfqws logs, never a directory glob.
// Exposed for pure path-selection tests; custom paths outside the nfqws log
// namespace remain operator-managed.
std::vector<std::string> nfqws_managed_log_paths(const std::string& config);

// Called by the daemon's existing once-per-minute log maintenance timer.
// Missing logs are not created and maintenance never restarts nfqws.
void maintain_nfqws_logs() noexcept;

} // namespace keen_pbr3
