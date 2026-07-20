#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

#include <cstdint>
#include <string>

namespace keen_pbr3 {

// Ready-made lists borrowed from the awg-manager catalogue.
//
// The upstream project maintains one file with every preset it ships, and
// keeps adding and removing entries. Fetching that file weekly means the
// choice stays current without us curating a copy by hand - the copy we did
// keep by hand went stale within days.
void register_catalog_handler(ApiServer& server, ApiContext& ctx);

// Downloads the catalogue when the cached copy is older than a week.
// Returns true when a fresh copy was stored.
//
// The fwmark routes the download through a tunnel. It matters more here than
// for ordinary lists: the catalogue lives on GitHub, which is exactly the kind
// of host a user reaches for this software because they cannot reach directly.
bool refresh_catalog_if_stale(bool force = false, uint32_t fwmark = 0);

// Outbound tag the catalogue should be downloaded through, empty for direct.
std::string catalog_detour();

} // namespace keen_pbr3

#endif
