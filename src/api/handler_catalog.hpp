#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

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
bool refresh_catalog_if_stale(bool force = false);

} // namespace keen_pbr3

#endif
