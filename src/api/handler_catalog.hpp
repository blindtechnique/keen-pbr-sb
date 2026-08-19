#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <string>

namespace keen_pbr3 {

// Ready-made lists that ship inside the package.
//
// The catalogue is package data: one file in the IPK holds every preset, and a
// release is how it changes. Nothing is fetched on a stock install, so a
// blocked or hostile network cannot decide what the router offers.
void register_catalog_handler(ApiServer& server, ApiContext& ctx);

// Downloads the catalogue when one is configured and the cached copy is older
// than a week. Returns true when a fresh copy was stored, and false without
// touching the network when no source URL is configured - which is the normal
// case, because the catalogue comes with the package.
//
// The fwmark routes the download through a tunnel. It matters more here than
// for ordinary lists: a configured catalogue is usually on GitHub, which is
// exactly the kind of host a user reaches for this software because they
// cannot reach it directly.
bool refresh_catalog_if_stale(bool force = false, uint32_t fwmark = 0);

// The catalogue URL an operator configured in catalog-source.json, or empty
// when the packaged catalogue is in use. Exposed for tests: the production
// path reads the file, and this takes its parsed contents.
std::string catalog_source_url_for_testing(const nlohmann::json& settings);

// Redirects the three files this module reads - packaged catalogue, source
// settings, download cache - so tests can exercise which one wins. Empty
// strings restore the production paths. Not for production use: the daemon
// reads these from several threads and this setter takes no lock.
void set_catalog_paths_for_testing(const std::string& bundled,
                                   const std::string& settings,
                                   const std::string& cache);

// Outbound tag the catalogue should be downloaded through, empty for direct.
std::string catalog_detour();

// Returns the same authoritative server-owned snapshot exposed by
// GET /api/catalog. Setup preview/apply must call this instead of accepting
// catalogue records from the client.
nlohmann::json load_catalog_snapshot();

// Adds stable provenance hashes to visible presets and their routing
// companions. Shared companion catalogIdentityId values intentionally produce
// one identity across different visible parents.
void add_catalog_identities(nlohmann::json& snapshot);

// Applies the package-owned routing companion metadata to a downloaded
// upstream catalogue. The upstream remains authoritative for ordinary
// presets, while the small local overlay keeps split domain/IP routing
// available both online and from the bundled fallback.
nlohmann::json enrich_catalog_with_routing_companions(
    nlohmann::json upstream_presets,
    const nlohmann::json& bundled_presets);

} // namespace keen_pbr3

#endif
