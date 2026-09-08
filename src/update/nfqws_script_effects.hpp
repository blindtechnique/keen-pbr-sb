#pragma once

#include <string>
#include <vector>

namespace keen_pbr3 {

// Exact additional leaves named by known Entware nfqws2 maintainer scripts.
// Merge these into the observed old/target capture union before any script
// runs. The usual binary, init script and package data paths remain separate.
// Existing capture bounds and no-follow rules apply; this does not scan paths
// or authorize directory cleanup. It is not an inventory of arbitrary future
// package scripts, runtime files, or user-configured script effects.
std::vector<std::string> nfqws_known_script_effect_paths();

} // namespace keen_pbr3
