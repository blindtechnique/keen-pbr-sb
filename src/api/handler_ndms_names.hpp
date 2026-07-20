#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

namespace keen_pbr3 {

// Human names for interfaces, taken from the router's own configuration.
//
// keen-pbr works in kernel interface names - nwg2, ppp0, eth3 - because that
// is what routing needs. The person who set the router up named the same
// things differently in NDMS: "sddvpn.mooo.com AWG2", "Провайдер", "Гостевая
// сеть". Showing our names where theirs exist is the single largest source of
// confusion in the interface, and the firmware already knows the mapping.
void register_ndms_names_handler(ApiServer& server, ApiContext& ctx);

} // namespace keen_pbr3

#endif
