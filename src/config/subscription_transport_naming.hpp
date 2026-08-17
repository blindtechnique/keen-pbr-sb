#pragma once

#include <set>
#include <string>

namespace keen_pbr3 {

// Derives the kernel interface name for a transport created from a
// subscription entry.
//
// This mirrors generateTransportIdentity in frontend/src/lib/technical-id.ts:
// a protocol prefix and the first free sequence number, so a transport created
// by the importer is indistinguishable from one the operator created by hand
// in the dialog. A second naming scheme would work, but then "where did this
// tunnel come from" becomes readable from the interface name, and the roadmap
// is explicit that import is the same create pipeline, not a parallel one.
//
// The name must match TransportSpec's interface pattern ^[A-Za-z0-9_.-]{1,15}$
// and be unique among both existing interfaces and existing tags - the
// frontend reserves identity against both sets, because a tag and an
// interface share one namespace in the operator's head even though the
// schema keeps them apart.

// The prefix for a share-link scheme, lowercased: "vless" -> "vless",
// "hysteria2"/"hy2" -> "hys", "naive+quic" -> "naive". Unknown schemes get
// "proxy" - by the time this runs the scheme has already passed the
// supported-scheme check, so this is a seam, not a branch that decides.
std::string subscription_interface_prefix(const std::string& scheme);

// First free "<prefix><sequence>" not present in `taken`. The caller passes
// existing interfaces AND tags merged, plus anything already assigned in the
// same batch. Empty string only if 99999 names are taken, which is not a
// router, it is an attack - and refusing is the right answer to it.
std::string derive_subscription_interface(
    const std::string& scheme,
    const std::set<std::string>& taken);

} // namespace keen_pbr3
