#pragma once

// The body bound belongs to the fetch policy, and `too_large` below is defined
// in terms of it: one subscription has one size limit, not two.
#include "subscription_fetch_policy.hpp"

#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Turns a fetched sing-box subscription body into a preview the operator can
// act on, and nothing else. It decodes, deduplicates, derives tags and names
// the conflicts; it does not fetch, does not validate protocol semantics and
// does not mutate configuration.
//
// Two boundaries are deliberate.
//
// It does not parse share links. transport-manager already owns that
// (extensions/transport-manager/internal/transport/share_link.go) and is the
// authority on what it will accept. A second parser here would drift from the
// one that actually runs, and the drift would show up as an import that
// previews cleanly and then fails on create. This module reads only the parts
// of a link every scheme shares - scheme, authority, fragment - and leaves the
// verdict on the link itself to the component that consumes it.
//
// It cannot leak a secret, structurally rather than carefully. A share link
// carries its credential in the userinfo (a VLESS UUID, a Trojan password) or,
// for vmess, inside a base64 payload. SubscriptionCandidate therefore has no
// field that can hold a link. The raw links come back in a separate vector,
// positionally aligned with the candidates, so a preview response can be built
// from the candidates alone and a redaction step cannot be forgotten.

// How the body was encoded, once decoding has been attempted.
enum class SubscriptionDocumentKind : std::uint8_t {
    // One share link per line, already plain text.
    link_list,
    // The whole body was base64; the decoded text is a link list.
    base64_link_list,
    // A sing-box configuration document rather than a link list. Named
    // separately so the operator is told what they pasted instead of that it
    // was unreadable; importing outbound objects is a different contract and
    // is not planned here.
    json_document,
    // Decoded, but contained no line that looks like a share link.
    empty,
    // Neither plain nor base64 produced anything resembling a link list.
    unrecognized,
    // Larger than kSubscriptionMaximumBytes, or more lines than
    // kSubscriptionMaximumEntries. Refused whole rather than truncated: a
    // silently shortened import is a worse answer than a refused one.
    too_large,
};

// Whether a candidate can be offered, and if not, what it collides with.
enum class SubscriptionCandidateDisposition : std::uint8_t {
    // Nothing objects to importing it.
    importable,
    // The same endpoint appeared earlier in this same document. Subscriptions
    // routinely repeat entries; only the first occurrence is offered.
    duplicate_in_document,
    // Byte-identical to a link already configured as a transport.
    already_configured,
    // The tag derived from the remark is taken by an existing transport whose
    // link is different. Needs the operator to choose, not a silent rename.
    tag_conflict,
    // A scheme transport-manager does not accept.
    scheme_not_supported,
    // Not a link at all.
    malformed,
};

const char* subscription_document_kind_name(
    SubscriptionDocumentKind kind) noexcept;
const char* subscription_candidate_disposition_name(
    SubscriptionCandidateDisposition disposition) noexcept;

// One offered entry. Carries no credential, because it has nowhere to put one.
struct SubscriptionCandidate {
    // Lowercased scheme, e.g. "vless". Empty when malformed.
    std::string scheme;
    // Host and port as they appeared, with any userinfo removed. Empty for
    // vmess, whose endpoint lives inside a base64 payload this module does not
    // open.
    std::string endpoint;
    // The URI fragment, percent-decoded: what subscriptions use as the human
    // label. May be empty, and may be any UTF-8 - it is not a tag.
    std::string remark;
    // A tag derived from the remark, already matching the TransportSpec tag
    // pattern and already unique within this plan. Empty when the candidate is
    // not importable.
    std::string suggested_tag;
    SubscriptionCandidateDisposition disposition{
        SubscriptionCandidateDisposition::malformed};
    // For duplicate_in_document: index of the occurrence that was offered.
    std::size_t duplicate_of{0U};
    // 1-based line in the decoded document. Lets the operator find an entry
    // their provider has mislabelled.
    std::size_t source_line{0U};
};

struct SubscriptionImportPlan {
    SubscriptionDocumentKind kind{
        SubscriptionDocumentKind::unrecognized};
    std::vector<SubscriptionCandidate> candidates;
    // Positionally aligned with `candidates`. Never put these in a response,
    // a log, or an error message.
    std::vector<std::string> links;
};

// A subscription is configuration, not payload. Both bounds refuse rather than
// truncate.
inline constexpr std::size_t kSubscriptionMaximumEntries = 512U;
inline constexpr std::size_t kSubscriptionMaximumTagLength = 24U;

// Schemes transport-manager accepts, mirrored from parseShareLink in
// share_link.go. Kept here so an unsupported entry is named in the preview
// instead of failing later at create time; the list is coupled to that file
// and a test pins the coupling.
bool subscription_scheme_supported(const std::string& scheme) noexcept;

// Normalizes a remark into a candidate tag matching "^[a-z][a-z0-9_]{0,23}$".
// Returns an empty string only if it cannot, which it never does: a remark
// with nothing usable in it falls back to a positional name.
std::string derive_subscription_tag(const std::string& remark,
                                    std::size_t position);

// Builds the plan. `existing_tags` and `existing_links` describe the transports
// already configured; both may be empty.
SubscriptionImportPlan plan_subscription_import(
    const std::string& body,
    const std::set<std::string>& existing_tags,
    const std::set<std::string>& existing_links);

} // namespace keen_pbr3
