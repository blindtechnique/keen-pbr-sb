#pragma once

#include "../config/config.hpp"
#include "../dns/dnsmasq_gen.hpp"
#include "../dns/keenetic_dns.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace keen_pbr3 {

enum class RuntimeState;

struct ResolverGenerationSnapshot {
    Config config;
    KeeneticDnsCacheView keenetic_dns;
    std::shared_ptr<const ListCacheGenerationSnapshot> list_cache_snapshot;
    ResolverType resolver_type;
    ResolverIpv6Policy ipv6_policy;
    std::vector<std::string> trusted_dns_interfaces;
    std::string expected_hash;
    std::uint64_t generation{0};
    std::uint64_t stream_epoch{0};
};

// Selection for one generate-resolver-config IPC request.  The caller must
// reject a malformed non-empty requested_attempt_id before entering this
// seam.  Keeping validation at the protocol boundary lets this helper remain
// independent from the resolver-hook process launcher.
enum class RuntimeResolverStreamSelectionError {
    none,
    stream_busy,
    attempt_mismatch,
    generation_unavailable,
};

struct RuntimeResolverStreamSelection {
    std::shared_ptr<const ResolverGenerationSnapshot> generation;
    std::uint64_t stream_epoch{0};
    bool correlated_attempt{false};
    RuntimeResolverStreamSelectionError error{
        RuntimeResolverStreamSelectionError::none};

    explicit operator bool() const noexcept {
        return generation != nullptr &&
               error == RuntimeResolverStreamSelectionError::none;
    }
};

// An active hook owns a private immutable generation.  Only its exact opaque
// attempt id may select that generation; an uncorrelated/manual request never
// falls through to it.  With no active hook, both an ordinary request and a
// valid stale helper token select only the committed generation.
RuntimeResolverStreamSelection select_runtime_resolver_stream_generation(
    std::string_view requested_attempt_id,
    std::string_view active_attempt_id,
    const std::shared_ptr<const ResolverGenerationSnapshot>&
        committed_generation,
    const std::shared_ptr<const ResolverGenerationSnapshot>&
        active_generation) noexcept;

std::string_view runtime_resolver_stream_selection_error_code(
    RuntimeResolverStreamSelectionError error) noexcept;

// Authorizes the already selected immutable generation against lifecycle
// state.  A correlated active hook may stream a private candidate/rollback
// while the old runtime is routing, even when no committed pointer exists.
// An uncorrelated request is always pointer-bound to the committed generation.
// With routing inactive, retain the narrower lifecycle-start exception: only
// the exact inactive activation pointer may stream during starting/applying.
bool runtime_resolver_stream_selection_available(
    RuntimeState runtime_state,
    bool routing_runtime_active,
    const RuntimeResolverStreamSelection& selection,
    const std::shared_ptr<const ResolverGenerationSnapshot>&
        committed_generation,
    const std::shared_ptr<const ResolverGenerationSnapshot>&
        inactive_activation_generation) noexcept;

// Completion acknowledges a hook only while the same attempt still owns the
// same immutable pointer and the stream epoch captured at admission.  This is
// intentionally independent from the committed generation: config candidate
// and rollback streams remain private until their outer transaction publishes.
bool runtime_resolver_stream_completion_is_exact(
    std::string_view completed_attempt_id,
    std::uint64_t completed_stream_epoch,
    const std::shared_ptr<const ResolverGenerationSnapshot>&
        completed_generation,
    std::string_view active_attempt_id,
    const std::shared_ptr<const ResolverGenerationSnapshot>&
        active_generation) noexcept;

// Complete immutable input for one resolver generation. The builder below
// must not consult Daemon, a live CacheManager, the Keenetic cache or kernel
// capability probes: a prepared config candidate can therefore be hashed
// before it becomes the active runtime generation.
struct RuntimeResolverGenerationInput {
    Config config;
    KeeneticDnsCacheView keenetic_dns;
    std::shared_ptr<const ListCacheGenerationSnapshot> list_cache_snapshot;
    std::size_t list_max_file_size_bytes{0};
    ResolverType resolver_type{ResolverType::DNSMASQ_IPSET};
    ResolverIpv6Policy ipv6_policy;
    std::vector<std::string> trusted_dns_interfaces;
    std::uint64_t generation{0};
};

// Builds the complete resolver snapshot and its canonical hash solely from
// the explicit input. A pinned list generation is mandatory; there is no live
// CacheManager fallback at this worker-safe boundary.
ResolverGenerationSnapshot build_runtime_resolver_generation_snapshot(
    const RuntimeResolverGenerationInput& input);

} // namespace keen_pbr3
