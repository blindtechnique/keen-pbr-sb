#include "runtime_resolver_generation_snapshot.hpp"

#include "../dns/dns_router.hpp"
#include "../lists/list_streamer.hpp"
#include "../runtime/runtime_state_machine.hpp"

#include <keen-pbr/version.hpp>

#include <map>
#include <stdexcept>

namespace keen_pbr3 {

RuntimeResolverStreamSelection select_runtime_resolver_stream_generation(
    std::string_view requested_attempt_id,
    std::string_view active_attempt_id,
    const std::shared_ptr<const ResolverGenerationSnapshot>&
        committed_generation,
    const std::shared_ptr<const ResolverGenerationSnapshot>&
        active_generation) noexcept {
    RuntimeResolverStreamSelection selection;

    if (active_attempt_id.empty()) {
        selection.generation = committed_generation;
        if (selection.generation) {
            selection.stream_epoch = selection.generation->stream_epoch;
        } else {
            selection.error =
                RuntimeResolverStreamSelectionError::generation_unavailable;
        }
        return selection;
    }

    if (requested_attempt_id.empty()) {
        selection.error =
            RuntimeResolverStreamSelectionError::stream_busy;
        return selection;
    }
    if (requested_attempt_id != active_attempt_id) {
        selection.error =
            RuntimeResolverStreamSelectionError::attempt_mismatch;
        return selection;
    }
    if (!active_generation || active_generation->stream_epoch == 0U) {
        selection.error =
            RuntimeResolverStreamSelectionError::generation_unavailable;
        return selection;
    }

    selection.generation = active_generation;
    selection.stream_epoch = active_generation->stream_epoch;
    selection.correlated_attempt = true;
    return selection;
}

std::string_view runtime_resolver_stream_selection_error_code(
    RuntimeResolverStreamSelectionError error) noexcept {
    switch (error) {
        case RuntimeResolverStreamSelectionError::none:
            return {};
        case RuntimeResolverStreamSelectionError::stream_busy:
            return "resolver_stream_busy";
        case RuntimeResolverStreamSelectionError::attempt_mismatch:
            return "resolver_attempt_mismatch";
        case RuntimeResolverStreamSelectionError::generation_unavailable:
            return "resolver_generation_unavailable";
    }
    return "resolver_generation_unavailable";
}

bool runtime_resolver_stream_selection_available(
    RuntimeState runtime_state,
    bool routing_runtime_active,
    const RuntimeResolverStreamSelection& selection,
    const std::shared_ptr<const ResolverGenerationSnapshot>&
        committed_generation,
    const std::shared_ptr<const ResolverGenerationSnapshot>&
        inactive_activation_generation) noexcept {
    if (!selection || !selection.generation->list_cache_snapshot) {
        return false;
    }

    if (selection.correlated_attempt) {
        if (selection.stream_epoch == 0U ||
            selection.generation->stream_epoch !=
                selection.stream_epoch) {
            return false;
        }
    } else if (selection.generation != committed_generation) {
        // A manual request must never use a private pointer, including when a
        // caller accidentally retains one after the exact attempt retires.
        return false;
    }

    if (routing_runtime_active) {
        return runtime_state != RuntimeState::stopped &&
               runtime_state != RuntimeState::shutting_down;
    }

    // Cold boot and stopped-runtime config bootstrap intentionally keep this
    // generation private until the exact stream succeeds. The correlated
    // attempt plus this lifecycle pointer is the admission authority.
    const bool exact_inactive_activation =
        selection.correlated_attempt && inactive_activation_generation &&
        selection.generation == inactive_activation_generation;
    return exact_inactive_activation &&
           (runtime_state == RuntimeState::starting ||
            runtime_state == RuntimeState::applying);
}

bool runtime_resolver_stream_completion_is_exact(
    std::string_view completed_attempt_id,
    std::uint64_t completed_stream_epoch,
    const std::shared_ptr<const ResolverGenerationSnapshot>&
        completed_generation,
    std::string_view active_attempt_id,
    const std::shared_ptr<const ResolverGenerationSnapshot>&
        active_generation) noexcept {
    return !completed_attempt_id.empty() &&
           completed_attempt_id == active_attempt_id &&
           completed_stream_epoch != 0U && completed_generation &&
           active_generation &&
           completed_generation == active_generation &&
           completed_generation->stream_epoch == completed_stream_epoch &&
           active_generation->stream_epoch == completed_stream_epoch;
}

ResolverGenerationSnapshot build_runtime_resolver_generation_snapshot(
    const RuntimeResolverGenerationInput& input) {
    if (!input.list_cache_snapshot) {
        throw std::invalid_argument(
            "runtime resolver generation requires a pinned list snapshot");
    }
    if (input.list_max_file_size_bytes == 0) {
        throw std::invalid_argument(
            "runtime resolver generation requires a non-zero list size limit");
    }

    ResolverGenerationSnapshot snapshot;
    snapshot.config = input.config;
    snapshot.keenetic_dns = input.keenetic_dns;
    snapshot.list_cache_snapshot = input.list_cache_snapshot;
    snapshot.resolver_type = input.resolver_type;
    snapshot.ipv6_policy = input.ipv6_policy;
    snapshot.trusted_dns_interfaces = input.trusted_dns_interfaces;
    snapshot.generation = input.generation;

    ListStreamer streamer(
        input.list_max_file_size_bytes,
        snapshot.list_cache_snapshot);
    const DnsConfig dns_cfg =
        snapshot.config.dns.value_or(DnsConfig{});
    DnsServerRegistry dns_registry(
        dns_cfg, snapshot.keenetic_dns.snapshot);
    // DnsmasqGenerator retains references while computing the hash. Keep
    // optional defaults alive for the complete call.
    const RouteConfig route_cfg =
        snapshot.config.route.value_or(RouteConfig{});
    const std::map<std::string, ListConfig> lists =
        snapshot.config.lists.value_or(
            std::map<std::string, ListConfig>{});
    DnsmasqGenerator generator(
        dns_registry,
        streamer,
        route_cfg,
        dns_cfg,
        lists,
        snapshot.resolver_type,
        KEEN_PBR3_VERSION_FULL_STRING,
        snapshot.ipv6_policy,
        snapshot.trusted_dns_interfaces);
    snapshot.expected_hash = generator.compute_config_hash();
    return snapshot;
}

} // namespace keen_pbr3
