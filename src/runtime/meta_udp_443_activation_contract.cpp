#include "meta_udp_443_activation_contract.hpp"

#include "meta_udp_443_policy.hpp"

#include "conntrack_destination_retirement.hpp"
#include "../util/ipv6_support.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <utility>
#include <unistd.h>

namespace keen_pbr3 {
namespace {

constexpr std::size_t kActivationMaxFlows = 256U;
constexpr std::size_t kActivationMaxDestinationCidrs = 1024U;
constexpr std::size_t kActivationMaxSnapshotBytes =
    2U * 1024U * 1024U;
constexpr std::size_t kActivationMaxSnapshotLines = 8192U;

std::vector<std::string> local_interface_addresses_from(
    const std::vector<DumpedInterface>& interfaces) {
    std::vector<std::string> addresses;
    for (const auto& interface : interfaces) {
        addresses.insert(
            addresses.end(),
            interface.ipv4_addresses.begin(),
            interface.ipv4_addresses.end());
        addresses.insert(
            addresses.end(),
            interface.ipv6_addresses.begin(),
            interface.ipv6_addresses.end());
    }
    std::sort(addresses.begin(), addresses.end());
    addresses.erase(
        std::unique(addresses.begin(), addresses.end()),
        addresses.end());
    return addresses;
}

} // namespace

SystemMetaUdp443ActivationBackendServices::
SystemMetaUdp443ActivationBackendServices(
    ConntrackManager& conntrack_manager,
    NetlinkManager& netlink)
    : conntrack_manager_(conntrack_manager), netlink_(netlink) {}

bool SystemMetaUdp443ActivationBackendServices::
    fastnat_is_disabled_or_unavailable() {
    return system_fastnat_is_disabled_or_unavailable();
}

ConntrackCleanupResult SystemMetaUdp443ActivationBackendServices::
    probe_exact_cleanup_capability(bool ipv6_enabled) {
    return conntrack_manager_.probe_exact_cleanup_capability(
        ipv6_enabled);
}

std::vector<DumpedInterface>
SystemMetaUdp443ActivationBackendServices::dump_interfaces() {
    return netlink_.dump_interfaces();
}

ConntrackFlowObservation SystemMetaUdp443ActivationBackendServices::
    observe_forwarded_destination_flows(
        const std::vector<std::string>& destination_cidrs,
        const std::vector<std::string>& local_interface_addresses,
        std::uint32_t owned_mask,
        const ConntrackFlowObservationOptions& options,
        const std::vector<std::string>& media_guard_source_addresses,
        const std::vector<std::string>& media_seed_destination_cidrs,
        const std::set<std::uint32_t>& media_seed_owned_marks) {
    return conntrack_manager_.observe_forwarded_destination_flows(
        destination_cidrs,
        local_interface_addresses,
        owned_mask,
        options,
        media_guard_source_addresses,
        media_seed_destination_cidrs,
        media_seed_owned_marks);
}

ConntrackFlowObservationOptions
meta_udp443_activation_observation_options(bool ipv6_enabled) {
    ConntrackFlowObservationOptions options;
    options.ipv6_enabled = ipv6_enabled;
    options.max_flows = kActivationMaxFlows;
    options.max_destination_input_cidrs =
        kActivationMaxDestinationCidrs;
    options.max_snapshot_bytes = kActivationMaxSnapshotBytes;
    options.max_snapshot_lines = kActivationMaxSnapshotLines;
    options.allow_foreign_mark_bits_for_media = true;
    options.include_ordinary_destination_flows = false;
    options.media_seed_udp_destination_port = 443U;
    return options;
}

bool system_fastnat_is_disabled_or_unavailable() {
    constexpr std::array<const char*, 2> paths{
        "/proc/sys/net/netfilter/nf_conntrack_fastnat",
        "/proc/sys/net/ipv4/netfilter/ip_conntrack_fastnat",
    };
    for (const char* path : paths) {
        std::ifstream input(path);
        if (!input) {
            if (::access(path, F_OK) == 0) {
                return false;
            }
            continue;
        }
        std::string value;
        std::string extra;
        if (!(input >> value) || (input >> extra) || value != "0") {
            return false;
        }
    }
    // Kernels without either control do not provide Keenetic FastNAT and are
    // therefore already on the ordinary netfilter path.
    return true;
}

std::optional<MetaUdp443ActivationPlan>
prepare_meta_udp443_activation_or_throw(
    const MetaUdp443ActivationInput& input,
    MetaUdp443ActivationBackendServices& services) {
    const auto owned_mask = fwmark_mask_value(
        input.config.fwmark.value_or(FwmarkConfig{}));
    const auto selection = resolve_meta_udp_443_policy_selection(
        input.config, input.candidate_rules, owned_mask);
    if (!selection.active()) {
        return std::nullopt;
    }
    if (!services.fastnat_is_disabled_or_unavailable()) {
        throw MetaUdp443ActivationError(
            "daemon.meta_udp443_policy=messages_first requires verified "
            "FastNAT-off packet traversal");
    }

    std::set<std::uint32_t> cleanup_owned_marks{selection.fwmark};
    if (input.committed_fwmark.has_value()) {
        if (input.committed_owned_mask != owned_mask) {
            throw MetaUdp443ActivationError(
                "Meta UDP/443 messages-first cannot change the fwmark mask "
                "while the policy is active; switch to balanced first");
        }
        if (*input.committed_fwmark == 0U ||
            (*input.committed_fwmark & ~owned_mask) != 0U) {
            throw MetaUdp443ActivationError(
                "Meta UDP/443 messages-first cannot prove the previously "
                "committed route mark for exact activation cleanup");
        }
        cleanup_owned_marks.insert(*input.committed_fwmark);
    }

    const bool ipv6_enabled =
        resolve_ipv6_support(input.config).enabled;
    const auto capability =
        services.probe_exact_cleanup_capability(ipv6_enabled);
    if (capability == ConntrackCleanupResult::CommandUnavailable) {
        throw MetaUdp443ActivationError(
            "daemon.meta_udp443_policy=messages_first requires the "
            "conntrack utility for exact activation cleanup");
    }
    if (capability != ConntrackCleanupResult::Succeeded) {
        throw MetaUdp443ActivationError(
            "daemon.meta_udp443_policy=messages_first could not verify "
            "the exact conntrack cleanup capability");
    }

    const std::set<std::string> list_names(
        selection.list_names.begin(), selection.list_names.end());
    auto coverage = collect_conntrack_destination_retirement_coverage(
        destination_retirement_plan_for_lists(list_names),
        input.candidate_list_content_state);
    std::sort(
        coverage.destination_selectors.begin(),
        coverage.destination_selectors.end());
    coverage.destination_selectors.erase(
        std::unique(
            coverage.destination_selectors.begin(),
            coverage.destination_selectors.end()),
        coverage.destination_selectors.end());
    if (coverage.partial() || coverage.destination_selectors.empty() ||
        runtime_recovery_detail::contains_global_destination_selector(
            coverage)) {
        throw MetaUdp443ActivationError(
            "Meta UDP/443 messages-first policy requires complete "
            "authoritative activation cleanup coverage before publication");
    }

    const auto local_addresses = local_interface_addresses_from(
        services.dump_interfaces());
    const auto observation_options =
        meta_udp443_activation_observation_options(ipv6_enabled);
    const auto observation =
        services.observe_forwarded_destination_flows(
            coverage.destination_selectors,
            local_addresses,
            owned_mask,
            observation_options,
            {},
            coverage.destination_selectors,
            {});
    const bool allow_unmarked_cleanup =
        selection.allow_unmarked_cleanup &&
        input.forwarded_scope_allows_unmarked_cleanup;
    const auto candidates = select_meta_udp_443_cleanup_candidates(
        observation,
        cleanup_owned_marks,
        owned_mask,
        allow_unmarked_cleanup);
    if (!candidates.complete) {
        throw MetaUdp443ActivationError(
            "Meta UDP/443 messages-first policy requires a complete exact "
            "conntrack activation snapshot before publication");
    }

    return MetaUdp443ActivationPlan{
        selection.fwmark,
        owned_mask,
        std::move(cleanup_owned_marks),
        std::move(coverage.destination_selectors),
        ipv6_enabled,
        allow_unmarked_cleanup,
        std::move(candidates.flows)};
}

std::optional<MetaUdp443ActivationPlan>
prepare_meta_udp443_activation_or_throw(
    const MetaUdp443ActivationInput& input,
    ConntrackManager& conntrack_manager,
    NetlinkManager& netlink) {
    SystemMetaUdp443ActivationBackendServices services{
        conntrack_manager, netlink};
    return prepare_meta_udp443_activation_or_throw(input, services);
}

} // namespace keen_pbr3
