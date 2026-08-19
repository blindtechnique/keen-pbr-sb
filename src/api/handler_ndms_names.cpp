#ifdef WITH_API

#include "handler_ndms_names.hpp"

#include "../keenetic/ndms_catalog_cache.hpp"
#include "../keenetic/ndms_interface_inventory.hpp"
#include "../keenetic/ndms_interface_management.hpp"
#include "../keenetic/ndms_native_create_policy.hpp"
#include "../keenetic/ndms_native_import_readiness.hpp"
#include "../keenetic/ndms_vpn_server_service_cache.hpp"

#include <nlohmann/json.hpp>
#include <utility>

namespace keen_pbr3 {

namespace {

api::Kind api_tunnel_kind(NdmsTunnelKind kind) {
    switch (kind) {
    case NdmsTunnelKind::amnezia_wireguard:
        return api::Kind::AMNEZIA_WIREGUARD;
    case NdmsTunnelKind::wireguard:
        return api::Kind::WIREGUARD;
    case NdmsTunnelKind::openvpn:
        return api::Kind::OPENVPN;
    case NdmsTunnelKind::ike:
        return api::Kind::IKE;
    case NdmsTunnelKind::l2tp:
        return api::Kind::L2_TP;
    case NdmsTunnelKind::sstp:
        return api::Kind::SSTP;
    case NdmsTunnelKind::openconnect:
        return api::Kind::OPENCONNECT;
    case NdmsTunnelKind::http_proxy:
        return api::Kind::HTTP_PROXY;
    case NdmsTunnelKind::https_proxy:
        return api::Kind::HTTPS_PROXY;
    case NdmsTunnelKind::socks5_proxy:
        return api::Kind::SOCKS5_PROXY;
    }
    throw std::runtime_error("unsupported NDMS tunnel kind");
}

api::NdmsInterfaceRoleEnum api_interface_role(NdmsInterfaceRole role) {
    switch (role) {
    case NdmsInterfaceRole::client:
        return api::NdmsInterfaceRoleEnum::CLIENT;
    case NdmsInterfaceRole::server:
        return api::NdmsInterfaceRoleEnum::SERVER;
    case NdmsInterfaceRole::unknown:
        return api::NdmsInterfaceRoleEnum::UNKNOWN;
    }
    return api::NdmsInterfaceRoleEnum::UNKNOWN;
}

api::CatalogStatus api_catalog_status(
    NdmsCatalogCacheStatus status) {
    switch (status) {
    case NdmsCatalogCacheStatus::fresh:
        return api::CatalogStatus::FRESH;
    case NdmsCatalogCacheStatus::stale:
        return api::CatalogStatus::STALE;
    case NdmsCatalogCacheStatus::unavailable:
        return api::CatalogStatus::UNAVAILABLE;
    }
    return api::CatalogStatus::UNAVAILABLE;
}

api::NdmsVpnServerKind api_vpn_server_kind(
    NdmsVpnServerServiceKind kind) {
    switch (kind) {
    case NdmsVpnServerServiceKind::l2tp:
        return api::NdmsVpnServerKind::L2_TP;
    case NdmsVpnServerServiceKind::ikev1:
        return api::NdmsVpnServerKind::IKEV1;
    case NdmsVpnServerServiceKind::ikev2:
        return api::NdmsVpnServerKind::IKEV2;
    case NdmsVpnServerServiceKind::sstp:
        return api::NdmsVpnServerKind::SSTP;
    case NdmsVpnServerServiceKind::openconnect:
        return api::NdmsVpnServerKind::OPENCONNECT;
    }
    throw std::runtime_error("unsupported NDMS VPN server service kind");
}

const char* catalog_status_name(NdmsCatalogCacheStatus status) noexcept {
    switch (status) {
    case NdmsCatalogCacheStatus::fresh:
        return "fresh";
    case NdmsCatalogCacheStatus::stale:
        return "stale";
    case NdmsCatalogCacheStatus::unavailable:
        return "unavailable";
    }
    return "unavailable";
}

api::NdmsManagementBlockerElement api_management_blocker(
    NdmsInterfaceManagementBlocker blocker) {
    switch (blocker) {
    case NdmsInterfaceManagementBlocker::unsupported_kind:
        return api::NdmsManagementBlockerElement::UNSUPPORTED_KIND;
    case NdmsInterfaceManagementBlocker::unsupported_role:
        return api::NdmsManagementBlockerElement::UNSUPPORTED_ROLE;
    case NdmsInterfaceManagementBlocker::role_unknown:
        return api::NdmsManagementBlockerElement::ROLE_UNKNOWN;
    case NdmsInterfaceManagementBlocker::kernel_identity_unresolved:
        return api::NdmsManagementBlockerElement::
            KERNEL_IDENTITY_UNRESOLVED;
    case NdmsInterfaceManagementBlocker::typed_rci_unavailable:
        return api::NdmsManagementBlockerElement::TYPED_RCI_UNAVAILABLE;
    case NdmsInterfaceManagementBlocker::automatic_backup_unavailable:
        return api::NdmsManagementBlockerElement::
            AUTOMATIC_BACKUP_UNAVAILABLE;
    case NdmsInterfaceManagementBlocker::ownership_unknown:
        return api::NdmsManagementBlockerElement::OWNERSHIP_UNKNOWN;
    case NdmsInterfaceManagementBlocker::optimistic_revision_unavailable:
        return api::NdmsManagementBlockerElement::
            OPTIMISTIC_REVISION_UNAVAILABLE;
    }
    throw std::runtime_error("unsupported NDMS management blocker");
}

api::NdmsInterfaceManagementReadiness api_management_readiness(
    const NdmsTunnelInterface& tunnel) {
    const auto readiness = assess_ndms_interface_management(tunnel);
    api::NdmsInterfaceManagementReadiness result{};
    result.candidate = readiness.candidate;
    result.identity_stable = readiness.identity_stable;
    result.observed_revision = readiness.observed_revision;
    result.configuration_snapshot_available =
        readiness.configuration_snapshot_available;
    result.blockers.reserve(readiness.blockers.size());
    for (const auto blocker : readiness.blockers) {
        result.blockers.push_back(api_management_blocker(blocker));
    }
    return result;
}

api::NdmsNativeImportTargetRange native_import_target_range(
    const NdmsNativeWireguardTargetRange& source) {
    api::NdmsNativeImportTargetRange range{};
    range.prefix = api::NdmsNativeImportTargetPrefix::WIREGUARD;
    range.first_index = source.first_index;
    range.last_index = source.last_index;
    return range;
}

api::NdmsNativeImportJournalState api_native_import_journal_state(
    const NdmsNativeImportJournalReadinessState state) noexcept {
    switch (state) {
    case NdmsNativeImportJournalReadinessState::clean_never_activated:
        return api::NdmsNativeImportJournalState::CLEAN_NEVER_ACTIVATED;
    case NdmsNativeImportJournalReadinessState::clean:
        return api::NdmsNativeImportJournalState::CLEAN;
    case NdmsNativeImportJournalReadinessState::recovery_required:
        return api::NdmsNativeImportJournalState::RECOVERY_REQUIRED;
    case NdmsNativeImportJournalReadinessState::unsafe:
        return api::NdmsNativeImportJournalState::UNSAFE;
    case NdmsNativeImportJournalReadinessState::unavailable:
        return api::NdmsNativeImportJournalState::UNAVAILABLE;
    }
    return api::NdmsNativeImportJournalState::UNAVAILABLE;
}

api::NdmsNativeImportReadiness native_import_readiness(
    const NdmsNativeImportReadinessProvider& readiness_provider) {
    const auto policy = preview_ndms_native_create_policy();
    api::NdmsNativeImportReadiness readiness{};
    readiness.preview_only = policy.preview_only;
    readiness.apply_available = policy.apply_available;
    readiness.operation = policy.operation;
    readiness.request_name = policy.request_name;
    readiness.allocator_range =
        native_import_target_range(policy.allocator_range);
    readiness.eligible_returned_targets = native_import_target_range(
        policy.eligible_returned_targets);
    readiness.protected_targets.reserve(policy.protected_targets.size());
    for (const auto& range : policy.protected_targets) {
        readiness.protected_targets.push_back(
            native_import_target_range(range));
    }
    readiness.journal_state =
        api::NdmsNativeImportJournalState::DORMANT;
    if (readiness_provider) {
        try {
            readiness.journal_state = api_native_import_journal_state(
                readiness_provider());
        } catch (...) {
            // The endpoint stays available and fail-closed. A provider fault
            // can only degrade the redacted report; it cannot change any
            // mutation flag or remove an independent blocker.
            readiness.journal_state =
                api::NdmsNativeImportJournalState::UNAVAILABLE;
        }
    }
    readiness.reconcile_barrier_state =
        api::NdmsNativeImportReconcileBarrierState::DORMANT;
    readiness.blockers.reserve(policy.blockers.size());
    for (const auto blocker : policy.blockers) {
        switch (blocker) {
        case NdmsNativeCreatePolicyBlocker::writer_disabled:
            readiness.blockers.push_back(
                api::NdmsNativeImportBlocker::WRITER_DISABLED);
            break;
        case NdmsNativeCreatePolicyBlocker::allocator_range_unfenced:
            readiness.blockers.push_back(
                api::NdmsNativeImportBlocker::ALLOCATOR_RANGE_UNFENCED);
            break;
        case NdmsNativeCreatePolicyBlocker::
            recovery_journal_not_integrated:
            readiness.blockers.push_back(
                api::NdmsNativeImportBlocker::
                    RECOVERY_JOURNAL_NOT_INTEGRATED);
            break;
        case NdmsNativeCreatePolicyBlocker::
            reconcile_barrier_not_integrated:
            readiness.blockers.push_back(
                api::NdmsNativeImportBlocker::
                    RECONCILE_BARRIER_NOT_INTEGRATED);
            break;
        }
    }
    return readiness;
}

api::NdmsInterfaceInventoryResponse typed_inventory(
    const NdmsInterfaceCatalog& catalog,
    NdmsCatalogCacheStatus catalog_status,
    const NdmsNativeImportReadinessProvider& readiness_provider) {
    api::NdmsInterfaceInventoryResponse response{};
    response.available =
        catalog.firmware_available &&
        catalog_status == NdmsCatalogCacheStatus::fresh;
    response.catalog_status = api_catalog_status(catalog_status);
    response.read_only = true;
    response.mutation_mode = api::MutationMode::DISABLED;
    response.required_guards = {
        api::RequiredGuard::TYPED_RCI,
        api::RequiredGuard::AUTOMATIC_BACKUP,
        api::RequiredGuard::OWNERSHIP_CHECK,
        api::RequiredGuard::OPTIMISTIC_REVISION,
    };
    response.native_import_readiness =
        native_import_readiness(readiness_provider);

    response.interfaces.reserve(catalog.tunnels.size());
    for (const auto& tunnel : catalog.tunnels) {
        api::NdmsTunnelInterfaceElement item{};
        item.id = tunnel.id;
        item.firmware_interface_name = tunnel.firmware_interface_name;
        item.kernel_name = tunnel.kernel_name;
        item.label = tunnel.label;
        item.firmware_type = tunnel.firmware_type;
        item.kind = api_tunnel_kind(tunnel.kind);
        item.owner = api::Owner::KEENETIC;
        item.role = api_interface_role(tunnel.role);
        const bool catalog_is_fresh =
            catalog_status == NdmsCatalogCacheStatus::fresh;
        item.internal_vpn_server_candidate =
            catalog_is_fresh &&
            tunnel.internal_vpn_server_candidate;
        item.internal_vpn_server_role_confirmation_required =
            catalog_is_fresh &&
            tunnel.internal_vpn_server_role_confirmation_required;
        item.connected = tunnel.connected;
        item.link = tunnel.link;
        item.capabilities.can_edit = false;
        item.capabilities.can_delete = false;
        item.capabilities.can_hide = false;
        item.capabilities.backup_required = true;
        item.management_readiness = api_management_readiness(tunnel);
        response.interfaces.push_back(std::move(item));
    }
    return response;
}

api::NdmsVpnServerServiceInventoryResponse typed_vpn_service_inventory(
    const NdmsVpnServerServiceCatalog& catalog,
    NdmsCatalogCacheStatus catalog_status) {
    api::NdmsVpnServerServiceInventoryResponse response{};
    response.available =
        catalog.firmware_available &&
        catalog_status == NdmsCatalogCacheStatus::fresh;
    response.catalog_status = api_catalog_status(catalog_status);
    response.read_only = true;
    response.services.reserve(catalog.services.size());
    for (const auto& service : catalog.services) {
        api::NdmsVpnServerService item{};
        item.id = service.id;
        item.kind = api_vpn_server_kind(service.kind);
        item.label = service.label;
        item.enabled = service.enabled;
        item.bound_interface_id = service.bound_interface_id;
        item.inventory_revision = service.inventory_revision;
        item.source_cidrs.reserve(
            service.source_cidrs_v4.size() +
            service.source_cidrs_v6.size());
        item.source_cidrs.insert(
            item.source_cidrs.end(),
            service.source_cidrs_v4.begin(),
            service.source_cidrs_v4.end());
        item.source_cidrs.insert(
            item.source_cidrs.end(),
            service.source_cidrs_v6.begin(),
            service.source_cidrs_v6.end());
        response.services.push_back(std::move(item));
    }
    return response;
}

using RuntimeInterfaceNamesFn = std::function<std::vector<std::string>()>;
using TrafficInterfacesObserver =
    std::function<void(std::vector<std::string>)>;

struct CatalogResponse {
    NdmsInterfaceCatalog catalog;
    NdmsCatalogCacheStatus status{NdmsCatalogCacheStatus::unavailable};
};

CatalogResponse catalog_for_response(
    NdmsCatalogCache& cache,
    const RuntimeInterfaceNamesFn& runtime_interface_names_fn) {
    auto snapshot = cache.get();
    std::vector<std::string> runtime_interface_names;
    try {
        runtime_interface_names = runtime_interface_names_fn();
    } catch (...) {
        // Runtime inventory is advisory for kernel-name resolution. The NDMS
        // metadata remains safe and useful when that live view is unavailable.
    }
    return {
        resolve_ndms_kernel_names(
            snapshot.catalog, runtime_interface_names),
        snapshot.status,
    };
}

void register_ndms_names_routes(
    ApiServer& server,
    NdmsCatalogCache& cache,
    RuntimeInterfaceNamesFn runtime_interface_names_fn,
    NdmsNativeImportReadinessProvider native_import_readiness_provider,
    TrafficInterfacesObserver traffic_interfaces_observer = {}) {
    server.get(
        "/api/system/interface-names",
        [&cache, runtime_interface_names_fn]() -> std::string {
            const auto response =
                catalog_for_response(cache, runtime_interface_names_fn);
            return nlohmann::json{
                {"names",
                 response.catalog.names.is_object()
                     ? response.catalog.names
                     : nlohmann::json::object()},
                {"available",
                 response.catalog.firmware_available &&
                     response.status == NdmsCatalogCacheStatus::fresh},
                {"catalog_status",
                 catalog_status_name(response.status)},
            }.dump();
        });

    server.get(
        "/api/system/ndms/interfaces",
        [&cache,
         runtime_interface_names_fn,
         native_import_readiness_provider,
         traffic_interfaces_observer]() -> std::string {
            const auto response =
                catalog_for_response(cache, runtime_interface_names_fn);
            if (traffic_interfaces_observer) {
                std::vector<std::string> interface_names;
                interface_names.reserve(response.catalog.tunnels.size());
                for (const auto& tunnel : response.catalog.tunnels) {
                    if (tunnel.kernel_name) {
                        interface_names.push_back(*tunnel.kernel_name);
                    }
                }
                traffic_interfaces_observer(std::move(interface_names));
            }
            return nlohmann::json(
                       typed_inventory(
                           response.catalog,
                           response.status,
                           native_import_readiness_provider))
                .dump();
        });
}

void register_ndms_vpn_server_services_route(
    ApiServer& server,
    NdmsVpnServerServiceCache& cache) {
    server.get(
        "/api/system/ndms/vpn-server-services",
        [&cache]() -> std::string {
            const auto snapshot = cache.get();
            return nlohmann::json(
                       typed_vpn_service_inventory(
                           snapshot.catalog, snapshot.status))
                .dump();
        });
}

} // namespace

void register_ndms_names_handler(ApiServer& server, ApiContext& ctx) {
    register_ndms_names_routes(
        server,
        shared_ndms_catalog_cache(),
        [&ctx] {
            const auto inventory = ctx.get_runtime_interfaces();
            std::vector<std::string> names;
            names.reserve(inventory.interfaces.size());
            for (const auto& interface : inventory.interfaces) {
                names.push_back(interface.name);
            }
            return names;
        },
        ctx.get_ndms_native_import_readiness_fn,
        [&ctx](std::vector<std::string> names) {
            ctx.replace_interface_traffic_targets(
                "native-tunnels", std::move(names));
        });
    register_ndms_vpn_server_services_route(
        server, shared_ndms_vpn_server_service_cache());
}

#ifdef KEEN_PBR3_TESTING
void register_ndms_names_handler_for_tests(ApiServer& server,
                                           NdmsCatalogCache& cache,
                                           std::vector<std::string>
                                               runtime_interface_names,
                                           NdmsNativeImportReadinessProvider
                                               native_import_readiness_provider) {
    register_ndms_names_routes(
        server,
        cache,
        [runtime_interface_names = std::move(runtime_interface_names)] {
            return runtime_interface_names;
        },
        std::move(native_import_readiness_provider));
}

void register_ndms_vpn_server_services_handler_for_tests(
    ApiServer& server,
    NdmsVpnServerServiceCache& cache) {
    register_ndms_vpn_server_services_route(server, cache);
}
#endif

} // namespace keen_pbr3

#endif // WITH_API
