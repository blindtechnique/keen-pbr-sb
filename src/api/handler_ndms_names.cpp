#ifdef WITH_API

#include "handler_ndms_names.hpp"

#include "../http/http_client.hpp"
#include "../keenetic/ndms_interface_inventory.hpp"
#include "../keenetic/ndms_interface_management.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <utility>

namespace keen_pbr3 {

namespace {

constexpr const char* kRciInterfaces =
    "http://127.0.0.1:79/rci/show/interface";
// The firmware's local web server is intentionally queried once for both the
// legacy name map and the typed tunnel inventory.
constexpr auto kCacheTtl = std::chrono::seconds(30);
constexpr auto kFailureRetry = std::chrono::seconds(5);

NdmsInterfaceCatalog unavailable_catalog() {
    return parse_ndms_interface_catalog(nlohmann::json{});
}

bool is_rci_error_object(const nlohmann::json& response) {
    if (response.find("error") != response.end()) return true;

    const auto status = response.find("status");
    if (status == response.end() || !status->is_string()) return false;
    auto value = status->get<std::string>();
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return value == "error" || value == "failed";
}

NdmsInterfaceCatalog parse_catalog_response(const std::string& response_body) {
    const auto response = nlohmann::json::parse(response_body);
    if (!response.is_object()) {
        throw std::runtime_error("NDMS RCI response is not an object");
    }
    if (response.empty()) {
        throw std::runtime_error("NDMS RCI response is empty");
    }
    if (is_rci_error_object(response)) {
        throw std::runtime_error("NDMS RCI returned an error object");
    }

    auto catalog = parse_ndms_interface_catalog(response);
    if (!catalog.firmware_available) {
        throw std::runtime_error("NDMS RCI response is unavailable");
    }
    return catalog;
}

NdmsCatalogCache& catalog_cache() {
    static NdmsCatalogCache cache(
        [] {
            HttpClient client;
            client.set_timeout(std::chrono::seconds(3));
            client.set_max_response_size(2U * 1024U * 1024U);
            return client.download(kRciInterfaces);
        },
        kCacheTtl,
        kFailureRetry);
    return cache;
}

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

api::Role api_interface_role(NdmsInterfaceRole role) {
    switch (role) {
    case NdmsInterfaceRole::client:
        return api::Role::CLIENT;
    case NdmsInterfaceRole::server:
        return api::Role::SERVER;
    case NdmsInterfaceRole::unknown:
        return api::Role::UNKNOWN;
    }
    return api::Role::UNKNOWN;
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

api::NdmsInterfaceInventoryResponse typed_inventory(
    const NdmsInterfaceCatalog& catalog) {
    api::NdmsInterfaceInventoryResponse response{};
    response.available = catalog.firmware_available;
    response.read_only = true;
    response.mutation_mode = api::MutationMode::DISABLED;
    response.required_guards = {
        api::RequiredGuard::TYPED_RCI,
        api::RequiredGuard::AUTOMATIC_BACKUP,
        api::RequiredGuard::OWNERSHIP_CHECK,
        api::RequiredGuard::OPTIMISTIC_REVISION,
    };

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

using RuntimeInterfaceNamesFn = std::function<std::vector<std::string>()>;
using TrafficInterfacesObserver =
    std::function<void(std::vector<std::string>)>;

NdmsInterfaceCatalog catalog_for_response(
    NdmsCatalogCache& cache,
    const RuntimeInterfaceNamesFn& runtime_interface_names_fn) {
    auto catalog = cache.get().catalog;
    std::vector<std::string> runtime_interface_names;
    try {
        runtime_interface_names = runtime_interface_names_fn();
    } catch (...) {
        // Runtime inventory is advisory for kernel-name resolution. The NDMS
        // metadata remains safe and useful when that live view is unavailable.
    }
    return resolve_ndms_kernel_names(catalog, runtime_interface_names);
}

void register_ndms_names_routes(
    ApiServer& server,
    NdmsCatalogCache& cache,
    RuntimeInterfaceNamesFn runtime_interface_names_fn,
    TrafficInterfacesObserver traffic_interfaces_observer = {}) {
    server.get(
        "/api/system/interface-names",
        [&cache, runtime_interface_names_fn]() -> std::string {
            const auto catalog =
                catalog_for_response(cache, runtime_interface_names_fn);
            return nlohmann::json{
                {"names",
                 catalog.names.is_object()
                     ? catalog.names
                     : nlohmann::json::object()},
                {"available", catalog.firmware_available},
            }.dump();
        });

    server.get(
        "/api/system/ndms/interfaces",
        [&cache,
         runtime_interface_names_fn,
         traffic_interfaces_observer]() -> std::string {
            const auto catalog =
                catalog_for_response(cache, runtime_interface_names_fn);
            if (traffic_interfaces_observer) {
                std::vector<std::string> interface_names;
                interface_names.reserve(catalog.tunnels.size());
                for (const auto& tunnel : catalog.tunnels) {
                    if (tunnel.kernel_name) {
                        interface_names.push_back(*tunnel.kernel_name);
                    }
                }
                traffic_interfaces_observer(std::move(interface_names));
            }
            return nlohmann::json(typed_inventory(catalog)).dump();
        });
}

} // namespace

NdmsCatalogCache::NdmsCatalogCache(FetchFn fetch_fn,
                                   Clock::duration cache_ttl,
                                   Clock::duration failure_retry,
                                   NowFn now_fn)
    : fetch_fn_(std::move(fetch_fn)),
      now_fn_(std::move(now_fn)),
      cache_ttl_(cache_ttl),
      failure_retry_(failure_retry) {
    if (!fetch_fn_) {
        throw std::invalid_argument("NDMS catalog fetch function is required");
    }
    if (!now_fn_) {
        now_fn_ = [] {
            return Clock::now();
        };
    }
}

NdmsCatalogSnapshot NdmsCatalogCache::snapshot_locked() const {
    if (catalog_) return {*catalog_, status_};
    return {unavailable_catalog(), NdmsCatalogCacheStatus::unavailable};
}

NdmsCatalogSnapshot NdmsCatalogCache::get() {
    const auto now = now_fn_();
    std::unique_lock<std::mutex> lock(mutex_);
    if (refresh_attempted_ && now < refresh_after_) {
        return snapshot_locked();
    }

    if (refresh_in_progress_) {
        const auto observed_generation = refresh_generation_;
        refresh_finished_.wait(
            lock,
            [this, observed_generation] {
                return refresh_generation_ != observed_generation;
            });
        return snapshot_locked();
    }

    refresh_in_progress_ = true;
    lock.unlock();

    std::optional<NdmsInterfaceCatalog> refreshed;
    try {
        // Both the loopback request and defensive parsing deliberately happen
        // outside mutex_ so cached readers never serialize behind network I/O.
        refreshed = parse_catalog_response(fetch_fn_());
    } catch (...) {
        // OpenWrt, older Keenetic firmware, transient RCI failures and malformed
        // payloads all map to unavailable/stale cache state, not an API error.
    }
    const auto completed_at = now_fn_();

    lock.lock();
    refresh_attempted_ = true;
    if (refreshed) {
        catalog_ = std::move(*refreshed);
        status_ = NdmsCatalogCacheStatus::fresh;
        refresh_after_ = completed_at + cache_ttl_;
    } else {
        status_ = catalog_ ? NdmsCatalogCacheStatus::stale
                           : NdmsCatalogCacheStatus::unavailable;
        refresh_after_ = completed_at + failure_retry_;
    }
    refresh_in_progress_ = false;
    ++refresh_generation_;
    auto result = snapshot_locked();
    lock.unlock();
    refresh_finished_.notify_all();
    return result;
}

void register_ndms_names_handler(ApiServer& server, ApiContext& ctx) {
    register_ndms_names_routes(
        server,
        catalog_cache(),
        [&ctx] {
            const auto inventory = ctx.get_runtime_interfaces();
            std::vector<std::string> names;
            names.reserve(inventory.interfaces.size());
            for (const auto& interface : inventory.interfaces) {
                names.push_back(interface.name);
            }
            return names;
        },
        [&ctx](std::vector<std::string> names) {
            ctx.replace_interface_traffic_targets(
                "native-tunnels", std::move(names));
        });
}

#ifdef KEEN_PBR3_TESTING
void register_ndms_names_handler_for_tests(ApiServer& server,
                                           NdmsCatalogCache& cache,
                                           std::vector<std::string>
                                               runtime_interface_names) {
    register_ndms_names_routes(
        server,
        cache,
        [runtime_interface_names = std::move(runtime_interface_names)] {
            return runtime_interface_names;
        });
}
#endif

} // namespace keen_pbr3

#endif // WITH_API
