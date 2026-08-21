#include "ndms_native_direct_observation.hpp"

#include "ndms_native_import_identity.hpp"
#include "ndms_native_import_recovery_probe.hpp"
#include "ndms_native_secret_redaction.hpp"
#include "ndms_wireguard_identity.hpp"

#include "../http/http_client.hpp"

#include <algorithm>
#include <cctype>
#include <set>
#include <utility>

namespace keen_pbr3 {

namespace {

constexpr std::string_view kRciBase{"http://127.0.0.1:79/rci/"};
constexpr std::string_view kSlotRevisionPrefix{"ndms-wg-slot-v1-"};

struct JsonReadResult final {
    std::optional<nlohmann::json> document;
    NdmsNativeDirectObservationFailure failure{
        NdmsNativeDirectObservationFailure::none};
};

class StringWipeGuard final {
public:
    explicit StringWipeGuard(std::string& value) noexcept : value_(value) {}
    ~StringWipeGuard() {
        volatile char* bytes = value_.empty() ? nullptr : value_.data();
        for (std::size_t index = 0U; index < value_.size(); ++index) {
            bytes[index] = 0;
        }
        value_.clear();
    }

private:
    std::string& value_;
};

void wipe_json_strings(nlohmann::json& value) noexcept {
    try {
        if (value.is_string()) {
            auto& text = value.get_ref<std::string&>();
            volatile char* bytes = text.empty() ? nullptr : text.data();
            for (std::size_t index = 0U; index < text.size(); ++index) {
                bytes[index] = 0;
            }
            text.clear();
            return;
        }
        if (value.is_object()) {
            for (auto& [key, child] : value.items()) {
                (void)key;
                wipe_json_strings(child);
            }
            return;
        }
        if (value.is_array()) {
            for (auto& child : value) wipe_json_strings(child);
        }
    } catch (...) {
        // This is a best-effort cleanup path in a noexcept destructor.  The
        // ordinary nlohmann traversal above performs no allocation.
    }
}

class JsonWipeGuard final {
public:
    explicit JsonWipeGuard(nlohmann::json& value) noexcept : value_(value) {}
    ~JsonWipeGuard() { wipe_json_strings(value_); }

private:
    nlohmann::json& value_;
};

std::string ascii_lower(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    value = value.substr(first, last - first + 1U);
    std::transform(
        value.begin(), value.end(), value.begin(),
        [](const unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return value;
}

bool explicit_error_status(const nlohmann::json& value) {
    if (value.is_string()) {
        const auto status = ascii_lower(value.get<std::string>());
        return status == "error" || status == "failed" ||
               status == "failure";
    }
    if (value.is_object()) {
        if (value.contains("error")) return true;
        const auto status = value.find("status");
        return status != value.end() && explicit_error_status(*status);
    }
    if (value.is_array()) {
        return std::any_of(
            value.begin(), value.end(),
            [](const nlohmann::json& item) {
                return explicit_error_status(item);
            });
    }
    return false;
}

bool is_rci_error_object(const nlohmann::json& document) {
    if (!document.is_object()) return false;
    if (document.contains("error")) return true;
    const auto status = document.find("status");
    return status != document.end() && explicit_error_status(*status);
}

JsonReadResult parse_object_response(std::string& body,
                                     const std::size_t maximum_bytes,
                                     const bool allow_empty_object) {
    StringWipeGuard body_guard(body);
    if (body.size() > maximum_bytes) {
        return {{}, NdmsNativeDirectObservationFailure::response_too_large};
    }
    if (body.empty()) {
        return {{}, NdmsNativeDirectObservationFailure::empty_response};
    }

    bool duplicate_key = false;
    std::vector<std::set<std::string>> object_keys;
    const auto callback =
        [&duplicate_key, &object_keys](
            const int,
            const nlohmann::json::parse_event_t event,
            nlohmann::json& parsed) {
            switch (event) {
            case nlohmann::json::parse_event_t::object_start:
                object_keys.emplace_back();
                break;
            case nlohmann::json::parse_event_t::key:
                if (object_keys.empty() || !parsed.is_string() ||
                    !object_keys.back()
                         .insert(parsed.get_ref<const std::string&>())
                         .second) {
                    duplicate_key = true;
                }
                break;
            case nlohmann::json::parse_event_t::object_end:
                if (!object_keys.empty()) object_keys.pop_back();
                break;
            default:
                break;
            }
            return true;
        };

    auto document = nlohmann::json::parse(
        body.begin(), body.end(), callback, false, true);
    if (document.is_discarded()) {
        return {{}, NdmsNativeDirectObservationFailure::malformed_json};
    }
    if (duplicate_key) {
        wipe_json_strings(document);
        return {{}, NdmsNativeDirectObservationFailure::duplicate_json_key};
    }
    if (!document.is_object()) {
        wipe_json_strings(document);
        return {{}, NdmsNativeDirectObservationFailure::response_not_object};
    }
    if (is_rci_error_object(document)) {
        wipe_json_strings(document);
        return {{}, NdmsNativeDirectObservationFailure::rci_error_response};
    }
    if (!allow_empty_object && document.empty()) {
        return {{}, NdmsNativeDirectObservationFailure::empty_response};
    }
    return {std::move(document), NdmsNativeDirectObservationFailure::none};
}

JsonReadResult read_fixed_document(
    const std::shared_ptr<HttpTransport>& transport,
    const std::string& endpoint,
    const std::size_t maximum_bytes,
    const bool allow_empty_object) {
    try {
        HttpClient client(transport);
        client.set_timeout(kNdmsNativeDirectObservationTimeout);
        client.set_max_response_size(maximum_bytes);
        HttpRequestOptions options;
        options.destination_filter = [](const std::string& address) {
            return ndms_native_direct_loopback_destination_permitted(address);
        };
        options.max_redirects = 0;
        auto body = client.download(endpoint, options);
        return parse_object_response(
            body, maximum_bytes, allow_empty_object);
    } catch (...) {
        return {{}, NdmsNativeDirectObservationFailure::transport_failed};
    }
}

bool catalog_document_shape_is_strict(const nlohmann::json& document) {
    if (document.empty()) return false;
    return std::all_of(
        document.begin(), document.end(),
        [](const nlohmann::json& entry) { return entry.is_object(); });
}

bool catalog_slot_evidence_is_safe(
    const NdmsWireguardCatalogSlotEvidence& slot) noexcept {
    const auto prefixed_sha256 = [](const std::string_view value,
                                    const std::string_view prefix) {
        return value.size() == prefix.size() + 64U &&
               value.compare(0U, prefix.size(), prefix) == 0 &&
               std::all_of(
                   value.begin() + static_cast<std::ptrdiff_t>(prefix.size()),
                   value.end(), [](const unsigned char character) {
                       return (character >= '0' && character <= '9') ||
                              (character >= 'a' && character <= 'f');
                   });
    };
    switch (slot.state) {
    case NdmsWireguardCatalogSlotState::absent:
        return slot.structural_revision.empty();
    case NdmsWireguardCatalogSlotState::occupied:
        return prefixed_sha256(
            slot.structural_revision, kSlotRevisionPrefix);
    case NdmsWireguardCatalogSlotState::unsafe:
        return false;
    }
    return false;
}

bool catalog_is_safe(
    const NdmsInterfaceCatalog& catalog,
    const NdmsNativeDirectCatalogScope scope) noexcept {
    if (!catalog.firmware_available ||
        !catalog.wireguard_slot_evidence_complete ||
        !std::all_of(
            catalog.wireguard_slots.begin(),
            catalog.wireguard_slots.end(),
            catalog_slot_evidence_is_safe)) {
        return false;
    }

    // Runtime state must expose a typed WG/AWG tunnel. Current Keenetic
    // running-config instead exposes the same occupied slot under its exact
    // WireguardN key without repeating `type` or `interface-name`. For that
    // scope, exactly one canonical metadata row is the complete marker-scan
    // surface; exact target config/runtime/ASC reads below still prove the
    // protocol before any recovery action can become authoritative.
    for (std::size_t slot = 0U;
         slot < catalog.wireguard_slots.size(); ++slot) {
        if (catalog.wireguard_slots[slot].state !=
            NdmsWireguardCatalogSlotState::occupied) {
            continue;
        }
        const auto expected = "Wireguard" + std::to_string(slot);
        const auto matches = scope ==
                NdmsNativeDirectCatalogScope::runtime_state
            ? std::count_if(
                  catalog.tunnels.begin(), catalog.tunnels.end(),
                  [&expected](const NdmsTunnelInterface& tunnel) {
                      return tunnel.firmware_interface_name == expected &&
                             (tunnel.kind == NdmsTunnelKind::wireguard ||
                              tunnel.kind ==
                                  NdmsTunnelKind::amnezia_wireguard);
                  })
            : std::count_if(
                  catalog.interface_metadata.begin(),
                  catalog.interface_metadata.end(),
                  [&expected](const NdmsInterfaceMetadata& metadata) {
                      return metadata.firmware_interface_name == expected;
                  });
        if (matches != 1) return false;
    }
    return true;
}

bool is_wireguard_kind(const NdmsTunnelKind kind) noexcept {
    return kind == NdmsTunnelKind::wireguard ||
           kind == NdmsTunnelKind::amnezia_wireguard;
}

NdmsTunnelKind tunnel_kind_from_asc(
    const NdmsNativeAscClass asc_class) noexcept {
    return asc_class == NdmsNativeAscClass::amnezia_wg
        ? NdmsTunnelKind::amnezia_wireguard
        : NdmsTunnelKind::wireguard;
}

std::string target_endpoint(const std::string_view path) {
    return std::string{kRciBase} + std::string{path};
}

struct TargetReadResult final {
    std::optional<NdmsNativeImportRecoveryTargetEvidence> evidence;
    std::optional<NdmsNativeAscClass> asc_class;
    NdmsNativeDirectObservationFailure failure{
        NdmsNativeDirectObservationFailure::none};
    NdmsNativeDirectDocumentKind failed_document{
        NdmsNativeDirectDocumentKind::none};
    std::optional<NdmsNativeTargetReadFailure::Reason>
        evidence_failure;
};

TargetReadResult read_target(
    const std::shared_ptr<HttpTransport>& transport,
    const std::string& interface_name) {
    const auto config_path =
        "show/rc/interface/" + interface_name;
    const auto runtime_path = "show/interface/" + interface_name;
    const auto asc_path =
        config_path + "/wireguard/asc";

    auto config = read_fixed_document(
        transport, target_endpoint(config_path),
        kNdmsNativeDirectTargetMaximumBytes, false);
    if (!config.document) {
        return {{}, {}, config.failure,
                NdmsNativeDirectDocumentKind::target_config, {}};
    }
    JsonWipeGuard config_guard(*config.document);

    auto runtime = read_fixed_document(
        transport, target_endpoint(runtime_path),
        kNdmsNativeDirectTargetMaximumBytes, false);
    if (!runtime.document) {
        return {{}, {}, runtime.failure,
                NdmsNativeDirectDocumentKind::target_runtime, {}};
    }
    JsonWipeGuard runtime_guard(*runtime.document);

    auto asc = read_fixed_document(
        transport, target_endpoint(asc_path),
        kNdmsNativeDirectTargetMaximumBytes, true);
    if (!asc.document) {
        return {{}, {}, asc.failure,
                NdmsNativeDirectDocumentKind::target_asc, {}};
    }
    JsonWipeGuard asc_guard(*asc.document);

    // The firmware's running-config document can contain preshared keys.  It
    // is redacted here before it reaches the secret-independent evidence
    // builder; the raw body and DOM strings are overwritten on every return.
    const auto redacted_config = redact_ndms_secret_material(
        *config.document, interface_name);
    const auto built = build_ndms_native_target_evidence(
        interface_name, redacted_config, *runtime.document, *asc.document);
    if (!built.evidence || !built.asc_class) {
        return {{}, {},
                NdmsNativeDirectObservationFailure::target_evidence_refused,
                NdmsNativeDirectDocumentKind::none,
                built.failure
                    ? std::optional<NdmsNativeTargetReadFailure::Reason>{
                          built.failure->reason}
                    : std::nullopt};
    }
    return {built.evidence, built.asc_class,
            NdmsNativeDirectObservationFailure::none,
            NdmsNativeDirectDocumentKind::none, {}};
}

} // namespace

bool NdmsNativeDirectRecoveryObservation::complete() const noexcept {
    return failure == NdmsNativeDirectObservationFailure::none &&
           snapshot.has_value() && !catalog_revision.empty() &&
           catalog_scope == requested_catalog_scope;
}

NdmsNativeDirectObservationGateway::NdmsNativeDirectObservationGateway()
    : NdmsNativeDirectObservationGateway(default_http_transport()) {}

NdmsNativeDirectObservationGateway::NdmsNativeDirectObservationGateway(
    std::shared_ptr<HttpTransport> transport,
    NowFn now_fn)
    : transport_(std::move(transport)), now_fn_(std::move(now_fn)) {
    if (!transport_) {
        throw std::invalid_argument(
            "direct NDMS observation requires an HTTP transport");
    }
    if (!now_fn_) {
        now_fn_ = [] { return Clock::now(); };
    }
}

NdmsNativeDirectCatalogObservation
NdmsNativeDirectObservationGateway::observe_catalog(
    const NdmsNativeDirectCatalogScope scope) const noexcept {
    try {
        const auto endpoint =
            scope == NdmsNativeDirectCatalogScope::running_config
                ? kNdmsNativeDirectRunningConfigCatalogEndpoint
                : kNdmsNativeDirectRuntimeCatalogEndpoint;
        auto read = read_fixed_document(
            transport_, std::string{endpoint},
            kNdmsNativeDirectCatalogMaximumBytes, false);
        if (!read.document) return {{}, read.failure, scope};
        JsonWipeGuard document_guard(*read.document);
        if (!catalog_document_shape_is_strict(*read.document)) {
            return {{},
                    NdmsNativeDirectObservationFailure::catalog_malformed,
                    scope};
        }

        auto catalog = parse_ndms_interface_catalog(*read.document);
        if (!catalog.firmware_available) {
            return {{},
                    NdmsNativeDirectObservationFailure::catalog_unavailable,
                    scope};
        }

        // Direct observations deliberately carry no process-local cache
        // generations.  Durable authority is recorded later against the
        // canonical measured payload revision, not inferred from these zeroes.
        NdmsCatalogSnapshot snapshot{
            std::move(catalog),
            NdmsCatalogCacheStatus::fresh,
            true,
            now_fn_(),
            0U,
            0U,
            0U,
        };
        return {std::move(snapshot),
                NdmsNativeDirectObservationFailure::none,
                scope};
    } catch (...) {
        return {{}, NdmsNativeDirectObservationFailure::transport_failed,
                scope};
    }
}

NdmsNativeDirectRecoveryObservation
NdmsNativeDirectObservationGateway::observe_recovery(
    const std::string_view marker,
    const std::optional<std::string>& expected_target) const noexcept {
    return observe_recovery(
        NdmsNativeDirectCatalogScope::runtime_state,
        marker,
        expected_target);
}

NdmsNativeDirectRecoveryObservation
NdmsNativeDirectObservationGateway::observe_recovery(
    const NdmsNativeDirectCatalogScope scope,
    const std::string_view marker,
    const std::optional<std::string>& expected_target) const noexcept {
    NdmsNativeDirectRecoveryObservation result;
    result.requested_catalog_scope = scope;
    try {
        if (!ndms_native_import_transaction_id_from_marker(marker)) {
            result.failure =
                NdmsNativeDirectObservationFailure::invalid_marker;
            return result;
        }

        std::optional<NdmsWireguardIdentity> expected_identity;
        if (expected_target) {
            expected_identity =
                parse_ndms_wireguard_identity(*expected_target);
            if (!expected_identity ||
                expected_identity->canonical_name() != *expected_target ||
                !ndms_wireguard_identity_is_managed_candidate(
                    *expected_identity)) {
                result.failure =
                    NdmsNativeDirectObservationFailure::invalid_target;
                return result;
            }
        }

        auto catalog_read = observe_catalog(scope);
        result.catalog_scope = catalog_read.scope;
        if (!catalog_read.snapshot) {
            result.failure = catalog_read.failure;
            result.failed_document =
                NdmsNativeDirectDocumentKind::catalog;
            return result;
        }
        result.snapshot = std::move(catalog_read.snapshot);
        if (!catalog_is_safe(result.snapshot->catalog, scope)) {
            result.failure =
                NdmsNativeDirectObservationFailure::catalog_unsafe;
            return result;
        }

        std::vector<std::string> marker_sightings;
        if (scope == NdmsNativeDirectCatalogScope::runtime_state) {
            for (const auto& tunnel : result.snapshot->catalog.tunnels) {
                if (tunnel.label.find(marker) != std::string::npos) {
                    marker_sightings.push_back(
                        tunnel.firmware_interface_name);
                }
            }
        } else {
            for (const auto& metadata :
                 result.snapshot->catalog.interface_metadata) {
                const auto identity = parse_ndms_wireguard_identity(
                    metadata.firmware_interface_name);
                if (identity &&
                    metadata.label.find(marker) != std::string::npos) {
                    marker_sightings.push_back(
                        metadata.firmware_interface_name);
                }
            }
        }
        if (marker_sightings.size() >
            kNdmsNativeDirectMaximumMarkerSightings) {
            result.failure =
                NdmsNativeDirectObservationFailure::ambiguous_marker;
            return result;
        }

        std::set<std::string> evidence_targets;
        if (!marker_sightings.empty()) {
            const auto identity = parse_ndms_wireguard_identity(
                marker_sightings.front());
            if (!identity ||
                identity->canonical_name() !=
                    marker_sightings.front() ||
                !ndms_wireguard_identity_is_managed_candidate(*identity) ||
                result.snapshot->catalog
                        .wireguard_slots[identity->slot]
                        .state !=
                    NdmsWireguardCatalogSlotState::occupied) {
                result.failure = NdmsNativeDirectObservationFailure::
                    marker_target_not_managed_wireguard;
                return result;
            }
            if (scope == NdmsNativeDirectCatalogScope::runtime_state) {
                const auto typed = std::find_if(
                    result.snapshot->catalog.tunnels.begin(),
                    result.snapshot->catalog.tunnels.end(),
                    [&](const NdmsTunnelInterface& tunnel) {
                        return tunnel.firmware_interface_name ==
                                   marker_sightings.front() &&
                               is_wireguard_kind(tunnel.kind);
                    });
                if (typed == result.snapshot->catalog.tunnels.end()) {
                    result.failure = NdmsNativeDirectObservationFailure::
                        marker_target_not_managed_wireguard;
                    return result;
                }
            }
            evidence_targets.insert(marker_sightings.front());
        }

        if (expected_identity &&
            result.snapshot->catalog
                    .wireguard_slots[expected_identity->slot]
                    .state == NdmsWireguardCatalogSlotState::occupied) {
            evidence_targets.insert(*expected_target);
        }
        if (evidence_targets.size() >
            kNdmsNativeDirectMaximumEvidenceTargets) {
            result.failure =
                NdmsNativeDirectObservationFailure::ambiguous_marker;
            return result;
        }

        for (const auto& interface_name : evidence_targets) {
            const auto target = read_target(transport_, interface_name);
            if (!target.evidence || !target.asc_class) {
                result.target_evidence.clear();
                result.target_protocols.clear();
                result.failure = target.failure;
                result.failed_document = target.failed_document;
                result.failed_interface = interface_name;
                result.target_evidence_failure = target.evidence_failure;
                return result;
            }
            result.target_evidence.push_back(*target.evidence);
            result.target_protocols.push_back(
                {interface_name, *target.asc_class});
        }

        if (scope == NdmsNativeDirectCatalogScope::running_config) {
            // Materialize only the bounded, directly measured targets. This
            // lets the common recovery probe scan the real running-config
            // label while keeping protocol and kernel identity sourced from
            // the exact target reads and local interface inventory.
            for (const auto& protocol : result.target_protocols) {
                const auto existing = std::find_if(
                    result.snapshot->catalog.tunnels.begin(),
                    result.snapshot->catalog.tunnels.end(),
                    [&](const NdmsTunnelInterface& tunnel) {
                        return tunnel.firmware_interface_name ==
                            protocol.interface_name;
                    });
                if (existing != result.snapshot->catalog.tunnels.end()) {
                    continue;
                }
                const auto metadata = std::find_if(
                    result.snapshot->catalog.interface_metadata.begin(),
                    result.snapshot->catalog.interface_metadata.end(),
                    [&](const NdmsInterfaceMetadata& item) {
                        return item.firmware_interface_name ==
                            protocol.interface_name;
                    });
                const auto identity = parse_ndms_wireguard_identity(
                    protocol.interface_name);
                if (metadata ==
                        result.snapshot->catalog.interface_metadata.end() ||
                    !identity ||
                    result.snapshot->catalog
                            .wireguard_slots[identity->slot]
                            .state !=
                        NdmsWireguardCatalogSlotState::occupied) {
                    result.target_evidence.clear();
                    result.target_protocols.clear();
                    result.failure = NdmsNativeDirectObservationFailure::
                        catalog_unsafe;
                    return result;
                }
                result.snapshot->catalog.tunnels.push_back(
                    NdmsTunnelInterface{
                        metadata->id,
                        metadata->firmware_interface_name,
                        std::nullopt,
                        metadata->label,
                        metadata->firmware_type,
                        tunnel_kind_from_asc(protocol.asc_class),
                        NdmsInterfaceRole::unknown,
                        false,
                        false,
                        metadata->connected,
                        metadata->link,
                        result.snapshot->catalog
                            .wireguard_slots[identity->slot]
                            .structural_revision,
                    });
            }
            std::sort(
                result.snapshot->catalog.tunnels.begin(),
                result.snapshot->catalog.tunnels.end(),
                [](const NdmsTunnelInterface& left,
                   const NdmsTunnelInterface& right) {
                    return left.firmware_interface_name <
                        right.firmware_interface_name;
                });
        }

        result.catalog_revision =
            ndms_native_import_recovery_catalog_revision(
                result.snapshot->catalog, result.target_evidence);
        result.failure = NdmsNativeDirectObservationFailure::none;
        return result;
    } catch (...) {
        result.target_evidence.clear();
        result.target_protocols.clear();
        result.catalog_revision.clear();
        result.failure =
            NdmsNativeDirectObservationFailure::transport_failed;
        return result;
    }
}

const char* ndms_native_direct_observation_failure_name(
    const NdmsNativeDirectObservationFailure failure) noexcept {
    switch (failure) {
    case NdmsNativeDirectObservationFailure::none:
        return "none";
    case NdmsNativeDirectObservationFailure::invalid_marker:
        return "invalid_marker";
    case NdmsNativeDirectObservationFailure::invalid_target:
        return "invalid_target";
    case NdmsNativeDirectObservationFailure::transport_failed:
        return "transport_failed";
    case NdmsNativeDirectObservationFailure::response_too_large:
        return "response_too_large";
    case NdmsNativeDirectObservationFailure::empty_response:
        return "empty_response";
    case NdmsNativeDirectObservationFailure::malformed_json:
        return "malformed_json";
    case NdmsNativeDirectObservationFailure::duplicate_json_key:
        return "duplicate_json_key";
    case NdmsNativeDirectObservationFailure::response_not_object:
        return "response_not_object";
    case NdmsNativeDirectObservationFailure::rci_error_response:
        return "rci_error_response";
    case NdmsNativeDirectObservationFailure::catalog_malformed:
        return "catalog_malformed";
    case NdmsNativeDirectObservationFailure::catalog_unavailable:
        return "catalog_unavailable";
    case NdmsNativeDirectObservationFailure::catalog_unsafe:
        return "catalog_unsafe";
    case NdmsNativeDirectObservationFailure::ambiguous_marker:
        return "ambiguous_marker";
    case NdmsNativeDirectObservationFailure::
        marker_target_not_managed_wireguard:
        return "marker_target_not_managed_wireguard";
    case NdmsNativeDirectObservationFailure::target_evidence_refused:
        return "target_evidence_refused";
    }
    return "transport_failed";
}

} // namespace keen_pbr3
