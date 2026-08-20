#ifdef WITH_API

#include "handler_ndms_native_delete.hpp"

#include "handlers.hpp"
#include "server.hpp"

#include "../keenetic/ndms_native_import_identity.hpp"
#include "../keenetic/ndms_native_tunnel_import.hpp"
#include "../keenetic/ndms_wireguard_identity.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstddef>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

template <typename Enum>
bool known_enum_value(const Enum value,
                      const Enum first,
                      const Enum last) noexcept {
    using Underlying = std::underlying_type_t<Enum>;
    const auto numeric = static_cast<Underlying>(value);
    return numeric >= static_cast<Underlying>(first) &&
           numeric <= static_cast<Underlying>(last);
}

template <typename Enum>
bool known_optional_enum_value(const std::optional<Enum>& value,
                               const Enum first,
                               const Enum last) noexcept {
    return !value.has_value() || known_enum_value(*value, first, last);
}

bool public_interface_name(const std::string_view value) noexcept {
    const auto identity = parse_ndms_wireguard_identity(value);
    return identity.has_value() &&
           ndms_wireguard_identity_is_managed_candidate(*identity) &&
           identity->canonical_name() == value;
}

bool bounded_opaque_revision(const std::string_view value) noexcept {
    // The HTTP layer deliberately does not interpret ownership schema or
    // digest prefixes. It only prevents an unbounded/non-token value from
    // crossing the callback seam; the coordinator compares the opaque bytes
    // with the freshly read claim and validates its v2/v3 domain.
    return !value.empty() && value.size() <= 128U &&
           std::all_of(
               value.begin(), value.end(), [](const unsigned char character) {
                   const bool ascii_alnum =
                       (character >= 'a' && character <= 'z') ||
                       (character >= 'A' && character <= 'Z') ||
                       (character >= '0' && character <= '9');
                   return ascii_alnum || character == '-' ||
                          character == '_' || character == '.' ||
                          character == ':';
               });
}

std::string ascii_lower_trimmed(std::string value) {
    const auto not_ows = [](const unsigned char character) {
        return character != ' ' && character != '\t';
    };
    const auto first = std::find_if(value.begin(), value.end(), not_ows);
    const auto last = std::find_if(value.rbegin(), value.rend(), not_ows)
                          .base();
    if (first >= last) return {};
    value = std::string{first, last};
    for (auto& character : value) {
        if (character >= 'A' && character <= 'Z') {
            character = static_cast<char>(character - 'A' + 'a');
        }
    }
    return value;
}

bool accepted_json_content_type(const httplib::Request& request) {
    if (request.get_header_value_count("Content-Type") != 1U) {
        return false;
    }
    return ascii_lower_trimmed(
               request.get_header_value("Content-Type")) ==
           "application/json";
}

enum class OwnerAcknowledgementHeaders {
    absent,
    accepted,
    invalid,
};

OwnerAcknowledgementHeaders owner_acknowledgement_headers(
    const httplib::Request& request) {
    const std::string race_name{kNdmsNativeDeleteRaceAcceptanceHeader};
    const std::string save_name{kNdmsNativeDeleteGlobalSaveHeader};
    const auto race_count = request.get_header_value_count(race_name);
    const auto save_count = request.get_header_value_count(save_name);
    if (race_count == 0U && save_count == 0U) {
        return OwnerAcknowledgementHeaders::absent;
    }
    if (race_count != 1U || save_count != 1U ||
        request.get_header_value(race_name) !=
            kNdmsNativeDeleteRaceAcceptanceValue ||
        request.get_header_value(save_name) !=
            kNdmsNativeDeleteGlobalSaveValue) {
        return OwnerAcknowledgementHeaders::invalid;
    }
    return OwnerAcknowledgementHeaders::accepted;
}

ApiServer::SensitiveRequestReservationPtr reserve_delete(
    const std::function<ApiServer::SensitiveRequestReservationPtr()>&
        reserve_fn) {
    if (!reserve_fn) {
        throw ApiError("native interface delete is unavailable", 503);
    }
    try {
        return reserve_fn();
    } catch (const ApiError&) {
        throw;
    } catch (...) {
        throw ApiError("native interface delete is unavailable", 503);
    }
}

NdmsNativeCooperativeDeleteRequest parse_delete_request(
    const std::string& raw) {
    bool duplicate_key = false;
    std::vector<std::unordered_set<std::string>> object_keys;
    const nlohmann::json::parser_callback_t duplicate_detector =
        [&duplicate_key, &object_keys](
            int,
            const nlohmann::json::parse_event_t event,
            nlohmann::json& parsed) {
            switch (event) {
            case nlohmann::json::parse_event_t::object_start:
                object_keys.emplace_back();
                break;
            case nlohmann::json::parse_event_t::key:
                if (object_keys.empty() || !parsed.is_string() ||
                    !object_keys.back()
                         .insert(parsed.get<std::string>())
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

    nlohmann::json document;
    try {
        document = nlohmann::json::parse(raw, duplicate_detector);
    } catch (...) {
        throw ApiError("native interface delete request is invalid", 400);
    }
    if (duplicate_key || !document.is_object() || document.size() != 3U ||
        !document.contains("interface_name") ||
        !document.contains("expected_ownership_revision") ||
        !document.contains("confirm_label") ||
        !document.at("interface_name").is_string() ||
        !document.at("expected_ownership_revision").is_string() ||
        !document.at("confirm_label").is_string()) {
        throw ApiError("native interface delete request is invalid", 400);
    }

    const auto interface_name =
        document.at("interface_name").get<std::string>();
    const auto expected_revision =
        document.at("expected_ownership_revision").get<std::string>();
    const auto confirm_label =
        document.at("confirm_label").get<std::string>();
    if (!public_interface_name(interface_name) ||
        !bounded_opaque_revision(expected_revision) ||
        confirm_label != interface_name) {
        throw ApiError("native interface delete request is invalid", 400);
    }

    NdmsNativeCooperativeDeleteRequest request;
    request.interface_name = interface_name;
    request.expected_ownership_revision = expected_revision;
    request.global_save_consent = NdmsNativeOwnerGlobalSaveConsent::
        acknowledged_all_pending_keenetic_changes;
    request.external_writer_race =
        NdmsNativeDeleteExternalWriterRaceAcceptance::owner_accepted;
    return request;
}

bool known_public_delete_enums(
    const NdmsNativeCooperativeDeleteResult& result) noexcept {
    return known_enum_value(
               result.status,
               NdmsNativeCooperativeDeleteStatus::blocked,
               NdmsNativeCooperativeDeleteStatus::
                   save_acknowledged_unverified) &&
           known_enum_value(
               result.stop,
               NdmsNativeCooperativeDeleteStop::none,
               NdmsNativeCooperativeDeleteStop::unexpected_failure) &&
           known_optional_enum_value(
               result.durable_phase,
               NdmsNativeDeleteWalPhase::prepared,
               NdmsNativeDeleteWalPhase::cleanup) &&
           known_optional_enum_value(
               result.kind,
               NdmsNativeTunnelImportKind::wireguard,
               NdmsNativeTunnelImportKind::amnezia_wireguard) &&
           known_optional_enum_value(
               result.transport_outcome,
               NdmsNativeExactMutationResponseOutcome::guard_rejected,
               NdmsNativeExactMutationResponseOutcome::
                   acknowledged_needs_observation) &&
           known_optional_enum_value(
               result.observation_failure,
               NdmsNativeDirectObservationFailure::none,
               NdmsNativeDirectObservationFailure::
                   target_evidence_refused);
}

void validate_public_delete_result(
    const NdmsNativeCooperativeDeleteResult& result) {
    if (!known_public_delete_enums(result)) {
        throw std::runtime_error("invalid native delete result enum");
    }
    if (result.external_writer_race_excluded ||
        result.external_writer_race_accepted !=
            result.global_save_scope_acknowledged) {
        throw std::runtime_error("incoherent native delete audit evidence");
    }

    const bool any_record_identity =
        result.durable_phase.has_value() ||
        result.transaction_id.has_value() ||
        result.interface_name.has_value() || result.kind.has_value();
    const bool has_record_identity =
        result.durable_phase.has_value() &&
        result.transaction_id.has_value() &&
        result.interface_name.has_value() && result.kind.has_value();
    if (any_record_identity != has_record_identity ||
        (has_record_identity &&
         (!valid_ndms_native_import_transaction_id(
              *result.transaction_id) ||
          !public_interface_name(*result.interface_name)))) {
        throw std::runtime_error("incoherent native delete identity");
    }
    if (has_record_identity != result.external_writer_race_accepted) {
        throw std::runtime_error(
            "native delete audit evidence lacks record identity");
    }

    const bool terminal =
        result.status == NdmsNativeCooperativeDeleteStatus::
            save_acknowledged_unverified;
    if (terminal) {
        if (result.stop != NdmsNativeCooperativeDeleteStop::none ||
            !has_record_identity ||
            result.durable_phase !=
                std::optional<NdmsNativeDeleteWalPhase>{
                    NdmsNativeDeleteWalPhase::cleanup} ||
            !result.external_writer_race_accepted ||
            !result.global_save_scope_acknowledged ||
            !result.ownership_tombstone_durable ||
            !result.rollback_snapshot_retained ||
            result.observation_failure.has_value()) {
            throw std::runtime_error(
                "incoherent terminal native delete result");
        }
    } else {
        if (result.stop == NdmsNativeCooperativeDeleteStop::none ||
            result.ownership_tombstone_durable ||
            result.rollback_snapshot_retained) {
            throw std::runtime_error(
                "incoherent nonterminal native delete result");
        }
        // A failure response intentionally has no durable identity when the
        // coordinator could not reread the WAL while retaining its writer
        // lease. The typed status, stop and current-invocation trace remain
        // useful, but phase/name/kind/audit evidence must all stay absent.
        // Complete known-record results remain subject to the strict identity
        // and durable-audit checks above.
        if (result.status == NdmsNativeCooperativeDeleteStatus::blocked &&
            (result.delete_perform_started || result.save_perform_started ||
             result.request_may_have_been_dispatched ||
             result.system_configuration_save_acknowledged ||
             result.transport_outcome.has_value() ||
             (result.durable_phase.has_value() &&
              *result.durable_phase != NdmsNativeDeleteWalPhase::prepared))) {
            throw std::runtime_error(
                "incoherent blocked native delete result");
        }
    }

    if ((result.delete_perform_started || result.save_perform_started ||
         result.request_may_have_been_dispatched ||
         result.system_configuration_save_acknowledged) &&
        !result.transport_outcome.has_value()) {
        throw std::runtime_error("native delete transport trace is missing");
    }
    const bool any_perform_started =
        result.delete_perform_started || result.save_perform_started;
    if (any_perform_started !=
        result.request_may_have_been_dispatched) {
        throw std::runtime_error("incoherent native delete dispatch trace");
    }
    // Transport facts describe only this invocation and can remain known even
    // when the final authoritative WAL reread fails. Their internal dispatch
    // coherence is still checked below without fabricating durable identity.
    if (result.transport_outcome.has_value() &&
        *result.transport_outcome !=
            NdmsNativeExactMutationResponseOutcome::guard_rejected &&
        *result.transport_outcome !=
            NdmsNativeExactMutationResponseOutcome::transport_failed &&
        !any_perform_started) {
        throw std::runtime_error(
            "native delete response outcome lacks a dispatch trace");
    }
    if (result.system_configuration_save_acknowledged &&
        (!result.save_perform_started ||
         !result.request_may_have_been_dispatched ||
         result.transport_outcome !=
             std::optional<NdmsNativeExactMutationResponseOutcome>{
                 NdmsNativeExactMutationResponseOutcome::
                     acknowledged_needs_observation})) {
        throw std::runtime_error("incoherent native delete save trace");
    }
    if (terminal && result.transport_outcome.has_value() &&
        result.transport_outcome !=
            std::optional<NdmsNativeExactMutationResponseOutcome>{
                NdmsNativeExactMutationResponseOutcome::
                    acknowledged_needs_observation}) {
        throw std::runtime_error(
            "incoherent terminal native delete transport outcome");
    }
    if (terminal &&
        (result.delete_perform_started && !result.save_perform_started)) {
        throw std::runtime_error(
            "terminal native delete result lacks current save trace");
    }
    if (terminal &&
        result.save_perform_started !=
            result.system_configuration_save_acknowledged) {
        throw std::runtime_error(
            "terminal native delete save trace is incomplete");
    }

    const bool observation_stop =
        result.stop ==
            NdmsNativeCooperativeDeleteStop::runtime_observation_failed ||
        result.stop == NdmsNativeCooperativeDeleteStop::
                           running_config_observation_failed;
    // Some recovery guards deliberately retain only the typed stop after a
    // failed observation and discard the narrower transport/parser reason.
    // If a reason is present it must belong to one of those two stops, but its
    // absence is a truthful redaction rather than an incoherent result.
    if (result.observation_failure.has_value() && !observation_stop) {
        throw std::runtime_error(
            "incoherent native delete observation failure");
    }
    // Observation failures can happen before the initial WAL publication or
    // after a transport whose durable WAL can no longer be read. The narrow
    // reason is therefore valid without a durable record projection.
}

const char* transport_outcome_name(
    const NdmsNativeExactMutationResponseOutcome outcome) {
    switch (outcome) {
    case NdmsNativeExactMutationResponseOutcome::guard_rejected:
        return "guard_rejected";
    case NdmsNativeExactMutationResponseOutcome::transport_failed:
        return "transport_failed";
    case NdmsNativeExactMutationResponseOutcome::body_too_large:
        return "body_too_large";
    case NdmsNativeExactMutationResponseOutcome::http_status_not_200:
        return "http_status_not_200";
    case NdmsNativeExactMutationResponseOutcome::content_type_not_json:
        return "content_type_not_json";
    case NdmsNativeExactMutationResponseOutcome::body_empty:
        return "body_empty";
    case NdmsNativeExactMutationResponseOutcome::shape_not_acknowledged:
        return "shape_not_acknowledged";
    case NdmsNativeExactMutationResponseOutcome::
        acknowledged_needs_observation:
        return "acknowledged_needs_observation";
    }
    throw std::runtime_error("invalid native delete transport outcome");
}

} // namespace

nlohmann::json ndms_native_delete_api_response(
    const NdmsNativeCooperativeDeleteResult& result) {
    validate_public_delete_result(result);
    nlohmann::json response{
        {"status", ndms_native_cooperative_delete_status_name(
                       result.status)},
        {"stop", ndms_native_cooperative_delete_stop_name(result.stop)},
        {"external_writer_race_excluded", false},
        {"external_writer_race_accepted",
         result.external_writer_race_accepted},
        {"global_save_scope_acknowledged",
         result.global_save_scope_acknowledged},
        {"delete_perform_started", result.delete_perform_started},
        {"save_perform_started", result.save_perform_started},
        {"request_may_have_been_dispatched",
         result.request_may_have_been_dispatched},
        {"system_configuration_save_acknowledged",
         result.system_configuration_save_acknowledged},
        {"ownership_tombstone_durable",
         result.ownership_tombstone_durable},
        {"rollback_snapshot_retained",
         result.rollback_snapshot_retained},
    };
    if (result.durable_phase.has_value()) {
        response["phase"] =
            ndms_native_delete_wal_phase_name(*result.durable_phase);
    }
    if (result.interface_name.has_value()) {
        response["interface_name"] = *result.interface_name;
    }
    if (result.kind.has_value()) {
        response["kind"] =
            ndms_native_tunnel_import_kind_name(*result.kind);
    }
    if (result.transport_outcome.has_value()) {
        response["transport_outcome"] =
            transport_outcome_name(*result.transport_outcome);
    }
    if (result.observation_failure.has_value()) {
        response["observation_failure"] =
            ndms_native_direct_observation_failure_name(
                *result.observation_failure);
    }
    return response;
}

void register_ndms_native_delete_handler(ApiServer& server,
                                         ApiContext& context) {
    server.post_sensitive(
        std::string{kNdmsNativeDeleteApiPath},
        kNdmsNativeDeleteRequestMaximumBytes,
        [&context](const httplib::Request& request) {
            if (!context.run_ndms_native_delete_fn ||
                !context.reserve_ndms_native_delete_fn) {
                throw ApiError("native interface delete is unavailable", 503);
            }
            if (!accepted_json_content_type(request)) {
                throw ApiError(
                    "native interface delete requires application/json",
                    415);
            }
            if (owner_acknowledgement_headers(request) !=
                OwnerAcknowledgementHeaders::accepted) {
                throw ApiError(
                    "native interface delete acknowledgements are required",
                    428);
            }
            return reserve_delete(context.reserve_ndms_native_delete_fn);
        },
        [&context](
            const httplib::Request&,
            SensitiveRequestBody body,
            const ApiServer::SensitiveRequestReservationPtr& reservation) {
            if (body.empty()) {
                throw ApiError(
                    "native interface delete body must not be empty", 400);
            }
            const auto request = parse_delete_request(
                body.take_string_once());
            const auto result = context.run_ndms_native_delete_fn(
                request, reservation);
            if (result.interface_name.has_value() &&
                *result.interface_name != request.interface_name) {
                throw std::runtime_error(
                    "native delete result target does not match request");
            }
            return ndms_native_delete_api_response(result).dump();
        });

    server.post_sensitive(
        std::string{kNdmsNativeDeleteRecoveryApiPath},
        1U,
        [&context](const httplib::Request& request) {
            if (!context.resume_ndms_native_delete_fn ||
                !context.reserve_ndms_native_delete_recovery_fn) {
                throw ApiError(
                    "native interface delete recovery is unavailable", 503);
            }
            if (owner_acknowledgement_headers(request) ==
                OwnerAcknowledgementHeaders::invalid) {
                throw ApiError(
                    "native interface delete recovery acknowledgements are invalid",
                    428);
            }
            return reserve_delete(
                context.reserve_ndms_native_delete_recovery_fn);
        },
        [&context](
            const httplib::Request& request,
            SensitiveRequestBody body,
            const ApiServer::SensitiveRequestReservationPtr& reservation) {
            if (!body.empty()) {
                throw ApiError(
                    "native interface delete recovery body must be empty",
                    400);
            }
            NdmsNativeCooperativeDeleteResumeAcknowledgement acknowledgement;
            if (owner_acknowledgement_headers(request) ==
                OwnerAcknowledgementHeaders::accepted) {
                acknowledgement.global_save_consent =
                    NdmsNativeOwnerGlobalSaveConsent::
                        acknowledged_all_pending_keenetic_changes;
                acknowledgement.external_writer_race =
                    NdmsNativeDeleteExternalWriterRaceAcceptance::
                        owner_accepted;
            }
            const auto result = context.resume_ndms_native_delete_fn(
                acknowledgement, reservation);
            return ndms_native_delete_api_response(result).dump();
        });
}

} // namespace keen_pbr3

#endif // WITH_API
