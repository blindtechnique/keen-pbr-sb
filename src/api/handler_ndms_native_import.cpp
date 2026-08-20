#ifdef WITH_API

#include "handler_ndms_native_import.hpp"

#include "handlers.hpp"
#include "server.hpp"

#include "../keenetic/ndms_native_import_identity.hpp"
#include "../keenetic/ndms_native_import_request.hpp"
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
#include <utility>

namespace keen_pbr3 {

namespace {

class WipeSensitiveString final {
public:
    explicit WipeSensitiveString(std::string& value) noexcept
        : value_(value) {}

    ~WipeSensitiveString() noexcept {
        if (!value_.empty()) {
            volatile char* cursor = value_.data();
            for (std::size_t index = 0U; index < value_.size(); ++index) {
                cursor[index] = 0;
            }
        }
        value_.clear();
    }

    WipeSensitiveString(const WipeSensitiveString&) = delete;
    WipeSensitiveString& operator=(const WipeSensitiveString&) = delete;

private:
    std::string& value_;
};

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

bool accepted_plain_text_content_type(const httplib::Request& request) {
    if (request.get_header_value_count("Content-Type") != 1U) {
        return false;
    }
    const auto value = ascii_lower_trimmed(
        request.get_header_value("Content-Type"));
    return value == "text/plain" ||
           value == "text/plain; charset=utf-8";
}

bool accepted_owner_race_header(const httplib::Request& request) {
    const std::string name{kNdmsNativeImportRaceAcceptanceHeader};
    return request.get_header_value_count(name) == 1U &&
           request.get_header_value(name) ==
               kNdmsNativeImportRaceAcceptanceValue;
}

bool public_interface_name(const std::string& value) {
    const auto identity = parse_ndms_wireguard_identity(value);
    return identity.has_value() &&
           ndms_wireguard_identity_is_managed_candidate(*identity) &&
           identity->canonical_name() == value;
}

bool public_kernel_interface_name(const std::string_view value) noexcept {
    if (value.empty() || value.size() > 15U || value == "." ||
        value == "..") {
        return false;
    }
    return std::all_of(
        value.begin(), value.end(), [](const unsigned char character) {
            const bool ascii_alnum =
                (character >= 'a' && character <= 'z') ||
                (character >= 'A' && character <= 'Z') ||
                (character >= '0' && character <= '9');
            return ascii_alnum || character == '_' ||
                   character == '-' || character == '.' ||
                   character == ':';
        });
}

bool public_created_identity(
    const NdmsNativeCooperativeImportResult& result) {
    return result.created_interface.has_value() &&
           public_interface_name(*result.created_interface) &&
           result.created_kernel_interface.has_value() &&
           public_kernel_interface_name(
               *result.created_kernel_interface);
}

bool public_created_identity(
    const NdmsNativeCooperativeImportResumeResult& result) {
    return result.created_interface.has_value() &&
           public_interface_name(*result.created_interface) &&
           result.created_kernel_interface.has_value() &&
           public_kernel_interface_name(
               *result.created_kernel_interface);
}

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

bool known_public_import_enums(
    const NdmsNativeCooperativeImportResult& result) noexcept {
    return known_enum_value(
               result.status,
               NdmsNativeCooperativeImportStatus::blocked,
               NdmsNativeCooperativeImportStatus::completed) &&
           known_enum_value(
               result.stop,
               NdmsNativeCooperativeImportStop::none,
               NdmsNativeCooperativeImportStop::unexpected_failure) &&
           known_optional_enum_value(
               result.kind,
               NdmsNativeTunnelImportKind::wireguard,
               NdmsNativeTunnelImportKind::amnezia_wireguard) &&
           known_optional_enum_value(
               result.delete_wal_readiness,
               NdmsNativeDeleteWalReadiness::clean,
               NdmsNativeDeleteWalReadiness::unsafe) &&
           known_optional_enum_value(
               result.import_wal_readiness,
               NdmsNativeCooperativeImportWalReadiness::clean,
               NdmsNativeCooperativeImportWalReadiness::unsafe) &&
           known_optional_enum_value(
               result.request_error,
               NdmsNativeTunnelImportErrorCode::input_too_large,
               NdmsNativeTunnelImportErrorCode::limit_exceeded) &&
           known_optional_enum_value(
               result.direct_observation_failure,
               NdmsNativeDirectObservationFailure::none,
               NdmsNativeDirectObservationFailure::
                   target_evidence_refused) &&
           known_optional_enum_value(
               result.baseline_error,
               NdmsNativeImportBaselineBuildError::none,
               NdmsNativeImportBaselineBuildError::
                   durable_observation_mismatch) &&
           known_optional_enum_value(
               result.executor_stop,
               NdmsNativeImportExecutionStop::none,
               NdmsNativeImportExecutionStop::ambiguous_response) &&
           known_optional_enum_value(
               result.forward_admission_state,
               NdmsNativeImportRecoveryAdmissionState::admitted,
               NdmsNativeImportRecoveryAdmissionState::
                   action_not_actionable) &&
           known_optional_enum_value(
               result.forward_dispatch_state,
               NdmsNativeImportRecoveryDispatchState::completed,
               NdmsNativeImportRecoveryDispatchState::step_failed) &&
           known_optional_enum_value(
               result.forward_failed_step,
               NdmsNativeImportRecoveryStep::
                   advance_wal_target_verified,
               NdmsNativeImportRecoveryStep::remove_wal_record);
}

void validate_public_import_result(
    const NdmsNativeCooperativeImportResult& result) {
    if (!known_public_import_enums(result)) {
        throw std::runtime_error("invalid native import result enum");
    }
    if (result.status != NdmsNativeCooperativeImportStatus::completed) {
        return;
    }
    if (result.stop != NdmsNativeCooperativeImportStop::none ||
        !result.transaction_id.has_value() ||
        !valid_ndms_native_import_transaction_id(
            *result.transaction_id) ||
        !result.expected_interface.has_value() ||
        !public_interface_name(*result.expected_interface) ||
        !public_created_identity(result) ||
        *result.expected_interface != *result.created_interface ||
        !result.kind.has_value() ||
        result.delete_wal_readiness !=
            std::optional<NdmsNativeDeleteWalReadiness>{
                NdmsNativeDeleteWalReadiness::clean} ||
        result.import_wal_readiness !=
            std::optional<NdmsNativeCooperativeImportWalReadiness>{
                NdmsNativeCooperativeImportWalReadiness::clean} ||
        !result.request_may_have_been_dispatched ||
        !result.ownership_published ||
        !result.external_ndms_writer_race_accepted ||
        result.wal_may_require_recovery ||
        !result.rollback_snapshot_may_be_retained) {
        throw std::runtime_error(
            "incoherent completed native import result");
    }
}

bool known_public_import_recovery_enums(
    const NdmsNativeCooperativeImportResumeResult& result) noexcept {
    return known_enum_value(
               result.status,
               NdmsNativeCooperativeImportResumeStatus::no_work,
               NdmsNativeCooperativeImportResumeStatus::completed) &&
           known_enum_value(
               result.stop,
               NdmsNativeCooperativeImportResumeStop::none,
               NdmsNativeCooperativeImportResumeStop::
                   unexpected_failure) &&
           known_optional_enum_value(
               result.kind,
               NdmsNativeTunnelImportKind::wireguard,
               NdmsNativeTunnelImportKind::amnezia_wireguard) &&
           known_optional_enum_value(
               result.phase,
               NdmsNativeImportWalPhase::prepared,
               NdmsNativeImportWalPhase::absence_verified) &&
           known_optional_enum_value(
               result.delete_wal_readiness,
               NdmsNativeDeleteWalReadiness::clean,
               NdmsNativeDeleteWalReadiness::unsafe) &&
           known_optional_enum_value(
               result.import_wal_readiness,
               NdmsNativeCooperativeImportWalReadiness::clean,
               NdmsNativeCooperativeImportWalReadiness::unsafe) &&
           known_optional_enum_value(
               result.direct_observation_failure,
               NdmsNativeDirectObservationFailure::none,
               NdmsNativeDirectObservationFailure::
                   target_evidence_refused) &&
           known_optional_enum_value(
               result.recovery_action,
               NdmsNativeImportRecoveryAction::
                   retry_read_only_observation,
               NdmsNativeImportRecoveryAction::block_unknown) &&
           known_optional_enum_value(
               result.forward_admission_state,
               NdmsNativeImportRecoveryAdmissionState::admitted,
               NdmsNativeImportRecoveryAdmissionState::
                   action_not_actionable) &&
           known_optional_enum_value(
               result.forward_dispatch_state,
               NdmsNativeImportRecoveryDispatchState::completed,
               NdmsNativeImportRecoveryDispatchState::step_failed) &&
           known_optional_enum_value(
               result.forward_failed_step,
               NdmsNativeImportRecoveryStep::
                   advance_wal_target_verified,
               NdmsNativeImportRecoveryStep::remove_wal_record);
}

bool forward_only_phase(const NdmsNativeImportWalPhase phase) noexcept {
    return phase == NdmsNativeImportWalPhase::response_recorded ||
           phase == NdmsNativeImportWalPhase::target_verified ||
           phase == NdmsNativeImportWalPhase::ownership_published;
}

bool forward_only_step(
    const NdmsNativeImportRecoveryStep step) noexcept {
    return step == NdmsNativeImportRecoveryStep::
                       advance_wal_target_verified ||
           step == NdmsNativeImportRecoveryStep::publish_ownership ||
           step == NdmsNativeImportRecoveryStep::
                       advance_wal_ownership_published ||
           step == NdmsNativeImportRecoveryStep::remove_wal_record;
}

void validate_public_import_recovery_result(
    const NdmsNativeCooperativeImportResumeResult& result) {
    if (!known_public_import_recovery_enums(result)) {
        throw std::runtime_error(
            "invalid native import recovery result enum");
    }
    if (result.ndms_import_request_dispatched ||
        result.ndms_delete_dispatched ||
        result.system_configuration_save_performed ||
        result.external_ndms_writer_race_excluded) {
        throw std::runtime_error(
            "native import recovery overclaimed router mutation");
    }

    const bool has_any_record_identity =
        result.transaction_id.has_value() ||
        result.expected_interface.has_value() ||
        result.kind.has_value() || result.phase.has_value();
    const bool has_complete_record_identity =
        result.transaction_id.has_value() &&
        result.expected_interface.has_value() &&
        result.kind.has_value() && result.phase.has_value();
    if (has_any_record_identity != has_complete_record_identity ||
        (has_complete_record_identity &&
         (!valid_ndms_native_import_transaction_id(
              *result.transaction_id) ||
          !public_interface_name(*result.expected_interface)))) {
        throw std::runtime_error(
            "invalid native import recovery record identity");
    }

    const bool has_any_created_identity =
        result.created_interface.has_value() ||
        result.created_kernel_interface.has_value();
    const bool has_created_identity = public_created_identity(result);
    if (has_any_created_identity != has_created_identity ||
        (has_created_identity &&
         (!result.expected_interface.has_value() ||
          *result.created_interface != *result.expected_interface))) {
        throw std::runtime_error(
            "invalid native import recovery created identity");
    }
    if (has_complete_record_identity &&
        (result.delete_wal_readiness !=
             std::optional<NdmsNativeDeleteWalReadiness>{
                 NdmsNativeDeleteWalReadiness::clean} ||
         result.import_wal_readiness !=
             std::optional<NdmsNativeCooperativeImportWalReadiness>{
                 NdmsNativeCooperativeImportWalReadiness::unfinished})) {
        throw std::runtime_error(
            "invalid native import recovery journal evidence");
    }

    const bool observation_failed =
        result.stop == NdmsNativeCooperativeImportResumeStop::
                           first_observation_failed ||
        result.stop == NdmsNativeCooperativeImportResumeStop::
                           second_observation_failed;
    if (result.direct_observation_failure.has_value() !=
            observation_failed ||
        (result.direct_observation_failure.has_value() &&
         *result.direct_observation_failure ==
             NdmsNativeDirectObservationFailure::none)) {
        throw std::runtime_error(
            "invalid native import recovery observation evidence");
    }

    const bool dispatch_step_failed =
        result.forward_dispatch_state ==
        std::optional<NdmsNativeImportRecoveryDispatchState>{
            NdmsNativeImportRecoveryDispatchState::step_failed};
    if (result.forward_failed_step.has_value() !=
            dispatch_step_failed ||
        (result.forward_failed_step.has_value() &&
         !forward_only_step(*result.forward_failed_step)) ||
        (result.forward_dispatch_state.has_value() &&
         result.forward_admission_state !=
             std::optional<NdmsNativeImportRecoveryAdmissionState>{
                 NdmsNativeImportRecoveryAdmissionState::admitted})) {
        throw std::runtime_error(
            "invalid native import recovery dispatch evidence");
    }
    const bool has_forward_evidence =
        result.recovery_action.has_value() ||
        result.forward_admission_state.has_value() ||
        result.forward_dispatch_state.has_value() ||
        result.forward_failed_step.has_value();
    if ((!has_complete_record_identity &&
         (has_created_identity || result.ownership_published ||
          has_forward_evidence)) ||
        (result.ownership_published && !has_created_identity) ||
        (result.wal_removed &&
         result.status !=
             NdmsNativeCooperativeImportResumeStatus::completed)) {
        throw std::runtime_error(
            "incoherent native import recovery evidence");
    }
    if ((has_created_identity || result.ownership_published ||
         has_forward_evidence) &&
        (!result.phase.has_value() ||
         !forward_only_phase(*result.phase))) {
        throw std::runtime_error(
            "native import recovery forward evidence has wrong phase");
    }
    if (has_created_identity && result.recovery_action.has_value() &&
        (*result.phase !=
             NdmsNativeImportWalPhase::ownership_published ||
         *result.recovery_action !=
             NdmsNativeImportRecoveryAction::
                 resume_forward_reconcile)) {
        throw std::runtime_error(
            "native import recovery action has wrong forward phase");
    }
    if (result.recovery_action.has_value() &&
        *result.phase !=
            NdmsNativeImportWalPhase::ownership_published &&
        result.stop != NdmsNativeCooperativeImportResumeStop::
                           recovery_action_not_forward_only) {
        throw std::runtime_error(
            "native import recovery action has impossible stop");
    }

    const auto require_stop_evidence = [](const bool condition) {
        if (!condition) {
            throw std::runtime_error(
                "native import recovery stop evidence is incoherent");
        }
    };
    const bool no_created_or_forward_evidence =
        !has_created_identity && !result.ownership_published &&
        !result.recovery_action.has_value() &&
        !result.forward_admission_state.has_value() &&
        !result.forward_dispatch_state.has_value() &&
        !result.forward_failed_step.has_value();
    const auto exact_dispatch_failure =
        [&](const NdmsNativeImportRecoveryStep expected_step) {
            return has_complete_record_identity &&
                   has_created_identity &&
                   result.forward_admission_state ==
                       std::optional<
                           NdmsNativeImportRecoveryAdmissionState>{
                           NdmsNativeImportRecoveryAdmissionState::
                               admitted} &&
                   result.forward_dispatch_state ==
                       std::optional<
                           NdmsNativeImportRecoveryDispatchState>{
                           NdmsNativeImportRecoveryDispatchState::
                               step_failed} &&
                   result.forward_failed_step ==
                       std::optional<NdmsNativeImportRecoveryStep>{
                           expected_step} &&
                   !result.direct_observation_failure.has_value();
        };

    switch (result.stop) {
    case NdmsNativeCooperativeImportResumeStop::none:
    case NdmsNativeCooperativeImportResumeStop::unexpected_failure:
        // An exception can preserve any already-validated monotonic prefix.
        // The generic ordering checks above still prevent evidence from
        // appearing before its durable record or forward-only phase.
        break;
    case NdmsNativeCooperativeImportResumeStop::writer_missing:
    case NdmsNativeCooperativeImportResumeStop::writer_lost:
        require_stop_evidence(
            !result.delete_wal_readiness.has_value() &&
            !result.import_wal_readiness.has_value() &&
            !has_complete_record_identity &&
            no_created_or_forward_evidence &&
            !result.direct_observation_failure.has_value());
        break;
    case NdmsNativeCooperativeImportResumeStop::delete_wal_not_clean:
        require_stop_evidence(
            result.delete_wal_readiness.has_value() &&
            *result.delete_wal_readiness !=
                NdmsNativeDeleteWalReadiness::clean &&
            !result.import_wal_readiness.has_value() &&
            !has_complete_record_identity &&
            no_created_or_forward_evidence &&
            !result.direct_observation_failure.has_value());
        break;
    case NdmsNativeCooperativeImportResumeStop::
        import_wal_not_single_safe:
        require_stop_evidence(
            result.delete_wal_readiness ==
                std::optional<NdmsNativeDeleteWalReadiness>{
                    NdmsNativeDeleteWalReadiness::clean} &&
            result.import_wal_readiness.has_value() &&
            *result.import_wal_readiness !=
                NdmsNativeCooperativeImportWalReadiness::clean &&
            !has_complete_record_identity &&
            no_created_or_forward_evidence &&
            !result.direct_observation_failure.has_value());
        break;
    case NdmsNativeCooperativeImportResumeStop::record_not_cooperative:
        require_stop_evidence(
            has_complete_record_identity &&
            no_created_or_forward_evidence &&
            !result.direct_observation_failure.has_value());
        break;
    case NdmsNativeCooperativeImportResumeStop::phase_not_forward_only:
        require_stop_evidence(
            has_complete_record_identity &&
            !forward_only_phase(*result.phase) &&
            no_created_or_forward_evidence &&
            !result.direct_observation_failure.has_value());
        break;
    case NdmsNativeCooperativeImportResumeStop::
        expected_target_not_managed:
    case NdmsNativeCooperativeImportResumeStop::
        observation_kind_mismatch:
    case NdmsNativeCooperativeImportResumeStop::
        durable_observation_failed:
    case NdmsNativeCooperativeImportResumeStop::observation_unstable:
        require_stop_evidence(
            has_complete_record_identity &&
            forward_only_phase(*result.phase) &&
            no_created_or_forward_evidence &&
            !result.direct_observation_failure.has_value());
        break;
    case NdmsNativeCooperativeImportResumeStop::
        first_observation_failed:
    case NdmsNativeCooperativeImportResumeStop::
        second_observation_failed:
        require_stop_evidence(
            has_complete_record_identity &&
            forward_only_phase(*result.phase) &&
            no_created_or_forward_evidence &&
            result.direct_observation_failure.has_value());
        break;
    case NdmsNativeCooperativeImportResumeStop::ownership_not_exact:
        require_stop_evidence(
            has_complete_record_identity &&
            forward_only_phase(*result.phase) &&
            !has_created_identity && !result.ownership_published &&
            !result.forward_admission_state.has_value() &&
            !result.forward_dispatch_state.has_value() &&
            !result.forward_failed_step.has_value() &&
            !result.direct_observation_failure.has_value() &&
            (!result.recovery_action.has_value() ||
             *result.phase ==
                 NdmsNativeImportWalPhase::ownership_published));
        break;
    case NdmsNativeCooperativeImportResumeStop::
        recovery_action_not_forward_only:
        require_stop_evidence(
            has_complete_record_identity &&
            forward_only_phase(*result.phase) &&
            !has_created_identity && !result.ownership_published &&
            result.recovery_action.has_value() &&
            !result.forward_admission_state.has_value() &&
            !result.forward_dispatch_state.has_value() &&
            !result.forward_failed_step.has_value() &&
            !result.direct_observation_failure.has_value());
        break;
    case NdmsNativeCooperativeImportResumeStop::
        forward_admission_failed:
        require_stop_evidence(
            has_complete_record_identity && has_created_identity &&
            result.forward_admission_state.has_value() &&
            *result.forward_admission_state !=
                NdmsNativeImportRecoveryAdmissionState::admitted &&
            !result.forward_dispatch_state.has_value() &&
            !result.forward_failed_step.has_value() &&
            !result.direct_observation_failure.has_value());
        break;
    case NdmsNativeCooperativeImportResumeStop::
        target_verified_wal_publish_failed:
        require_stop_evidence(exact_dispatch_failure(
            NdmsNativeImportRecoveryStep::
                advance_wal_target_verified));
        break;
    case NdmsNativeCooperativeImportResumeStop::ownership_publish_failed:
        require_stop_evidence(exact_dispatch_failure(
            NdmsNativeImportRecoveryStep::publish_ownership));
        break;
    case NdmsNativeCooperativeImportResumeStop::
        ownership_wal_publish_failed:
        require_stop_evidence(exact_dispatch_failure(
            NdmsNativeImportRecoveryStep::
                advance_wal_ownership_published));
        break;
    case NdmsNativeCooperativeImportResumeStop::wal_cleanup_failed:
        require_stop_evidence(exact_dispatch_failure(
            NdmsNativeImportRecoveryStep::remove_wal_record));
        break;
    }

    switch (result.status) {
    case NdmsNativeCooperativeImportResumeStatus::no_work:
        if (result.stop !=
                NdmsNativeCooperativeImportResumeStop::none ||
            has_complete_record_identity || has_created_identity ||
            result.delete_wal_readiness !=
                std::optional<NdmsNativeDeleteWalReadiness>{
                    NdmsNativeDeleteWalReadiness::clean} ||
            result.import_wal_readiness !=
                std::optional<NdmsNativeCooperativeImportWalReadiness>{
                    NdmsNativeCooperativeImportWalReadiness::clean} ||
            result.wal_may_require_recovery ||
            result.ownership_published || result.wal_removed ||
            result.direct_observation_failure.has_value() ||
            has_forward_evidence) {
            throw std::runtime_error(
                "incoherent no-work native import recovery result");
        }
        break;
    case NdmsNativeCooperativeImportResumeStatus::blocked:
        if (result.stop ==
                NdmsNativeCooperativeImportResumeStop::none ||
            result.wal_removed ||
            (has_complete_record_identity !=
             result.wal_may_require_recovery) ||
            result.forward_dispatch_state ==
                std::optional<NdmsNativeImportRecoveryDispatchState>{
                    NdmsNativeImportRecoveryDispatchState::completed}) {
            throw std::runtime_error(
                "incoherent blocked native import recovery result");
        }
        break;
    case NdmsNativeCooperativeImportResumeStatus::completed:
        if (result.stop !=
                NdmsNativeCooperativeImportResumeStop::none ||
            !has_complete_record_identity || !has_created_identity ||
            !forward_only_phase(*result.phase) ||
            result.wal_may_require_recovery ||
            !result.ownership_published || !result.wal_removed ||
            result.direct_observation_failure.has_value() ||
            result.forward_admission_state !=
                std::optional<NdmsNativeImportRecoveryAdmissionState>{
                    NdmsNativeImportRecoveryAdmissionState::admitted} ||
            result.forward_dispatch_state !=
                std::optional<NdmsNativeImportRecoveryDispatchState>{
                    NdmsNativeImportRecoveryDispatchState::completed} ||
            result.forward_failed_step.has_value() ||
            ((*result.phase ==
                  NdmsNativeImportWalPhase::ownership_published) !=
             (result.recovery_action ==
              std::optional<NdmsNativeImportRecoveryAction>{
                  NdmsNativeImportRecoveryAction::
                      resume_forward_reconcile}))) {
            throw std::runtime_error(
                "incoherent completed native import recovery result");
        }
        break;
    }
}

const char* import_wal_readiness_name(
    const NdmsNativeCooperativeImportWalReadiness readiness) noexcept {
    switch (readiness) {
    case NdmsNativeCooperativeImportWalReadiness::clean:
        return "clean";
    case NdmsNativeCooperativeImportWalReadiness::unfinished:
        return "unfinished";
    case NdmsNativeCooperativeImportWalReadiness::unsafe:
        return "unsafe";
    }
    return "unsafe";
}

ApiServer::SensitiveRequestReservationPtr reserve_import(
    const ApiContext& context) {
    if (!context.run_ndms_native_import_fn ||
        !context.reserve_ndms_native_import_fn) {
        throw ApiError("native import is unavailable", 503);
    }
    try {
        return context.reserve_ndms_native_import_fn();
    } catch (const ApiError&) {
        throw;
    } catch (...) {
        throw ApiError("native import is unavailable", 503);
    }
}

ApiServer::SensitiveRequestReservationPtr reserve_import_recovery(
    const ApiContext& context) {
    if (!context.resume_ndms_native_import_fn ||
        !context.reserve_ndms_native_import_recovery_fn) {
        throw ApiError("native import recovery is unavailable", 503);
    }
    try {
        return context.reserve_ndms_native_import_recovery_fn();
    } catch (const ApiError&) {
        throw;
    } catch (...) {
        throw ApiError("native import recovery is unavailable", 503);
    }
}

} // namespace

nlohmann::json ndms_native_import_api_response(
    const NdmsNativeCooperativeImportResult& result) {
    validate_public_import_result(result);
    nlohmann::json response{
        {"status", ndms_native_cooperative_import_status_name(
                       result.status)},
        {"stop", ndms_native_cooperative_import_stop_name(result.stop)},
        {"external_ndms_writer_race_excluded",
         false},
        {"external_ndms_writer_race_accepted",
         result.external_ndms_writer_race_accepted},
        {"system_configuration_save_performed",
         false},
        {"request_may_have_been_dispatched",
         result.request_may_have_been_dispatched},
        {"wal_may_require_recovery", result.wal_may_require_recovery},
        {"rollback_snapshot_may_be_retained",
         result.rollback_snapshot_may_be_retained},
        {"ownership_published", result.ownership_published},
    };

    if (result.transaction_id.has_value() &&
        valid_ndms_native_import_transaction_id(
            *result.transaction_id)) {
        response["transaction_id"] = *result.transaction_id;
    }
    if (result.expected_interface.has_value() &&
        public_interface_name(*result.expected_interface)) {
        response["expected_interface"] = *result.expected_interface;
    }
    if (public_created_identity(result)) {
        response["created_interface"] = *result.created_interface;
        response["created_kernel_interface"] =
            *result.created_kernel_interface;
    }
    if (result.kind.has_value()) {
        response["kind"] = ndms_native_tunnel_import_kind_name(
            *result.kind);
    }
    if (result.delete_wal_readiness.has_value()) {
        response["delete_wal_readiness"] =
            ndms_native_delete_wal_readiness_name(
                *result.delete_wal_readiness);
    }
    if (result.import_wal_readiness.has_value()) {
        response["import_wal_readiness"] = import_wal_readiness_name(
            *result.import_wal_readiness);
    }
    if (result.request_error.has_value()) {
        response["request_error"] =
            ndms_native_tunnel_import_error_code_name(
                *result.request_error);
    }
    if (result.direct_observation_failure.has_value()) {
        response["direct_observation_failure"] =
            ndms_native_direct_observation_failure_name(
                *result.direct_observation_failure);
    }
    if (result.baseline_error.has_value()) {
        response["baseline_error"] =
            ndms_native_import_baseline_build_error_name(
                *result.baseline_error);
    }
    if (result.executor_stop.has_value()) {
        response["executor_stop"] = ndms_native_import_execution_stop_name(
            *result.executor_stop);
    }
    if (result.forward_admission_state.has_value()) {
        response["forward_admission_state"] =
            ndms_native_import_recovery_admission_state_name(
                *result.forward_admission_state);
    }
    if (result.forward_dispatch_state.has_value()) {
        response["forward_dispatch_state"] =
            ndms_native_import_recovery_dispatch_state_name(
                *result.forward_dispatch_state);
    }
    if (result.forward_failed_step.has_value()) {
        response["forward_failed_step"] =
            ndms_native_import_recovery_step_name(
                *result.forward_failed_step);
    }
    return response;
}

nlohmann::json ndms_native_import_recovery_api_response(
    const NdmsNativeCooperativeImportResumeResult& result) {
    validate_public_import_recovery_result(result);
    nlohmann::json response{
        {"status", ndms_native_cooperative_import_resume_status_name(
                       result.status)},
        {"stop", ndms_native_cooperative_import_resume_stop_name(
                     result.stop)},
        {"ndms_import_request_dispatched", false},
        {"ndms_delete_dispatched", false},
        {"system_configuration_save_performed", false},
        {"external_ndms_writer_race_excluded", false},
        {"wal_may_require_recovery", result.wal_may_require_recovery},
        {"ownership_published", result.ownership_published},
        {"wal_removed", result.wal_removed},
    };

    // Deliberately omit transaction_id. It is validated above so a faulty
    // callback cannot smuggle arbitrary bytes through another field, but it
    // remains a private crash-recovery key rather than a UI identifier.
    if (result.expected_interface.has_value()) {
        response["expected_interface"] = *result.expected_interface;
    }
    if (result.created_interface.has_value()) {
        response["created_interface"] = *result.created_interface;
        response["created_kernel_interface"] =
            *result.created_kernel_interface;
    }
    if (result.kind.has_value()) {
        response["kind"] = ndms_native_tunnel_import_kind_name(
            *result.kind);
    }
    if (result.phase.has_value()) {
        response["phase"] = ndms_native_import_wal_phase_name(
            *result.phase);
    }
    if (result.delete_wal_readiness.has_value()) {
        response["delete_wal_readiness"] =
            ndms_native_delete_wal_readiness_name(
                *result.delete_wal_readiness);
    }
    if (result.import_wal_readiness.has_value()) {
        response["import_wal_readiness"] = import_wal_readiness_name(
            *result.import_wal_readiness);
    }
    if (result.direct_observation_failure.has_value()) {
        response["direct_observation_failure"] =
            ndms_native_direct_observation_failure_name(
                *result.direct_observation_failure);
    }
    if (result.recovery_action.has_value()) {
        response["recovery_action"] =
            ndms_native_import_recovery_action_name(
                *result.recovery_action);
    }
    if (result.forward_admission_state.has_value()) {
        response["forward_admission_state"] =
            ndms_native_import_recovery_admission_state_name(
                *result.forward_admission_state);
    }
    if (result.forward_dispatch_state.has_value()) {
        response["forward_dispatch_state"] =
            ndms_native_import_recovery_dispatch_state_name(
                *result.forward_dispatch_state);
    }
    if (result.forward_failed_step.has_value()) {
        response["forward_failed_step"] =
            ndms_native_import_recovery_step_name(
                *result.forward_failed_step);
    }
    return response;
}

void register_ndms_native_import_handler(ApiServer& server,
                                         ApiContext& ctx) {
    server.post_sensitive(
        std::string{kNdmsNativeImportPreflightApiPath},
        1U,
        [&ctx](const httplib::Request&) {
            return reserve_import(ctx);
        },
        [](const httplib::Request&,
           SensitiveRequestBody body,
           const ApiServer::SensitiveRequestReservationPtr&) {
            if (!body.empty()) {
                throw ApiError("native import preflight body must be empty",
                               400);
            }
            return nlohmann::json{
                {"admitted", true},
                {"owner_risk_acceptance_required", true},
                {"external_ndms_writer_race_excluded", false},
            }.dump();
        });

    server.post_sensitive(
        std::string{kNdmsNativeImportApiPath},
        kNdmsNativePreparedImportMaximumInputBytes,
        [&ctx](const httplib::Request& request) {
            if (!ctx.run_ndms_native_import_fn ||
                !ctx.reserve_ndms_native_import_fn) {
                throw ApiError("native import is unavailable", 503);
            }
            if (!accepted_plain_text_content_type(request)) {
                throw ApiError("native import requires text/plain", 415);
            }
            if (!accepted_owner_race_header(request)) {
                throw ApiError(
                    "external NDMS writer race acceptance is required",
                    428);
            }
            return reserve_import(ctx);
        },
        [&ctx](const httplib::Request&,
               SensitiveRequestBody body,
               const ApiServer::SensitiveRequestReservationPtr&
                   reservation) {
            if (body.empty()) {
                throw ApiError("native import body must not be empty", 400);
            }
            auto raw_configuration = body.take_string_once();
            WipeSensitiveString wipe_raw{raw_configuration};
            const auto result = ctx.run_ndms_native_import_fn(
                std::move(raw_configuration),
                NdmsNativeExternalWriterRaceAcceptance::owner_accepted,
                reservation);
            return ndms_native_import_api_response(result).dump();
        });

    server.post_sensitive(
        std::string{kNdmsNativeImportRecoveryApiPath},
        1U,
        [&ctx](const httplib::Request&) {
            return reserve_import_recovery(ctx);
        },
        [&ctx](
            const httplib::Request&,
            SensitiveRequestBody body,
            const ApiServer::SensitiveRequestReservationPtr& reservation) {
            if (!body.empty()) {
                throw ApiError(
                    "native import recovery body must be empty", 400);
            }
            const auto result =
                ctx.resume_ndms_native_import_fn(reservation);
            return ndms_native_import_recovery_api_response(result).dump();
        });
}

} // namespace keen_pbr3

#endif // WITH_API
