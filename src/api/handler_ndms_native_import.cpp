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

NdmsNativeExternalWriterRaceAcceptance recovery_owner_race_acceptance(
    const httplib::Request& request) {
    const std::string name{kNdmsNativeImportRaceAcceptanceHeader};
    const auto count = request.get_header_value_count(name);
    if (count == 0U) {
        return NdmsNativeExternalWriterRaceAcceptance::not_accepted;
    }
    if (count != 1U ||
        request.get_header_value(name) !=
            kNdmsNativeImportRaceAcceptanceValue) {
        throw ApiError(
            "external NDMS writer race acceptance is invalid", 428);
    }
    return NdmsNativeExternalWriterRaceAcceptance::owner_accepted;
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

bool blocked_public_import_stop(
    const NdmsNativeCooperativeImportStop stop) noexcept {
    switch (stop) {
    case NdmsNativeCooperativeImportStop::external_writer_race_not_accepted:
    case NdmsNativeCooperativeImportStop::writer_missing:
    case NdmsNativeCooperativeImportStop::writer_lost:
    case NdmsNativeCooperativeImportStop::delete_wal_not_clean:
    case NdmsNativeCooperativeImportStop::import_wal_not_clean:
    case NdmsNativeCooperativeImportStop::request_invalid:
    case NdmsNativeCooperativeImportStop::runtime_catalog_failed:
    case NdmsNativeCooperativeImportStop::running_config_catalog_failed:
    case NdmsNativeCooperativeImportStop::prewrite_catalog_unsafe:
    case NdmsNativeCooperativeImportStop::prewrite_catalog_diverged:
    case NdmsNativeCooperativeImportStop::marker_collision:
    case NdmsNativeCooperativeImportStop::first_free_target_not_managed:
    case NdmsNativeCooperativeImportStop::ownership_target_not_available:
    case NdmsNativeCooperativeImportStop::snapshot_target_not_available:
    case NdmsNativeCooperativeImportStop::durable_observation_failed:
    case NdmsNativeCooperativeImportStop::cooperative_baseline_failed:
    case NdmsNativeCooperativeImportStop::
        cooperative_writer_admission_failed:
    case NdmsNativeCooperativeImportStop::executor_blocked:
    case NdmsNativeCooperativeImportStop::unexpected_failure:
        return true;
    case NdmsNativeCooperativeImportStop::none:
    case NdmsNativeCooperativeImportStop::wal_record_unavailable:
    case NdmsNativeCooperativeImportStop::first_post_observation_failed:
    case NdmsNativeCooperativeImportStop::second_post_observation_failed:
    case NdmsNativeCooperativeImportStop::post_observation_kind_mismatch:
    case NdmsNativeCooperativeImportStop::post_observation_unstable:
    case NdmsNativeCooperativeImportStop::forward_completion_blocked:
    case NdmsNativeCooperativeImportStop::forward_admission_failed:
    case NdmsNativeCooperativeImportStop::
        target_verified_wal_publish_failed:
    case NdmsNativeCooperativeImportStop::ownership_publish_failed:
    case NdmsNativeCooperativeImportStop::ownership_wal_publish_failed:
    case NdmsNativeCooperativeImportStop::wal_cleanup_failed:
        return false;
    }
    return false;
}

bool recovery_public_import_stop(
    const NdmsNativeCooperativeImportStop stop) noexcept {
    switch (stop) {
    case NdmsNativeCooperativeImportStop::executor_blocked:
    case NdmsNativeCooperativeImportStop::wal_record_unavailable:
    case NdmsNativeCooperativeImportStop::first_post_observation_failed:
    case NdmsNativeCooperativeImportStop::second_post_observation_failed:
    case NdmsNativeCooperativeImportStop::post_observation_kind_mismatch:
    case NdmsNativeCooperativeImportStop::post_observation_unstable:
    case NdmsNativeCooperativeImportStop::forward_completion_blocked:
    case NdmsNativeCooperativeImportStop::forward_admission_failed:
    case NdmsNativeCooperativeImportStop::
        target_verified_wal_publish_failed:
    case NdmsNativeCooperativeImportStop::ownership_publish_failed:
    case NdmsNativeCooperativeImportStop::ownership_wal_publish_failed:
    case NdmsNativeCooperativeImportStop::wal_cleanup_failed:
    case NdmsNativeCooperativeImportStop::unexpected_failure:
        return true;
    case NdmsNativeCooperativeImportStop::none:
    case NdmsNativeCooperativeImportStop::external_writer_race_not_accepted:
    case NdmsNativeCooperativeImportStop::writer_missing:
    case NdmsNativeCooperativeImportStop::writer_lost:
    case NdmsNativeCooperativeImportStop::delete_wal_not_clean:
    case NdmsNativeCooperativeImportStop::import_wal_not_clean:
    case NdmsNativeCooperativeImportStop::request_invalid:
    case NdmsNativeCooperativeImportStop::runtime_catalog_failed:
    case NdmsNativeCooperativeImportStop::running_config_catalog_failed:
    case NdmsNativeCooperativeImportStop::prewrite_catalog_unsafe:
    case NdmsNativeCooperativeImportStop::prewrite_catalog_diverged:
    case NdmsNativeCooperativeImportStop::marker_collision:
    case NdmsNativeCooperativeImportStop::first_free_target_not_managed:
    case NdmsNativeCooperativeImportStop::ownership_target_not_available:
    case NdmsNativeCooperativeImportStop::snapshot_target_not_available:
    case NdmsNativeCooperativeImportStop::durable_observation_failed:
    case NdmsNativeCooperativeImportStop::cooperative_baseline_failed:
    case NdmsNativeCooperativeImportStop::
        cooperative_writer_admission_failed:
        return false;
    }
    return false;
}

bool blocked_cooperative_executor_stop(
    const NdmsNativeImportExecutionStop stop) noexcept {
    switch (stop) {
    case NdmsNativeImportExecutionStop::missing_dependency:
    case NdmsNativeImportExecutionStop::request_identity_invalid:
    case NdmsNativeImportExecutionStop::snapshot_identity_invalid:
    case NdmsNativeImportExecutionStop::observation_binding_invalid:
    case NdmsNativeImportExecutionStop::expected_target_ineligible:
    case NdmsNativeImportExecutionStop::baseline_mismatch:
    case NdmsNativeImportExecutionStop::incompatible_fence_mode:
    case NdmsNativeImportExecutionStop::authority_conflict:
    case NdmsNativeImportExecutionStop::cooperative_writer_required:
    case NdmsNativeImportExecutionStop::cooperative_writer_invalid:
    case NdmsNativeImportExecutionStop::cooperative_writer_lost:
    case NdmsNativeImportExecutionStop::cooperative_observation_changed:
    case NdmsNativeImportExecutionStop::request_binding_failed:
    case NdmsNativeImportExecutionStop::generation_observation_failed:
        return true;
    case NdmsNativeImportExecutionStop::none:
    case NdmsNativeImportExecutionStop::fence_required:
    case NdmsNativeImportExecutionStop::fence_invalid:
    case NdmsNativeImportExecutionStop::unfinished_transaction_present:
    case NdmsNativeImportExecutionStop::prepared_wal_publish_failed:
    case NdmsNativeImportExecutionStop::snapshot_publish_failed:
    case NdmsNativeImportExecutionStop::generation_reservation_failed:
    case NdmsNativeImportExecutionStop::generation_changed:
    case NdmsNativeImportExecutionStop::inflight_wal_publish_failed:
    case NdmsNativeImportExecutionStop::fence_lost_after_intent:
    case NdmsNativeImportExecutionStop::transport_failed:
    case NdmsNativeImportExecutionStop::response_wal_publish_failed:
    case NdmsNativeImportExecutionStop::ambiguous_response:
        return false;
    }
    return false;
}

bool recovery_cooperative_executor_stop(
    const NdmsNativeImportExecutionStop stop) noexcept {
    switch (stop) {
    case NdmsNativeImportExecutionStop::cooperative_writer_lost:
    case NdmsNativeImportExecutionStop::cooperative_observation_changed:
    case NdmsNativeImportExecutionStop::generation_observation_failed:
    case NdmsNativeImportExecutionStop::prepared_wal_publish_failed:
    case NdmsNativeImportExecutionStop::snapshot_publish_failed:
    case NdmsNativeImportExecutionStop::generation_reservation_failed:
    case NdmsNativeImportExecutionStop::generation_changed:
    case NdmsNativeImportExecutionStop::inflight_wal_publish_failed:
    case NdmsNativeImportExecutionStop::transport_failed:
    case NdmsNativeImportExecutionStop::response_wal_publish_failed:
    case NdmsNativeImportExecutionStop::ambiguous_response:
        return true;
    case NdmsNativeImportExecutionStop::none:
    case NdmsNativeImportExecutionStop::missing_dependency:
    case NdmsNativeImportExecutionStop::request_identity_invalid:
    case NdmsNativeImportExecutionStop::snapshot_identity_invalid:
    case NdmsNativeImportExecutionStop::observation_binding_invalid:
    case NdmsNativeImportExecutionStop::expected_target_ineligible:
    case NdmsNativeImportExecutionStop::baseline_mismatch:
    case NdmsNativeImportExecutionStop::incompatible_fence_mode:
    case NdmsNativeImportExecutionStop::fence_required:
    case NdmsNativeImportExecutionStop::authority_conflict:
    case NdmsNativeImportExecutionStop::cooperative_writer_required:
    case NdmsNativeImportExecutionStop::cooperative_writer_invalid:
    case NdmsNativeImportExecutionStop::request_binding_failed:
    case NdmsNativeImportExecutionStop::fence_invalid:
    case NdmsNativeImportExecutionStop::unfinished_transaction_present:
    case NdmsNativeImportExecutionStop::fence_lost_after_intent:
        return false;
    }
    return false;
}

bool recovery_may_precede_snapshot(
    const NdmsNativeImportExecutionStop stop) noexcept {
    return stop ==
               NdmsNativeImportExecutionStop::
                   prepared_wal_publish_failed ||
           stop == NdmsNativeImportExecutionStop::
                       cooperative_writer_lost ||
           stop == NdmsNativeImportExecutionStop::
                       cooperative_observation_changed;
}

void validate_public_import_result(
    const NdmsNativeCooperativeImportResult& result) {
    if (!known_public_import_enums(result)) {
        throw std::runtime_error("invalid native import result enum");
    }
    if (result.external_ndms_writer_race_excluded) {
        throw std::runtime_error(
            "native import result overclaimed router authority");
    }
    if (result.system_configuration_save_performed !=
        (result.status == NdmsNativeCooperativeImportStatus::completed)) {
        throw std::runtime_error(
            "native import result save evidence is incoherent");
    }

    const bool any_prepared_identity =
        result.transaction_id.has_value() || result.kind.has_value() ||
        result.expected_interface.has_value();
    const bool has_prepared_identity =
        result.transaction_id.has_value() && result.kind.has_value() &&
        result.expected_interface.has_value();
    if (result.transaction_id.has_value() != result.kind.has_value() ||
        (result.transaction_id.has_value() &&
         !valid_ndms_native_import_transaction_id(
             *result.transaction_id)) ||
        (result.expected_interface.has_value() &&
         (!result.transaction_id.has_value() ||
          !public_interface_name(*result.expected_interface)))) {
        throw std::runtime_error("invalid native import internal identity");
    }

    const bool any_created_identity =
        result.created_interface.has_value() ||
        result.created_kernel_interface.has_value();
    const bool has_created_identity = public_created_identity(result);
    if (any_created_identity != has_created_identity ||
        (has_created_identity &&
         (!result.expected_interface.has_value() ||
          *result.created_interface != *result.expected_interface))) {
        throw std::runtime_error("invalid native import created identity");
    }

    const auto clean_delete =
        std::optional<NdmsNativeDeleteWalReadiness>{
            NdmsNativeDeleteWalReadiness::clean};
    const auto clean_import =
        std::optional<NdmsNativeCooperativeImportWalReadiness>{
            NdmsNativeCooperativeImportWalReadiness::clean};
    if (any_prepared_identity &&
        (result.delete_wal_readiness != clean_delete ||
         result.import_wal_readiness != clean_import)) {
        throw std::runtime_error(
            "native import identity lacks clean admission evidence");
    }

    const bool catalog_observation_stop =
        result.stop ==
            NdmsNativeCooperativeImportStop::runtime_catalog_failed ||
        result.stop == NdmsNativeCooperativeImportStop::
                           running_config_catalog_failed;
    const bool post_observation_stop =
        result.stop == NdmsNativeCooperativeImportStop::
                           first_post_observation_failed ||
        result.stop == NdmsNativeCooperativeImportStop::
                           second_post_observation_failed;
    const bool observation_stop =
        catalog_observation_stop || post_observation_stop;
    if (result.request_error.has_value() !=
            (result.stop ==
             NdmsNativeCooperativeImportStop::request_invalid) ||
        (result.direct_observation_failure.has_value() &&
         (!observation_stop ||
          *result.direct_observation_failure ==
              NdmsNativeDirectObservationFailure::none)) ||
        (catalog_observation_stop &&
         !result.direct_observation_failure.has_value()) ||
        result.baseline_error.has_value() !=
            (result.stop == NdmsNativeCooperativeImportStop::
                                cooperative_baseline_failed) ||
        (result.baseline_error.has_value() &&
         *result.baseline_error ==
             NdmsNativeImportBaselineBuildError::none)) {
        throw std::runtime_error(
            "native import stop evidence is incoherent");
    }

    const bool has_forward_evidence =
        result.forward_admission_state.has_value() ||
        result.forward_dispatch_state.has_value() ||
        result.forward_failed_step.has_value();
    const bool dispatch_step_failed =
        result.forward_dispatch_state ==
        std::optional<NdmsNativeImportRecoveryDispatchState>{
            NdmsNativeImportRecoveryDispatchState::step_failed};
    const bool no_created_or_forward_evidence =
        !has_created_identity && !result.ownership_published &&
        !has_forward_evidence;
    const auto exact_dispatch_failure =
        [&](const NdmsNativeImportRecoveryStep expected_step) {
            return has_created_identity &&
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
                           expected_step};
        };
    if ((result.ownership_published && !has_created_identity) ||
        (has_forward_evidence && !has_created_identity) ||
        (has_created_identity &&
         (!result.request_may_have_been_dispatched ||
          !result.rollback_snapshot_may_be_retained)) ||
        (result.request_may_have_been_dispatched &&
         !result.rollback_snapshot_may_be_retained) ||
        (result.forward_dispatch_state.has_value() &&
         result.forward_admission_state !=
             std::optional<NdmsNativeImportRecoveryAdmissionState>{
                 NdmsNativeImportRecoveryAdmissionState::admitted}) ||
        (result.forward_failed_step.has_value() != dispatch_step_failed) ||
        (result.forward_dispatch_state ==
             std::optional<NdmsNativeImportRecoveryDispatchState>{
                 NdmsNativeImportRecoveryDispatchState::completed} &&
         result.status != NdmsNativeCooperativeImportStatus::completed)) {
        throw std::runtime_error(
            "native import mutation evidence is incoherent");
    }

    switch (result.status) {
    case NdmsNativeCooperativeImportStatus::blocked: {
        const bool consent_refused =
            result.stop == NdmsNativeCooperativeImportStop::
                               external_writer_race_not_accepted;
        const bool executor_blocked =
            result.stop ==
            NdmsNativeCooperativeImportStop::executor_blocked;
        const bool no_admission_evidence =
            !result.delete_wal_readiness.has_value() &&
            !result.import_wal_readiness.has_value();
        const bool clean_admission_evidence =
            result.delete_wal_readiness == clean_delete &&
            result.import_wal_readiness == clean_import;
        const bool request_identity_only =
            result.transaction_id.has_value() && result.kind.has_value() &&
            !result.expected_interface.has_value();
        bool exact_stop_evidence = false;
        switch (result.stop) {
        case NdmsNativeCooperativeImportStop::
            external_writer_race_not_accepted:
        case NdmsNativeCooperativeImportStop::writer_missing:
            exact_stop_evidence =
                !any_prepared_identity && no_admission_evidence;
            break;
        case NdmsNativeCooperativeImportStop::writer_lost:
            exact_stop_evidence =
                (!any_prepared_identity && no_admission_evidence) ||
                (has_prepared_identity && clean_admission_evidence);
            break;
        case NdmsNativeCooperativeImportStop::delete_wal_not_clean:
            exact_stop_evidence =
                !any_prepared_identity &&
                result.delete_wal_readiness.has_value() &&
                *result.delete_wal_readiness !=
                    NdmsNativeDeleteWalReadiness::clean &&
                !result.import_wal_readiness.has_value();
            break;
        case NdmsNativeCooperativeImportStop::import_wal_not_clean:
            exact_stop_evidence =
                !any_prepared_identity &&
                result.delete_wal_readiness == clean_delete &&
                result.import_wal_readiness.has_value() &&
                *result.import_wal_readiness !=
                    NdmsNativeCooperativeImportWalReadiness::clean;
            break;
        case NdmsNativeCooperativeImportStop::request_invalid:
            exact_stop_evidence =
                !any_prepared_identity && clean_admission_evidence;
            break;
        case NdmsNativeCooperativeImportStop::runtime_catalog_failed:
        case NdmsNativeCooperativeImportStop::
            running_config_catalog_failed:
        case NdmsNativeCooperativeImportStop::prewrite_catalog_unsafe:
        case NdmsNativeCooperativeImportStop::prewrite_catalog_diverged:
        case NdmsNativeCooperativeImportStop::marker_collision:
        case NdmsNativeCooperativeImportStop::
            first_free_target_not_managed:
            exact_stop_evidence =
                request_identity_only && clean_admission_evidence;
            break;
        case NdmsNativeCooperativeImportStop::
            ownership_target_not_available:
        case NdmsNativeCooperativeImportStop::
            snapshot_target_not_available:
        case NdmsNativeCooperativeImportStop::durable_observation_failed:
        case NdmsNativeCooperativeImportStop::cooperative_baseline_failed:
        case NdmsNativeCooperativeImportStop::
            cooperative_writer_admission_failed:
        case NdmsNativeCooperativeImportStop::executor_blocked:
            exact_stop_evidence =
                has_prepared_identity && clean_admission_evidence;
            break;
        case NdmsNativeCooperativeImportStop::unexpected_failure:
            // The outer catch can preserve any already validated prefix.
            exact_stop_evidence =
                (!any_prepared_identity && no_admission_evidence) ||
                ((request_identity_only || has_prepared_identity) &&
                 clean_admission_evidence);
            break;
        case NdmsNativeCooperativeImportStop::none:
        case NdmsNativeCooperativeImportStop::wal_record_unavailable:
        case NdmsNativeCooperativeImportStop::
            first_post_observation_failed:
        case NdmsNativeCooperativeImportStop::
            second_post_observation_failed:
        case NdmsNativeCooperativeImportStop::
            post_observation_kind_mismatch:
        case NdmsNativeCooperativeImportStop::post_observation_unstable:
        case NdmsNativeCooperativeImportStop::forward_completion_blocked:
        case NdmsNativeCooperativeImportStop::forward_admission_failed:
        case NdmsNativeCooperativeImportStop::
            target_verified_wal_publish_failed:
        case NdmsNativeCooperativeImportStop::ownership_publish_failed:
        case NdmsNativeCooperativeImportStop::
            ownership_wal_publish_failed:
        case NdmsNativeCooperativeImportStop::wal_cleanup_failed:
            break;
        }
        if (!blocked_public_import_stop(result.stop) ||
            !exact_stop_evidence ||
            result.external_ndms_writer_race_accepted == consent_refused ||
            result.wal_may_require_recovery ||
            result.request_may_have_been_dispatched ||
            result.rollback_snapshot_may_be_retained ||
            result.ownership_published || has_created_identity ||
            has_forward_evidence ||
            result.executor_stop.has_value() != executor_blocked ||
            (result.executor_stop.has_value() &&
             !blocked_cooperative_executor_stop(
                 *result.executor_stop))) {
            throw std::runtime_error(
                "incoherent blocked native import result");
        }
        break;
    }
    case NdmsNativeCooperativeImportStatus::recovery_required: {
        const bool executor_blocked =
            result.stop ==
            NdmsNativeCooperativeImportStop::executor_blocked;
        const bool executor_recovery_stop =
            result.executor_stop.has_value() &&
            recovery_cooperative_executor_stop(
                *result.executor_stop);
        const bool snapshot_may_be_absent =
            executor_blocked && executor_recovery_stop &&
            recovery_may_precede_snapshot(*result.executor_stop);
        if (!recovery_public_import_stop(result.stop) ||
            !result.external_ndms_writer_race_accepted ||
            !result.wal_may_require_recovery || !has_prepared_identity ||
            executor_blocked != executor_recovery_stop ||
            (!executor_blocked &&
             result.executor_stop !=
                 std::optional<NdmsNativeImportExecutionStop>{
                     NdmsNativeImportExecutionStop::none}) ||
            (!result.rollback_snapshot_may_be_retained &&
             !snapshot_may_be_absent) ||
            (executor_blocked &&
             result.executor_stop ==
                 std::optional<NdmsNativeImportExecutionStop>{
                     NdmsNativeImportExecutionStop::
                         prepared_wal_publish_failed} &&
             result.rollback_snapshot_may_be_retained) ||
            (!executor_blocked &&
             !result.request_may_have_been_dispatched) ||
            result.request_error.has_value() ||
            result.baseline_error.has_value()) {
            throw std::runtime_error(
                "incoherent recovery-required native import result");
        }

        switch (result.stop) {
        case NdmsNativeCooperativeImportStop::executor_blocked:
        case NdmsNativeCooperativeImportStop::wal_record_unavailable:
        case NdmsNativeCooperativeImportStop::first_post_observation_failed:
        case NdmsNativeCooperativeImportStop::second_post_observation_failed:
        case NdmsNativeCooperativeImportStop::
            post_observation_kind_mismatch:
        case NdmsNativeCooperativeImportStop::post_observation_unstable:
            if (!no_created_or_forward_evidence) {
                throw std::runtime_error(
                    "native import recovery stop has forward evidence");
            }
            break;
        case NdmsNativeCooperativeImportStop::forward_completion_blocked:
            if (result.ownership_published ||
                (has_created_identity &&
                 (result.forward_admission_state !=
                      std::optional<
                          NdmsNativeImportRecoveryAdmissionState>{
                          NdmsNativeImportRecoveryAdmissionState::
                              admitted} ||
                  result.forward_dispatch_state.has_value() ||
                  result.forward_failed_step.has_value())) ||
                (!has_created_identity && has_forward_evidence)) {
                throw std::runtime_error(
                    "native import forward stop evidence is incoherent");
            }
            break;
        case NdmsNativeCooperativeImportStop::forward_admission_failed:
            if (!has_created_identity ||
                !result.forward_admission_state.has_value() ||
                *result.forward_admission_state ==
                    NdmsNativeImportRecoveryAdmissionState::admitted ||
                result.forward_dispatch_state.has_value() ||
                result.forward_failed_step.has_value() ||
                result.ownership_published) {
                throw std::runtime_error(
                    "native import admission stop evidence is incoherent");
            }
            break;
        case NdmsNativeCooperativeImportStop::
            target_verified_wal_publish_failed:
            if (!exact_dispatch_failure(
                    NdmsNativeImportRecoveryStep::
                        advance_wal_target_verified) ||
                result.ownership_published) {
                throw std::runtime_error(
                    "native import dispatch stop evidence is incoherent");
            }
            break;
        case NdmsNativeCooperativeImportStop::ownership_publish_failed:
            if (!exact_dispatch_failure(
                    NdmsNativeImportRecoveryStep::publish_ownership)) {
                throw std::runtime_error(
                    "native import dispatch stop evidence is incoherent");
            }
            break;
        case NdmsNativeCooperativeImportStop::
            ownership_wal_publish_failed:
            if (!exact_dispatch_failure(
                    NdmsNativeImportRecoveryStep::
                        advance_wal_ownership_published)) {
                throw std::runtime_error(
                    "native import dispatch stop evidence is incoherent");
            }
            break;
        case NdmsNativeCooperativeImportStop::wal_cleanup_failed:
            if (!exact_dispatch_failure(
                    NdmsNativeImportRecoveryStep::remove_wal_record)) {
                throw std::runtime_error(
                    "native import dispatch stop evidence is incoherent");
            }
            break;
        case NdmsNativeCooperativeImportStop::unexpected_failure:
            // A catch may preserve any already validated monotonic prefix.
            break;
        case NdmsNativeCooperativeImportStop::none:
        case NdmsNativeCooperativeImportStop::
            external_writer_race_not_accepted:
        case NdmsNativeCooperativeImportStop::writer_missing:
        case NdmsNativeCooperativeImportStop::writer_lost:
        case NdmsNativeCooperativeImportStop::delete_wal_not_clean:
        case NdmsNativeCooperativeImportStop::import_wal_not_clean:
        case NdmsNativeCooperativeImportStop::request_invalid:
        case NdmsNativeCooperativeImportStop::runtime_catalog_failed:
        case NdmsNativeCooperativeImportStop::
            running_config_catalog_failed:
        case NdmsNativeCooperativeImportStop::prewrite_catalog_unsafe:
        case NdmsNativeCooperativeImportStop::prewrite_catalog_diverged:
        case NdmsNativeCooperativeImportStop::marker_collision:
        case NdmsNativeCooperativeImportStop::first_free_target_not_managed:
        case NdmsNativeCooperativeImportStop::
            ownership_target_not_available:
        case NdmsNativeCooperativeImportStop::
            snapshot_target_not_available:
        case NdmsNativeCooperativeImportStop::durable_observation_failed:
        case NdmsNativeCooperativeImportStop::cooperative_baseline_failed:
        case NdmsNativeCooperativeImportStop::
            cooperative_writer_admission_failed:
            throw std::runtime_error(
                "native import recovery stop family is incoherent");
        }
        break;
    }
    case NdmsNativeCooperativeImportStatus::completed:
        if (result.stop != NdmsNativeCooperativeImportStop::none ||
            !has_prepared_identity || !has_created_identity ||
            !result.external_ndms_writer_race_accepted ||
            !result.request_may_have_been_dispatched ||
            result.wal_may_require_recovery ||
            !result.rollback_snapshot_may_be_retained ||
            !result.ownership_published ||
            result.request_error.has_value() ||
            result.direct_observation_failure.has_value() ||
            result.baseline_error.has_value() ||
            result.executor_stop !=
                std::optional<NdmsNativeImportExecutionStop>{
                    NdmsNativeImportExecutionStop::none} ||
            result.forward_admission_state !=
                std::optional<NdmsNativeImportRecoveryAdmissionState>{
                    NdmsNativeImportRecoveryAdmissionState::admitted} ||
            result.forward_dispatch_state !=
                std::optional<NdmsNativeImportRecoveryDispatchState>{
                    NdmsNativeImportRecoveryDispatchState::completed} ||
            result.forward_failed_step.has_value()) {
            throw std::runtime_error(
                "incoherent completed native import result");
        }
        break;
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
               NdmsNativeImportRecoveryStep::remove_wal_record) &&
           known_optional_enum_value(
               result.recovery_admission_state,
               NdmsNativeImportRecoveryAdmissionState::admitted,
               NdmsNativeImportRecoveryAdmissionState::
                   action_not_actionable) &&
           known_optional_enum_value(
               result.recovery_dispatch_state,
               NdmsNativeImportRecoveryDispatchState::completed,
               NdmsNativeImportRecoveryDispatchState::step_failed) &&
           known_optional_enum_value(
               result.recovery_failed_step,
               NdmsNativeImportRecoveryStep::
                   advance_wal_target_verified,
               NdmsNativeImportRecoveryStep::remove_wal_record) &&
           known_optional_enum_value(
               result.delete_transport_outcome,
               NdmsNativeExactMutationResponseOutcome::guard_rejected,
               NdmsNativeExactMutationResponseOutcome::
                   acknowledged_needs_observation);
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

bool destructive_recovery_action(
    const NdmsNativeImportRecoveryAction action) noexcept {
    return action == NdmsNativeImportRecoveryAction::
                         rollback_delete_exact_owned ||
           action == NdmsNativeImportRecoveryAction::
                         retry_exact_owned_delete;
}

bool initially_dispatchable_recovery_action(
    const NdmsNativeImportRecoveryAction action,
    const NdmsNativeImportWalPhase phase) noexcept {
    using Action = NdmsNativeImportRecoveryAction;
    using Phase = NdmsNativeImportWalPhase;
    switch (action) {
    case Action::abort_without_mutation:
        return phase == Phase::prepared ||
               phase == Phase::import_may_be_inflight ||
               phase == Phase::response_recorded;
    case Action::rollback_delete_exact_owned:
        return phase == Phase::import_may_be_inflight ||
               phase == Phase::response_recorded;
    case Action::retry_exact_owned_delete:
        return phase == Phase::rollback_requested ||
               phase == Phase::delete_may_be_inflight;
    case Action::complete_rollback:
        return phase == Phase::target_verified ||
               phase == Phase::ownership_published ||
               phase == Phase::rollback_requested ||
               phase == Phase::delete_may_be_inflight ||
               phase == Phase::absence_verified;
    case Action::retry_read_only_observation:
    case Action::resume_forward_reconcile:
    case Action::block_unknown:
        return false;
    }
    return false;
}

bool failed_recovery_step_matches_durable_phase(
    const NdmsNativeImportRecoveryAction action,
    const NdmsNativeImportWalPhase phase,
    const NdmsNativeImportRecoveryStep step) noexcept {
    using Action = NdmsNativeImportRecoveryAction;
    using Phase = NdmsNativeImportWalPhase;
    using Step = NdmsNativeImportRecoveryStep;

    switch (action) {
    case Action::abort_without_mutation:
        return step == Step::remove_wal_record &&
               initially_dispatchable_recovery_action(action, phase);
    case Action::rollback_delete_exact_owned:
        switch (step) {
        case Step::advance_wal_rollback_requested:
            return phase == Phase::import_may_be_inflight ||
                   phase == Phase::response_recorded;
        case Step::remove_ownership_claim:
        case Step::advance_wal_delete_may_be_inflight:
            return phase == Phase::rollback_requested;
        case Step::delete_exact_owned_target:
        case Step::advance_wal_absence_verified:
            return phase == Phase::delete_may_be_inflight;
        case Step::remove_wal_record:
            return phase == Phase::absence_verified;
        case Step::advance_wal_target_verified:
        case Step::publish_ownership:
        case Step::advance_wal_ownership_published:
            return false;
        }
        return false;
    case Action::retry_exact_owned_delete:
        switch (step) {
        case Step::remove_ownership_claim:
            return phase == Phase::rollback_requested ||
                   phase == Phase::delete_may_be_inflight;
        case Step::advance_wal_delete_may_be_inflight:
            return phase == Phase::rollback_requested;
        case Step::delete_exact_owned_target:
        case Step::advance_wal_absence_verified:
            return phase == Phase::delete_may_be_inflight;
        case Step::remove_wal_record:
            return phase == Phase::absence_verified;
        case Step::advance_wal_target_verified:
        case Step::publish_ownership:
        case Step::advance_wal_ownership_published:
        case Step::advance_wal_rollback_requested:
            return false;
        }
        return false;
    case Action::complete_rollback:
        switch (step) {
        case Step::advance_wal_absence_verified:
            return phase == Phase::target_verified ||
                   phase == Phase::ownership_published ||
                   phase == Phase::rollback_requested ||
                   phase == Phase::delete_may_be_inflight;
        case Step::remove_ownership_claim:
            return phase == Phase::rollback_requested ||
                   phase == Phase::delete_may_be_inflight ||
                   phase == Phase::absence_verified;
        case Step::remove_wal_record:
            return phase == Phase::absence_verified;
        case Step::advance_wal_target_verified:
        case Step::publish_ownership:
        case Step::advance_wal_ownership_published:
        case Step::advance_wal_rollback_requested:
        case Step::advance_wal_delete_may_be_inflight:
        case Step::delete_exact_owned_target:
            return false;
        }
        return false;
    case Action::retry_read_only_observation:
    case Action::resume_forward_reconcile:
    case Action::block_unknown:
        return false;
    }
    return false;
}

bool recovery_action_matches_reported_phase(
    const NdmsNativeImportRecoveryAction action,
    const NdmsNativeImportWalPhase phase,
    const std::optional<NdmsNativeImportRecoveryDispatchState>& dispatch,
    const std::optional<NdmsNativeImportRecoveryStep>& failed_step) noexcept {
    if (dispatch != std::optional<NdmsNativeImportRecoveryDispatchState>{
                        NdmsNativeImportRecoveryDispatchState::step_failed}) {
        // Admission refusals, dispatcher refusals and successful dispatches
        // report the record phase from the start of this invocation.
        return !failed_step.has_value() &&
               initially_dispatchable_recovery_action(action, phase);
    }
    // A failed dispatch reloads the monotonic durable WAL phase.  Bind that
    // descendant to the exact prefix step that failed instead of pretending
    // the phase still names the plan's origin.
    return failed_step.has_value() &&
           failed_recovery_step_matches_durable_phase(
               action, phase, *failed_step);
}

bool cleanup_recovery_action(
    const NdmsNativeImportRecoveryAction action) noexcept {
    return action == NdmsNativeImportRecoveryAction::
                         abort_without_mutation ||
           action == NdmsNativeImportRecoveryAction::
                         rollback_delete_exact_owned ||
           action == NdmsNativeImportRecoveryAction::
                         retry_exact_owned_delete ||
           action == NdmsNativeImportRecoveryAction::complete_rollback;
}

void validate_public_import_recovery_result(
    const NdmsNativeCooperativeImportResumeResult& result) {
    using Status = NdmsNativeCooperativeImportResumeStatus;
    using Stop = NdmsNativeCooperativeImportResumeStop;
    using Admission = NdmsNativeImportRecoveryAdmissionState;
    using Dispatch = NdmsNativeImportRecoveryDispatchState;
    using Step = NdmsNativeImportRecoveryStep;
    using Action = NdmsNativeImportRecoveryAction;
    using Outcome = NdmsNativeExactMutationResponseOutcome;

    if (!known_public_import_recovery_enums(result)) {
        throw std::runtime_error(
            "invalid native import recovery result enum");
    }
    if (result.ndms_import_request_dispatched ||
        result.external_ndms_writer_race_excluded) {
        throw std::runtime_error(
            "native import recovery overclaimed router mutation");
    }

    const bool any_record_identity =
        result.transaction_id.has_value() ||
        result.expected_interface.has_value() ||
        result.kind.has_value() || result.phase.has_value();
    const bool has_record_identity =
        result.transaction_id.has_value() &&
        result.expected_interface.has_value() &&
        result.kind.has_value() && result.phase.has_value();
    if (any_record_identity != has_record_identity ||
        (has_record_identity &&
         (!valid_ndms_native_import_transaction_id(
              *result.transaction_id) ||
          !public_interface_name(*result.expected_interface)))) {
        throw std::runtime_error(
            "invalid native import recovery record identity");
    }

    const bool any_created_identity =
        result.created_interface.has_value() ||
        result.created_kernel_interface.has_value();
    const bool has_created_identity = public_created_identity(result);
    if (any_created_identity != has_created_identity ||
        (has_created_identity &&
         (!result.expected_interface.has_value() ||
          *result.created_interface != *result.expected_interface))) {
        throw std::runtime_error(
            "invalid native import recovery created identity");
    }
    if (result.system_configuration_save_performed !=
        (result.status == Status::completed && has_created_identity)) {
        throw std::runtime_error(
            "native import recovery save evidence is incoherent");
    }

    if (has_record_identity) {
        if (result.delete_wal_readiness !=
                std::optional<NdmsNativeDeleteWalReadiness>{
                    NdmsNativeDeleteWalReadiness::clean} ||
            result.import_wal_readiness !=
                std::optional<NdmsNativeCooperativeImportWalReadiness>{
                    NdmsNativeCooperativeImportWalReadiness::unfinished}) {
            throw std::runtime_error(
                "invalid native import recovery journal evidence");
        }
        if (result.status != Status::completed &&
            !result.wal_may_require_recovery) {
            throw std::runtime_error(
                "native import recovery hid its unfinished WAL");
        }
    } else if (result.wal_may_require_recovery ||
               result.ownership_published ||
               result.rollback_snapshot_retired || result.wal_removed) {
        throw std::runtime_error(
            "native import recovery durable evidence lacks identity");
    }
    if (result.status == Status::completed &&
        result.wal_may_require_recovery) {
        throw std::runtime_error(
            "completed native import recovery retained WAL authority");
    }

    const bool observation_stop =
        result.stop == Stop::first_observation_failed ||
        result.stop == Stop::second_observation_failed;
    if (result.direct_observation_failure.has_value() !=
            observation_stop ||
        (result.direct_observation_failure.has_value() &&
         *result.direct_observation_failure ==
             NdmsNativeDirectObservationFailure::none)) {
        throw std::runtime_error(
            "invalid native import recovery observation evidence");
    }

    const bool forward_step_failed =
        result.forward_dispatch_state ==
        std::optional<Dispatch>{Dispatch::step_failed};
    if (result.forward_failed_step.has_value() !=
            forward_step_failed ||
        (result.forward_failed_step.has_value() &&
         !forward_only_step(*result.forward_failed_step)) ||
        (result.forward_dispatch_state.has_value() &&
         result.forward_admission_state !=
             std::optional<Admission>{Admission::admitted})) {
        throw std::runtime_error(
            "invalid native import forward dispatch evidence");
    }
    const bool recovery_step_failed =
        result.recovery_dispatch_state ==
        std::optional<Dispatch>{Dispatch::step_failed};
    if (result.recovery_failed_step.has_value() !=
            recovery_step_failed ||
        (result.recovery_dispatch_state.has_value() &&
         result.recovery_admission_state !=
             std::optional<Admission>{Admission::admitted})) {
        throw std::runtime_error(
            "invalid native import rollback dispatch evidence");
    }

    const bool has_forward_evidence =
        result.forward_admission_state.has_value() ||
        result.forward_dispatch_state.has_value() ||
        result.forward_failed_step.has_value();
    const bool has_recovery_evidence =
        result.recovery_admission_state.has_value() ||
        result.recovery_dispatch_state.has_value() ||
        result.recovery_failed_step.has_value();
    if (has_forward_evidence && has_recovery_evidence) {
        throw std::runtime_error(
            "native import recovery mixed dispatch families");
    }
    if ((!has_record_identity &&
         (has_created_identity || result.recovery_action.has_value() ||
          has_forward_evidence || has_recovery_evidence)) ||
        (has_forward_evidence && !has_created_identity) ||
        (has_recovery_evidence && has_created_identity)) {
        throw std::runtime_error(
            "incoherent native import recovery evidence");
    }
    if ((has_created_identity || has_forward_evidence) &&
        (!result.phase.has_value() ||
         !forward_only_phase(*result.phase))) {
        throw std::runtime_error(
            "native import forward evidence has wrong phase");
    }
    if (has_recovery_evidence &&
        (!result.recovery_action.has_value() ||
         !recovery_action_matches_reported_phase(
             *result.recovery_action,
             *result.phase,
             result.recovery_dispatch_state,
             result.recovery_failed_step))) {
        throw std::runtime_error(
            "native import rollback dispatch has impossible action");
    }
    if (result.recovery_action ==
            std::optional<Action>{Action::resume_forward_reconcile} &&
        (!result.phase.has_value() ||
         *result.phase !=
             NdmsNativeImportWalPhase::ownership_published ||
         has_recovery_evidence)) {
        throw std::runtime_error(
            "native import forward reconcile has impossible evidence");
    }
    if (has_forward_evidence &&
        result.recovery_action.has_value() &&
        (*result.phase !=
             NdmsNativeImportWalPhase::ownership_published ||
         *result.recovery_action !=
             Action::resume_forward_reconcile)) {
        throw std::runtime_error(
            "native import forward dispatch has impossible action");
    }

    const bool all_delete_trace =
        result.delete_perform_started &&
        result.request_may_have_been_dispatched &&
        result.ndms_delete_dispatched;
    const bool any_delete_trace =
        result.delete_perform_started ||
        result.request_may_have_been_dispatched ||
        result.ndms_delete_dispatched;
    if (any_delete_trace != all_delete_trace ||
        (any_delete_trace &&
         !result.delete_transport_outcome.has_value())) {
        throw std::runtime_error(
            "native import recovery delete trace is incoherent");
    }
    if (result.delete_transport_outcome.has_value()) {
        const bool guard_rejected =
            *result.delete_transport_outcome ==
            Outcome::guard_rejected;
        const bool setup_failed_before_guard =
            *result.delete_transport_outcome ==
                Outcome::transport_failed &&
            result.stop == Stop::delete_guard_rejected;
        const bool coherent_transport_trace =
            (guard_rejected || setup_failed_before_guard)
                ? !any_delete_trace
                : all_delete_trace;
        if (!coherent_transport_trace ||
            !result.external_ndms_writer_race_accepted ||
            !result.recovery_action.has_value() ||
            !destructive_recovery_action(*result.recovery_action) ||
            result.recovery_admission_state !=
                std::optional<Admission>{Admission::admitted} ||
            !result.recovery_dispatch_state.has_value()) {
            throw std::runtime_error(
                "native import recovery delete outcome is incoherent");
        }
    }
    const bool destructive_delete_completed_before_failure =
        result.recovery_action.has_value() &&
        destructive_recovery_action(*result.recovery_action) &&
        (result.recovery_failed_step ==
             std::optional<Step>{Step::advance_wal_absence_verified} ||
         result.recovery_failed_step ==
             std::optional<Step>{Step::remove_wal_record});
    if (destructive_delete_completed_before_failure &&
        (!all_delete_trace ||
         !result.delete_transport_outcome.has_value() ||
         result.delete_transport_outcome ==
             std::optional<Outcome>{Outcome::guard_rejected})) {
        throw std::runtime_error(
            "native import recovery hid a completed delete prefix");
    }

    if (result.rollback_snapshot_retired &&
        (!has_record_identity || !result.recovery_action.has_value() ||
         !cleanup_recovery_action(*result.recovery_action) ||
         !has_recovery_evidence || has_forward_evidence ||
         result.ownership_published)) {
        throw std::runtime_error(
            "native import recovery snapshot evidence is incoherent");
    }
    if (result.wal_removed != (result.status == Status::completed)) {
        throw std::runtime_error(
            "native import recovery WAL removal is incoherent");
    }
    if (result.status == Status::recovery_required &&
        result.rollback_snapshot_retired &&
        result.stop != Stop::wal_cleanup_failed &&
        result.stop != Stop::unexpected_failure) {
        throw std::runtime_error(
            "native import recovery retired a snapshot at wrong stop");
    }

    const auto require = [](const bool condition) {
        if (!condition) {
            throw std::runtime_error(
                "native import recovery stop evidence is incoherent");
        }
    };
    const bool no_record_work_evidence =
        !has_created_identity && !result.ownership_published &&
        !result.recovery_action.has_value() &&
        !has_forward_evidence && !has_recovery_evidence &&
        !result.delete_transport_outcome.has_value() &&
        !any_delete_trace;
    const auto exact_forward_failure = [&](const Step step) {
        return result.status == Status::blocked &&
               has_record_identity && has_created_identity &&
               result.forward_admission_state ==
                   std::optional<Admission>{Admission::admitted} &&
               result.forward_dispatch_state ==
                   std::optional<Dispatch>{Dispatch::step_failed} &&
               result.forward_failed_step ==
                   std::optional<Step>{step} &&
               !result.direct_observation_failure.has_value();
    };
    const auto exact_recovery_failure = [&](const Step step) {
        return result.status == Status::recovery_required &&
               has_record_identity &&
               result.recovery_action.has_value() &&
               result.recovery_admission_state ==
                   std::optional<Admission>{Admission::admitted} &&
               result.recovery_dispatch_state ==
                   std::optional<Dispatch>{Dispatch::step_failed} &&
               result.recovery_failed_step ==
                   std::optional<Step>{step};
    };

    switch (result.stop) {
    case Stop::none:
    case Stop::unexpected_failure:
        break;
    case Stop::writer_missing:
    case Stop::writer_lost:
        require(result.status == Status::blocked &&
                !result.delete_wal_readiness.has_value() &&
                !result.import_wal_readiness.has_value() &&
                !has_record_identity && no_record_work_evidence &&
                !result.direct_observation_failure.has_value());
        break;
    case Stop::delete_wal_not_clean:
        require(result.status == Status::blocked &&
                result.delete_wal_readiness.has_value() &&
                *result.delete_wal_readiness !=
                    NdmsNativeDeleteWalReadiness::clean &&
                !result.import_wal_readiness.has_value() &&
                !has_record_identity && no_record_work_evidence);
        break;
    case Stop::import_wal_not_single_safe:
        require(result.status == Status::blocked &&
                result.delete_wal_readiness ==
                    std::optional<NdmsNativeDeleteWalReadiness>{
                        NdmsNativeDeleteWalReadiness::clean} &&
                result.import_wal_readiness.has_value() &&
                *result.import_wal_readiness !=
                    NdmsNativeCooperativeImportWalReadiness::clean &&
                !has_record_identity && no_record_work_evidence);
        break;
    case Stop::record_not_cooperative:
    case Stop::phase_not_forward_only:
    case Stop::expected_target_not_managed:
        require(result.status == Status::blocked &&
                has_record_identity && no_record_work_evidence &&
                !result.direct_observation_failure.has_value());
        break;
    case Stop::first_observation_failed:
    case Stop::second_observation_failed:
        require(has_record_identity &&
                result.direct_observation_failure.has_value() &&
                !has_created_identity && !has_forward_evidence);
        break;
    case Stop::observation_kind_mismatch:
    case Stop::durable_observation_failed:
    case Stop::observation_unstable:
        require(has_record_identity &&
                !result.direct_observation_failure.has_value() &&
                !has_created_identity && !has_forward_evidence);
        break;
    case Stop::ownership_not_exact:
        require(has_record_identity && !has_created_identity &&
                !has_forward_evidence && !result.ownership_published);
        break;
    case Stop::snapshot_not_exact:
        require(has_record_identity &&
                result.recovery_action.has_value() &&
                !has_created_identity && !has_forward_evidence &&
                !result.rollback_snapshot_retired);
        break;
    case Stop::recovery_action_not_forward_only:
    case Stop::recovery_action_not_actionable:
        require(result.status == Status::blocked &&
                has_record_identity && !has_created_identity &&
                result.recovery_action.has_value() &&
                !has_forward_evidence && !has_recovery_evidence &&
                !result.direct_observation_failure.has_value());
        break;
    case Stop::external_writer_race_not_accepted:
        require(result.status == Status::recovery_required &&
                has_record_identity &&
                result.recovery_action.has_value() &&
                destructive_recovery_action(*result.recovery_action) &&
                !result.external_ndms_writer_race_accepted &&
                !has_forward_evidence && !has_recovery_evidence &&
                !result.delete_transport_outcome.has_value());
        break;
    case Stop::forward_admission_failed:
        require(result.status == Status::blocked &&
                has_record_identity && has_created_identity &&
                result.forward_admission_state.has_value() &&
                *result.forward_admission_state !=
                    Admission::admitted &&
                !result.forward_dispatch_state.has_value() &&
                !result.forward_failed_step.has_value() &&
                !has_recovery_evidence);
        break;
    case Stop::recovery_admission_failed:
        require(result.status == Status::recovery_required &&
                has_record_identity &&
                result.recovery_action.has_value() &&
                result.recovery_admission_state.has_value() &&
                *result.recovery_admission_state !=
                    Admission::admitted &&
                !result.recovery_dispatch_state.has_value() &&
                !result.recovery_failed_step.has_value() &&
                !result.delete_transport_outcome.has_value());
        break;
    case Stop::target_verified_wal_publish_failed:
        require(exact_forward_failure(
            Step::advance_wal_target_verified));
        break;
    case Stop::ownership_publish_failed:
        require(exact_forward_failure(Step::publish_ownership));
        break;
    case Stop::ownership_wal_publish_failed:
        require(exact_forward_failure(
            Step::advance_wal_ownership_published));
        break;
    case Stop::rollback_wal_publish_failed:
        require(exact_recovery_failure(
            Step::advance_wal_rollback_requested));
        break;
    case Stop::ownership_retract_failed:
        require(exact_recovery_failure(
            Step::remove_ownership_claim));
        break;
    case Stop::delete_wal_publish_failed:
        require(exact_recovery_failure(
            Step::advance_wal_delete_may_be_inflight));
        break;
    case Stop::delete_guard_rejected:
        require(exact_recovery_failure(
                    Step::delete_exact_owned_target) &&
                (result.delete_transport_outcome ==
                     std::optional<Outcome>{Outcome::guard_rejected} ||
                 result.delete_transport_outcome ==
                     std::optional<Outcome>{Outcome::transport_failed}) &&
                !any_delete_trace);
        break;
    case Stop::delete_transport_ambiguous:
        require(exact_recovery_failure(
                    Step::delete_exact_owned_target) &&
                result.delete_transport_outcome.has_value() &&
                *result.delete_transport_outcome !=
                    Outcome::guard_rejected &&
                all_delete_trace);
        break;
    case Stop::absence_wal_publish_failed:
        require(exact_recovery_failure(
            Step::advance_wal_absence_verified));
        break;
    case Stop::snapshot_retirement_failed:
        require(exact_recovery_failure(Step::remove_wal_record) &&
                !result.rollback_snapshot_retired);
        break;
    case Stop::wal_cleanup_failed:
        require(exact_forward_failure(Step::remove_wal_record) ||
                (exact_recovery_failure(Step::remove_wal_record) &&
                 result.rollback_snapshot_retired));
        break;
    }

    switch (result.status) {
    case Status::no_work:
        if (result.stop != Stop::none ||
            has_record_identity || has_created_identity ||
            result.delete_wal_readiness !=
                std::optional<NdmsNativeDeleteWalReadiness>{
                    NdmsNativeDeleteWalReadiness::clean} ||
            result.import_wal_readiness !=
                std::optional<NdmsNativeCooperativeImportWalReadiness>{
                    NdmsNativeCooperativeImportWalReadiness::clean} ||
            result.wal_may_require_recovery ||
            result.ownership_published ||
            result.rollback_snapshot_retired || result.wal_removed ||
            result.direct_observation_failure.has_value() ||
            result.recovery_action.has_value() ||
            has_forward_evidence || has_recovery_evidence ||
            result.delete_transport_outcome.has_value() ||
            any_delete_trace) {
            throw std::runtime_error(
                "incoherent no-work native import recovery result");
        }
        break;
    case Status::blocked:
        if (result.stop == Stop::none || result.wal_removed ||
            result.rollback_snapshot_retired || any_delete_trace ||
            result.delete_transport_outcome.has_value() ||
            has_recovery_evidence ||
            result.forward_dispatch_state ==
                std::optional<Dispatch>{Dispatch::completed}) {
            throw std::runtime_error(
                "incoherent blocked native import recovery result");
        }
        break;
    case Status::recovery_required:
        if (result.stop == Stop::none || !has_record_identity ||
            !result.wal_may_require_recovery || result.wal_removed) {
            throw std::runtime_error(
                "incoherent recovery-required native import result");
        }
        break;
    case Status::completed:
        if (result.stop != Stop::none || !has_record_identity ||
            result.wal_may_require_recovery || !result.wal_removed ||
            result.direct_observation_failure.has_value() ||
            (has_created_identity ==
             result.rollback_snapshot_retired)) {
            throw std::runtime_error(
                "incoherent completed native import recovery result");
        }
        if (has_created_identity) {
            const bool ownership_reconcile =
                *result.phase ==
                NdmsNativeImportWalPhase::ownership_published;
            if (!forward_only_phase(*result.phase) ||
                !result.ownership_published || has_recovery_evidence ||
                result.delete_transport_outcome.has_value() ||
                any_delete_trace ||
                result.forward_admission_state !=
                    std::optional<Admission>{Admission::admitted} ||
                result.forward_dispatch_state !=
                    std::optional<Dispatch>{Dispatch::completed} ||
                result.forward_failed_step.has_value() ||
                (ownership_reconcile
                     ? result.recovery_action !=
                           std::optional<Action>{
                               Action::resume_forward_reconcile}
                     : result.recovery_action.has_value())) {
                throw std::runtime_error(
                    "incoherent forward-completed native import recovery");
            }
        } else {
            if (result.ownership_published || has_forward_evidence ||
                !result.rollback_snapshot_retired ||
                !result.recovery_action.has_value() ||
                !cleanup_recovery_action(*result.recovery_action) ||
                result.recovery_admission_state !=
                    std::optional<Admission>{Admission::admitted} ||
                result.recovery_dispatch_state !=
                    std::optional<Dispatch>{Dispatch::completed} ||
                result.recovery_failed_step.has_value() ||
                (destructive_recovery_action(
                     *result.recovery_action) != any_delete_trace) ||
                (destructive_recovery_action(
                     *result.recovery_action) &&
                 (!result.external_ndms_writer_race_accepted ||
                  !result.delete_transport_outcome.has_value()))) {
                throw std::runtime_error(
                    "incoherent cleanup-completed native import recovery");
            }
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

const char* import_recovery_transport_outcome_name(
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
    throw std::runtime_error(
        "invalid native import recovery transport outcome");
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
         result.system_configuration_save_performed},
        {"request_may_have_been_dispatched",
         result.request_may_have_been_dispatched},
        {"wal_may_require_recovery", result.wal_may_require_recovery},
        {"rollback_snapshot_may_be_retained",
         result.rollback_snapshot_may_be_retained},
        {"ownership_published", result.ownership_published},
    };

    // transaction_id remains an internal WAL/snapshot binding. It is checked
    // above for callback coherence but is never a public UI identifier.
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
        {"ndms_delete_dispatched", result.ndms_delete_dispatched},
        {"system_configuration_save_performed",
         result.system_configuration_save_performed},
        {"external_ndms_writer_race_excluded", false},
        {"external_ndms_writer_race_accepted",
         result.external_ndms_writer_race_accepted},
        {"delete_perform_started", result.delete_perform_started},
        {"request_may_have_been_dispatched",
         result.request_may_have_been_dispatched},
        {"wal_may_require_recovery", result.wal_may_require_recovery},
        {"ownership_published", result.ownership_published},
        {"rollback_snapshot_retired",
         result.rollback_snapshot_retired},
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
    if (result.recovery_admission_state.has_value()) {
        response["recovery_admission_state"] =
            ndms_native_import_recovery_admission_state_name(
                *result.recovery_admission_state);
    }
    if (result.recovery_dispatch_state.has_value()) {
        response["recovery_dispatch_state"] =
            ndms_native_import_recovery_dispatch_state_name(
                *result.recovery_dispatch_state);
    }
    if (result.recovery_failed_step.has_value()) {
        response["recovery_failed_step"] =
            ndms_native_import_recovery_step_name(
                *result.recovery_failed_step);
    }
    if (result.delete_transport_outcome.has_value()) {
        response["delete_transport_outcome"] =
            import_recovery_transport_outcome_name(
                *result.delete_transport_outcome);
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
        [&ctx](const httplib::Request& request) {
            static_cast<void>(recovery_owner_race_acceptance(request));
            return reserve_import_recovery(ctx);
        },
        [&ctx](
            const httplib::Request& request,
            SensitiveRequestBody body,
            const ApiServer::SensitiveRequestReservationPtr& reservation) {
            if (!body.empty()) {
                throw ApiError(
                    "native import recovery body must be empty", 400);
            }
            const auto acceptance =
                recovery_owner_race_acceptance(request);
            const auto result =
                ctx.resume_ndms_native_import_fn(
                    acceptance, reservation);
            if (result.external_ndms_writer_race_accepted !=
                (acceptance ==
                 NdmsNativeExternalWriterRaceAcceptance::
                     owner_accepted)) {
                throw std::runtime_error(
                    "native import recovery acceptance trace mismatch");
            }
            return ndms_native_import_recovery_api_response(result).dump();
        });
}

} // namespace keen_pbr3

#endif // WITH_API
