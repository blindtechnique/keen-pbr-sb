#include "handler_ndms_native_tombstone_forget.hpp"

#ifdef WITH_API

#include "handlers.hpp"
#include "server.hpp"

#include "../keenetic/ndms_wireguard_identity.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <algorithm>
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

constexpr std::string_view kTombstoneRevisionPrefix{
    "ndms-native-owner-tombstone-v1-"};
constexpr std::string_view kRollbackDiscardAcknowledgement{
    "permanently_discard_rollback_data"};
constexpr std::string_view kForeignReappearanceAcknowledgement{
    "accepted_reappearance_is_foreign"};

template <typename Enum>
bool known_enum_value(const Enum value,
                      const Enum first,
                      const Enum last) noexcept {
    using Underlying = std::underlying_type_t<Enum>;
    const auto numeric = static_cast<Underlying>(value);
    return numeric >= static_cast<Underlying>(first) &&
           numeric <= static_cast<Underlying>(last);
}

bool public_interface_name(const std::string_view value) noexcept {
    const auto identity = parse_ndms_wireguard_identity(value);
    return identity.has_value() &&
           ndms_wireguard_identity_is_managed_candidate(*identity) &&
           identity->canonical_name() == value;
}

bool exact_tombstone_revision(const std::string_view value) noexcept {
    if (value.size() != kTombstoneRevisionPrefix.size() + 64U ||
        value.substr(0U, kTombstoneRevisionPrefix.size()) !=
            kTombstoneRevisionPrefix) {
        return false;
    }
    return std::all_of(
        value.begin() +
            static_cast<std::string_view::difference_type>(
                kTombstoneRevisionPrefix.size()),
        value.end(), [](const char character) {
            return (character >= '0' && character <= '9') ||
                   (character >= 'a' && character <= 'f');
        });
}

std::string ascii_lower_trimmed(std::string value) {
    const auto not_ows = [](const unsigned char character) {
        return character != ' ' && character != '\t';
    };
    const auto first = std::find_if(value.begin(), value.end(), not_ows);
    const auto last =
        std::find_if(value.rbegin(), value.rend(), not_ows).base();
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
    return request.get_header_value_count("Content-Type") == 1U &&
           ascii_lower_trimmed(
               request.get_header_value("Content-Type")) ==
               "application/json";
}

ApiServer::SensitiveRequestReservationPtr reserve_forget(
    const std::function<ApiServer::SensitiveRequestReservationPtr()>&
        reserve_fn) {
    if (!reserve_fn) {
        throw ApiError(
            "native retained deletion retirement is unavailable", 503);
    }
    try {
        return reserve_fn();
    } catch (const ApiError&) {
        throw;
    } catch (...) {
        throw ApiError(
            "native retained deletion retirement is unavailable", 503);
    }
}

NdmsNativeTombstoneForgetRequest parse_forget_request(
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
        throw ApiError(
            "native retained deletion retirement request is invalid", 400);
    }
    static const std::unordered_set<std::string> required_keys{
        "interface_name",
        "expected_ownership_revision",
        "confirm_interface_name",
        "rollback_discard_acknowledgement",
        "foreign_reappearance_acknowledgement",
    };
    if (duplicate_key || !document.is_object() ||
        document.size() != required_keys.size()) {
        throw ApiError(
            "native retained deletion retirement request is invalid", 400);
    }
    for (const auto& key : required_keys) {
        if (!document.contains(key) || !document.at(key).is_string()) {
            throw ApiError(
                "native retained deletion retirement request is invalid",
                400);
        }
    }

    const auto interface_name =
        document.at("interface_name").get<std::string>();
    const auto revision = document.at("expected_ownership_revision")
                              .get<std::string>();
    const auto confirmation = document.at("confirm_interface_name")
                                  .get<std::string>();
    if (!public_interface_name(interface_name) ||
        confirmation != interface_name ||
        !exact_tombstone_revision(revision) ||
        document.at("rollback_discard_acknowledgement")
                .get<std::string>() != kRollbackDiscardAcknowledgement ||
        document.at("foreign_reappearance_acknowledgement")
                .get<std::string>() !=
            kForeignReappearanceAcknowledgement) {
        throw ApiError(
            "native retained deletion retirement request is invalid", 400);
    }

    NdmsNativeTombstoneForgetRequest request;
    request.interface_name = interface_name;
    request.confirmed_interface_name = confirmation;
    request.expected_ownership_revision = revision;
    request.exact_name_confirmation =
        NdmsNativeTombstoneExactNameConfirmation::confirmed;
    request.rollback_discard =
        NdmsNativeTombstoneRollbackDiscardAcknowledgement::
            permanently_discard_rollback_data;
    request.foreign_reappearance =
        NdmsNativeTombstoneForeignReappearanceAcknowledgement::
            accepted_reappearance_is_foreign;
    return request;
}

bool private_guard_stop(
    const NdmsNativeTombstoneForgetStop stop) noexcept {
    return stop == NdmsNativeTombstoneForgetStop::
                       exact_name_not_confirmed ||
           stop == NdmsNativeTombstoneForgetStop::
                       rollback_discard_not_acknowledged ||
           stop == NdmsNativeTombstoneForgetStop::
                       foreign_reappearance_not_acknowledged ||
           stop == NdmsNativeTombstoneForgetStop::
                       invalid_or_protected_target;
}

bool recovery_impossible_stop(
    const NdmsNativeTombstoneForgetStop stop) noexcept {
    return stop == NdmsNativeTombstoneForgetStop::writer_missing ||
           stop == NdmsNativeTombstoneForgetStop::ownership_absent ||
           stop == NdmsNativeTombstoneForgetStop::ownership_unreadable ||
           stop == NdmsNativeTombstoneForgetStop::
                       ownership_not_forget_capable ||
           stop == NdmsNativeTombstoneForgetStop::snapshot_unreadable ||
           stop == NdmsNativeTombstoneForgetStop::snapshot_mismatch;
}

void validate_public_forget_result(
    const NdmsNativeTombstoneForgetResult& result) {
    using Artifact = NdmsNativeTombstoneForgetArtifactState;
    using Status = NdmsNativeTombstoneForgetStatus;
    using Stop = NdmsNativeTombstoneForgetStop;

    if (!known_enum_value(
            result.status, Status::blocked, Status::forgotten) ||
        !known_enum_value(
            result.stop, Stop::none, Stop::unexpected_failure) ||
        !known_enum_value(
            result.snapshot_state,
            Artifact::unknown,
            Artifact::absent_durable) ||
        !known_enum_value(
            result.tombstone_state,
            Artifact::unknown,
            Artifact::absent_durable) ||
        !result.interface_name.has_value() ||
        !public_interface_name(*result.interface_name) ||
        result.router_mutation_attempted ||
        result.system_configuration_save_acknowledged ||
        private_guard_stop(result.stop)) {
        throw std::runtime_error(
            "invalid native retained deletion retirement result");
    }

    if (result.status == Status::forgotten) {
        if (result.stop != Stop::none ||
            result.snapshot_state != Artifact::absent_durable ||
            result.tombstone_state != Artifact::absent_durable ||
            !result.future_reappearance_is_foreign) {
            throw std::runtime_error(
                "incoherent forgotten native tombstone result");
        }
        return;
    }
    if (result.stop == Stop::none ||
        result.future_reappearance_is_foreign ||
        result.tombstone_state == Artifact::absent_durable) {
        throw std::runtime_error(
            "incoherent nonterminal native tombstone result");
    }

    if (result.status == Status::blocked) {
        if (result.stop == Stop::tombstone_retirement_failed) {
            throw std::runtime_error(
                "incoherent blocked native tombstone result");
        }
        const bool snapshot_retirement_failed =
            result.stop == Stop::snapshot_retirement_failed;
        const auto expected = snapshot_retirement_failed
            ? Artifact::retained
            : Artifact::unknown;
        if (result.snapshot_state != expected ||
            result.tombstone_state != expected) {
            throw std::runtime_error(
                "incoherent blocked native tombstone artifacts");
        }
        return;
    }

    if (result.status != Status::recovery_required ||
        recovery_impossible_stop(result.stop)) {
        throw std::runtime_error(
            "incoherent native tombstone recovery result");
    }
    if (result.stop == Stop::snapshot_retirement_failed) {
        if (result.snapshot_state == Artifact::absent_durable) {
            throw std::runtime_error(
                "incoherent failed snapshot retirement result");
        }
        return;
    }
    if (result.stop != Stop::unexpected_failure &&
        result.snapshot_state != Artifact::absent_durable) {
        throw std::runtime_error(
            "incoherent native tombstone recovery artifacts");
    }
}

} // namespace

nlohmann::json ndms_native_tombstone_forget_api_response(
    const NdmsNativeTombstoneForgetResult& result) {
    validate_public_forget_result(result);
    return nlohmann::json{
        {"status", ndms_native_tombstone_forget_status_name(
                       result.status)},
        {"stop", ndms_native_tombstone_forget_stop_name(result.stop)},
        {"interface_name", *result.interface_name},
        {"snapshot_state",
         ndms_native_tombstone_forget_artifact_state_name(
             result.snapshot_state)},
        {"tombstone_state",
         ndms_native_tombstone_forget_artifact_state_name(
             result.tombstone_state)},
        {"router_mutation_attempted", result.router_mutation_attempted},
        {"system_configuration_save_acknowledged",
         result.system_configuration_save_acknowledged},
        {"future_reappearance_is_foreign",
         result.future_reappearance_is_foreign},
    };
}

void register_ndms_native_tombstone_forget_handler(
    ApiServer& server,
    ApiContext& context) {
    server.post_sensitive(
        std::string{kNdmsNativeTombstoneForgetApiPath},
        kNdmsNativeTombstoneForgetRequestMaximumBytes,
        [&context](const httplib::Request& request) {
            if (!context.run_ndms_native_tombstone_forget_fn ||
                !context.reserve_ndms_native_tombstone_forget_fn) {
                throw ApiError(
                    "native retained deletion retirement is unavailable",
                    503);
            }
            if (!accepted_json_content_type(request)) {
                throw ApiError(
                    "native retained deletion retirement requires application/json",
                    415);
            }
            return reserve_forget(
                context.reserve_ndms_native_tombstone_forget_fn);
        },
        [&context](
            const httplib::Request&,
            SensitiveRequestBody body,
            const ApiServer::SensitiveRequestReservationPtr& reservation) {
            if (body.empty()) {
                throw ApiError(
                    "native retained deletion retirement body must not be empty",
                    400);
            }
            const auto request =
                parse_forget_request(body.take_string_once());
            const auto result =
                context.run_ndms_native_tombstone_forget_fn(
                    request, reservation);
            if (!result.interface_name.has_value() ||
                *result.interface_name != request.interface_name) {
                throw std::runtime_error(
                    "native retained deletion retirement target mismatch");
            }
            return ndms_native_tombstone_forget_api_response(result).dump();
        });
}

} // namespace keen_pbr3

#endif // WITH_API
