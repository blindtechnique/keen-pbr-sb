#include "ndms_native_import_wal.hpp"

#include "ndms_native_create_policy.hpp"
#include "ndms_native_import_identity.hpp"
#include "ndms_wireguard_identity.hpp"

#include "../crypto/sha256.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

using Json = nlohmann::json;

constexpr int kSchemaVersion = 4;
constexpr std::string_view kCandidateRevisionPrefix{
    "ndms-native-import-v1-"};
constexpr std::string_view kRequestBindingDigestPrefix{
    "ndms-import-request-binding-v2-"};
constexpr std::string_view kGenerationTicketPrefix{
    "ndms-create-ticket-v1-"};
constexpr std::string_view kResponseManifestDigestPrefix{
    "ndms-import-response-manifest-v3-"};
constexpr std::string_view kTargetRevisionPrefix{
    "ndms-rci-full-v1-"};
constexpr std::string_view kOwnershipRevisionPrefix{
    "ndms-native-owner-v2-"};
constexpr std::string_view kOwnershipRevisionV3Prefix{
    "ndms-native-owner-v3-"};

bool lower_hex(const std::string_view value) noexcept {
    return std::all_of(
        value.begin(), value.end(), [](const unsigned char character) {
            return (character >= '0' && character <= '9') ||
                   (character >= 'a' && character <= 'f');
        });
}

bool prefixed_digest(const std::string& value,
                     const std::string_view prefix) noexcept {
    return value.size() == prefix.size() + 64U &&
           value.compare(0U, prefix.size(), prefix) == 0 &&
           lower_hex(std::string_view{value}.substr(prefix.size()));
}

void update_binding_field(
    Sha256& hasher,
    const std::uint8_t tag,
    const std::string_view value) {
    hasher.update(&tag, sizeof(tag));
    std::array<std::uint8_t, 8U> encoded_size{};
    std::uint64_t size = value.size();
    for (std::size_t index = 0U; index < encoded_size.size(); ++index) {
        encoded_size[encoded_size.size() - 1U - index] =
            static_cast<std::uint8_t>(size & 0xffU);
        size >>= 8U;
    }
    hasher.update(encoded_size.data(), encoded_size.size());
    hasher.update(value.data(), value.size());
}

bool known_phase(const NdmsNativeImportWalPhase phase) noexcept {
    switch (phase) {
    case NdmsNativeImportWalPhase::prepared:
    case NdmsNativeImportWalPhase::import_may_be_inflight:
    case NdmsNativeImportWalPhase::response_recorded:
    case NdmsNativeImportWalPhase::target_verified:
    case NdmsNativeImportWalPhase::ownership_published:
    case NdmsNativeImportWalPhase::rollback_requested:
    case NdmsNativeImportWalPhase::delete_may_be_inflight:
    case NdmsNativeImportWalPhase::absence_verified:
        return true;
    }
    return false;
}

bool active_ownership_revision(const std::string& value) noexcept {
    return prefixed_digest(value, kOwnershipRevisionPrefix) ||
           prefixed_digest(value, kOwnershipRevisionV3Prefix);
}

bool known_kind(const NdmsNativeTunnelImportKind kind) noexcept {
    return kind == NdmsNativeTunnelImportKind::wireguard ||
           kind == NdmsNativeTunnelImportKind::amnezia_wireguard;
}

bool is_forward_verified_phase(
    const NdmsNativeImportWalPhase phase) noexcept {
    return phase == NdmsNativeImportWalPhase::target_verified ||
           phase == NdmsNativeImportWalPhase::ownership_published;
}

bool is_rollback_phase(const NdmsNativeImportWalPhase phase) noexcept {
    return phase == NdmsNativeImportWalPhase::rollback_requested ||
           phase == NdmsNativeImportWalPhase::delete_may_be_inflight ||
           phase == NdmsNativeImportWalPhase::absence_verified;
}

void require(bool condition, const char* message) {
    if (!condition) throw NdmsNativeImportWalError(message);
}

void validate_record(const NdmsNativeImportWalRecord& record) {
    require(
        valid_ndms_native_import_execution_mode(record.execution_mode),
        "native import WAL execution mode is invalid");
    require(
        known_phase(record.phase),
        "native import WAL phase is invalid");
    require(
        known_kind(record.kind),
        "native import WAL kind is invalid");
    require(
        valid_ndms_native_import_transaction_id(record.transaction_id),
        "native import WAL transaction id is invalid");
    require(
        valid_ndms_native_import_marker(
            record.marker, record.transaction_id),
        "native import WAL marker is invalid");
    require(
        prefixed_digest(
            record.candidate_revision, kCandidateRevisionPrefix),
        "native import WAL candidate revision is invalid");
    require(
        prefixed_digest(
            record.request_binding_sha256,
            kRequestBindingDigestPrefix),
        "native import WAL request binding digest is invalid");
    require(
        prefixed_digest(
            record.generation_ticket, kGenerationTicketPrefix),
        "native import WAL generation ticket is invalid");
    require(
        valid_ndms_native_import_persisted_baseline(record.baseline),
        "native import WAL baseline is invalid");
    require(
        record.execution_mode == record.baseline.execution_mode,
        "native import WAL execution mode differs from baseline");
    require(
        record.baseline.maintenance_base_generation ==
            record.maintenance_base_generation,
        "native import WAL baseline generation is inconsistent");
    require(
        valid_ndms_native_observation_binding(
            record.observation_binding),
        "native import WAL observation binding is invalid");
    if (record.execution_mode ==
        NdmsNativeImportExecutionMode::cooperative_stock_import) {
        require(
            record.baseline.durable_observation_binding.has_value() &&
                *record.baseline.durable_observation_binding ==
                    record.observation_binding,
            "cooperative native import WAL observation binding differs from baseline");
    }
    require(
        record.request_binding_sha256 ==
            ndms_native_import_request_binding_digest(
                record.transaction_id,
                record.marker,
                record.candidate_revision,
                record.kind,
                record.baseline.expected_created_interface),
        "native import WAL request binding verification failed");

    const bool prepared =
        record.phase == NdmsNativeImportWalPhase::prepared;
    if (prepared) {
        require(
            !record.reserved_generation.has_value(),
            "prepared native import WAL cannot reserve a generation");
    } else {
        require(
            record.reserved_generation.has_value(),
            "active native import WAL needs a reserved generation");
        require(
            record.maintenance_base_generation !=
                std::numeric_limits<std::uint32_t>::max() &&
            *record.reserved_generation ==
                record.maintenance_base_generation + 1U,
            "native import WAL generation transition is invalid");
    }

    if (record.response_manifest_sha256.has_value()) {
        require(
            prefixed_digest(
                *record.response_manifest_sha256,
                kResponseManifestDigestPrefix),
            "native import WAL response manifest digest is invalid");
    }
    if (record.created_interface.has_value()) {
        require(
            ndms_native_created_target_is_eligible(
                *record.created_interface),
            "native import WAL created target is not eligible");
        require(
            *record.created_interface ==
                record.baseline.expected_created_interface,
            "native import WAL created target differs from baseline");
    }
    require(
        prefixed_digest(
            record.snapshot_revision, kCandidateRevisionPrefix),
        "native import WAL snapshot revision is invalid");
    require(
        record.snapshot_revision == record.candidate_revision,
        "native import WAL snapshot revision differs from request");
    if (record.target_full_revision.has_value()) {
        require(
            prefixed_digest(
                *record.target_full_revision, kTargetRevisionPrefix),
            "native import WAL target revision is invalid");
    }
    if (record.ownership_revision.has_value()) {
        require(
            active_ownership_revision(*record.ownership_revision),
            "native import WAL ownership revision is invalid");
    }

    if (record.phase == NdmsNativeImportWalPhase::prepared ||
        record.phase ==
            NdmsNativeImportWalPhase::import_may_be_inflight) {
        require(
            !record.response_manifest_sha256.has_value() &&
                !record.created_interface.has_value() &&
                !record.target_full_revision.has_value() &&
                !record.ownership_revision.has_value(),
            "early native import WAL phase contains post-state evidence");
    }
    if (record.phase ==
        NdmsNativeImportWalPhase::response_recorded) {
        require(
            record.response_manifest_sha256.has_value(),
            "response-recorded native import WAL needs a manifest");
        require(
            !record.target_full_revision.has_value() &&
                !record.ownership_revision.has_value(),
            "response-recorded native import WAL contains verified evidence");
    }
    if (is_forward_verified_phase(record.phase)) {
        require(
            record.response_manifest_sha256.has_value() &&
                record.created_interface.has_value() &&
                record.target_full_revision.has_value(),
            "verified native import WAL lacks exact target evidence");
    }
    if (record.phase ==
        NdmsNativeImportWalPhase::target_verified) {
        require(
            !record.ownership_revision.has_value(),
            "target-verified native import WAL cannot publish ownership");
    }
    if (record.phase ==
        NdmsNativeImportWalPhase::ownership_published) {
        require(
            record.ownership_revision.has_value(),
            "ownership-published native import WAL lacks ownership revision");
    }

    // Rollback phases deliberately retain any already recorded safe evidence,
    // but do not require it: rollback may branch immediately after the durable
    // import intent when the POST result is ambiguous.
    (void)is_rollback_phase(record.phase);
}

bool valid_record_for_recovery(
    const NdmsNativeImportWalRecord& record) noexcept {
    try {
        validate_record(record);
        return true;
    } catch (...) {
        // The recovery classifier is a fail-closed public boundary. It must
        // not authorize forward/delete work for an in-memory record that did
        // not come from the validated codec, and it must remain noexcept even
        // if validation itself cannot allocate.
        return false;
    }
}

const char* kind_name(const NdmsNativeTunnelImportKind kind) noexcept {
    return kind == NdmsNativeTunnelImportKind::amnezia_wireguard
               ? "amnezia_wireguard"
               : "wireguard";
}

NdmsNativeTunnelImportKind parse_kind(const std::string& value) {
    if (value == "wireguard") {
        return NdmsNativeTunnelImportKind::wireguard;
    }
    if (value == "amnezia_wireguard") {
        return NdmsNativeTunnelImportKind::amnezia_wireguard;
    }
    throw NdmsNativeImportWalError(
        "native import WAL kind is invalid");
}

NdmsNativeImportExecutionMode parse_execution_mode(
    const std::string& value) {
    if (value == "allocator_fenced") {
        return NdmsNativeImportExecutionMode::allocator_fenced;
    }
    if (value == "cooperative_stock_import") {
        return NdmsNativeImportExecutionMode::cooperative_stock_import;
    }
    throw NdmsNativeImportWalError(
        "native import WAL execution mode is invalid");
}

NdmsNativeImportWalPhase parse_phase(const std::string& value) {
    if (value == "prepared") {
        return NdmsNativeImportWalPhase::prepared;
    }
    if (value == "import_may_be_inflight") {
        return NdmsNativeImportWalPhase::import_may_be_inflight;
    }
    if (value == "response_recorded") {
        return NdmsNativeImportWalPhase::response_recorded;
    }
    if (value == "target_verified") {
        return NdmsNativeImportWalPhase::target_verified;
    }
    if (value == "ownership_published") {
        return NdmsNativeImportWalPhase::ownership_published;
    }
    if (value == "rollback_requested") {
        return NdmsNativeImportWalPhase::rollback_requested;
    }
    if (value == "delete_may_be_inflight") {
        return NdmsNativeImportWalPhase::delete_may_be_inflight;
    }
    if (value == "absence_verified") {
        return NdmsNativeImportWalPhase::absence_verified;
    }
    throw NdmsNativeImportWalError(
        "native import WAL phase is invalid");
}

Json optional_string_json(const std::optional<std::string>& value) {
    return value ? Json(*value) : Json(nullptr);
}

Json optional_generation_json(
    const std::optional<std::uint32_t>& value) {
    return value ? Json(*value) : Json(nullptr);
}

Json durable_observation_stamp_json(
    const std::optional<NdmsNativeObservationStamp>& stamp) {
    if (!stamp.has_value()) return Json(nullptr);
    return {
        {"authority_id", stamp->authority_id},
        {"sequence", stamp->sequence},
        {"mutation_epoch", stamp->mutation_epoch},
        {"catalog_revision", stamp->catalog_revision},
        {"ledger_integrity", stamp->ledger_integrity},
    };
}

Json durable_observation_binding_json(
    const std::optional<NdmsNativeObservationBinding>& binding) {
    if (!binding.has_value()) return Json(nullptr);
    return {
        {"authority_id", binding->authority_id},
        {"mutation_epoch", binding->mutation_epoch},
        {"baseline_sequence", binding->baseline_sequence},
    };
}

Json baseline_json(
    const NdmsNativeImportPersistedBaseline& baseline) {
    return {
        {"execution_mode",
         ndms_native_import_execution_mode_name(
             baseline.execution_mode)},
        {"expected_created_interface",
         baseline.expected_created_interface},
        {"expected_target_slot", baseline.expected_target_slot},
        {"occupancy_hex", baseline.occupancy_hex},
        {"protected_catalog_sha256",
         baseline.protected_catalog_sha256},
        {"observation_generation",
         baseline.observation_generation},
        {"observation_epoch", baseline.observation_epoch},
        {"invalidation_epoch", baseline.invalidation_epoch},
        {"maintenance_base_generation",
         baseline.maintenance_base_generation},
        {"allocator_generation", baseline.allocator_generation},
        {"durable_observation_stamp",
         durable_observation_stamp_json(
             baseline.durable_observation_stamp)},
        {"durable_observation_binding",
         durable_observation_binding_json(
             baseline.durable_observation_binding)},
        {"baseline_sha256", baseline.baseline_sha256},
    };
}

Json observation_binding_json(
    const NdmsNativeObservationBinding& binding) {
    return {
        {"authority_id", binding.authority_id},
        {"mutation_epoch", binding.mutation_epoch},
        {"baseline_sequence", binding.baseline_sequence},
    };
}

Json document_without_integrity(
    const NdmsNativeImportWalRecord& record) {
    validate_record(record);
    return {
        {"schema_version", kSchemaVersion},
        {"transaction_id", record.transaction_id},
        {"execution_mode",
         ndms_native_import_execution_mode_name(
             record.execution_mode)},
        {"phase", ndms_native_import_wal_phase_name(record.phase)},
        {"kind", kind_name(record.kind)},
        {"marker", record.marker},
        {"candidate_revision", record.candidate_revision},
        {"request_binding_sha256", record.request_binding_sha256},
        {"generation_ticket", record.generation_ticket},
        {"maintenance_base_generation",
         record.maintenance_base_generation},
        {"observation_binding",
         observation_binding_json(record.observation_binding)},
        {"baseline", baseline_json(record.baseline)},
        {"reserved_generation",
         optional_generation_json(record.reserved_generation)},
        {"response_manifest_sha256",
         optional_string_json(record.response_manifest_sha256)},
        {"created_interface",
         optional_string_json(record.created_interface)},
        {"snapshot_revision", record.snapshot_revision},
        {"target_full_revision",
         optional_string_json(record.target_full_revision)},
        {"ownership_revision",
         optional_string_json(record.ownership_revision)},
    };
}

void require_exact_keys(
    const Json& document,
    const std::initializer_list<const char*> keys) {
    require(
        document.is_object(),
        "native import WAL root must be an object");
    std::set<std::string> expected;
    for (const char* key : keys) expected.emplace(key);
    std::set<std::string> actual;
    for (auto iterator = document.begin();
         iterator != document.end(); ++iterator) {
        actual.emplace(iterator.key());
    }
    require(
        actual == expected,
        "native import WAL has missing or unknown fields");
}

std::uint64_t parse_unsigned_u64(
    const Json& value,
    const char* message) {
    require(value.is_number_unsigned(), message);
    return value.get<std::uint64_t>();
}

NdmsNativeObservationBinding parse_observation_binding(
    const Json& value) {
    require_exact_keys(
        value,
        {"authority_id", "mutation_epoch", "baseline_sequence"});
    require(
        value.at("authority_id").is_string(),
        "native import WAL observation authority type is invalid");
    NdmsNativeObservationBinding binding;
    binding.authority_id =
        value.at("authority_id").get<std::string>();
    binding.mutation_epoch = parse_unsigned_u64(
        value.at("mutation_epoch"),
        "native import WAL mutation epoch type is invalid");
    binding.baseline_sequence = parse_unsigned_u64(
        value.at("baseline_sequence"),
        "native import WAL baseline sequence type is invalid");
    require(
        valid_ndms_native_observation_binding(binding),
        "native import WAL observation binding verification failed");
    return binding;
}

std::optional<NdmsNativeObservationBinding>
parse_optional_observation_binding(const Json& value) {
    if (value.is_null()) return std::nullopt;
    return parse_observation_binding(value);
}

std::optional<NdmsNativeObservationStamp>
parse_optional_observation_stamp(const Json& value) {
    if (value.is_null()) return std::nullopt;
    require_exact_keys(
        value,
        {"authority_id", "sequence", "mutation_epoch",
         "catalog_revision", "ledger_integrity"});
    for (const char* field :
         {"authority_id", "catalog_revision", "ledger_integrity"}) {
        require(
            value.at(field).is_string(),
            "native import WAL durable observation stamp type is invalid");
    }
    NdmsNativeObservationStamp stamp;
    stamp.authority_id =
        value.at("authority_id").get<std::string>();
    stamp.sequence = parse_unsigned_u64(
        value.at("sequence"),
        "native import WAL durable observation sequence is invalid");
    stamp.mutation_epoch = parse_unsigned_u64(
        value.at("mutation_epoch"),
        "native import WAL durable observation epoch is invalid");
    stamp.catalog_revision =
        value.at("catalog_revision").get<std::string>();
    stamp.ledger_integrity =
        value.at("ledger_integrity").get<std::string>();
    require(
        valid_ndms_native_observation_stamp(stamp),
        "native import WAL durable observation stamp verification failed");
    return stamp;
}

NdmsNativeImportPersistedBaseline parse_baseline(
    const Json& value) {
    require_exact_keys(
        value,
        {"execution_mode",
         "expected_created_interface",
         "expected_target_slot",
         "occupancy_hex",
         "protected_catalog_sha256",
         "observation_generation",
         "observation_epoch",
         "invalidation_epoch",
         "maintenance_base_generation",
         "allocator_generation",
         "durable_observation_stamp",
         "durable_observation_binding",
         "baseline_sha256"});
    for (const char* field :
         {"execution_mode", "expected_created_interface", "occupancy_hex",
          "protected_catalog_sha256", "baseline_sha256"}) {
        require(
            value.at(field).is_string(),
            "native import WAL baseline string type is invalid");
    }

    const auto target_slot = parse_unsigned_u64(
        value.at("expected_target_slot"),
        "native import WAL baseline target slot type is invalid");
    require(
        target_slot <= std::numeric_limits<std::uint8_t>::max(),
        "native import WAL baseline target slot is too large");
    const auto maintenance = parse_unsigned_u64(
        value.at("maintenance_base_generation"),
        "native import WAL baseline maintenance generation type is invalid");
    require(
        maintenance <= std::numeric_limits<std::uint32_t>::max(),
        "native import WAL baseline maintenance generation is too large");

    NdmsNativeImportPersistedBaseline baseline;
    baseline.execution_mode = parse_execution_mode(
        value.at("execution_mode").get<std::string>());
    baseline.expected_created_interface =
        value.at("expected_created_interface").get<std::string>();
    baseline.expected_target_slot =
        static_cast<std::uint8_t>(target_slot);
    baseline.occupancy_hex =
        value.at("occupancy_hex").get<std::string>();
    baseline.protected_catalog_sha256 =
        value.at("protected_catalog_sha256").get<std::string>();
    baseline.observation_generation = parse_unsigned_u64(
        value.at("observation_generation"),
        "native import WAL baseline observation generation type is invalid");
    baseline.observation_epoch = parse_unsigned_u64(
        value.at("observation_epoch"),
        "native import WAL baseline observation epoch type is invalid");
    baseline.invalidation_epoch = parse_unsigned_u64(
        value.at("invalidation_epoch"),
        "native import WAL baseline invalidation epoch type is invalid");
    baseline.maintenance_base_generation =
        static_cast<std::uint32_t>(maintenance);
    baseline.allocator_generation = parse_unsigned_u64(
        value.at("allocator_generation"),
        "native import WAL baseline allocator generation type is invalid");
    baseline.durable_observation_stamp =
        parse_optional_observation_stamp(
            value.at("durable_observation_stamp"));
    baseline.durable_observation_binding =
        parse_optional_observation_binding(
            value.at("durable_observation_binding"));
    baseline.baseline_sha256 =
        value.at("baseline_sha256").get<std::string>();
    require(
        valid_ndms_native_import_persisted_baseline(baseline),
        "native import WAL baseline verification failed");
    return baseline;
}

Json parse_without_duplicate_keys(const std::string_view body) {
    bool duplicate = false;
    std::vector<std::set<std::string>> object_keys;
    const auto callback =
        [&duplicate, &object_keys](
            int,
            const Json::parse_event_t event,
            Json& parsed) {
            if (event == Json::parse_event_t::object_start) {
                object_keys.emplace_back();
            } else if (event == Json::parse_event_t::key) {
                if (object_keys.empty() || !parsed.is_string()) {
                    duplicate = true;
                } else if (!object_keys.back()
                                .insert(parsed.get<std::string>())
                                .second) {
                    duplicate = true;
                }
            } else if (event == Json::parse_event_t::object_end) {
                if (object_keys.empty()) {
                    duplicate = true;
                } else {
                    object_keys.pop_back();
                }
            }
            return true;
        };

    try {
        auto document = Json::parse(
            body.begin(), body.end(), callback, true, false);
        require(
            !duplicate && object_keys.empty(),
            "native import WAL contains duplicate keys");
        return document;
    } catch (const NdmsNativeImportWalError&) {
        throw;
    } catch (const Json::exception&) {
        throw NdmsNativeImportWalError(
            "native import WAL is not valid JSON");
    }
}

std::optional<std::string> parse_optional_string(
    const Json& value,
    const char* message) {
    if (value.is_null()) return std::nullopt;
    require(value.is_string(), message);
    return value.get<std::string>();
}

std::optional<std::uint32_t> parse_optional_generation(
    const Json& value) {
    if (value.is_null()) return std::nullopt;
    require(
        value.is_number_unsigned(),
        "native import WAL reserved generation type is invalid");
    const auto parsed = value.get<std::uint64_t>();
    require(
        parsed <= std::numeric_limits<std::uint32_t>::max(),
        "native import WAL reserved generation is too large");
    return static_cast<std::uint32_t>(parsed);
}

// The fingerprint is demanded exactly when the record is allowed to carry
// one. validate_record forbids target_full_revision at prepared,
// import_may_be_inflight and response_recorded, and the observation can set
// target_fingerprint_matches only from a revision the record carries - so
// requiring it unconditionally made this false at precisely the phases a
// crashed import lands on, and every such import ended in block_unknown: the
// interface it created stayed on the router forever and its WAL record blocked
// every future import.
//
// At those phases ownership rests on the marker triple, which is what the
// design intends and all the evidence that exists there. The marker is derived
// from this transaction's own id, so exactly one interface carrying it was
// created by this transaction; the slot was free in the baseline; the carrier
// is down; the slot is inside the managed range. A revision would add nothing,
// because nothing ever read this target to record one.
bool exact_owned_target(
    const NdmsNativeImportWalRecord& record,
    const NdmsNativeImportRecoveryObservation& observation) noexcept {
    if (observation.marker_match_count != 1U ||
        !observation.marker_target.has_value() ||
        !observation.target_absent_in_baseline ||
        !observation.target_down) {
        return false;
    }
    if (record.target_full_revision.has_value() &&
        !observation.target_fingerprint_matches) {
        return false;
    }
    if (record.created_interface.has_value() &&
        *record.created_interface != *observation.marker_target) {
        return false;
    }
    return ndms_native_created_target_is_eligible(
        *observation.marker_target);
}

} // namespace

std::string ndms_native_import_request_binding_digest(
    const std::string_view transaction_id,
    const std::string_view marker,
    const std::string_view candidate_revision,
    const NdmsNativeTunnelImportKind kind,
    const std::string_view expected_created_interface) {
    constexpr std::string_view domain{
        "keen-pbr.ndms-native-import.request-binding.v2"};
    Sha256 hasher;
    update_binding_field(hasher, 0U, domain);
    update_binding_field(hasher, 1U, transaction_id);
    update_binding_field(hasher, 2U, marker);
    update_binding_field(hasher, 3U, candidate_revision);
    update_binding_field(
        hasher, 4U, ndms_native_tunnel_import_kind_name(kind));
    update_binding_field(hasher, 5U, expected_created_interface);
    return std::string{kRequestBindingDigestPrefix} +
           hasher.hex_digest();
}

bool NdmsNativeImportWalRecord::operator==(
    const NdmsNativeImportWalRecord& other) const noexcept {
    return transaction_id == other.transaction_id &&
           execution_mode == other.execution_mode &&
           phase == other.phase && kind == other.kind &&
           marker == other.marker &&
           candidate_revision == other.candidate_revision &&
           request_binding_sha256 ==
               other.request_binding_sha256 &&
           generation_ticket == other.generation_ticket &&
           maintenance_base_generation ==
               other.maintenance_base_generation &&
           observation_binding == other.observation_binding &&
           baseline == other.baseline &&
           reserved_generation == other.reserved_generation &&
           response_manifest_sha256 ==
               other.response_manifest_sha256 &&
           created_interface == other.created_interface &&
           snapshot_revision == other.snapshot_revision &&
           target_full_revision == other.target_full_revision &&
           ownership_revision == other.ownership_revision;
}

std::string serialize_ndms_native_import_wal(
    const NdmsNativeImportWalRecord& record) {
    auto document = document_without_integrity(record);
    document["integrity_sha256"] = Sha256::hex(document.dump());
    auto serialized = document.dump(2) + "\n";
    require(
        serialized.size() <= kNdmsNativeImportWalMaximumBytes,
        "native import WAL exceeds its size limit");
    return serialized;
}

NdmsNativeImportWalRecord parse_ndms_native_import_wal(
    const std::string_view body) {
    require(
        !body.empty() &&
            body.size() <= kNdmsNativeImportWalMaximumBytes,
        "native import WAL body size is invalid");
    const auto document = parse_without_duplicate_keys(body);
    require_exact_keys(
        document,
        {"schema_version",
         "transaction_id",
         "execution_mode",
         "phase",
         "kind",
         "marker",
         "candidate_revision",
         "request_binding_sha256",
         "generation_ticket",
         "maintenance_base_generation",
         "observation_binding",
         "baseline",
         "reserved_generation",
         "response_manifest_sha256",
         "created_interface",
         "snapshot_revision",
         "target_full_revision",
         "ownership_revision",
         "integrity_sha256"});

    require(
        document.at("schema_version").is_number_integer() &&
            document.at("schema_version").get<int>() == kSchemaVersion,
        "native import WAL schema version is invalid");
    for (const char* field :
         {"transaction_id", "execution_mode", "phase", "kind", "marker",
          "candidate_revision", "request_binding_sha256",
          "generation_ticket",
          "integrity_sha256"}) {
        require(
            document.at(field).is_string(),
            "native import WAL string field type is invalid");
    }
    require(
        document.at("maintenance_base_generation")
            .is_number_unsigned(),
        "native import WAL base generation type is invalid");
    const auto base =
        document.at("maintenance_base_generation")
            .get<std::uint64_t>();
    require(
        base <= std::numeric_limits<std::uint32_t>::max(),
        "native import WAL base generation is too large");

    NdmsNativeImportWalRecord record;
    record.transaction_id =
        document.at("transaction_id").get<std::string>();
    record.execution_mode = parse_execution_mode(
        document.at("execution_mode").get<std::string>());
    record.phase = parse_phase(
        document.at("phase").get<std::string>());
    record.kind = parse_kind(
        document.at("kind").get<std::string>());
    record.marker = document.at("marker").get<std::string>();
    record.candidate_revision =
        document.at("candidate_revision").get<std::string>();
    record.request_binding_sha256 =
        document.at("request_binding_sha256").get<std::string>();
    record.generation_ticket =
        document.at("generation_ticket").get<std::string>();
    record.maintenance_base_generation =
        static_cast<std::uint32_t>(base);
    record.observation_binding = parse_observation_binding(
        document.at("observation_binding"));
    record.baseline = parse_baseline(document.at("baseline"));
    record.reserved_generation = parse_optional_generation(
        document.at("reserved_generation"));
    record.response_manifest_sha256 = parse_optional_string(
        document.at("response_manifest_sha256"),
        "native import WAL response manifest digest type is invalid");
    record.created_interface = parse_optional_string(
        document.at("created_interface"),
        "native import WAL created target type is invalid");
    require(
        document.at("snapshot_revision").is_string(),
        "native import WAL snapshot revision type is invalid");
    record.snapshot_revision =
        document.at("snapshot_revision").get<std::string>();
    record.target_full_revision = parse_optional_string(
        document.at("target_full_revision"),
        "native import WAL target revision type is invalid");
    record.ownership_revision = parse_optional_string(
        document.at("ownership_revision"),
        "native import WAL ownership revision type is invalid");
    validate_record(record);

    const auto integrity =
        document.at("integrity_sha256").get<std::string>();
    require(
        integrity.size() == 64U && lower_hex(integrity),
        "native import WAL integrity digest is invalid");
    require(
        integrity == Sha256::hex(document_without_integrity(record).dump()),
        "native import WAL integrity verification failed");
    return record;
}

bool valid_ndms_native_import_wal_transition(
    const NdmsNativeImportWalPhase from,
    const NdmsNativeImportWalPhase to) noexcept {
    if (from == to) return true;
    switch (from) {
    case NdmsNativeImportWalPhase::prepared:
        return to == NdmsNativeImportWalPhase::import_may_be_inflight;
    case NdmsNativeImportWalPhase::import_may_be_inflight:
        return to == NdmsNativeImportWalPhase::response_recorded ||
               to == NdmsNativeImportWalPhase::rollback_requested;
    case NdmsNativeImportWalPhase::response_recorded:
        return to == NdmsNativeImportWalPhase::target_verified ||
               to == NdmsNativeImportWalPhase::rollback_requested;
    case NdmsNativeImportWalPhase::target_verified:
        return to == NdmsNativeImportWalPhase::ownership_published ||
               to == NdmsNativeImportWalPhase::rollback_requested ||
               to == NdmsNativeImportWalPhase::absence_verified;
    case NdmsNativeImportWalPhase::ownership_published:
        return to == NdmsNativeImportWalPhase::rollback_requested ||
               to == NdmsNativeImportWalPhase::absence_verified;
    case NdmsNativeImportWalPhase::rollback_requested:
        return to == NdmsNativeImportWalPhase::delete_may_be_inflight ||
               to == NdmsNativeImportWalPhase::absence_verified;
    case NdmsNativeImportWalPhase::delete_may_be_inflight:
        return to == NdmsNativeImportWalPhase::absence_verified;
    case NdmsNativeImportWalPhase::absence_verified:
        return false;
    }
    return false;
}

NdmsNativeImportRecoveryAction classify_ndms_native_import_recovery(
    const NdmsNativeImportWalRecord& record,
    const NdmsNativeImportRecoveryObservation& observation) noexcept {
    if (!valid_record_for_recovery(record)) {
        return NdmsNativeImportRecoveryAction::block_unknown;
    }
    if (!observation.authoritative) {
        return NdmsNativeImportRecoveryAction::
            retry_read_only_observation;
    }
    if (!observation.protected_catalog_unchanged ||
        observation.marker_match_count > 1U ||
        (observation.marker_match_count == 0U &&
         observation.marker_target.has_value()) ||
        (observation.marker_match_count == 1U &&
         !observation.marker_target.has_value())) {
        return NdmsNativeImportRecoveryAction::block_unknown;
    }

    const bool exact_owned = exact_owned_target(record, observation);
    const bool absent = observation.marker_match_count == 0U;

    // A codec-valid prepared record is durable proof that the later
    // import_may_be_inflight intent was never published, so the executor was
    // not allowed to enter the POST boundary. It does not need a generation
    // advance that may never happen after a crash before reserve_next().
    if (record.phase == NdmsNativeImportWalPhase::prepared) {
        return absent
                   ? NdmsNativeImportRecoveryAction::abort_without_mutation
                   : NdmsNativeImportRecoveryAction::block_unknown;
    }
    if (!observation.generation_advanced) {
        return NdmsNativeImportRecoveryAction::
            retry_read_only_observation;
    }

    switch (record.phase) {
    case NdmsNativeImportWalPhase::prepared:
        return NdmsNativeImportRecoveryAction::block_unknown;
    case NdmsNativeImportWalPhase::import_may_be_inflight:
    case NdmsNativeImportWalPhase::response_recorded:
        if (absent) {
            return observation.stable_absence
                       ? NdmsNativeImportRecoveryAction::
                             abort_without_mutation
                       : NdmsNativeImportRecoveryAction::
                             retry_read_only_observation;
        }
        return exact_owned
                   ? NdmsNativeImportRecoveryAction::
                         rollback_delete_exact_owned
                   : NdmsNativeImportRecoveryAction::block_unknown;
    case NdmsNativeImportWalPhase::target_verified:
        if (absent) {
            return observation.stable_absence
                       ? NdmsNativeImportRecoveryAction::complete_rollback
                       : NdmsNativeImportRecoveryAction::
                             retry_read_only_observation;
        }
        return exact_owned
                   ? NdmsNativeImportRecoveryAction::
                         rollback_delete_exact_owned
                   : NdmsNativeImportRecoveryAction::block_unknown;
    case NdmsNativeImportWalPhase::ownership_published:
        if (absent) {
            return observation.stable_absence
                       ? NdmsNativeImportRecoveryAction::complete_rollback
                       : NdmsNativeImportRecoveryAction::
                             retry_read_only_observation;
        }
        return exact_owned && observation.ownership_record_matches
                   ? NdmsNativeImportRecoveryAction::
                         resume_forward_reconcile
                   : NdmsNativeImportRecoveryAction::block_unknown;
    case NdmsNativeImportWalPhase::rollback_requested:
    case NdmsNativeImportWalPhase::delete_may_be_inflight:
        if (absent) {
            return observation.stable_absence
                       ? NdmsNativeImportRecoveryAction::complete_rollback
                       : NdmsNativeImportRecoveryAction::
                             retry_read_only_observation;
        }
        return exact_owned
                   ? NdmsNativeImportRecoveryAction::
                         retry_exact_owned_delete
                   : NdmsNativeImportRecoveryAction::block_unknown;
    case NdmsNativeImportWalPhase::absence_verified:
        if (absent && observation.stable_absence) {
            return NdmsNativeImportRecoveryAction::complete_rollback;
        }
        return absent
                   ? NdmsNativeImportRecoveryAction::
                         retry_read_only_observation
                   : NdmsNativeImportRecoveryAction::block_unknown;
    }
    return NdmsNativeImportRecoveryAction::block_unknown;
}

const char* ndms_native_import_wal_phase_name(
    const NdmsNativeImportWalPhase phase) noexcept {
    switch (phase) {
    case NdmsNativeImportWalPhase::prepared:
        return "prepared";
    case NdmsNativeImportWalPhase::import_may_be_inflight:
        return "import_may_be_inflight";
    case NdmsNativeImportWalPhase::response_recorded:
        return "response_recorded";
    case NdmsNativeImportWalPhase::target_verified:
        return "target_verified";
    case NdmsNativeImportWalPhase::ownership_published:
        return "ownership_published";
    case NdmsNativeImportWalPhase::rollback_requested:
        return "rollback_requested";
    case NdmsNativeImportWalPhase::delete_may_be_inflight:
        return "delete_may_be_inflight";
    case NdmsNativeImportWalPhase::absence_verified:
        return "absence_verified";
    }
    return "unknown";
}

const char* ndms_native_import_recovery_action_name(
    const NdmsNativeImportRecoveryAction action) noexcept {
    switch (action) {
    case NdmsNativeImportRecoveryAction::retry_read_only_observation:
        return "retry_read_only_observation";
    case NdmsNativeImportRecoveryAction::abort_without_mutation:
        return "abort_without_mutation";
    case NdmsNativeImportRecoveryAction::rollback_delete_exact_owned:
        return "rollback_delete_exact_owned";
    case NdmsNativeImportRecoveryAction::resume_forward_reconcile:
        return "resume_forward_reconcile";
    case NdmsNativeImportRecoveryAction::retry_exact_owned_delete:
        return "retry_exact_owned_delete";
    case NdmsNativeImportRecoveryAction::complete_rollback:
        return "complete_rollback";
    case NdmsNativeImportRecoveryAction::block_unknown:
        return "block_unknown";
    }
    return "unknown";
}

} // namespace keen_pbr3
