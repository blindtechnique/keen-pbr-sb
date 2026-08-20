#include "ndms_native_delete_wal.hpp"

#include "ndms_native_create_policy.hpp"
#include "ndms_native_import_identity.hpp"
#include "ndms_native_observation_store.hpp"

#include "../crypto/sha256.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <set>
#include <string>
#include <utility>

namespace keen_pbr3 {
namespace {

constexpr std::string_view kIntegrityPrefix{
    "ndms-native-delete-wal-v1-"};
constexpr std::string_view kOwnershipRevisionPrefix{
    "ndms-native-owner-v2-"};
constexpr std::string_view kOwnershipRevisionV3Prefix{
    "ndms-native-owner-v3-"};
constexpr std::string_view kSnapshotRevisionPrefix{
    "ndms-native-import-v1-"};
constexpr std::string_view kTargetFullRevisionPrefix{
    "ndms-rci-full-v1-"};

bool lower_hex(const std::string_view value,
               const std::size_t count) noexcept {
    return value.size() == count &&
           std::all_of(value.begin(), value.end(), [](const char value) {
               return (value >= '0' && value <= '9') ||
                      (value >= 'a' && value <= 'f');
           });
}

bool revision(const std::string_view value,
              const std::string_view prefix) noexcept {
    return value.size() == prefix.size() + 64U &&
           value.substr(0U, prefix.size()) == prefix &&
           lower_hex(value.substr(prefix.size()), 64U);
}

bool known_kind(const NdmsNativeTunnelImportKind kind) noexcept {
    return kind == NdmsNativeTunnelImportKind::wireguard ||
           kind == NdmsNativeTunnelImportKind::amnezia_wireguard;
}

const char* kind_name(const NdmsNativeTunnelImportKind kind) {
    switch (kind) {
    case NdmsNativeTunnelImportKind::wireguard:
        return "wireguard";
    case NdmsNativeTunnelImportKind::amnezia_wireguard:
        return "amnezia_wireguard";
    }
    throw NdmsNativeDeleteWalError("native delete kind is invalid");
}

NdmsNativeTunnelImportKind parse_kind(const std::string& value) {
    if (value == "wireguard") {
        return NdmsNativeTunnelImportKind::wireguard;
    }
    if (value == "amnezia_wireguard") {
        return NdmsNativeTunnelImportKind::amnezia_wireguard;
    }
    throw NdmsNativeDeleteWalError("native delete kind is unknown");
}

NdmsNativeDeleteWalPhase parse_phase(const std::string& value) {
    for (const auto phase : {
             NdmsNativeDeleteWalPhase::prepared,
             NdmsNativeDeleteWalPhase::delete_may_be_inflight,
             NdmsNativeDeleteWalPhase::running_absence_verified,
             NdmsNativeDeleteWalPhase::save_may_be_inflight,
             NdmsNativeDeleteWalPhase::save_acknowledged_unverified,
             NdmsNativeDeleteWalPhase::cleanup}) {
        if (value == ndms_native_delete_wal_phase_name(phase)) {
            return phase;
        }
    }
    throw NdmsNativeDeleteWalError("native delete WAL phase is unknown");
}

void update_field(Sha256& hasher, const std::string_view value) {
    const auto size = static_cast<std::uint64_t>(value.size());
    std::array<unsigned char, 8U> length{};
    for (std::size_t index = 0U; index < length.size(); ++index) {
        length[index] = static_cast<unsigned char>(
            size >> (56U - index * 8U));
    }
    hasher.update(
        reinterpret_cast<const char*>(length.data()), length.size());
    hasher.update(value.data(), value.size());
}

void update_number(Sha256& hasher, const std::uint64_t value) {
    update_field(hasher, std::to_string(value));
}

void update_pair(Sha256& hasher,
                 const NdmsNativeDeleteObservationPair& pair) {
    update_field(hasher, pair.runtime_catalog_revision);
    update_number(hasher, pair.runtime_sequence);
    update_field(hasher, pair.running_config_catalog_revision);
    update_number(hasher, pair.running_config_sequence);
}

void update_optional_pair(
    Sha256& hasher,
    const std::optional<NdmsNativeDeleteObservationPair>& pair) {
    update_field(hasher, pair ? "present" : "absent");
    if (pair) update_pair(hasher, *pair);
}

void update_optional_string(
    Sha256& hasher,
    const std::optional<std::string>& value) {
    update_field(hasher, value ? "present" : "absent");
    if (value) update_field(hasher, *value);
}

bool structurally_valid(
    const NdmsNativeDeleteWalRecord& record) noexcept {
    try {
        if (record.schema_version != kNdmsNativeDeleteWalSchemaVersion ||
            !valid_ndms_native_import_transaction_id(
                record.transaction_id) ||
            !ndms_native_created_target_is_eligible(
                record.interface_name) ||
            !known_kind(record.kind) ||
            (!revision(record.ownership_revision,
                       kOwnershipRevisionPrefix) &&
             !revision(record.ownership_revision,
                       kOwnershipRevisionV3Prefix)) ||
            !valid_ndms_native_import_transaction_id(
                record.ownership_transaction_id) ||
            !valid_ndms_native_import_marker(
                record.marker, record.ownership_transaction_id) ||
            !revision(record.snapshot_revision,
                      kSnapshotRevisionPrefix) ||
            !revision(record.target_full_revision,
                      kTargetFullRevisionPrefix) ||
            !revision(record.keen_pbr_dependency_revision,
                      kNdmsNativeDeleteDependencyRevisionPrefix) ||
            !valid_ndms_native_delete_observation_pair(
                record.preflight_observations) ||
            !valid_ndms_native_observation_binding(
                record.observation_binding) ||
            record.observation_binding.baseline_sequence !=
                record.preflight_observations.
                    running_config_sequence ||
            !record.owner_global_save_acknowledged ||
            !record.external_writer_race_accepted) {
            return false;
        }

        const auto pair_after = [](const auto& pair,
                                   const std::uint64_t sequence) {
            return valid_ndms_native_delete_observation_pair(pair) &&
                   pair.runtime_sequence > sequence;
        };
        if (record.delete_absence_observations &&
            !pair_after(*record.delete_absence_observations,
                        record.observation_binding.baseline_sequence)) {
            return false;
        }
        if (record.post_save_absence_observations &&
            (!record.delete_absence_observations ||
             !pair_after(
                 *record.post_save_absence_observations,
                 record.delete_absence_observations->
                     running_config_sequence))) {
            return false;
        }
        if (record.tombstone_revision &&
            !revision(*record.tombstone_revision,
                      kNdmsNativeOwnershipTombstoneRevisionPrefix)) {
            return false;
        }

        switch (record.phase) {
        case NdmsNativeDeleteWalPhase::prepared:
        case NdmsNativeDeleteWalPhase::delete_may_be_inflight:
            return !record.delete_absence_observations &&
                   !record.post_save_absence_observations &&
                   !record.tombstone_revision;
        case NdmsNativeDeleteWalPhase::running_absence_verified:
        case NdmsNativeDeleteWalPhase::save_may_be_inflight:
            return record.delete_absence_observations.has_value() &&
                   !record.post_save_absence_observations &&
                   !record.tombstone_revision;
        case NdmsNativeDeleteWalPhase::save_acknowledged_unverified:
            return record.delete_absence_observations.has_value() &&
                   record.post_save_absence_observations.has_value() &&
                   !record.tombstone_revision;
        case NdmsNativeDeleteWalPhase::cleanup:
            return record.delete_absence_observations.has_value() &&
                   record.post_save_absence_observations.has_value() &&
                   record.tombstone_revision.has_value();
        }
    } catch (...) {
    }
    return false;
}

nlohmann::json pair_json(
    const NdmsNativeDeleteObservationPair& pair) {
    return nlohmann::json{
        {"runtime_catalog_revision", pair.runtime_catalog_revision},
        {"runtime_sequence", pair.runtime_sequence},
        {"running_config_catalog_revision",
         pair.running_config_catalog_revision},
        {"running_config_sequence", pair.running_config_sequence},
    };
}

nlohmann::json optional_pair_json(
    const std::optional<NdmsNativeDeleteObservationPair>& pair) {
    return pair ? pair_json(*pair) : nlohmann::json(nullptr);
}

nlohmann::json optional_string_json(
    const std::optional<std::string>& value) {
    return value ? nlohmann::json(*value) : nlohmann::json(nullptr);
}

nlohmann::json record_json(const NdmsNativeDeleteWalRecord& record) {
    return nlohmann::json{
        {"schema_version", record.schema_version},
        {"transaction_id", record.transaction_id},
        {"phase", ndms_native_delete_wal_phase_name(record.phase)},
        {"interface_name", record.interface_name},
        {"kind", kind_name(record.kind)},
        {"ownership_revision", record.ownership_revision},
        {"ownership_transaction_id", record.ownership_transaction_id},
        {"marker", record.marker},
        {"snapshot_revision", record.snapshot_revision},
        {"target_full_revision", record.target_full_revision},
        {"keen_pbr_dependency_revision",
         record.keen_pbr_dependency_revision},
        {"preflight_observations",
         pair_json(record.preflight_observations)},
        {"observation_binding",
         {{"authority_id", record.observation_binding.authority_id},
          {"mutation_epoch", record.observation_binding.mutation_epoch},
          {"baseline_sequence",
           record.observation_binding.baseline_sequence}}},
        {"owner_global_save_acknowledged",
         record.owner_global_save_acknowledged},
        {"external_writer_race_accepted",
         record.external_writer_race_accepted},
        {"delete_absence_observations",
         optional_pair_json(record.delete_absence_observations)},
        {"post_save_absence_observations",
         optional_pair_json(record.post_save_absence_observations)},
        {"tombstone_revision",
         optional_string_json(record.tombstone_revision)},
        {"integrity", record.integrity},
    };
}

void require_exact_keys(
    const nlohmann::json& value,
    const std::set<std::string>& expected,
    const char* what) {
    if (!value.is_object() || value.size() != expected.size()) {
        throw NdmsNativeDeleteWalError(
            std::string("native delete WAL ") + what +
            " has an invalid shape");
    }
    for (auto item = value.begin(); item != value.end(); ++item) {
        if (expected.find(item.key()) == expected.end()) {
            throw NdmsNativeDeleteWalError(
                std::string("native delete WAL ") + what +
                " has an unknown field");
        }
    }
}

NdmsNativeDeleteObservationPair parse_pair(
    const nlohmann::json& value) {
    require_exact_keys(
        value,
        {"runtime_catalog_revision", "runtime_sequence",
         "running_config_catalog_revision", "running_config_sequence"},
        "observation pair");
    NdmsNativeDeleteObservationPair pair;
    pair.runtime_catalog_revision =
        value.at("runtime_catalog_revision").get<std::string>();
    pair.runtime_sequence =
        value.at("runtime_sequence").get<std::uint64_t>();
    pair.running_config_catalog_revision =
        value.at("running_config_catalog_revision").get<std::string>();
    pair.running_config_sequence =
        value.at("running_config_sequence").get<std::uint64_t>();
    return pair;
}

std::optional<NdmsNativeDeleteObservationPair> parse_optional_pair(
    const nlohmann::json& value) {
    if (value.is_null()) return std::nullopt;
    return parse_pair(value);
}

std::optional<std::string> parse_optional_string(
    const nlohmann::json& value) {
    if (value.is_null()) return std::nullopt;
    return value.get<std::string>();
}

} // namespace

bool NdmsNativeDeleteObservationPair::operator==(
    const NdmsNativeDeleteObservationPair& other) const noexcept {
    return runtime_catalog_revision == other.runtime_catalog_revision &&
           runtime_sequence == other.runtime_sequence &&
           running_config_catalog_revision ==
               other.running_config_catalog_revision &&
           running_config_sequence == other.running_config_sequence;
}

bool NdmsNativeDeleteWalRecord::operator==(
    const NdmsNativeDeleteWalRecord& other) const noexcept {
    return schema_version == other.schema_version &&
           transaction_id == other.transaction_id &&
           phase == other.phase &&
           interface_name == other.interface_name && kind == other.kind &&
           ownership_revision == other.ownership_revision &&
           ownership_transaction_id == other.ownership_transaction_id &&
           marker == other.marker &&
           snapshot_revision == other.snapshot_revision &&
           target_full_revision == other.target_full_revision &&
           keen_pbr_dependency_revision ==
               other.keen_pbr_dependency_revision &&
           preflight_observations == other.preflight_observations &&
           observation_binding == other.observation_binding &&
           owner_global_save_acknowledged ==
               other.owner_global_save_acknowledged &&
           external_writer_race_accepted ==
               other.external_writer_race_accepted &&
           delete_absence_observations ==
               other.delete_absence_observations &&
           post_save_absence_observations ==
               other.post_save_absence_observations &&
           tombstone_revision == other.tombstone_revision &&
           integrity == other.integrity;
}

bool valid_ndms_native_delete_observation_pair(
    const NdmsNativeDeleteObservationPair& pair) noexcept {
    return valid_ndms_native_observation_catalog_revision(
               pair.runtime_catalog_revision) &&
           pair.runtime_sequence != 0U &&
           valid_ndms_native_observation_catalog_revision(
               pair.running_config_catalog_revision) &&
           pair.running_config_sequence > pair.runtime_sequence;
}

bool valid_ndms_native_delete_wal_record(
    const NdmsNativeDeleteWalRecord& record) noexcept {
    if (!structurally_valid(record)) return false;
    try {
        return record.integrity == ndms_native_delete_wal_integrity(record);
    } catch (...) {
        return false;
    }
}

bool valid_ndms_native_delete_wal_transition(
    const NdmsNativeDeleteWalPhase before,
    const NdmsNativeDeleteWalPhase after) noexcept {
    switch (before) {
    case NdmsNativeDeleteWalPhase::prepared:
        return after ==
               NdmsNativeDeleteWalPhase::delete_may_be_inflight;
    case NdmsNativeDeleteWalPhase::delete_may_be_inflight:
        return after ==
               NdmsNativeDeleteWalPhase::running_absence_verified;
    case NdmsNativeDeleteWalPhase::running_absence_verified:
        return after == NdmsNativeDeleteWalPhase::save_may_be_inflight;
    case NdmsNativeDeleteWalPhase::save_may_be_inflight:
        return after ==
               NdmsNativeDeleteWalPhase::save_acknowledged_unverified;
    case NdmsNativeDeleteWalPhase::save_acknowledged_unverified:
        return after == NdmsNativeDeleteWalPhase::cleanup;
    case NdmsNativeDeleteWalPhase::cleanup:
        return false;
    }
    return false;
}

std::string ndms_native_delete_wal_integrity(
    const NdmsNativeDeleteWalRecord& record) {
    if (!structurally_valid(record)) {
        throw NdmsNativeDeleteWalError(
            "native delete WAL cannot be integrity-bound");
    }
    Sha256 hasher;
    update_field(hasher, "keen-pbr.ndms-native-delete-wal.integrity.v1");
    update_number(hasher, record.schema_version);
    update_field(hasher, record.transaction_id);
    update_field(hasher, ndms_native_delete_wal_phase_name(record.phase));
    update_field(hasher, record.interface_name);
    update_field(hasher, kind_name(record.kind));
    update_field(hasher, record.ownership_revision);
    update_field(hasher, record.ownership_transaction_id);
    update_field(hasher, record.marker);
    update_field(hasher, record.snapshot_revision);
    update_field(hasher, record.target_full_revision);
    update_field(hasher, record.keen_pbr_dependency_revision);
    update_pair(hasher, record.preflight_observations);
    update_field(hasher, record.observation_binding.authority_id);
    update_number(hasher, record.observation_binding.mutation_epoch);
    update_number(hasher, record.observation_binding.baseline_sequence);
    update_field(
        hasher,
        record.owner_global_save_acknowledged ? "true" : "false");
    update_field(
        hasher,
        record.external_writer_race_accepted ? "true" : "false");
    update_optional_pair(hasher, record.delete_absence_observations);
    update_optional_pair(hasher, record.post_save_absence_observations);
    update_optional_string(hasher, record.tombstone_revision);
    return std::string{kIntegrityPrefix} + hasher.hex_digest();
}

std::string serialize_ndms_native_delete_wal(
    const NdmsNativeDeleteWalRecord& record) {
    if (!valid_ndms_native_delete_wal_record(record)) {
        throw NdmsNativeDeleteWalError(
            "native delete WAL record is invalid");
    }
    const auto serialized = record_json(record).dump();
    if (serialized.size() > kNdmsNativeDeleteWalMaximumBytes) {
        throw NdmsNativeDeleteWalError(
            "native delete WAL record exceeds its byte bound");
    }
    return serialized;
}

NdmsNativeDeleteWalRecord parse_ndms_native_delete_wal(
    const std::string_view serialized) {
    if (serialized.empty() ||
        serialized.size() > kNdmsNativeDeleteWalMaximumBytes) {
        throw NdmsNativeDeleteWalError(
            "native delete WAL serialized size is invalid");
    }
    try {
        const auto document = nlohmann::json::parse(
            serialized.begin(), serialized.end());
        require_exact_keys(
            document,
            {"schema_version", "transaction_id", "phase",
             "interface_name", "kind", "ownership_revision",
             "ownership_transaction_id", "marker", "snapshot_revision",
             "target_full_revision", "keen_pbr_dependency_revision",
             "preflight_observations", "observation_binding",
             "owner_global_save_acknowledged",
             "external_writer_race_accepted",
             "delete_absence_observations",
             "post_save_absence_observations", "tombstone_revision",
             "integrity"},
            "record");
        require_exact_keys(
            document.at("observation_binding"),
            {"authority_id", "mutation_epoch", "baseline_sequence"},
            "observation binding");

        NdmsNativeDeleteWalRecord record;
        record.schema_version =
            document.at("schema_version").get<std::uint32_t>();
        record.transaction_id =
            document.at("transaction_id").get<std::string>();
        record.phase = parse_phase(
            document.at("phase").get<std::string>());
        record.interface_name =
            document.at("interface_name").get<std::string>();
        record.kind = parse_kind(document.at("kind").get<std::string>());
        record.ownership_revision =
            document.at("ownership_revision").get<std::string>();
        record.ownership_transaction_id =
            document.at("ownership_transaction_id").get<std::string>();
        record.marker = document.at("marker").get<std::string>();
        record.snapshot_revision =
            document.at("snapshot_revision").get<std::string>();
        record.target_full_revision =
            document.at("target_full_revision").get<std::string>();
        record.keen_pbr_dependency_revision =
            document.at("keen_pbr_dependency_revision")
                .get<std::string>();
        record.preflight_observations =
            parse_pair(document.at("preflight_observations"));
        const auto& binding = document.at("observation_binding");
        record.observation_binding.authority_id =
            binding.at("authority_id").get<std::string>();
        record.observation_binding.mutation_epoch =
            binding.at("mutation_epoch").get<std::uint64_t>();
        record.observation_binding.baseline_sequence =
            binding.at("baseline_sequence").get<std::uint64_t>();
        record.owner_global_save_acknowledged =
            document.at("owner_global_save_acknowledged").get<bool>();
        record.external_writer_race_accepted =
            document.at("external_writer_race_accepted").get<bool>();
        record.delete_absence_observations = parse_optional_pair(
            document.at("delete_absence_observations"));
        record.post_save_absence_observations = parse_optional_pair(
            document.at("post_save_absence_observations"));
        record.tombstone_revision = parse_optional_string(
            document.at("tombstone_revision"));
        record.integrity =
            document.at("integrity").get<std::string>();
        if (!valid_ndms_native_delete_wal_record(record)) {
            throw NdmsNativeDeleteWalError(
                "native delete WAL validation failed");
        }
        return record;
    } catch (const NdmsNativeDeleteWalError&) {
        throw;
    } catch (...) {
        throw NdmsNativeDeleteWalError(
            "native delete WAL parsing failed");
    }
}

const char* ndms_native_delete_wal_phase_name(
    const NdmsNativeDeleteWalPhase phase) noexcept {
    switch (phase) {
    case NdmsNativeDeleteWalPhase::prepared:
        return "prepared";
    case NdmsNativeDeleteWalPhase::delete_may_be_inflight:
        return "delete_may_be_inflight";
    case NdmsNativeDeleteWalPhase::running_absence_verified:
        return "running_absence_verified";
    case NdmsNativeDeleteWalPhase::save_may_be_inflight:
        return "save_may_be_inflight";
    case NdmsNativeDeleteWalPhase::save_acknowledged_unverified:
        return "save_acknowledged_unverified";
    case NdmsNativeDeleteWalPhase::cleanup:
        return "cleanup";
    }
    return "unknown";
}

} // namespace keen_pbr3
