#pragma once

#include "ndms_native_writer_lease.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>

#ifdef KEEN_PBR3_TESTING
#include <functional>
#endif

namespace keen_pbr3 {

inline constexpr char kNdmsNativeObservationStateFilename[] =
    "observation.state";
inline constexpr char kNdmsNativeObservationCatalogRevisionPrefix[] =
    "ndms-native-catalog-v1-";
inline constexpr char kNdmsNativeObservationIntegrityPrefix[] =
    "ndms-native-observation-integrity-v1-";

class NdmsNativeObservationStoreError final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Restart-stable identity of the observation authority. Sequence is global
// within that authority; mutation_epoch advances durably before any mutation
// intent can be dispatched. A newly provisioned ledger starts at zero/zero
// and cannot begin a mutation until a baseline observation has been recorded.
struct NdmsNativeObservationLedger final {
    std::string authority_id;
    std::uint64_t sequence{0U};
    std::uint64_t mutation_epoch{0U};
    std::optional<std::string> last_catalog_revision;
    std::string integrity;

    bool operator==(
        const NdmsNativeObservationLedger& other) const noexcept;
};

enum class NdmsNativeObservationReadState : std::uint8_t {
    absent,
    valid,
    unreadable,
};

struct NdmsNativeObservationReadResult final {
    NdmsNativeObservationReadState state{
        NdmsNativeObservationReadState::unreadable};
    std::optional<NdmsNativeObservationLedger> ledger;
};

// Returned only after a complete catalog observation was durably sequenced.
// It is evidence, not a mutation credential; the writer lease remains the
// authority at every write boundary.
struct NdmsNativeObservationStamp final {
    std::string authority_id;
    std::uint64_t sequence{0U};
    std::uint64_t mutation_epoch{0U};
    std::string catalog_revision;
    std::string ledger_integrity;
};

// Durable hand-off from the baseline world into the mutation world. Recovery
// accepts observations only when authority_id matches, sequence advances past
// baseline_sequence, and the ledger still carries this exact mutation_epoch.
struct NdmsNativeMutationEpoch final {
    std::string authority_id;
    std::uint64_t baseline_sequence{0U};
    std::uint64_t mutation_epoch{0U};
    std::string baseline_catalog_revision;
    std::string ledger_integrity;
};

// Minimal non-secret WAL binding. The WAL persists this triple; recovery then
// joins it to the durable ledger and requires observations with the same
// authority/epoch and sequence strictly greater than baseline_sequence.
struct NdmsNativeObservationBinding final {
    std::string authority_id;
    std::uint64_t mutation_epoch{0U};
    std::uint64_t baseline_sequence{0U};

    bool operator==(
        const NdmsNativeObservationBinding& other) const noexcept;
};

#ifdef KEEN_PBR3_TESTING
enum class NdmsNativeObservationStoreFaultStage : std::uint8_t {
    after_temporary_file_fsync,
    after_initial_link_before_temporary_unlink,
    after_replace_rename_before_directory_fsync,
    after_directory_fsync,
};

struct NdmsNativeObservationStoreTestHooks final {
    bool allow_current_process_owner{false};
    std::function<std::string()> authority_id_factory;
    std::function<void(NdmsNativeObservationStoreFaultStage)>
        fault_injector;
};
#endif

// Single-file, owner-only durable observation ledger. Every update is written
// through an O_EXCL temporary, fsync'd, atomically published and followed by a
// directory fsync. All mutation methods require the same cooperative writer
// lease and operate through its already validated directory descriptor.
class NdmsNativeObservationStore final {
public:
    explicit NdmsNativeObservationStore(
        std::filesystem::path state_directory);
#ifdef KEEN_PBR3_TESTING
    NdmsNativeObservationStore(
        std::filesystem::path state_directory,
        NdmsNativeObservationStoreTestHooks hooks);
#endif

    NdmsNativeObservationReadResult read() const noexcept;

    // Idempotently creates the zero/zero authority. Existing valid state is
    // returned unchanged; existing unreadable state is never regenerated.
    NdmsNativeObservationLedger provision(
        NdmsNativeWriterLease& writer);

    // Sequences one complete direct catalog read in the current epoch.
    NdmsNativeObservationStamp record_observation(
        NdmsNativeWriterLease& writer,
        std::string catalog_revision);

    // CASes the exact baseline stamp and persists epoch+1 before returning.
    NdmsNativeMutationEpoch begin_mutation(
        NdmsNativeWriterLease& writer,
        const NdmsNativeObservationStamp& baseline);

    // Sequences a recovery/post-mutation observation only while the same
    // durable authority and mutation epoch still stand.
    NdmsNativeObservationStamp record_mutation_observation(
        NdmsNativeWriterLease& writer,
        const NdmsNativeMutationEpoch& mutation,
        std::string catalog_revision);

    // Restart-safe issuer boundary for an integrity-validated WAL record.
    // The binding must still name the ledger's exact authority and current
    // mutation epoch, and the ledger sequence may never be behind its durable
    // baseline. Callers must invoke this only after one complete direct read.
    NdmsNativeObservationStamp record_recovery_observation(
        NdmsNativeWriterLease& writer,
        const NdmsNativeObservationBinding& wal_binding,
        std::string catalog_revision);

    const std::filesystem::path& state_directory() const noexcept;

private:
    void verify_writer(NdmsNativeWriterLease& writer) const;

    std::filesystem::path state_directory_;
#ifdef KEEN_PBR3_TESTING
    NdmsNativeObservationStoreTestHooks test_hooks_;
#endif
};

bool valid_ndms_native_observation_catalog_revision(
    const std::string& revision) noexcept;
// Verifies the complete self-contained durable stamp, including the ledger
// integrity over authority, sequence, epoch and catalog revision. This is a
// corruption/mix-up check, not a replacement for matching a WAL binding.
bool valid_ndms_native_observation_stamp(
    const NdmsNativeObservationStamp& stamp) noexcept;
bool valid_ndms_native_observation_binding(
    const NdmsNativeObservationBinding& binding) noexcept;
NdmsNativeObservationBinding ndms_native_observation_binding(
    const NdmsNativeMutationEpoch& mutation);
std::string ndms_native_observation_integrity(
    const NdmsNativeObservationLedger& ledger);
const char* ndms_native_observation_read_state_name(
    NdmsNativeObservationReadState state) noexcept;

} // namespace keen_pbr3
