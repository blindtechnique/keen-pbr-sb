#include "ndms_native_import_recovery_lease.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {

namespace {

// Beside the store, never inside it: an unknown name inside the store makes
// every inventory unsafe by design.
std::filesystem::path lease_path(const NdmsNativeImportWalStore& store) {
    auto path = store.state_directory();
    path += ".recovery-lock";
    return path;
}

} // namespace

NdmsNativeImportRecoveryLease::NdmsNativeImportRecoveryLease(
    const int descriptor) noexcept
    : descriptor_(descriptor) {}

NdmsNativeImportRecoveryLease::NdmsNativeImportRecoveryLease(
    NdmsNativeImportRecoveryLease&& other) noexcept
    : descriptor_(other.descriptor_) {
    other.descriptor_ = -1;
}

NdmsNativeImportRecoveryLease& NdmsNativeImportRecoveryLease::operator=(
    NdmsNativeImportRecoveryLease&& other) noexcept {
    if (this != &other) {
        if (descriptor_ >= 0) (void)::close(descriptor_);
        descriptor_ = other.descriptor_;
        other.descriptor_ = -1;
    }
    return *this;
}

NdmsNativeImportRecoveryLease::~NdmsNativeImportRecoveryLease() {
    // Closing the descriptor releases the kernel flock; a crashed holder
    // releases the same way, which is the reason flock and not a lock file's
    // existence carries the exclusivity.
    if (descriptor_ >= 0) (void)::close(descriptor_);
}

bool NdmsNativeImportRecoveryLease::held() const noexcept {
    return descriptor_ >= 0;
}

NdmsNativeImportRecoveryAdmission admit_ndms_native_import_recovery(
    const NdmsNativeImportWalStore& store,
    const NdmsNativeImportWalRecord& classified_record,
    const NdmsNativeImportRecoveryObservation& observation) {
    NdmsNativeImportRecoveryAdmission admission;

    const auto path = lease_path(store);
    const int descriptor = ::open(
        path.c_str(),
        O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
        S_IRUSR | S_IWUSR);
    if (descriptor < 0) {
        admission.state =
            NdmsNativeImportRecoveryAdmissionState::lease_io_error;
        return admission;
    }
    struct stat status {};
    if (::fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode)) {
        (void)::close(descriptor);
        admission.state =
            NdmsNativeImportRecoveryAdmissionState::lease_io_error;
        return admission;
    }
    if (::flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
        (void)::close(descriptor);
        // Never waited for: recovery that blocks on a peer deadlocks on a
        // stuck one. The caller retries on its own schedule.
        admission.state =
            NdmsNativeImportRecoveryAdmissionState::lease_busy;
        return admission;
    }
    NdmsNativeImportRecoveryLease lease(descriptor);

    // Everything below runs under the lease, and every refusal path returns
    // by value without moving the lease in - destruction releases it, so a
    // refused caller leaves no lock behind.
    const auto inventory = store.try_inventory();
    if (!inventory.recovery_permitted() || inventory.items.size() != 1U) {
        admission.state = NdmsNativeImportRecoveryAdmissionState::
            inventory_not_ready;
        return admission;
    }

    const auto loaded = store.load(classified_record.transaction_id);
    if (!loaded.recovery_permitted()) {
        admission.state =
            NdmsNativeImportRecoveryAdmissionState::record_missing;
        return admission;
    }
    // The compare-and-swap half. A classification is a statement about one
    // exact record; a record that was advanced since - a phase written, a
    // response recorded - makes that statement about something that no longer
    // exists, however same-named it is.
    if (!(*loaded.record == classified_record)) {
        admission.state =
            NdmsNativeImportRecoveryAdmissionState::record_changed;
        return admission;
    }

    // Re-derived from the re-read record under the lease, never carried over
    // from the caller's earlier call - so the action the lease authorizes is
    // provably about the bytes the store holds right now.
    const auto action =
        classify_ndms_native_import_recovery(*loaded.record, observation);
    if (action == NdmsNativeImportRecoveryAction::
                      retry_read_only_observation ||
        action == NdmsNativeImportRecoveryAction::block_unknown) {
        admission.state = NdmsNativeImportRecoveryAdmissionState::
            action_not_actionable;
        return admission;
    }

    admission.state = NdmsNativeImportRecoveryAdmissionState::admitted;
    admission.action = action;
    admission.lease = std::move(lease);
    return admission;
}

const char* ndms_native_import_recovery_admission_state_name(
    const NdmsNativeImportRecoveryAdmissionState state) noexcept {
    switch (state) {
    case NdmsNativeImportRecoveryAdmissionState::admitted:
        return "admitted";
    case NdmsNativeImportRecoveryAdmissionState::lease_busy:
        return "lease_busy";
    case NdmsNativeImportRecoveryAdmissionState::lease_io_error:
        return "lease_io_error";
    case NdmsNativeImportRecoveryAdmissionState::inventory_not_ready:
        return "inventory_not_ready";
    case NdmsNativeImportRecoveryAdmissionState::record_missing:
        return "record_missing";
    case NdmsNativeImportRecoveryAdmissionState::record_changed:
        return "record_changed";
    case NdmsNativeImportRecoveryAdmissionState::action_not_actionable:
        return "action_not_actionable";
    }
    return "lease_io_error";
}

} // namespace keen_pbr3
