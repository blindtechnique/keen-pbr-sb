#pragma once

#include "../runtime/runtime_mutation_admission.hpp"
#include "../update/maintenance_lock.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>

namespace keen_pbr3 {

class NdmsNativeObservationStore;
struct NdmsNativeWriterAdmission;

// This name is deliberately narrower than "global NDMS". The lease excludes
// every cooperating keen-pbr process and every in-process runtime writer, but
// Keenetic's Web UI, ndmc and third-party managers do not participate in this
// protocol. It therefore cannot by itself issue an allocator-fence receipt.
enum class NdmsNativeWriterLeaseScope : std::uint8_t {
    keen_pbr_cooperative,
};

enum class NdmsNativeWriterAdmissionState : std::uint8_t {
    admitted,
    outer_guard_missing,
    outer_guard_lost,
    state_directory_unsafe,
    lease_busy,
    lease_io_error,
};

#ifdef KEEN_PBR3_TESTING
struct NdmsNativeWriterLeaseTestHooks final {
    // Production requires root:root. Unit tests may instead pin the exact
    // owner/group to the current process while retaining 0700/0600 checks.
    bool allow_current_process_owner{false};
};
#endif

// RAII composition of the established lock order:
//
//   MaintenanceCoordinator -> RuntimeMutationAdmission -> native flock
//
// The first two move-only guards are acquired by the caller in that order and
// handed in. This type never acquires either outer lock, so it cannot create a
// reverse-order entrance. Destruction releases the native flock first, then
// runtime admission, then maintenance.
class NdmsNativeWriterLease final {
public:
    NdmsNativeWriterLease(NdmsNativeWriterLease&& other) noexcept;
    NdmsNativeWriterLease& operator=(
        NdmsNativeWriterLease&& other) noexcept;
    NdmsNativeWriterLease(const NdmsNativeWriterLease&) = delete;
    NdmsNativeWriterLease& operator=(const NdmsNativeWriterLease&) = delete;
    ~NdmsNativeWriterLease() noexcept;

    bool held() const noexcept;
    NdmsNativeWriterLeaseScope scope() const noexcept;
    std::uint32_t maintenance_base_generation() const noexcept;
    // Delegates the existing exact-next generation CAS without exposing the
    // raw maintenance capability. The complete composite lease is verified
    // first; MaintenanceLease::reserve performs its own final ownership/CAS
    // check immediately before publishing expected + 1.
    std::uint32_t reserve_maintenance_generation(
        std::uint32_t expected_generation);
    std::uint64_t runtime_token() const noexcept;
    const std::filesystem::path& state_directory() const noexcept;

    // Revalidates both outer guards and the descriptor/path identity of the
    // owner-only lock immediately before an irreversible RCI dispatch.
    void verify_held();

private:
    NdmsNativeWriterLease() = default;
    NdmsNativeWriterLease(
        std::filesystem::path state_directory,
        std::unique_ptr<MaintenanceLease> maintenance,
        RuntimeMutationAdmission::Lease runtime,
        int directory_descriptor,
        int lock_descriptor,
        std::uint32_t owner,
        std::uint32_t group) noexcept;

    static NdmsNativeWriterAdmission admit_with_policy(
        std::filesystem::path state_directory,
        std::unique_ptr<MaintenanceLease> maintenance,
        RuntimeMutationAdmission::Lease runtime,
        std::uint32_t owner,
        std::uint32_t group,
        bool require_root_process);

    void release_native_noexcept() noexcept;

    // Declaration order is intentional. After the destructor body closes the
    // native descriptors, members unwind in reverse: runtime, then maintenance.
    std::unique_ptr<MaintenanceLease> maintenance_;
    RuntimeMutationAdmission::Lease runtime_;
    std::filesystem::path state_directory_;
    int directory_descriptor_{-1};
    int lock_descriptor_{-1};
    std::uint32_t owner_{0U};
    std::uint32_t group_{0U};

    friend struct NdmsNativeWriterAdmission;
    friend NdmsNativeWriterAdmission admit_ndms_native_writer(
        std::filesystem::path,
        std::unique_ptr<MaintenanceLease>,
        RuntimeMutationAdmission::Lease);
#ifdef KEEN_PBR3_TESTING
    friend NdmsNativeWriterAdmission admit_ndms_native_writer(
        std::filesystem::path,
        std::unique_ptr<MaintenanceLease>,
        RuntimeMutationAdmission::Lease,
        NdmsNativeWriterLeaseTestHooks);
#endif
    friend class NdmsNativeObservationStore;
};

struct NdmsNativeWriterAdmission final {
    NdmsNativeWriterAdmissionState state{
        NdmsNativeWriterAdmissionState::lease_io_error};
    NdmsNativeWriterLease lease;
};

// The arguments encode the lock order: callers must already own maintenance
// and then runtime admission. On every refusal both are released by RAII.
NdmsNativeWriterAdmission admit_ndms_native_writer(
    std::filesystem::path state_directory,
    std::unique_ptr<MaintenanceLease> maintenance,
    RuntimeMutationAdmission::Lease runtime);

#ifdef KEEN_PBR3_TESTING
NdmsNativeWriterAdmission admit_ndms_native_writer(
    std::filesystem::path state_directory,
    std::unique_ptr<MaintenanceLease> maintenance,
    RuntimeMutationAdmission::Lease runtime,
    NdmsNativeWriterLeaseTestHooks hooks);
#endif

const char* ndms_native_writer_lease_scope_name(
    NdmsNativeWriterLeaseScope scope) noexcept;
const char* ndms_native_writer_admission_state_name(
    NdmsNativeWriterAdmissionState state) noexcept;

} // namespace keen_pbr3
