#pragma once

#include "ndms_native_create_policy.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace keen_pbr3 {

// A receipt may be issued only by a provider that can prove one of these
// pre-dispatch exclusion properties. Observing a successful import afterwards
// is deliberately not a fourth mode.
enum class NdmsNativeAllocatorFenceMode : std::uint8_t {
    bounded_atomic_import,
    exact_create_if_absent,
    global_ndms_writer_lease,
};

enum class NdmsNativeAllocatorFenceAvailability : std::uint8_t {
    // The measured KeeneticOS 5.1.1 surface exposes neither a bounded allocator,
    // an atomic create-if-absent primitive, nor a global NDMS writer lease.
    unavailable_on_keeneticos_5_1_1,
};

enum class NdmsNativeAllocatorFenceValidationError : std::uint8_t {
    none,
    required_range_invalid,
    receipt_range_invalid,
    mode_invalid,
    mode_mismatch,
    exact_target_required,
    exact_target_invalid,
    exact_target_mismatch,
    firmware_identity_invalid,
    firmware_identity_mismatch,
    implementation_digest_invalid,
    implementation_digest_mismatch,
    request_binding_digest_invalid,
    request_binding_digest_mismatch,
    generation_ticket_invalid,
    generation_ticket_mismatch,
    generation_invalid,
    generation_mismatch,
    lifetime_invalid,
    minimum_remaining_invalid,
    not_yet_valid,
    expired,
    minimum_remaining_insufficient,
};

using NdmsNativeAllocatorMonotonicClock = std::chrono::steady_clock;
using NdmsNativeAllocatorMonotonicTime =
    NdmsNativeAllocatorMonotonicClock::time_point;
using NdmsNativeAllocatorMonotonicDuration =
    NdmsNativeAllocatorMonotonicClock::duration;

constexpr std::uint8_t kNdmsNativeAllocatorFirstManagedSlot = 5U;
constexpr std::uint8_t kNdmsNativeAllocatorLastManagedSlot = 98U;
constexpr auto kNdmsNativeAllocatorMaximumReceiptLifetime =
    std::chrono::seconds{30};

inline constexpr char kNdmsNativeAllocatorImplementationDigestPrefix[] =
    "ndms-allocator-implementation-v1-";
inline constexpr char kNdmsNativeAllocatorRequestBindingDigestPrefix[] =
    "ndms-import-request-binding-v1-";
inline constexpr char kNdmsNativeAllocatorGenerationTicketPrefix[] =
    "ndms-create-ticket-v1-";
inline constexpr char kNdmsNativeAllocatorKeeneticOs511FirmwareIdentity[] =
    "KeeneticOS-5.1.1";

constexpr NdmsNativeWireguardTargetRange
ndms_native_allocator_required_range() noexcept {
    return {
        kNdmsNativeAllocatorFirstManagedSlot,
        kNdmsNativeAllocatorLastManagedSlot,
    };
}

// Authoritative values supplied by the future executor at the moment it asks
// whether a receipt still covers a mutation. There is intentionally no caller
// boolean such as `locked`, `atomic` or `safe` in this contract.
struct NdmsNativeAllocatorFenceExpectation {
    NdmsNativeAllocatorFenceMode mode{
        NdmsNativeAllocatorFenceMode::bounded_atomic_import};
    NdmsNativeWireguardTargetRange range{
        ndms_native_allocator_required_range()};
    std::string firmware_identity;
    std::string implementation_digest;
    // Digest of the exact canonical request bytes computed by the executor.
    // The fence validates only this domain-separated value and never handles
    // or serializes the potentially secret request itself.
    std::string request_binding_digest;
    std::string generation_ticket;
    // Optional pre-dispatch binding for bounded import/global-lease modes.
    // Exact-create-if-absent always requires it. A target learned from the
    // response is too late and cannot be retrofitted into a receipt.
    std::optional<std::string> exact_target;
    std::uint64_t current_generation{0U};
    NdmsNativeAllocatorMonotonicTime now;
    // The receipt must remain valid for the caller's complete bounded
    // dispatch window, not merely at the instant of this check.
    NdmsNativeAllocatorMonotonicDuration minimum_remaining{};
};

struct NdmsNativeAllocatorFenceValidation;

#ifdef KEEN_PBR3_TESTING
struct NdmsNativeAllocatorFenceTestFields;
class NdmsNativeAllocatorFenceTestIssuer;
#endif

// Move-only and non-default-constructible. Production callers can retain or
// consume a receipt, but cannot manufacture one from public fields. The
// current 5.1.1 provider below never constructs this type at all.
class NdmsNativeAllocatorFenceReceipt final {
public:
    NdmsNativeAllocatorFenceReceipt(
        NdmsNativeAllocatorFenceReceipt&& other) noexcept;
    NdmsNativeAllocatorFenceReceipt& operator=(
        NdmsNativeAllocatorFenceReceipt&& other) noexcept;
    NdmsNativeAllocatorFenceReceipt(
        const NdmsNativeAllocatorFenceReceipt&) = delete;
    NdmsNativeAllocatorFenceReceipt& operator=(
        const NdmsNativeAllocatorFenceReceipt&) = delete;
    ~NdmsNativeAllocatorFenceReceipt() = default;

private:
    struct ConstructionKey final {};

    NdmsNativeAllocatorFenceReceipt(
        ConstructionKey,
        NdmsNativeAllocatorFenceMode mode,
        NdmsNativeWireguardTargetRange range,
        std::string firmware_identity,
        std::string implementation_digest,
        std::string request_binding_digest,
        std::string generation_ticket,
        std::optional<std::string> exact_target,
        std::uint64_t generation,
        NdmsNativeAllocatorMonotonicTime issued_at,
        NdmsNativeAllocatorMonotonicTime expires_at);

    void poison_after_move() noexcept;

    NdmsNativeAllocatorFenceMode mode_;
    NdmsNativeWireguardTargetRange range_;
    std::string firmware_identity_;
    std::string implementation_digest_;
    std::string request_binding_digest_;
    std::string generation_ticket_;
    std::optional<std::string> exact_target_;
    std::uint64_t generation_{0U};
    NdmsNativeAllocatorMonotonicTime issued_at_;
    NdmsNativeAllocatorMonotonicTime expires_at_;

    friend struct NdmsNativeAllocatorFenceValidation;
    friend NdmsNativeAllocatorFenceValidation
    validate_ndms_native_allocator_fence(
        const NdmsNativeAllocatorFenceReceipt&,
        const NdmsNativeAllocatorFenceExpectation&) noexcept;
#ifdef KEEN_PBR3_TESTING
    friend class NdmsNativeAllocatorFenceTestIssuer;
#endif
};

struct NdmsNativeAllocatorFenceValidation final {
    NdmsNativeAllocatorFenceValidationError error{
        NdmsNativeAllocatorFenceValidationError::receipt_range_invalid};

    bool authorizes() const noexcept {
        return error == NdmsNativeAllocatorFenceValidationError::none;
    }
};

NdmsNativeAllocatorFenceValidation validate_ndms_native_allocator_fence(
    const NdmsNativeAllocatorFenceReceipt& receipt,
    const NdmsNativeAllocatorFenceExpectation& expectation) noexcept;

// Pure description of the measured current-firmware capability. No probing,
// locking, allocation or RCI I/O occurs in either method.
class NdmsNativeKeeneticOs511AllocatorFenceProvider final {
public:
    NdmsNativeAllocatorFenceAvailability availability() const noexcept;

    std::optional<NdmsNativeAllocatorFenceReceipt> try_acquire(
        const NdmsNativeAllocatorFenceExpectation& expectation) const noexcept;
};

const char* ndms_native_allocator_fence_mode_name(
    NdmsNativeAllocatorFenceMode mode) noexcept;
const char* ndms_native_allocator_fence_availability_name(
    NdmsNativeAllocatorFenceAvailability availability) noexcept;
const char* ndms_native_allocator_fence_validation_error_name(
    NdmsNativeAllocatorFenceValidationError error) noexcept;

#ifdef KEEN_PBR3_TESTING
// This surface is omitted from production builds. It exists only so tests can
// exercise fail-closed validation of receipts that no current provider can
// issue, including malformed fields and future-provider modes.
struct NdmsNativeAllocatorFenceTestFields final {
    NdmsNativeAllocatorFenceMode mode{
        NdmsNativeAllocatorFenceMode::bounded_atomic_import};
    NdmsNativeWireguardTargetRange range{
        ndms_native_allocator_required_range()};
    std::string firmware_identity;
    std::string implementation_digest;
    std::string request_binding_digest;
    std::string generation_ticket;
    std::optional<std::string> exact_target;
    std::uint64_t generation{0U};
    NdmsNativeAllocatorMonotonicTime issued_at;
    NdmsNativeAllocatorMonotonicTime expires_at;
};

class NdmsNativeAllocatorFenceTestIssuer final {
public:
    static NdmsNativeAllocatorFenceReceipt issue_unchecked(
        NdmsNativeAllocatorFenceTestFields fields);
};
#endif

} // namespace keen_pbr3
