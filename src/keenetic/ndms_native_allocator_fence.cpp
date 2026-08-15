#include "ndms_native_allocator_fence.hpp"

#include "ndms_wireguard_identity.hpp"

#include <algorithm>
#include <cstddef>
#include <string_view>
#include <utility>

namespace keen_pbr3 {

namespace {

constexpr std::size_t kMaximumFirmwareIdentityBytes = 96U;

bool required_range(
    const NdmsNativeWireguardTargetRange& range) noexcept {
    return range == ndms_native_allocator_required_range();
}

bool valid_mode(const NdmsNativeAllocatorFenceMode mode) noexcept {
    switch (mode) {
    case NdmsNativeAllocatorFenceMode::bounded_atomic_import:
    case NdmsNativeAllocatorFenceMode::exact_create_if_absent:
    case NdmsNativeAllocatorFenceMode::global_ndms_writer_lease:
        return true;
    }
    return false;
}

bool has_prefix(const std::string& value,
                const std::string_view prefix) noexcept {
    return value.size() >= prefix.size() &&
           std::equal(prefix.begin(), prefix.end(), value.begin());
}

bool lowercase_hex_digest(const std::string& value,
                          const std::string_view prefix) noexcept {
    if (value.size() != prefix.size() + 64U ||
        !has_prefix(value, prefix)) {
        return false;
    }
    return std::all_of(
        value.begin() + static_cast<std::ptrdiff_t>(prefix.size()),
        value.end(),
        [](const unsigned char character) {
            return (character >= '0' && character <= '9') ||
                   (character >= 'a' && character <= 'f');
        });
}

bool valid_firmware_identity(const std::string& value) noexcept {
    if (value.empty() || value.size() > kMaximumFirmwareIdentityBytes) {
        return false;
    }
    return std::all_of(
        value.begin(), value.end(), [](const unsigned char character) {
            return (character >= 'a' && character <= 'z') ||
                   (character >= 'A' && character <= 'Z') ||
                   (character >= '0' && character <= '9') ||
                   character == '.' || character == '-' ||
                   character == '_' || character == '+';
        });
}

bool valid_exact_target(
    const std::optional<std::string>& target) noexcept {
    if (!target) return true;
    const auto identity = parse_ndms_wireguard_identity(*target);
    return identity.has_value() &&
           ndms_wireguard_identity_is_managed_candidate(*identity) &&
           identity->slot >= kNdmsNativeAllocatorFirstManagedSlot &&
           identity->slot <= kNdmsNativeAllocatorLastManagedSlot;
}

NdmsNativeAllocatorFenceValidation failure(
    const NdmsNativeAllocatorFenceValidationError error) noexcept {
    return {error};
}

} // namespace

NdmsNativeAllocatorFenceReceipt::NdmsNativeAllocatorFenceReceipt(
    ConstructionKey,
    const NdmsNativeAllocatorFenceMode mode,
    const NdmsNativeWireguardTargetRange range,
    std::string firmware_identity,
    std::string implementation_digest,
    std::string request_binding_digest,
    std::string generation_ticket,
    std::optional<std::string> exact_target,
    const std::uint64_t generation,
    const NdmsNativeAllocatorMonotonicTime issued_at,
    const NdmsNativeAllocatorMonotonicTime expires_at)
    : mode_(mode),
      range_(range),
      firmware_identity_(std::move(firmware_identity)),
      implementation_digest_(std::move(implementation_digest)),
      request_binding_digest_(std::move(request_binding_digest)),
      generation_ticket_(std::move(generation_ticket)),
      exact_target_(std::move(exact_target)),
      generation_(generation),
      issued_at_(issued_at),
      expires_at_(expires_at) {}

NdmsNativeAllocatorFenceReceipt::NdmsNativeAllocatorFenceReceipt(
    NdmsNativeAllocatorFenceReceipt&& other) noexcept
    : mode_(other.mode_),
      range_(other.range_),
      firmware_identity_(std::move(other.firmware_identity_)),
      implementation_digest_(std::move(other.implementation_digest_)),
      request_binding_digest_(std::move(other.request_binding_digest_)),
      generation_ticket_(std::move(other.generation_ticket_)),
      exact_target_(std::move(other.exact_target_)),
      generation_(other.generation_),
      issued_at_(other.issued_at_),
      expires_at_(other.expires_at_) {
    other.poison_after_move();
}

NdmsNativeAllocatorFenceReceipt&
NdmsNativeAllocatorFenceReceipt::operator=(
    NdmsNativeAllocatorFenceReceipt&& other) noexcept {
    if (this == &other) {
        poison_after_move();
        return *this;
    }

    mode_ = other.mode_;
    range_ = other.range_;
    firmware_identity_ = std::move(other.firmware_identity_);
    implementation_digest_ = std::move(other.implementation_digest_);
    request_binding_digest_ = std::move(other.request_binding_digest_);
    generation_ticket_ = std::move(other.generation_ticket_);
    exact_target_ = std::move(other.exact_target_);
    generation_ = other.generation_;
    issued_at_ = other.issued_at_;
    expires_at_ = other.expires_at_;
    other.poison_after_move();
    return *this;
}

void NdmsNativeAllocatorFenceReceipt::poison_after_move() noexcept {
    mode_ = static_cast<NdmsNativeAllocatorFenceMode>(255U);
    range_ = {0U, 0U};
    std::fill(
        firmware_identity_.begin(), firmware_identity_.end(), '\0');
    firmware_identity_.clear();
    std::fill(
        implementation_digest_.begin(),
        implementation_digest_.end(),
        '\0');
    implementation_digest_.clear();
    std::fill(
        request_binding_digest_.begin(),
        request_binding_digest_.end(),
        '\0');
    request_binding_digest_.clear();
    std::fill(
        generation_ticket_.begin(), generation_ticket_.end(), '\0');
    generation_ticket_.clear();
    if (exact_target_) {
        std::fill(exact_target_->begin(), exact_target_->end(), '\0');
        exact_target_->clear();
    }
    exact_target_.reset();
    generation_ = 0U;
    issued_at_ = NdmsNativeAllocatorMonotonicTime{};
    expires_at_ = issued_at_;
}

NdmsNativeAllocatorFenceValidation validate_ndms_native_allocator_fence(
    const NdmsNativeAllocatorFenceReceipt& receipt,
    const NdmsNativeAllocatorFenceExpectation& expectation) noexcept {
    if (!required_range(expectation.range)) {
        return failure(
            NdmsNativeAllocatorFenceValidationError::required_range_invalid);
    }
    if (!required_range(receipt.range_)) {
        return failure(
            NdmsNativeAllocatorFenceValidationError::receipt_range_invalid);
    }
    if (!valid_mode(receipt.mode_) || !valid_mode(expectation.mode)) {
        return failure(
            NdmsNativeAllocatorFenceValidationError::mode_invalid);
    }
    if (receipt.mode_ != expectation.mode) {
        return failure(
            NdmsNativeAllocatorFenceValidationError::mode_mismatch);
    }

    if (!valid_exact_target(expectation.exact_target) ||
        !valid_exact_target(receipt.exact_target_)) {
        return failure(
            NdmsNativeAllocatorFenceValidationError::exact_target_invalid);
    }
    if (receipt.mode_ ==
        NdmsNativeAllocatorFenceMode::exact_create_if_absent) {
        if (!expectation.exact_target || !receipt.exact_target_) {
            return failure(
                NdmsNativeAllocatorFenceValidationError::
                    exact_target_required);
        }
    }
    if (receipt.exact_target_ != expectation.exact_target) {
        return failure(
            NdmsNativeAllocatorFenceValidationError::
                exact_target_mismatch);
    }

    if (!valid_firmware_identity(expectation.firmware_identity) ||
        !valid_firmware_identity(receipt.firmware_identity_)) {
        return failure(
            NdmsNativeAllocatorFenceValidationError::
                firmware_identity_invalid);
    }
    if (receipt.firmware_identity_ != expectation.firmware_identity) {
        return failure(
            NdmsNativeAllocatorFenceValidationError::
                firmware_identity_mismatch);
    }

    if (!lowercase_hex_digest(
            expectation.implementation_digest,
            kNdmsNativeAllocatorImplementationDigestPrefix) ||
        !lowercase_hex_digest(
            receipt.implementation_digest_,
            kNdmsNativeAllocatorImplementationDigestPrefix)) {
        return failure(
            NdmsNativeAllocatorFenceValidationError::
                implementation_digest_invalid);
    }
    if (receipt.implementation_digest_ !=
        expectation.implementation_digest) {
        return failure(
            NdmsNativeAllocatorFenceValidationError::
                implementation_digest_mismatch);
    }

    if (!lowercase_hex_digest(
            expectation.request_binding_digest,
            kNdmsNativeAllocatorRequestBindingDigestPrefix) ||
        !lowercase_hex_digest(
            receipt.request_binding_digest_,
            kNdmsNativeAllocatorRequestBindingDigestPrefix)) {
        return failure(
            NdmsNativeAllocatorFenceValidationError::
                request_binding_digest_invalid);
    }
    if (receipt.request_binding_digest_ !=
        expectation.request_binding_digest) {
        return failure(
            NdmsNativeAllocatorFenceValidationError::
                request_binding_digest_mismatch);
    }

    if (!lowercase_hex_digest(
            expectation.generation_ticket,
            kNdmsNativeAllocatorGenerationTicketPrefix) ||
        !lowercase_hex_digest(
            receipt.generation_ticket_,
            kNdmsNativeAllocatorGenerationTicketPrefix)) {
        return failure(
            NdmsNativeAllocatorFenceValidationError::
                generation_ticket_invalid);
    }
    if (receipt.generation_ticket_ != expectation.generation_ticket) {
        return failure(
            NdmsNativeAllocatorFenceValidationError::
                generation_ticket_mismatch);
    }

    if (receipt.generation_ == 0U || expectation.current_generation == 0U) {
        return failure(
            NdmsNativeAllocatorFenceValidationError::generation_invalid);
    }
    if (receipt.generation_ != expectation.current_generation) {
        return failure(
            NdmsNativeAllocatorFenceValidationError::generation_mismatch);
    }

    if (receipt.issued_at_ >= receipt.expires_at_ ||
        receipt.expires_at_ - receipt.issued_at_ >
            kNdmsNativeAllocatorMaximumReceiptLifetime) {
        return failure(
            NdmsNativeAllocatorFenceValidationError::lifetime_invalid);
    }
    if (expectation.minimum_remaining <=
            NdmsNativeAllocatorMonotonicDuration::zero() ||
        expectation.minimum_remaining >
            kNdmsNativeAllocatorMaximumReceiptLifetime) {
        return failure(
            NdmsNativeAllocatorFenceValidationError::
                minimum_remaining_invalid);
    }
    if (expectation.now < receipt.issued_at_) {
        return failure(
            NdmsNativeAllocatorFenceValidationError::not_yet_valid);
    }
    if (expectation.now >= receipt.expires_at_) {
        return failure(
            NdmsNativeAllocatorFenceValidationError::expired);
    }
    if (receipt.expires_at_ - expectation.now <
        expectation.minimum_remaining) {
        return failure(
            NdmsNativeAllocatorFenceValidationError::
                minimum_remaining_insufficient);
    }

    return {NdmsNativeAllocatorFenceValidationError::none};
}

NdmsNativeAllocatorFenceAvailability
NdmsNativeKeeneticOs511AllocatorFenceProvider::availability() const noexcept {
    return NdmsNativeAllocatorFenceAvailability::
        unavailable_on_keeneticos_5_1_1;
}

std::optional<NdmsNativeAllocatorFenceReceipt>
NdmsNativeKeeneticOs511AllocatorFenceProvider::try_acquire(
    const NdmsNativeAllocatorFenceExpectation& expectation) const noexcept {
    static_cast<void>(expectation);
    return std::nullopt;
}

const char* ndms_native_allocator_fence_mode_name(
    const NdmsNativeAllocatorFenceMode mode) noexcept {
    switch (mode) {
    case NdmsNativeAllocatorFenceMode::bounded_atomic_import:
        return "bounded_atomic_import";
    case NdmsNativeAllocatorFenceMode::exact_create_if_absent:
        return "exact_create_if_absent";
    case NdmsNativeAllocatorFenceMode::global_ndms_writer_lease:
        return "global_ndms_writer_lease";
    }
    return "unknown";
}

const char* ndms_native_allocator_fence_availability_name(
    const NdmsNativeAllocatorFenceAvailability availability) noexcept {
    switch (availability) {
    case NdmsNativeAllocatorFenceAvailability::
        unavailable_on_keeneticos_5_1_1:
        return "unavailable_on_keeneticos_5_1_1";
    }
    return "unknown";
}

const char* ndms_native_allocator_fence_validation_error_name(
    const NdmsNativeAllocatorFenceValidationError error) noexcept {
    switch (error) {
    case NdmsNativeAllocatorFenceValidationError::none:
        return "none";
    case NdmsNativeAllocatorFenceValidationError::required_range_invalid:
        return "required_range_invalid";
    case NdmsNativeAllocatorFenceValidationError::receipt_range_invalid:
        return "receipt_range_invalid";
    case NdmsNativeAllocatorFenceValidationError::mode_invalid:
        return "mode_invalid";
    case NdmsNativeAllocatorFenceValidationError::mode_mismatch:
        return "mode_mismatch";
    case NdmsNativeAllocatorFenceValidationError::exact_target_required:
        return "exact_target_required";
    case NdmsNativeAllocatorFenceValidationError::exact_target_invalid:
        return "exact_target_invalid";
    case NdmsNativeAllocatorFenceValidationError::exact_target_mismatch:
        return "exact_target_mismatch";
    case NdmsNativeAllocatorFenceValidationError::firmware_identity_invalid:
        return "firmware_identity_invalid";
    case NdmsNativeAllocatorFenceValidationError::firmware_identity_mismatch:
        return "firmware_identity_mismatch";
    case NdmsNativeAllocatorFenceValidationError::
        implementation_digest_invalid:
        return "implementation_digest_invalid";
    case NdmsNativeAllocatorFenceValidationError::
        implementation_digest_mismatch:
        return "implementation_digest_mismatch";
    case NdmsNativeAllocatorFenceValidationError::
        request_binding_digest_invalid:
        return "request_binding_digest_invalid";
    case NdmsNativeAllocatorFenceValidationError::
        request_binding_digest_mismatch:
        return "request_binding_digest_mismatch";
    case NdmsNativeAllocatorFenceValidationError::generation_ticket_invalid:
        return "generation_ticket_invalid";
    case NdmsNativeAllocatorFenceValidationError::generation_ticket_mismatch:
        return "generation_ticket_mismatch";
    case NdmsNativeAllocatorFenceValidationError::generation_invalid:
        return "generation_invalid";
    case NdmsNativeAllocatorFenceValidationError::generation_mismatch:
        return "generation_mismatch";
    case NdmsNativeAllocatorFenceValidationError::lifetime_invalid:
        return "lifetime_invalid";
    case NdmsNativeAllocatorFenceValidationError::minimum_remaining_invalid:
        return "minimum_remaining_invalid";
    case NdmsNativeAllocatorFenceValidationError::not_yet_valid:
        return "not_yet_valid";
    case NdmsNativeAllocatorFenceValidationError::expired:
        return "expired";
    case NdmsNativeAllocatorFenceValidationError::
        minimum_remaining_insufficient:
        return "minimum_remaining_insufficient";
    }
    return "unknown";
}

#ifdef KEEN_PBR3_TESTING
NdmsNativeAllocatorFenceReceipt
NdmsNativeAllocatorFenceTestIssuer::issue_unchecked(
    NdmsNativeAllocatorFenceTestFields fields) {
    return NdmsNativeAllocatorFenceReceipt{
        NdmsNativeAllocatorFenceReceipt::ConstructionKey{},
        fields.mode,
        fields.range,
        std::move(fields.firmware_identity),
        std::move(fields.implementation_digest),
        std::move(fields.request_binding_digest),
        std::move(fields.generation_ticket),
        std::move(fields.exact_target),
        fields.generation,
        fields.issued_at,
        fields.expires_at,
    };
}
#endif

} // namespace keen_pbr3
