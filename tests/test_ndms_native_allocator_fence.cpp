#include <doctest/doctest.h>

#include "keenetic/ndms_native_allocator_fence.hpp"
#include "keenetic/ndms_native_import_response.hpp"

#include <chrono>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

using namespace keen_pbr3;

namespace {

template <typename Type, typename = void>
struct HasPublicReceiptFactory : std::false_type {};

template <typename Type>
struct HasPublicReceiptFactory<
    Type,
    std::void_t<decltype(Type::issue(
        std::declval<NdmsNativeAllocatorFenceTestFields>()))>>
    : std::true_type {};

template <typename Type, typename = void>
struct CanValidateAsAllocatorReceipt : std::false_type {};

template <typename Type>
struct CanValidateAsAllocatorReceipt<
    Type,
    std::void_t<decltype(validate_ndms_native_allocator_fence(
        std::declval<const Type&>(),
        std::declval<
            const NdmsNativeAllocatorFenceExpectation&>()))>>
    : std::true_type {};

static_assert(
    NdmsNativeAllocatorMonotonicClock::is_steady,
    "allocator receipts must use a monotonic clock");
static_assert(!std::is_default_constructible_v<
              NdmsNativeAllocatorFenceReceipt>);
static_assert(!std::is_copy_constructible_v<
              NdmsNativeAllocatorFenceReceipt>);
static_assert(!std::is_copy_assignable_v<
              NdmsNativeAllocatorFenceReceipt>);
static_assert(std::is_move_constructible_v<
              NdmsNativeAllocatorFenceReceipt>);
static_assert(std::is_nothrow_move_constructible_v<
              NdmsNativeAllocatorFenceReceipt>);
static_assert(std::is_nothrow_move_assignable_v<
              NdmsNativeAllocatorFenceReceipt>);
static_assert(!std::is_aggregate_v<
              NdmsNativeAllocatorFenceReceipt>);
static_assert(!std::is_constructible_v<
              NdmsNativeAllocatorFenceReceipt,
              NdmsNativeAllocatorFenceTestFields>);
static_assert(!HasPublicReceiptFactory<
              NdmsNativeAllocatorFenceReceipt>::value);
static_assert(!std::is_constructible_v<
              NdmsNativeAllocatorFenceReceipt,
              NdmsNativeImportResponseManifestV3>);
static_assert(!std::is_convertible_v<
              NdmsNativeImportResponseManifestV3,
              NdmsNativeAllocatorFenceReceipt>);
static_assert(!CanValidateAsAllocatorReceipt<
              NdmsNativeImportResponseManifestV3>::value);

const auto kIssuedAt = NdmsNativeAllocatorMonotonicTime{
    std::chrono::seconds{1000}};
const auto kNow = kIssuedAt + std::chrono::seconds{5};
const auto kExpiresAt = kIssuedAt + std::chrono::seconds{30};

std::string allocator_digest(const char digit = 'a') {
    return std::string{kNdmsNativeAllocatorImplementationDigestPrefix} +
           std::string(64U, digit);
}

std::string generation_ticket(const char digit = 'b') {
    return std::string{kNdmsNativeAllocatorGenerationTicketPrefix} +
           std::string(64U, digit);
}

std::string request_binding_digest(const char digit = 'c') {
    return std::string{kNdmsNativeAllocatorRequestBindingDigestPrefix} +
           std::string(64U, digit);
}

NdmsNativeAllocatorFenceTestFields valid_fields(
    const NdmsNativeAllocatorFenceMode mode =
        NdmsNativeAllocatorFenceMode::bounded_atomic_import) {
    NdmsNativeAllocatorFenceTestFields fields;
    fields.mode = mode;
    fields.firmware_identity =
        kNdmsNativeAllocatorKeeneticOs511FirmwareIdentity;
    fields.implementation_digest = allocator_digest();
    fields.request_binding_digest = request_binding_digest();
    fields.generation_ticket = generation_ticket();
    fields.generation = 41U;
    fields.issued_at = kIssuedAt;
    fields.expires_at = kExpiresAt;
    if (mode ==
        NdmsNativeAllocatorFenceMode::exact_create_if_absent) {
        fields.exact_target = "Wireguard5";
    }
    return fields;
}

NdmsNativeAllocatorFenceExpectation valid_expectation(
    const NdmsNativeAllocatorFenceMode mode =
        NdmsNativeAllocatorFenceMode::bounded_atomic_import) {
    NdmsNativeAllocatorFenceExpectation expectation;
    expectation.mode = mode;
    expectation.firmware_identity =
        kNdmsNativeAllocatorKeeneticOs511FirmwareIdentity;
    expectation.implementation_digest = allocator_digest();
    expectation.request_binding_digest = request_binding_digest();
    expectation.generation_ticket = generation_ticket();
    expectation.current_generation = 41U;
    expectation.now = kNow;
    expectation.minimum_remaining = std::chrono::seconds{20};
    if (mode ==
        NdmsNativeAllocatorFenceMode::exact_create_if_absent) {
        expectation.exact_target = "Wireguard5";
    }
    return expectation;
}

NdmsNativeAllocatorFenceValidation validate_fields(
    NdmsNativeAllocatorFenceTestFields fields,
    const NdmsNativeAllocatorFenceExpectation& expectation) {
    const auto receipt =
        NdmsNativeAllocatorFenceTestIssuer::issue_unchecked(
            std::move(fields));
    return validate_ndms_native_allocator_fence(receipt, expectation);
}

} // namespace

TEST_CASE("current KeeneticOS allocator fence provider is unavailable") {
    NdmsNativeKeeneticOs511AllocatorFenceProvider provider;
    CHECK(provider.availability() ==
          NdmsNativeAllocatorFenceAvailability::
              unavailable_on_keeneticos_5_1_1);
    CHECK(std::string{ndms_native_allocator_fence_availability_name(
              provider.availability())} ==
          "unavailable_on_keeneticos_5_1_1");

    for (const auto mode : {
             NdmsNativeAllocatorFenceMode::bounded_atomic_import,
             NdmsNativeAllocatorFenceMode::exact_create_if_absent,
             NdmsNativeAllocatorFenceMode::global_ndms_writer_lease}) {
        CAPTURE(ndms_native_allocator_fence_mode_name(mode));
        CHECK_FALSE(provider.try_acquire(valid_expectation(mode)).has_value());
    }

    auto caller_claim = valid_expectation();
    caller_claim.firmware_identity = "caller-says-safe";
    caller_claim.implementation_digest = allocator_digest('c');
    caller_claim.generation_ticket = generation_ticket('d');
    CHECK_FALSE(provider.try_acquire(caller_claim).has_value());
}

TEST_CASE("future allocator fence modes validate only their exact binding") {
    for (const auto mode : {
             NdmsNativeAllocatorFenceMode::bounded_atomic_import,
             NdmsNativeAllocatorFenceMode::exact_create_if_absent,
             NdmsNativeAllocatorFenceMode::global_ndms_writer_lease}) {
        CAPTURE(ndms_native_allocator_fence_mode_name(mode));
        const auto result =
            validate_fields(valid_fields(mode), valid_expectation(mode));
        CHECK(result.authorizes());
        CHECK(result.error == NdmsNativeAllocatorFenceValidationError::none);
    }

    auto expectation = valid_expectation();
    expectation.mode =
        NdmsNativeAllocatorFenceMode::global_ndms_writer_lease;
    CHECK(validate_fields(valid_fields(), expectation).error ==
          NdmsNativeAllocatorFenceValidationError::mode_mismatch);

    auto invalid_mode = valid_fields();
    invalid_mode.mode = static_cast<NdmsNativeAllocatorFenceMode>(255U);
    CHECK(validate_fields(
              std::move(invalid_mode), valid_expectation()).error ==
          NdmsNativeAllocatorFenceValidationError::mode_invalid);

    for (const auto mode : {
             NdmsNativeAllocatorFenceMode::bounded_atomic_import,
             NdmsNativeAllocatorFenceMode::global_ndms_writer_lease}) {
        CAPTURE(ndms_native_allocator_fence_mode_name(mode));
        auto fields = valid_fields(mode);
        auto bound = valid_expectation(mode);
        fields.exact_target = "Wireguard47";
        bound.exact_target = "Wireguard47";
        CHECK(validate_fields(std::move(fields), bound).authorizes());
    }
}

TEST_CASE("allocator fence receipt move construction is single-use") {
    const auto expectation = valid_expectation();
    auto source = NdmsNativeAllocatorFenceTestIssuer::issue_unchecked(
        valid_fields());

    auto first_consumer = std::move(source);
    CHECK(validate_ndms_native_allocator_fence(
              first_consumer, expectation)
              .authorizes());
    auto other_request = expectation;
    other_request.request_binding_digest = request_binding_digest('d');
    CHECK(validate_ndms_native_allocator_fence(
              first_consumer, other_request)
              .error ==
          NdmsNativeAllocatorFenceValidationError::
              request_binding_digest_mismatch);
    CHECK_FALSE(validate_ndms_native_allocator_fence(source, expectation)
                    .authorizes());

    auto replay_from_source = std::move(source);
    CHECK_FALSE(validate_ndms_native_allocator_fence(
                    replay_from_source, expectation)
                    .authorizes());
    CHECK_FALSE(validate_ndms_native_allocator_fence(source, expectation)
                    .authorizes());
}

TEST_CASE("allocator fence receipt move assignment poisons every source") {
    auto expectation = valid_expectation(
        NdmsNativeAllocatorFenceMode::global_ndms_writer_lease);
    expectation.exact_target = "Wireguard47";
    auto fields = valid_fields(
        NdmsNativeAllocatorFenceMode::global_ndms_writer_lease);
    fields.exact_target = "Wireguard47";
    auto source = NdmsNativeAllocatorFenceTestIssuer::issue_unchecked(
        std::move(fields));

    auto destination =
        NdmsNativeAllocatorFenceTestIssuer::issue_unchecked(
            valid_fields());
    destination = std::move(source);
    CHECK(validate_ndms_native_allocator_fence(
              destination, expectation)
              .authorizes());
    auto other_request = expectation;
    other_request.request_binding_digest = request_binding_digest('d');
    CHECK(validate_ndms_native_allocator_fence(
              destination, other_request)
              .error ==
          NdmsNativeAllocatorFenceValidationError::
              request_binding_digest_mismatch);
    CHECK_FALSE(validate_ndms_native_allocator_fence(source, expectation)
                    .authorizes());

    auto replay_destination =
        NdmsNativeAllocatorFenceTestIssuer::issue_unchecked(
            valid_fields(
                NdmsNativeAllocatorFenceMode::global_ndms_writer_lease));
    replay_destination = std::move(source);
    CHECK_FALSE(validate_ndms_native_allocator_fence(
                    replay_destination, expectation)
                    .authorizes());
    CHECK_FALSE(validate_ndms_native_allocator_fence(source, expectation)
                    .authorizes());
}

TEST_CASE("allocator fence range is exactly Wireguard5 through Wireguard98") {
    auto expectation = valid_expectation();
    expectation.range.first_index = 4U;
    CHECK(validate_fields(valid_fields(), expectation).error ==
          NdmsNativeAllocatorFenceValidationError::required_range_invalid);

    expectation = valid_expectation();
    expectation.range.last_index = 99U;
    CHECK(validate_fields(valid_fields(), expectation).error ==
          NdmsNativeAllocatorFenceValidationError::required_range_invalid);

    auto receipt = valid_fields();
    receipt.range.first_index = 6U;
    CHECK(validate_fields(std::move(receipt), valid_expectation()).error ==
          NdmsNativeAllocatorFenceValidationError::receipt_range_invalid);

    receipt = valid_fields();
    receipt.range.last_index = 97U;
    CHECK(validate_fields(std::move(receipt), valid_expectation()).error ==
          NdmsNativeAllocatorFenceValidationError::receipt_range_invalid);
}

TEST_CASE("exact-create allocator fence rejects protected targets") {
    for (const std::string target : {
             "Wireguard0", "Wireguard4", "Wireguard99", "Wireguard126",
             "Wireguard05", "Wireguard127"}) {
        CAPTURE(target);
        auto fields = valid_fields(
            NdmsNativeAllocatorFenceMode::exact_create_if_absent);
        auto expectation = valid_expectation(
            NdmsNativeAllocatorFenceMode::exact_create_if_absent);
        fields.exact_target = target;
        expectation.exact_target = target;
        CHECK(validate_fields(std::move(fields), expectation).error ==
              NdmsNativeAllocatorFenceValidationError::exact_target_invalid);
    }

    for (const std::string target : {"Wireguard5", "Wireguard98"}) {
        CAPTURE(target);
        auto fields = valid_fields(
            NdmsNativeAllocatorFenceMode::exact_create_if_absent);
        auto expectation = valid_expectation(
            NdmsNativeAllocatorFenceMode::exact_create_if_absent);
        fields.exact_target = target;
        expectation.exact_target = target;
        CHECK(validate_fields(std::move(fields), expectation).authorizes());
    }

    auto fields = valid_fields(
        NdmsNativeAllocatorFenceMode::exact_create_if_absent);
    auto expectation = valid_expectation(
        NdmsNativeAllocatorFenceMode::exact_create_if_absent);
    fields.exact_target = "Wireguard6";
    CHECK(validate_fields(std::move(fields), expectation).error ==
          NdmsNativeAllocatorFenceValidationError::exact_target_mismatch);

    fields = valid_fields(
        NdmsNativeAllocatorFenceMode::exact_create_if_absent);
    fields.exact_target.reset();
    CHECK(validate_fields(std::move(fields), expectation).error ==
          NdmsNativeAllocatorFenceValidationError::exact_target_required);
}

TEST_CASE("allocator fence binds firmware implementation and generation ticket") {
    auto expectation = valid_expectation();
    expectation.firmware_identity = "KeeneticOS-5.1.2";
    CHECK(validate_fields(valid_fields(), expectation).error ==
          NdmsNativeAllocatorFenceValidationError::
              firmware_identity_mismatch);

    expectation = valid_expectation();
    expectation.implementation_digest = allocator_digest('c');
    CHECK(validate_fields(valid_fields(), expectation).error ==
          NdmsNativeAllocatorFenceValidationError::
              implementation_digest_mismatch);

    expectation = valid_expectation();
    expectation.implementation_digest = "caller-bool-safe";
    CHECK(validate_fields(valid_fields(), expectation).error ==
          NdmsNativeAllocatorFenceValidationError::
              implementation_digest_invalid);

    expectation = valid_expectation();
    expectation.generation_ticket = generation_ticket('c');
    CHECK(validate_fields(valid_fields(), expectation).error ==
          NdmsNativeAllocatorFenceValidationError::
              generation_ticket_mismatch);

    expectation = valid_expectation();
    expectation.generation_ticket.back() = 'G';
    CHECK(validate_fields(valid_fields(), expectation).error ==
          NdmsNativeAllocatorFenceValidationError::
              generation_ticket_invalid);
}

TEST_CASE("allocator fence requires the exact pre-dispatch request binding") {
    auto expectation = valid_expectation();
    expectation.request_binding_digest.clear();
    CHECK(validate_fields(valid_fields(), expectation).error ==
          NdmsNativeAllocatorFenceValidationError::
              request_binding_digest_invalid);

    auto fields = valid_fields();
    fields.request_binding_digest.clear();
    CHECK(validate_fields(std::move(fields), valid_expectation()).error ==
          NdmsNativeAllocatorFenceValidationError::
              request_binding_digest_invalid);

    expectation = valid_expectation();
    expectation.request_binding_digest.back() = 'G';
    CHECK(validate_fields(valid_fields(), expectation).error ==
          NdmsNativeAllocatorFenceValidationError::
              request_binding_digest_invalid);

    expectation = valid_expectation();
    expectation.request_binding_digest = request_binding_digest('d');
    CHECK(validate_fields(valid_fields(), expectation).error ==
          NdmsNativeAllocatorFenceValidationError::
              request_binding_digest_mismatch);
}

TEST_CASE("allocator fence expires monotonically and on generation change") {
    auto expectation = valid_expectation();
    expectation.current_generation = 42U;
    CHECK(validate_fields(valid_fields(), expectation).error ==
          NdmsNativeAllocatorFenceValidationError::generation_mismatch);

    expectation = valid_expectation();
    expectation.current_generation = 0U;
    CHECK(validate_fields(valid_fields(), expectation).error ==
          NdmsNativeAllocatorFenceValidationError::generation_invalid);

    expectation = valid_expectation();
    expectation.now = kIssuedAt - std::chrono::nanoseconds{1};
    CHECK(validate_fields(valid_fields(), expectation).error ==
          NdmsNativeAllocatorFenceValidationError::not_yet_valid);

    expectation = valid_expectation();
    expectation.now = kExpiresAt;
    CHECK(validate_fields(valid_fields(), expectation).error ==
          NdmsNativeAllocatorFenceValidationError::expired);

    auto fields = valid_fields();
    fields.expires_at = fields.issued_at;
    CHECK(validate_fields(std::move(fields), valid_expectation()).error ==
          NdmsNativeAllocatorFenceValidationError::lifetime_invalid);

    fields = valid_fields();
    fields.expires_at = fields.issued_at +
                        kNdmsNativeAllocatorMaximumReceiptLifetime +
                        std::chrono::nanoseconds{1};
    CHECK(validate_fields(std::move(fields), valid_expectation()).error ==
          NdmsNativeAllocatorFenceValidationError::lifetime_invalid);
}

TEST_CASE("allocator fence reserves the complete dispatch time budget") {
    auto expectation = valid_expectation();
    expectation.minimum_remaining =
        NdmsNativeAllocatorMonotonicDuration::zero();
    CHECK(validate_fields(valid_fields(), expectation).error ==
          NdmsNativeAllocatorFenceValidationError::
              minimum_remaining_invalid);

    expectation = valid_expectation();
    expectation.minimum_remaining =
        NdmsNativeAllocatorMonotonicDuration{-1};
    CHECK(validate_fields(valid_fields(), expectation).error ==
          NdmsNativeAllocatorFenceValidationError::
              minimum_remaining_invalid);

    expectation = valid_expectation();
    expectation.minimum_remaining =
        kNdmsNativeAllocatorMaximumReceiptLifetime +
        NdmsNativeAllocatorMonotonicDuration{1};
    CHECK(validate_fields(valid_fields(), expectation).error ==
          NdmsNativeAllocatorFenceValidationError::
              minimum_remaining_invalid);

    expectation = valid_expectation();
    expectation.now = kExpiresAt - std::chrono::seconds{20};
    CHECK(validate_fields(valid_fields(), expectation).authorizes());

    expectation.now += NdmsNativeAllocatorMonotonicDuration{1};
    CHECK(validate_fields(valid_fields(), expectation).error ==
          NdmsNativeAllocatorFenceValidationError::
              minimum_remaining_insufficient);
}

TEST_CASE("post-result target cannot retroactively authorize an import") {
    auto expectation = valid_expectation(
        NdmsNativeAllocatorFenceMode::bounded_atomic_import);
    // This target represents a canonical successful post-result. Adding it
    // after dispatch does not turn an unbound bounded-import receipt into an
    // exact-target fence, and response manifests have no validator overload.
    expectation.exact_target = "Wireguard5";
    CHECK(validate_fields(
              valid_fields(
                  NdmsNativeAllocatorFenceMode::bounded_atomic_import),
              expectation)
              .error ==
          NdmsNativeAllocatorFenceValidationError::exact_target_mismatch);
}
