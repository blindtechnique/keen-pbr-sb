#include <doctest/doctest.h>

#include "keenetic/ndms_native_import_baseline.hpp"

#include <chrono>
#include <cstdint>
#include <limits>
#include <string>
#include <type_traits>
#include <vector>

using namespace keen_pbr3;

namespace {

static_assert(
    !std::is_default_constructible<
        NdmsNativeImportBaselineEvidence>::value,
    "baseline evidence must come from the validated builder");
static_assert(
    !std::is_default_constructible<
        NdmsNativeImportBaselineComparison>::value,
    "comparison facts must come from the pure comparator");
static_assert(
    !std::is_constructible<
        NdmsNativeImportBaselineComparison,
        bool,
        bool,
        bool>::value,
    "callers must not manufacture recovery booleans");
static_assert(
    !std::is_copy_assignable<
        NdmsNativeImportBaselineComparison>::value,
    "comparison facts must remain immutable");

nlohmann::json wireguard_record(
    const std::uint8_t slot,
    const std::string& description = {}) {
    const auto name = "Wireguard" + std::to_string(slot);
    return {
        {"type", "Bridge"},
        {"interface-name", name},
        {"description",
         description.empty()
             ? "slot-" + std::to_string(slot)
             : description},
        {"connected", true},
        {"link", true},
        {"uptime", static_cast<std::uint64_t>(slot) + 10U},
    };
}

nlohmann::json occupied_slots(
    const std::vector<std::uint8_t>& slots) {
    auto payload = nlohmann::json::object();
    for (const auto slot : slots) {
        payload["Wireguard" + std::to_string(slot)] =
            wireguard_record(slot);
    }
    return payload;
}

NdmsCatalogSnapshot authoritative_snapshot(
    const nlohmann::json& payload,
    const std::uint64_t observation_generation = 7U,
    const std::uint64_t epoch = 3U) {
    NdmsCatalogSnapshot snapshot;
    snapshot.catalog = parse_ndms_interface_catalog(payload);
    snapshot.status = NdmsCatalogCacheStatus::fresh;
    snapshot.refreshed = true;
    snapshot.observed_at =
        std::chrono::steady_clock::time_point{
            std::chrono::seconds{123}};
    snapshot.observation_generation = observation_generation;
    snapshot.observation_epoch = epoch;
    snapshot.invalidation_epoch = epoch;
    return snapshot;
}

NdmsCatalogSnapshot baseline_snapshot() {
    return authoritative_snapshot(
        occupied_slots({0U, 1U, 2U, 3U, 4U, 6U}));
}

NdmsNativeImportBaselineBuildResult build_valid(
    const NdmsCatalogSnapshot& snapshot,
    const std::string_view expected = "Wireguard5",
    const std::uint32_t maintenance = 41U,
    const std::uint64_t allocator = 17U) {
    return build_ndms_native_import_baseline(
        snapshot, expected, maintenance, allocator);
}

void check_error(
    const NdmsNativeImportBaselineBuildResult& result,
    const NdmsNativeImportBaselineBuildError expected) {
    CHECK_FALSE(result.success());
    CHECK(result.error == expected);
    CHECK_FALSE(result.evidence.has_value());
}

std::vector<std::uint8_t> slot_range(
    const std::uint8_t first,
    const std::uint8_t last) {
    std::vector<std::uint8_t> slots;
    for (unsigned int slot = first; slot <= last; ++slot) {
        slots.push_back(static_cast<std::uint8_t>(slot));
    }
    return slots;
}

} // namespace

TEST_CASE("native import baseline is fixed bounded and generation bound") {
    const auto snapshot = baseline_snapshot();
    const auto first = build_valid(snapshot);
    REQUIRE(first.success());
    REQUIRE(first.evidence.has_value());
    const auto& evidence = *first.evidence;

    CHECK(evidence.expected_created_interface() == "Wireguard5");
    CHECK(evidence.expected_target_slot() == 5U);
    CHECK(evidence.occupancy().size() ==
          kNdmsNativeImportOccupancyBytes);
    CHECK(evidence.occupancy()[0] == 0x5fU);
    CHECK(evidence.occupancy()[15] == 0U);
    CHECK(evidence.occupancy_hex() ==
          "5f000000000000000000000000000000");
    CHECK(evidence.occupancy_hex().size() ==
          kNdmsNativeImportOccupancyHexCharacters);
    CHECK(evidence.protected_catalog_sha256().rfind(
              kNdmsNativeImportProtectedCatalogDigestPrefix, 0U) == 0U);
    CHECK(evidence.protected_catalog_sha256().size() ==
          std::string{
              kNdmsNativeImportProtectedCatalogDigestPrefix}.size() +
              64U);
    CHECK(evidence.baseline_sha256().rfind(
              kNdmsNativeImportBaselineDigestPrefix, 0U) == 0U);
    CHECK(evidence.baseline_sha256().size() ==
          std::string{kNdmsNativeImportBaselineDigestPrefix}.size() +
              64U);
    CHECK(evidence.observation_generation() == 7U);
    CHECK(evidence.observation_epoch() == 3U);
    CHECK(evidence.invalidation_epoch() == 3U);
    CHECK(evidence.maintenance_base_generation() == 41U);
    CHECK(evidence.allocator_generation() == 17U);
    CHECK(evidence.protected_catalog_sha256() ==
          "ndms-protected-wg-catalog-v1-"
          "eb6b0a8fa4ba4e56d9dfd5ad81ebf1c85480aed648aedf4e650b49d92fee79cb");
    CHECK(evidence.baseline_sha256() ==
          "ndms-native-import-baseline-v1-"
          "1ca209cefdf70f825d4605fc0b87a541c3c7e88a2e4abf1f0648d003c2d7232f");

    const auto persisted =
        persist_ndms_native_import_baseline(evidence);
    CHECK(valid_ndms_native_import_persisted_baseline(persisted));
    CHECK(persisted.expected_created_interface ==
          evidence.expected_created_interface());
    CHECK(persisted.expected_target_slot ==
          evidence.expected_target_slot());
    CHECK(persisted.occupancy_hex == evidence.occupancy_hex());
    CHECK(persisted.baseline_sha256 == evidence.baseline_sha256());

    const auto repeated = build_valid(snapshot);
    REQUIRE(repeated.success());
    CHECK(repeated.evidence->occupancy() == evidence.occupancy());
    CHECK(repeated.evidence->protected_catalog_sha256() ==
          evidence.protected_catalog_sha256());
    CHECK(repeated.evidence->baseline_sha256() ==
          evidence.baseline_sha256());

    auto next_observation = snapshot;
    next_observation.observation_generation = 8U;
    const auto rebound = build_valid(next_observation);
    REQUIRE(rebound.success());
    CHECK(rebound.evidence->protected_catalog_sha256() ==
          evidence.protected_catalog_sha256());
    CHECK(rebound.evidence->baseline_sha256() !=
          evidence.baseline_sha256());
}

TEST_CASE("persisted native import baseline fails closed on alternate encodings") {
    const auto built = build_valid(baseline_snapshot());
    REQUIRE(built.success());
    const auto canonical =
        persist_ndms_native_import_baseline(*built.evidence);

    auto protected_target = canonical;
    protected_target.expected_created_interface = "Wireguard4";
    protected_target.expected_target_slot = 4U;
    CHECK_FALSE(valid_ndms_native_import_persisted_baseline(
        protected_target));

    auto slot_mismatch = canonical;
    slot_mismatch.expected_target_slot = 6U;
    CHECK_FALSE(valid_ndms_native_import_persisted_baseline(
        slot_mismatch));

    auto first_free_mismatch = canonical;
    first_free_mismatch.occupancy_hex[0] = '4';
    REQUIRE(first_free_mismatch.occupancy_hex !=
            canonical.occupancy_hex);
    CHECK_FALSE(valid_ndms_native_import_persisted_baseline(
        first_free_mismatch));

    auto spare_bit = canonical;
    spare_bit.occupancy_hex.back() = '0';
    spare_bit.occupancy_hex[spare_bit.occupancy_hex.size() - 2U] = '8';
    CHECK_FALSE(valid_ndms_native_import_persisted_baseline(spare_bit));

    auto forged_digest = canonical;
    forged_digest.baseline_sha256.back() =
        forged_digest.baseline_sha256.back() == '0' ? '1' : '0';
    CHECK_FALSE(valid_ndms_native_import_persisted_baseline(
        forged_digest));

    auto epoch_mismatch = canonical;
    ++epoch_mismatch.invalidation_epoch;
    CHECK_FALSE(valid_ndms_native_import_persisted_baseline(
        epoch_mismatch));
}

TEST_CASE("native import baseline requires an exact authoritative refresh") {
    SUBCASE("firmware unavailable") {
        auto snapshot = baseline_snapshot();
        snapshot.catalog.firmware_available = false;
        check_error(
            build_valid(snapshot),
            NdmsNativeImportBaselineBuildError::firmware_unavailable);
    }
    SUBCASE("catalog stale") {
        auto snapshot = baseline_snapshot();
        snapshot.status = NdmsCatalogCacheStatus::stale;
        check_error(
            build_valid(snapshot),
            NdmsNativeImportBaselineBuildError::catalog_not_fresh);
    }
    SUBCASE("refresh not completed") {
        auto snapshot = baseline_snapshot();
        snapshot.refreshed = false;
        check_error(
            build_valid(snapshot),
            NdmsNativeImportBaselineBuildError::catalog_not_refreshed);
    }
    SUBCASE("observation instant absent") {
        auto snapshot = baseline_snapshot();
        snapshot.observed_at.reset();
        check_error(
            build_valid(snapshot),
            NdmsNativeImportBaselineBuildError::
                catalog_observation_missing);
    }
    SUBCASE("observation generation zero") {
        auto snapshot = baseline_snapshot();
        snapshot.observation_generation = 0U;
        check_error(
            build_valid(snapshot),
            NdmsNativeImportBaselineBuildError::
                observation_generation_invalid);
    }
    SUBCASE("observation belongs to an invalidated epoch") {
        auto snapshot = baseline_snapshot();
        ++snapshot.invalidation_epoch;
        check_error(
            build_valid(snapshot),
            NdmsNativeImportBaselineBuildError::
                observation_epoch_mismatch);
    }
    SUBCASE("raw slot evidence is incomplete") {
        auto snapshot = baseline_snapshot();
        snapshot.catalog.wireguard_slot_evidence_complete = false;
        check_error(
            build_valid(snapshot),
            NdmsNativeImportBaselineBuildError::
                slot_evidence_incomplete);
    }
    SUBCASE("unsafe slot cannot hide behind complete flag") {
        auto snapshot = baseline_snapshot();
        snapshot.catalog.wireguard_slots[9].state =
            NdmsWireguardCatalogSlotState::unsafe;
        check_error(
            build_valid(snapshot),
            NdmsNativeImportBaselineBuildError::
                slot_evidence_invalid);
    }
    SUBCASE("occupied slot needs a canonical structural revision") {
        auto snapshot = baseline_snapshot();
        snapshot.catalog.wireguard_slots[6].structural_revision =
            "forged";
        check_error(
            build_valid(snapshot),
            NdmsNativeImportBaselineBuildError::
                slot_evidence_invalid);
    }
    SUBCASE("absent slot cannot carry a revision") {
        auto snapshot = baseline_snapshot();
        snapshot.catalog.wireguard_slots[7].structural_revision =
            "ndms-wg-slot-v1-" + std::string(64U, 'a');
        check_error(
            build_valid(snapshot),
            NdmsNativeImportBaselineBuildError::
                slot_evidence_invalid);
    }
    SUBCASE("maintenance generation cannot advance") {
        check_error(
            build_valid(
                baseline_snapshot(),
                "Wireguard5",
                std::numeric_limits<std::uint32_t>::max()),
            NdmsNativeImportBaselineBuildError::
                maintenance_generation_exhausted);
    }
    SUBCASE("allocator generation zero") {
        check_error(
            build_valid(
                baseline_snapshot(), "Wireguard5", 41U, 0U),
            NdmsNativeImportBaselineBuildError::
                allocator_generation_invalid);
    }
}

TEST_CASE("native import baseline enforces the complete stock allocator scan") {
    SUBCASE("first free system slot blocks") {
        check_error(
            build_valid(authoritative_snapshot(nlohmann::json::object())),
            NdmsNativeImportBaselineBuildError::
                first_free_target_protected);
    }
    SUBCASE("protected expected target is invalid") {
        check_error(
            build_valid(baseline_snapshot(), "Wireguard4"),
            NdmsNativeImportBaselineBuildError::expected_target_invalid);
        check_error(
            build_valid(baseline_snapshot(), "Wireguard99"),
            NdmsNativeImportBaselineBuildError::expected_target_invalid);
    }
    SUBCASE("expected target must be the exact canonical identity") {
        for (const auto target : {
                 "Wireguard05",
                 " Wireguard5",
                 "Wireguard5/description",
                 "wireguard5",
             }) {
            check_error(
                build_valid(baseline_snapshot(), target),
                NdmsNativeImportBaselineBuildError::
                    expected_target_invalid);
        }
    }
    SUBCASE("occupied expected target blocks") {
        const auto snapshot = authoritative_snapshot(
            occupied_slots({0U, 1U, 2U, 3U, 4U, 5U}));
        check_error(
            build_valid(snapshot),
            NdmsNativeImportBaselineBuildError::
                expected_target_occupied);
    }
    SUBCASE("another eligible slot is first") {
        check_error(
            build_valid(baseline_snapshot(), "Wireguard7"),
            NdmsNativeImportBaselineBuildError::
                expected_target_not_first_free);
    }
    SUBCASE("first free sentinel slot blocks") {
        const auto snapshot = authoritative_snapshot(
            occupied_slots(slot_range(0U, 98U)));
        check_error(
            build_valid(snapshot, "Wireguard98"),
            NdmsNativeImportBaselineBuildError::
                first_free_target_protected);
    }
    SUBCASE("full allocator namespace blocks") {
        const auto snapshot = authoritative_snapshot(
            occupied_slots(slot_range(0U, 126U)));
        check_error(
            build_valid(snapshot, "Wireguard98"),
            NdmsNativeImportBaselineBuildError::
                allocator_namespace_full);
    }
    SUBCASE("last managed slot can be the exact first free") {
        const auto snapshot = authoritative_snapshot(
            occupied_slots(slot_range(0U, 97U)));
        const auto result = build_valid(snapshot, "Wireguard98");
        REQUIRE(result.success());
        CHECK(result.evidence->expected_target_slot() == 98U);
        CHECK((result.evidence->occupancy()[12] & 0x04U) == 0U);
        CHECK(result.evidence->occupancy()[15] == 0U);
    }
    SUBCASE("last namespace slot has a bounded bit and no slot 127 bit") {
        const auto snapshot = authoritative_snapshot(
            occupied_slots({0U, 1U, 2U, 3U, 4U, 6U, 126U}));
        const auto result = build_valid(snapshot);
        REQUIRE(result.success());
        CHECK(result.evidence->occupancy()[15] == 0x40U);
        CHECK(result.evidence->occupancy_hex().substr(30U) == "40");
    }
}

TEST_CASE("native import baseline ignores runtime-only catalog changes") {
    auto payload = occupied_slots({0U, 1U, 2U, 3U, 4U, 6U});
    const auto first = build_valid(authoritative_snapshot(payload));
    REQUIRE(first.success());

    payload["Wireguard6"]["connected"] = false;
    payload["Wireguard6"]["link"] = false;
    payload["Wireguard6"]["uptime"] = 999999U;
    auto changed_snapshot = authoritative_snapshot(payload);
    changed_snapshot.catalog = resolve_ndms_kernel_names(
        changed_snapshot.catalog, {"nwg0", "nwg6"});
    const auto second = build_valid(changed_snapshot);
    REQUIRE(second.success());

    CHECK(second.evidence->occupancy() == first.evidence->occupancy());
    CHECK(second.evidence->protected_catalog_sha256() ==
          first.evidence->protected_catalog_sha256());
    CHECK(second.evidence->baseline_sha256() ==
          first.evidence->baseline_sha256());
}

TEST_CASE("native import baseline comparison derives redacted facts") {
    const auto baseline_result = build_valid(baseline_snapshot());
    REQUIRE(baseline_result.success());
    const auto& baseline = *baseline_result.evidence;

    auto post_payload =
        occupied_slots({0U, 1U, 2U, 3U, 4U, 5U, 6U});
    auto post = authoritative_snapshot(post_payload, 1U, 0U);
    const auto matching =
        compare_ndms_native_import_baseline(baseline, post);
    CHECK(matching.current_catalog_authoritative());
    CHECK(matching.target_absent_in_baseline());
    CHECK(matching.protected_catalog_unchanged());

    const auto persisted =
        persist_ndms_native_import_baseline(baseline);
    const auto persisted_matching =
        compare_ndms_native_import_baseline(persisted, post);
    CHECK(persisted_matching.current_catalog_authoritative());
    CHECK(persisted_matching.target_absent_in_baseline());
    CHECK(persisted_matching.protected_catalog_unchanged());

    auto tampered = persisted;
    tampered.baseline_sha256.back() =
        tampered.baseline_sha256.back() == '0' ? '1' : '0';
    const auto tampered_comparison =
        compare_ndms_native_import_baseline(tampered, post);
    CHECK_FALSE(tampered_comparison.current_catalog_authoritative());
    CHECK_FALSE(tampered_comparison.target_absent_in_baseline());
    CHECK_FALSE(tampered_comparison.protected_catalog_unchanged());

    post_payload["Wireguard5"]["description"] =
        "target state is deliberately excluded";
    post = authoritative_snapshot(post_payload, 2U, 0U);
    const auto target_changed =
        compare_ndms_native_import_baseline(baseline, post);
    CHECK(target_changed.current_catalog_authoritative());
    CHECK(target_changed.protected_catalog_unchanged());

    post_payload["Wireguard6"]["description"] =
        "protected peer changed";
    post = authoritative_snapshot(post_payload, 3U, 0U);
    const auto protected_changed =
        compare_ndms_native_import_baseline(baseline, post);
    CHECK(protected_changed.current_catalog_authoritative());
    CHECK_FALSE(protected_changed.protected_catalog_unchanged());
    const auto persisted_protected_changed =
        compare_ndms_native_import_baseline(persisted, post);
    CHECK(persisted_protected_changed.current_catalog_authoritative());
    CHECK(persisted_protected_changed.target_absent_in_baseline());
    CHECK_FALSE(
        persisted_protected_changed.protected_catalog_unchanged());

    post.status = NdmsCatalogCacheStatus::stale;
    const auto stale =
        compare_ndms_native_import_baseline(baseline, post);
    CHECK_FALSE(stale.current_catalog_authoritative());
    CHECK(stale.target_absent_in_baseline());
    CHECK_FALSE(stale.protected_catalog_unchanged());

    post = authoritative_snapshot(post_payload, 4U, 0U);
    post.catalog.wireguard_slots[7].state =
        NdmsWireguardCatalogSlotState::unsafe;
    const auto unsafe =
        compare_ndms_native_import_baseline(baseline, post);
    CHECK_FALSE(unsafe.current_catalog_authoritative());
    CHECK_FALSE(unsafe.protected_catalog_unchanged());
}

TEST_CASE("native import baseline build errors have stable redacted names") {
    for (const auto error : {
             NdmsNativeImportBaselineBuildError::none,
             NdmsNativeImportBaselineBuildError::firmware_unavailable,
             NdmsNativeImportBaselineBuildError::catalog_not_fresh,
             NdmsNativeImportBaselineBuildError::catalog_not_refreshed,
             NdmsNativeImportBaselineBuildError::
                 catalog_observation_missing,
             NdmsNativeImportBaselineBuildError::
                 observation_generation_invalid,
             NdmsNativeImportBaselineBuildError::
                 observation_epoch_mismatch,
             NdmsNativeImportBaselineBuildError::
                 slot_evidence_incomplete,
             NdmsNativeImportBaselineBuildError::
                 slot_evidence_invalid,
             NdmsNativeImportBaselineBuildError::expected_target_invalid,
             NdmsNativeImportBaselineBuildError::
                 allocator_namespace_full,
             NdmsNativeImportBaselineBuildError::
                 first_free_target_protected,
             NdmsNativeImportBaselineBuildError::
                 expected_target_occupied,
             NdmsNativeImportBaselineBuildError::
                 expected_target_not_first_free,
             NdmsNativeImportBaselineBuildError::
                 maintenance_generation_exhausted,
             NdmsNativeImportBaselineBuildError::
                 allocator_generation_invalid,
         }) {
        const auto name =
            std::string{ndms_native_import_baseline_build_error_name(error)};
        CHECK_FALSE(name.empty());
        CHECK(name.find("Wireguard") == std::string::npos);
        CHECK(name.find("ndms-wg-slot-v1-") == std::string::npos);
    }
}
