#include <doctest/doctest.h>

#include "keenetic/ndms_native_create_policy.hpp"
#include "keenetic/ndms_wireguard_identity.hpp"

#include <string>
#include <vector>

using namespace keen_pbr3;

TEST_CASE("WireGuard identities share one strict canonical parser") {
    const auto zero = parse_ndms_wireguard_identity("Wireguard0");
    REQUIRE(zero.has_value());
    CHECK(zero->slot == 0U);
    CHECK(zero->slot_class ==
          NdmsWireguardSlotClass::protected_system);
    CHECK(zero->canonical_name() == "Wireguard0");

    const auto five = parse_ndms_wireguard_identity("Wireguard5");
    REQUIRE(five.has_value());
    CHECK(ndms_wireguard_identity_is_managed_candidate(*five));
    CHECK_FALSE(ndms_wireguard_identity_is_protected(*five));

    const auto ninety_eight =
        parse_ndms_wireguard_identity("Wireguard98");
    REQUIRE(ninety_eight.has_value());
    CHECK(ninety_eight->slot_class ==
          NdmsWireguardSlotClass::managed_candidate);

    const auto ninety_nine =
        parse_ndms_wireguard_identity("Wireguard99");
    REQUIRE(ninety_nine.has_value());
    CHECK(ninety_nine->slot_class ==
          NdmsWireguardSlotClass::protected_sentinel);

    const auto one_twenty_six =
        parse_ndms_wireguard_identity("Wireguard126");
    REQUIRE(one_twenty_six.has_value());
    CHECK(one_twenty_six->slot_class ==
          NdmsWireguardSlotClass::protected_sentinel);
    CHECK(ndms_wireguard_identity_is_protected(*one_twenty_six));

    for (const std::string invalid : {
             "Wireguard", "Wireguard00", "Wireguard05",
             "Wireguard010", "Wireguard127", "wireguard5",
             "Wireguard5/../../system", "Wireguard5?x"}) {
        CAPTURE(invalid);
        CHECK_FALSE(parse_ndms_wireguard_identity(invalid).has_value());
    }
}

TEST_CASE("native create policy describes only the dormant stock primitive") {
    const auto policy = preview_ndms_native_create_policy();
    CHECK(ndms_native_create_policy_is_consistent(policy));
    CHECK(policy.preview_only);
    CHECK_FALSE(policy.apply_available);
    CHECK(policy.operation == "interface.wireguard.import");
    CHECK(policy.request_name.empty());
    CHECK(policy.batch_item_count == 1U);
    const NdmsNativeWireguardTargetRange allocator{0U, 126U};
    const NdmsNativeWireguardTargetRange eligible{5U, 98U};
    const std::vector<NdmsNativeWireguardTargetRange> protected_ranges{
        {0U, 4U}, {99U, 126U}};
    const std::vector<NdmsNativeCreatePolicyBlocker> blockers{
        NdmsNativeCreatePolicyBlocker::writer_disabled,
        NdmsNativeCreatePolicyBlocker::allocator_range_unfenced,
        NdmsNativeCreatePolicyBlocker::
            recovery_journal_not_integrated,
        NdmsNativeCreatePolicyBlocker::
            reconcile_barrier_not_integrated};
    CHECK(policy.allocator_range == allocator);
    CHECK(policy.eligible_returned_targets == eligible);
    CHECK(policy.protected_targets == protected_ranges);
    CHECK(policy.blockers == blockers);
    CHECK(std::string{ndms_native_dormant_facility_state_name(
              policy.journal_state)} == "dormant");
}

TEST_CASE("native create result policy separates eligible and protected targets") {
    for (const std::string eligible :
         {"Wireguard5", "Wireguard47", "Wireguard98"}) {
        CHECK(ndms_native_created_target_is_eligible(eligible));
        CHECK_FALSE(ndms_native_created_target_is_protected(eligible));
    }
    for (const std::string protected_target :
         {"Wireguard0", "Wireguard4", "Wireguard99",
          "Wireguard100", "Wireguard126"}) {
        CHECK_FALSE(
            ndms_native_created_target_is_eligible(protected_target));
        CHECK(ndms_native_created_target_is_protected(protected_target));
    }
    for (const std::string unsupported :
         {"Wireguard127", "Wireguard999", "Wireguard05"}) {
        CHECK_FALSE(ndms_native_created_target_is_eligible(unsupported));
        CHECK_FALSE(ndms_native_created_target_is_protected(unsupported));
    }
}

TEST_CASE("native create policy consistency rejects every capability escalation") {
    const auto original = preview_ndms_native_create_policy();

    auto apply = original;
    apply.apply_available = true;
    CHECK_FALSE(ndms_native_create_policy_is_consistent(apply));

    auto named = original;
    named.request_name = "Wireguard5";
    CHECK_FALSE(ndms_native_create_policy_is_consistent(named));

    auto widened = original;
    widened.eligible_returned_targets.last_index = 99U;
    CHECK_FALSE(ndms_native_create_policy_is_consistent(widened));

    auto missing_blocker = original;
    missing_blocker.blockers.erase(
        missing_blocker.blockers.begin());
    CHECK_FALSE(ndms_native_create_policy_is_consistent(missing_blocker));
}
