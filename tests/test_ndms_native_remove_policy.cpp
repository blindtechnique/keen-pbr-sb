#include <doctest/doctest.h>

#include "../src/keenetic/ndms_native_remove_policy.hpp"

#include "../src/keenetic/ndms_native_interface_delete.hpp"

#include <algorithm>
#include <string>

namespace keen_pbr3 {

TEST_CASE("removal never claims an allocator fence it does not need") {
    // The whole reason this policy is separate from the create policy. The
    // stock import posts an empty name, so the firmware chooses the slot and
    // creation waits on a guarantee 5.1.1 does not offer. Removal names its
    // target exactly and allocates nothing. Reporting one readiness for both
    // would tell an operator that removing a tunnel waits on a fence.
    const auto policy = preview_ndms_native_remove_policy();
    for (const auto blocker : policy.blockers) {
        const std::string name =
            ndms_native_remove_policy_blocker_name(blocker);
        CHECK(name.find("fence") == std::string::npos);
        CHECK(name.find("allocator") == std::string::npos);
    }
    // ...and the create policy still does declare it, so this is a real
    // difference rather than both having quietly dropped it.
    const auto create = preview_ndms_native_create_policy();
    CHECK(std::find(create.blockers.begin(), create.blockers.end(),
                    NdmsNativeCreatePolicyBlocker::
                        allocator_range_unfenced) !=
          create.blockers.end());
}

TEST_CASE("the removal preview offers nothing and says why") {
    const auto policy = preview_ndms_native_remove_policy();
    CHECK(policy.preview_only);
    CHECK_FALSE(policy.apply_available);
    CHECK(ndms_native_remove_policy_is_consistent(policy));
    // Two honest blockers: the master switch, and the fact that a claim can
    // only exist after an import that this firmware cannot perform.
    CHECK(policy.blockers.size() == 2U);
}

TEST_CASE("a preview that promised more would be inconsistent") {
    auto policy = preview_ndms_native_remove_policy();
    policy.apply_available = true;
    CHECK_FALSE(ndms_native_remove_policy_is_consistent(policy));

    policy = preview_ndms_native_remove_policy();
    policy.blockers.clear();
    CHECK_FALSE(ndms_native_remove_policy_is_consistent(policy));

    policy = preview_ndms_native_remove_policy();
    policy.removable_targets = {0U, 126U};
    CHECK_FALSE(ndms_native_remove_policy_is_consistent(policy));

    policy = preview_ndms_native_remove_policy();
    policy.protected_targets.clear();
    CHECK_FALSE(ndms_native_remove_policy_is_consistent(policy));
}

TEST_CASE("the published operation is the command actually issued") {
    // The readiness report and the implementation must not describe different
    // commands: an operator reading "no interface" has to get exactly that.
    const auto policy = preview_ndms_native_remove_policy();
    const auto command =
        ndms_native_interface_delete_command("Wireguard5");
    CHECK(command.rfind(policy.operation, 0U) == 0U);
    CHECK(command == policy.operation + " Wireguard5");
}

TEST_CASE("only managed candidates are removable, and by one rule") {
    for (const char* name : {"Wireguard5", "Wireguard50", "Wireguard98"}) {
        CHECK(ndms_native_removable_target(name));
    }
    for (const char* name : {"Wireguard0", "Wireguard4", "Wireguard99",
                             "Wireguard126", "wireguard5", "Wireguard05",
                             "Wireguard", ""}) {
        CHECK_FALSE(ndms_native_removable_target(name));
    }
    // Shared with the create policy's eligibility rule rather than restated:
    // two definitions of "managed candidate" is how they come to disagree.
    const auto policy = preview_ndms_native_remove_policy();
    for (unsigned slot = 0U; slot <= 126U; ++slot) {
        const auto name = "Wireguard" + std::to_string(slot);
        CHECK(ndms_native_removable_target(name) ==
              policy.removable_targets.contains(
                  static_cast<std::uint8_t>(slot)));
    }
}

TEST_CASE("every blocker has a name") {
    for (const auto blocker :
         {NdmsNativeRemovePolicyBlocker::writer_disabled,
          NdmsNativeRemovePolicyBlocker::
              no_claims_can_exist_until_import_works}) {
        CHECK(std::string(
                  ndms_native_remove_policy_blocker_name(blocker))
                  .size() > 0U);
    }
}

} // namespace keen_pbr3
