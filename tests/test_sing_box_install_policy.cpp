#include <doctest/doctest.h>

#include "../src/update/sing_box_install_policy.hpp"

#include <algorithm>
#include <string>

namespace keen_pbr3 {

namespace {

using Blocker = SingBoxInstallBlocker;
using Operation = SingBoxInstallOperation;

constexpr const char* kPinned = "1.13.14";

// A router where everything is in order: Entware present, a known
// architecture, a writable target, nothing installed, nothing running.
SingBoxInstallObservation ready() {
    SingBoxInstallObservation observation;
    observation.entware_architecture = "aarch64-3.10";
    observation.entware_present = true;
    observation.target_directory_writable = true;
    observation.running_transports = 0U;
    return observation;
}

bool blocked_by(const SingBoxInstallPolicy& policy, const Blocker blocker) {
    return std::find(policy.blockers.begin(), policy.blockers.end(),
                     blocker) != policy.blockers.end();
}

} // namespace

TEST_CASE("the asset architecture is mapped, never guessed") {
    // Guessing is how an ARM binary lands on a MIPS router.
    CHECK(sing_box_asset_architecture("aarch64-3.10") == "arm64");
    CHECK(sing_box_asset_architecture("armv7-3.2") == "armv7");
    CHECK(sing_box_asset_architecture("mipsel-3.4") == "mipsle");
    CHECK(sing_box_asset_architecture("mips-3.4") == "mips");
    CHECK(sing_box_asset_architecture("x64-3.2") == "amd64");

    for (const char* unmapped :
         {"", "aarch64", "-3.10", "aarch64-", "riscv64-6.1", "arm64-3.10",
          "AARCH64-3.10"}) {
        CHECK(sing_box_asset_architecture(unmapped).empty());
    }
}

TEST_CASE("a ready router is offered a first install") {
    const auto policy = evaluate_sing_box_install(ready(), kPinned);
    CHECK(policy.available);
    CHECK(policy.operation == Operation::install);
    CHECK(policy.blockers.empty());
    CHECK(policy.asset_architecture == "arm64");
}

TEST_CASE("an unreadable architecture is unsupported, not assumed") {
    // The read failing and the architecture being exotic are the same answer:
    // this build does not know which asset to fetch, so it fetches none.
    auto observation = ready();
    observation.entware_architecture.clear();
    const auto policy = evaluate_sing_box_install(observation, kPinned);
    CHECK_FALSE(policy.available);
    // The operation says what installing would do; being blocked does not
    // make that unknowable, and on a router with nothing installed it is an
    // install.
    CHECK(policy.operation == Operation::install);
    CHECK(blocked_by(policy, Blocker::architecture_unsupported));
    CHECK(policy.asset_architecture.empty());
}

TEST_CASE("without Entware the architecture question is unaskable") {
    auto observation = ready();
    observation.entware_present = false;
    const auto policy = evaluate_sing_box_install(observation, kPinned);
    CHECK(blocked_by(policy, Blocker::entware_absent));
    // Not also reported as unsupported: there is one reason, and naming a
    // second invented one makes the first harder to act on.
    CHECK_FALSE(blocked_by(policy, Blocker::architecture_unsupported));
}

TEST_CASE("a binary this daemon did not install is never replaced silently") {
    // The marker file is the only thing distinguishing ours from the
    // operator's. Absent marker with a present binary means theirs, and
    // overwriting it is their decision to make explicitly.
    auto observation = ready();
    observation.binary_present = true;
    observation.managed_marker_matches_binary = false;
    const auto policy = evaluate_sing_box_install(observation, kPinned);
    CHECK_FALSE(policy.available);
    CHECK(blocked_by(policy, Blocker::foreign_binary_present));

    observation.managed_marker_matches_binary = true;
    observation.installed_version = "1.12.0";
    const auto ours = evaluate_sing_box_install(observation, kPinned);
    CHECK(ours.available);
    CHECK(ours.operation == Operation::replace);
}

TEST_CASE("running transports block the swap under them") {
    auto observation = ready();
    observation.running_transports = 1U;
    const auto policy = evaluate_sing_box_install(observation, kPinned);
    CHECK_FALSE(policy.available);
    CHECK(blocked_by(policy, Blocker::transports_running));
}


TEST_CASE("a transport count nobody took is not a count of zero") {
    // The fail-open this replaced: an unreachable transport manager, or a
    // caller that supplied no probe, produced 0 - and 0 means "nothing is
    // running", which authorises the one operation the manager exists to veto.
    auto observation = ready();
    observation.running_transports.reset();
    const auto policy = evaluate_sing_box_install(observation, kPinned);
    CHECK_FALSE(policy.available);
    CHECK(blocked_by(policy, Blocker::transport_state_unknown));
    // Named apart from a nonzero count, because the operator fixes them
    // differently: one is "stop your tunnels", the other is "your transport
    // manager is down".
    CHECK_FALSE(blocked_by(policy, Blocker::transports_running));
}

TEST_CASE("a target that cannot be written to is a blocker, not a surprise") {
    auto observation = ready();
    observation.target_directory_writable = false;
    const auto policy = evaluate_sing_box_install(observation, kPinned);
    CHECK_FALSE(policy.available);
    CHECK(blocked_by(policy, Blocker::target_not_writable));
}

TEST_CASE("reinstalling the pinned version is not called an upgrade") {
    auto observation = ready();
    observation.binary_present = true;
    observation.managed_marker_matches_binary = true;
    observation.installed_version = kPinned;
    const auto policy = evaluate_sing_box_install(observation, kPinned);
    CHECK(policy.available);
    CHECK(policy.operation == Operation::reinstall_same_version);
}

TEST_CASE("a binary that will not say its version is not the pinned one") {
    // Ours, present, and silent. It might be the pinned release and might be
    // a truncated download; the only honest description of putting the pinned
    // one there is "replace".
    auto observation = ready();
    observation.binary_present = true;
    observation.managed_marker_matches_binary = true;
    observation.installed_version.clear();
    const auto policy = evaluate_sing_box_install(observation, kPinned);
    CHECK(policy.available);
    CHECK(policy.operation == Operation::replace);
}

TEST_CASE("every blocker is reported, not just the first") {
    // An operator who fixes the one reason they were shown, only to be handed
    // the next, learns to distrust the report.
    auto observation = ready();
    observation.entware_architecture = "riscv64-6.1";
    observation.target_directory_writable = false;
    observation.binary_present = true;
    observation.running_transports = 2U;
    const auto policy = evaluate_sing_box_install(observation, kPinned);

    CHECK(policy.blockers.size() == 4U);
    CHECK(blocked_by(policy, Blocker::architecture_unsupported));
    CHECK(blocked_by(policy, Blocker::target_not_writable));
    CHECK(blocked_by(policy, Blocker::foreign_binary_present));
    CHECK(blocked_by(policy, Blocker::transports_running));
}

TEST_CASE("the promises this implementation cannot keep stay false") {
    // Item 7 asks for pinned+signed with exact rescue recovery. Pinned is
    // done; the other two are not, and a client must not be able to render a
    // capability that does not exist. These flags turning true is a visible
    // change to this test, which is the point of them being fields.
    const auto policy = evaluate_sing_box_install(ready(), kPinned);
    // Earned: the installer refuses a release without either supported digest
    // source, verifies the archive before unpacking it, and requires the
    // unpacked binary to report the pinned version. Turning this back to false,
    // or claiming it without those three, both change this test.
    CHECK(policy.verified_archive_checksum);
    // Still not kept. GitHub release assets carry no signature this daemon can
    // check, and the best-effort previous copy has no verified rollback action.
    CHECK_FALSE(policy.signed_release);
    CHECK_FALSE(policy.exact_rollback);
}

TEST_CASE("a previous binary entry alone is not exact rollback") {
    auto observation = ready();
    observation.previous_binary_present = true;
    CHECK_FALSE(evaluate_sing_box_install(observation, kPinned).exact_rollback);
}

TEST_CASE("only running transports can be consented away") {
    // Consent answers the one blocker that is about the operator's choice.
    // Nobody can agree Entware into existence, agree a directory into being
    // writable, or agree away a binary that belongs to them - and a build that
    // let them would stop somebody's tunnels for an install that then refused
    // anyway.
    auto observation = ready();
    observation.running_transports = 2U;
    const auto running = evaluate_sing_box_install(observation, kPinned);
    REQUIRE_FALSE(running.available);
    CHECK(sing_box_install_awaits_transport_consent(running));

    // A second blocker alongside it is not consentable.
    auto also_unwritable = observation;
    also_unwritable.target_directory_writable = false;
    CHECK_FALSE(sing_box_install_awaits_transport_consent(
        evaluate_sing_box_install(also_unwritable, kPinned)));

    // Nothing blocking is not a case for consent either: answering true here
    // would let a caller consent to stopping transports that are not running.
    const auto available = evaluate_sing_box_install(ready(), kPinned);
    REQUIRE(available.available);
    CHECK_FALSE(sing_box_install_awaits_transport_consent(available));

    // An unknown count blocks and is NOT consentable - nobody knows what would
    // be stopped, so nobody can have agreed to it.
    auto unknown = ready();
    unknown.running_transports.reset();
    CHECK_FALSE(sing_box_install_awaits_transport_consent(
        evaluate_sing_box_install(unknown, kPinned)));
}

TEST_CASE("every blocker and operation has a name") {
    for (const auto blocker :
         {Blocker::architecture_unsupported, Blocker::entware_absent,
          Blocker::target_not_writable, Blocker::foreign_binary_present,
          Blocker::transports_running, Blocker::transport_state_unknown}) {
        CHECK(std::string(sing_box_install_blocker_name(blocker)).size() >
              0U);
    }
    for (const auto operation :
         {Operation::install, Operation::replace,
          Operation::reinstall_same_version}) {
        CHECK(std::string(sing_box_install_operation_name(operation))
                  .size() > 0U);
    }
}

TEST_CASE("a blocked install still says what installing would do") {
    // Measured on NC-1812: sing-box at exactly the pinned version, our marker
    // present, one transport running. The capability answered "blocked" and
    // nothing else, so the WebUI could not tell "stop your tunnel and I will
    // update you" from "stop your tunnel so I can install what you already
    // have" - and offered an Update button that had nothing to do.
    auto observation = ready();
    observation.binary_present = true;
    observation.managed_marker_matches_binary = true;
    observation.installed_version = kPinned;
    observation.running_transports = 1U;

    const auto policy = evaluate_sing_box_install(observation, kPinned);
    CHECK_FALSE(policy.available);
    CHECK(blocked_by(policy, Blocker::transports_running));
    // The operation is what installing WOULD do, and it does not become
    // unknowable because something is in the way.
    CHECK(policy.operation ==
          SingBoxInstallOperation::reinstall_same_version);
}

TEST_CASE("consent is not asked for an install that would change nothing") {
    // Dropping somebody tunnels so the daemon can reinstall the version
    // already on the router is a question whose honest answer is always no.
    auto observation = ready();
    observation.binary_present = true;
    observation.managed_marker_matches_binary = true;
    observation.installed_version = kPinned;
    observation.running_transports = 2U;
    CHECK_FALSE(sing_box_install_awaits_transport_consent(
        evaluate_sing_box_install(observation, kPinned)));

    // A different installed version is worth the interruption, so consent is
    // asked there.
    observation.installed_version = "1.12.0";
    CHECK(sing_box_install_awaits_transport_consent(
        evaluate_sing_box_install(observation, kPinned)));
}

} // namespace keen_pbr3
