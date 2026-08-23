#include <doctest/doctest.h>

#include "../src/update/component_boot_recovery.hpp"

#include <string>

namespace keen_pbr3 {

namespace {

ComponentTransactionRecord mutating_record() {
    ComponentTransactionRecord record;
    record.component = "nfqws2-keenetic";
    record.operation = "upgrade";
    record.phase = ComponentTransactionPhase::mutating;
    record.binary_sha256 = std::string(64, 'a');
    record.previous_version = "1.2.4";
    record.target_version = "1.2.5";
    record.exact_previous_ipk = true;
    return record;
}

ComponentBootRecoveryEvidence abandoned_with(
    const ComponentTransactionRecord& record) {
    ComponentBootRecoveryEvidence evidence;
    evidence.journal.state = ComponentTransactionState::abandoned;
    evidence.journal.record = record;
    return evidence;
}

IpkSlotInspection usable_ipk(const std::string& version) {
    IpkSlotInspection inspection;
    inspection.state = IpkSlotState::usable;
    RetainedIpk retained;
    retained.version = version;
    retained.sha256 = std::string(64, 'c');
    retained.size = 10;
    retained.filename = "x.ipk";
    inspection.retained = retained;
    return inspection;
}

} // namespace

TEST_CASE("no journal or a live owner means nothing to recover") {
    ComponentBootRecoveryEvidence evidence;
    CHECK(decide_component_boot_recovery(evidence).action ==
          ComponentBootRecoveryAction::none);
    evidence.journal.state = ComponentTransactionState::in_flight;
    evidence.journal.record = mutating_record();
    CHECK(decide_component_boot_recovery(evidence).action ==
          ComponentBootRecoveryAction::none);
}

TEST_CASE("an unreadable journal is handed to the operator, never guessed") {
    ComponentBootRecoveryEvidence evidence;
    evidence.journal.state = ComponentTransactionState::unreadable;
    evidence.previous_ipk = usable_ipk("1.2.4");
    evidence.capture = ComponentCaptureState::usable;
    const auto plan = decide_component_boot_recovery(evidence);
    CHECK(plan.action == ComponentBootRecoveryAction::manual);
    CHECK_FALSE(plan.clear_journal_on_success);
}

TEST_CASE("interrupted before mutation: the journal is simply cleared") {
    auto record = mutating_record();
    record.phase = ComponentTransactionPhase::started;
    const auto plan = decide_component_boot_recovery(abandoned_with(record));
    CHECK(plan.action == ComponentBootRecoveryAction::clear_journal);
    CHECK(plan.clear_journal_on_success);
}

TEST_CASE("package provably unchanged: restore files, or manual without a capture") {
    auto evidence = abandoned_with(mutating_record());
    evidence.installed_version = "1.2.4";
    evidence.installed_binary_sha256 = std::string(64, 'a');

    SUBCASE("with a usable capture") {
        evidence.capture = ComponentCaptureState::usable;
        const auto plan = decide_component_boot_recovery(evidence);
        CHECK(plan.action == ComponentBootRecoveryAction::restore_files);
        CHECK(plan.clear_journal_on_success);
    }
    SUBCASE("without one") {
        evidence.capture = ComponentCaptureState::incomplete;
        const auto plan = decide_component_boot_recovery(evidence);
        CHECK(plan.action == ComponentBootRecoveryAction::manual);
        CHECK_FALSE(plan.clear_journal_on_success);
    }
    SUBCASE("an unknown digest is not a match") {
        evidence.installed_binary_sha256.clear();
        evidence.capture = ComponentCaptureState::usable;
        evidence.previous_ipk = usable_ipk("1.2.4");
        const auto plan = decide_component_boot_recovery(evidence);
        // Falls through to the exact reinstall, which does not depend on
        // reading the binary.
        CHECK(plan.action == ComponentBootRecoveryAction::reinstall_previous);
    }
}

TEST_CASE("package changed and the exact previous ipk is held: reinstall it") {
    auto evidence = abandoned_with(mutating_record());
    evidence.installed_version = "1.2.5";
    evidence.installed_binary_sha256 = std::string(64, 'b');
    evidence.previous_ipk = usable_ipk("1.2.4");
    evidence.capture = ComponentCaptureState::usable;

    const auto plan = decide_component_boot_recovery(evidence);
    CHECK(plan.action == ComponentBootRecoveryAction::reinstall_previous);
    CHECK(plan.reinstall_version == "1.2.4");
    CHECK(plan.clear_journal_on_success);

    SUBCASE("the store holds another version: that is not the exact one") {
        evidence.previous_ipk = usable_ipk("1.2.3");
        const auto other = decide_component_boot_recovery(evidence);
        CHECK(other.action == ComponentBootRecoveryAction::restore_files_inexact);
        CHECK_FALSE(other.clear_journal_on_success);
        CHECK(other.reason.find("no longer holds") != std::string::npos);
    }
    SUBCASE("the store's copy is corrupt") {
        evidence.previous_ipk.state = IpkSlotState::corrupt;
        evidence.previous_ipk.retained.reset();
        CHECK(decide_component_boot_recovery(evidence).action ==
              ComponentBootRecoveryAction::restore_files_inexact);
    }
    SUBCASE("the journal never promised an exact copy: the store is not consulted") {
        auto record = mutating_record();
        record.exact_previous_ipk = false;
        auto unpromised = abandoned_with(record);
        unpromised.installed_version = "1.2.5";
        unpromised.previous_ipk = usable_ipk("1.2.4");
        unpromised.capture = ComponentCaptureState::usable;
        const auto plan2 = decide_component_boot_recovery(unpromised);
        CHECK(plan2.action == ComponentBootRecoveryAction::restore_files_inexact);
        CHECK(plan2.reason.find("no exact previous package was retained") !=
              std::string::npos);
    }
    SUBCASE("exact ipk but no capture: reinstall alone would overstate") {
        evidence.capture = ComponentCaptureState::absent;
        const auto plan3 = decide_component_boot_recovery(evidence);
        CHECK(plan3.action == ComponentBootRecoveryAction::manual);
    }
    SUBCASE("nothing at all") {
        evidence.previous_ipk = IpkSlotInspection{};
        evidence.capture = ComponentCaptureState::absent;
        CHECK(decide_component_boot_recovery(evidence).action ==
              ComponentBootRecoveryAction::manual);
    }
}

TEST_CASE("a legacy journal without versions can only restore files inexactly") {
    ComponentTransactionRecord record;
    record.component = "nfqws2-keenetic";
    record.operation = "upgrade";
    record.phase = ComponentTransactionPhase::verifying;
    auto evidence = abandoned_with(record);
    evidence.installed_version = "1.2.4";
    evidence.previous_ipk = usable_ipk("1.2.4");
    evidence.capture = ComponentCaptureState::usable;
    const auto plan = decide_component_boot_recovery(evidence);
    CHECK(plan.action == ComponentBootRecoveryAction::restore_files_inexact);
    CHECK_FALSE(plan.clear_journal_on_success);
}

TEST_CASE("every recovery action has a distinct name") {
    CHECK(std::string(component_boot_recovery_action_name(
              ComponentBootRecoveryAction::none)) == "none");
    CHECK(std::string(component_boot_recovery_action_name(
              ComponentBootRecoveryAction::reinstall_previous)) ==
          "reinstall_previous");
    CHECK(std::string(component_boot_recovery_action_name(
              ComponentBootRecoveryAction::restore_files_inexact)) ==
          "restore_files_inexact");
    CHECK(std::string(component_boot_recovery_action_name(
              ComponentBootRecoveryAction::manual)) == "manual");
}

} // namespace keen_pbr3
