#include <doctest/doctest.h>

#include "../src/keenetic/ndms_native_ownership_store.hpp"

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace keen_pbr3 {

namespace {

namespace fs = std::filesystem;

class TempDirectory {
public:
    TempDirectory() {
        std::string pattern =
            (fs::temp_directory_path() / "keen-pbr-own-XXXXXX").string();
        std::vector<char> writable(pattern.begin(), pattern.end());
        writable.push_back('\0');
        const char* created = ::mkdtemp(writable.data());
        REQUIRE(created != nullptr);
        path = created;
    }

    ~TempDirectory() {
        std::error_code error;
        fs::remove_all(path, error);
    }

    fs::path path;
};

NdmsNativeOwnershipRecord record_fixture() {
    NdmsNativeOwnershipRecord record;
    record.interface_name = "Wireguard5";
    record.transaction_id = std::string(32U, 'a');
    record.marker = "kpbr-ni-v1-" + record.transaction_id;
    record.snapshot_revision =
        "ndms-native-import-v1-" + std::string(64U, 'c');
    record.target_full_revision =
        "ndms-rci-full-v1-" + std::string(64U, 'b');
    return record;
}

NdmsNativeOwnershipLifecycleEvidence lifecycle_evidence_fixture() {
    NdmsNativeOwnershipLifecycleEvidence evidence;
    evidence.transaction_id = std::string(32U, 'd');
    evidence.observation_binding = {std::string(32U, 'e'), 9U, 7U};
    evidence.runtime_catalog_revision =
        "ndms-native-catalog-v1-" + std::string(64U, 'f');
    evidence.runtime_sequence = 8U;
    evidence.running_config_catalog_revision =
        "ndms-native-catalog-v1-" + std::string(64U, '1');
    evidence.running_config_sequence = 9U;
    return evidence;
}

NdmsNativeOwnershipRecord lifecycle_record(
    NdmsNativeOwnershipRecord record,
    const NdmsNativeOwnershipLifecycle lifecycle) {
    record.schema_version = kNdmsNativeOwnershipSchemaVersion;
    record.lifecycle = lifecycle;
    if (lifecycle ==
        NdmsNativeOwnershipLifecycle::active_running_only) {
        record.lifecycle_evidence.reset();
    } else {
        record.lifecycle_evidence = lifecycle_evidence_fixture();
    }
    return record;
}

std::string ownership_body(const NdmsNativeOwnershipRecord& record) {
    const char* kind = record.kind ==
                               NdmsNativeTunnelImportKind::amnezia_wireguard
                           ? "amnezia_wireguard"
                           : "wireguard";
    std::string body = std::string(
        record.schema_version == 2U
            ? "keen-pbr-native-ownership-v2\n"
            : "keen-pbr-native-ownership-v3\n") +
        record.interface_name + "\n" + record.transaction_id + "\n" +
        record.marker + "\n" + kind + "\n" +
        record.snapshot_revision + "\n" +
        record.target_full_revision + "\n";
    if (record.schema_version == 2U) return body;
    body += std::string{ndms_native_ownership_lifecycle_name(
                record.lifecycle)} + "\n";
    if (!record.lifecycle_evidence) {
        for (std::size_t index = 0U; index < 8U; ++index) body += "-\n";
        return body;
    }
    const auto& evidence = *record.lifecycle_evidence;
    body += evidence.transaction_id + "\n" +
            evidence.observation_binding.authority_id + "\n" +
            std::to_string(evidence.observation_binding.mutation_epoch) +
            "\n" +
            std::to_string(evidence.observation_binding.baseline_sequence) +
            "\n" + evidence.runtime_catalog_revision + "\n" +
            std::to_string(evidence.runtime_sequence) + "\n" +
            evidence.running_config_catalog_revision + "\n" +
            std::to_string(evidence.running_config_sequence) + "\n";
    return body;
}

bool has_ownership_temporary(const fs::path& directory) {
    for (const auto& entry : fs::directory_iterator(directory)) {
        if (entry.path().filename().string().rfind(
                ".keen-pbr-ownership-tmp-", 0U) == 0U) {
            return true;
        }
    }
    return false;
}

int exited_child_status(const pid_t child) {
    int status = 0;
    pid_t waited = -1;
    do {
        waited = ::waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    REQUIRE(waited == child);
    REQUIRE(WIFEXITED(status));
    return WEXITSTATUS(status);
}

} // namespace

TEST_CASE("a published claim reads back exactly, with a stable revision") {
    TempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    const auto record = record_fixture();
    const auto revision = store.publish(record);
    CHECK(revision == ndms_native_ownership_revision(record));

    const auto read = store.read("Wireguard5");
    REQUIRE(read.state == NdmsNativeOwnershipReadState::valid);
    REQUIRE(read.record.has_value());
    CHECK(*read.record == record);
    REQUIRE(read.revision.has_value());
    CHECK(*read.revision == revision);

    // Any field change moves the revision - the WAL carries the digest, and a
    // digest that survived a field change would let a swapped claim pass the
    // ownership_record_matches comparison.
    auto other = record;
    other.snapshot_revision =
        "ndms-native-import-v1-" + std::string(64U, 'd');
    CHECK(ndms_native_ownership_revision(other) != revision);
    other = record;
    other.target_full_revision =
        "ndms-rci-full-v1-" + std::string(64U, 'c');
    CHECK(ndms_native_ownership_revision(other) != revision);
}

TEST_CASE("a protected slot cannot even be claimed") {
    TempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    for (const char* name : {"Wireguard0", "Wireguard99", "Wireguard126",
                             "Wireguard05", "wireguard5", "Wireguard127"}) {
        auto record = record_fixture();
        record.interface_name = name;
        CHECK_THROWS(store.publish(record));
        // And a claim planted by hand is refused at read, before any caller
        // can act on it.
        CHECK(store.read(name).state ==
              NdmsNativeOwnershipReadState::unreadable);
    }
}

TEST_CASE("a torn claim is unreadable, never absent") {
    TempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    store.publish(record_fixture());

    std::ofstream torn(directory.path / "ownership" / "Wireguard5",
                       std::ios::binary | std::ios::trunc);
    torn << "keen-pbr-native-ownership-v2\nWireguard5\n";
    torn.close();

    // "No claim" is exactly the reading that must not come from a torn one:
    // it would tell recovery the interface belongs to the operator.
    CHECK(store.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::unreadable);
}

TEST_CASE("legacy v1 ownership is quarantined, never read as absence") {
    TempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    const auto record = record_fixture();
    store.publish(record);

    std::ofstream legacy(
        directory.path / "ownership" / "Wireguard5",
        std::ios::binary | std::ios::trunc);
    legacy << "keen-pbr-native-ownership-v1\n"
           << record.interface_name << '\n'
           << record.transaction_id << '\n'
           << record.marker << "\nwireguard\n"
           << record.target_full_revision << '\n';
    legacy.close();

    // Production mutation was disabled when v1 existed, so there is no
    // automatic adoption. Legacy claims require an explicit owner action;
    // silently treating one as absent could authorize somebody else's slot.
    CHECK(store.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::unreadable);
    CHECK_FALSE(store.remove_exact(record));
}

TEST_CASE("a claim naming a different interface than its filename is refused") {
    TempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    auto record = record_fixture();
    record.interface_name = "Wireguard6";
    store.publish(record);

    std::error_code error;
    fs::rename(directory.path / "ownership" / "Wireguard6",
               directory.path / "ownership" / "Wireguard5", error);
    REQUIRE_FALSE(error);
    // A renamed claim asserts ownership of an interface it never named.
    CHECK(store.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::unreadable);
}

TEST_CASE("remove_exact removes only the claim it was shown") {
    TempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    const auto record = record_fixture();
    store.publish(record);

    auto different = record;
    different.target_full_revision =
        "ndms-rci-full-v1-" + std::string(64U, 'c');
    CHECK_FALSE(store.remove_exact(different));
    CHECK(store.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::valid);

    CHECK(store.remove_exact(record));
    CHECK(store.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::absent);
    // Removing an absent claim is not a success: the caller asked to remove
    // something that is not what the store holds.
    CHECK_FALSE(store.remove_exact(record));
}

TEST_CASE("the published revision satisfies the recovery observation") {
    TempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    const auto claim = record_fixture();
    const auto revision = store.publish(claim);

    // The wiring the classifier's ownership_published phase depends on: the
    // WAL carries this revision, the store returns it on read, and the
    // observation builder compares the two.
    NdmsNativeImportWalRecord record;
    record.ownership_revision = revision;
    const auto read = store.read("Wireguard5");
    REQUIRE(read.revision.has_value());
    CHECK(*read.revision == *record.ownership_revision);
}

TEST_CASE("claims are immutable and an exact retry repairs publication durability") {
    TempDirectory directory;
    const auto state = directory.path / "ownership";
    const auto record = record_fixture();

    NdmsNativeOwnershipStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    hooks.fault_injector = [](const auto stage) {
        if (stage == NdmsNativeOwnershipStoreFaultStage::
                         post_rename_directory_fsync) {
            throw std::runtime_error("injected directory fsync failure");
        }
    };
    NdmsNativeOwnershipStore interrupted(state, hooks);
    CHECK_THROWS(interrupted.publish(record));
    CHECK(fs::exists(state / "Wireguard5"));

    NdmsNativeOwnershipStore retry(state);
    const auto revision = retry.publish(record);
    CHECK(revision == ndms_native_ownership_revision(record));

    auto different = record;
    different.target_full_revision =
        "ndms-rci-full-v1-" + std::string(64U, 'c');
    CHECK_THROWS(retry.publish(different));
    const auto read = retry.read("Wireguard5");
    REQUIRE(read.record.has_value());
    CHECK(*read.record == record);
}

TEST_CASE("replace_exact has no unlink gap and is crash-idempotent") {
    TempDirectory directory;
    const auto state = directory.path / "ownership";
    const auto expected = record_fixture();
    const auto replacement = lifecycle_record(
        expected,
        NdmsNativeOwnershipLifecycle::
            active_save_acknowledged_unverified);

    NdmsNativeOwnershipStore initial(state);
    initial.publish(expected);

    bool existed_after_atomic_replace = false;
    NdmsNativeOwnershipStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    hooks.fault_injector = [&](const auto stage) {
        if (stage == NdmsNativeOwnershipStoreFaultStage::
                         post_rename_directory_fsync) {
            existed_after_atomic_replace =
                fs::exists(state / "Wireguard5");
            throw std::runtime_error("injected replace fsync failure");
        }
    };
    NdmsNativeOwnershipStore interrupted(state, hooks);
    CHECK_FALSE(interrupted.replace_exact(expected, replacement)
                    .has_value());
    CHECK(existed_after_atomic_replace);

    NdmsNativeOwnershipStore retry(state);
    const auto visible = retry.read("Wireguard5");
    REQUIRE(visible.record.has_value());
    CHECK(*visible.record == replacement);
    const auto revision = retry.replace_exact(expected, replacement);
    REQUIRE(revision.has_value());
    CHECK(*revision == ndms_native_ownership_revision(replacement));

    auto stale = expected;
    stale.target_full_revision =
        "ndms-rci-full-v1-" + std::string(64U, 'e');
    CHECK_FALSE(retry.replace_exact(stale, expected).has_value());
    auto rebound_snapshot = replacement;
    rebound_snapshot.snapshot_revision =
        "ndms-native-import-v1-" + std::string(64U, 'e');
    CHECK_FALSE(
        retry.replace_exact(replacement, rebound_snapshot).has_value());
    auto rebound_target = replacement;
    rebound_target.target_full_revision =
        "ndms-rci-full-v1-" + std::string(64U, 'f');
    CHECK_FALSE(
        retry.replace_exact(replacement, rebound_target).has_value());
    auto rebound_evidence = replacement;
    ++rebound_evidence.lifecycle_evidence->runtime_sequence;
    CHECK_FALSE(
        retry.replace_exact(replacement, rebound_evidence).has_value());
    const auto final_read = retry.read("Wireguard5");
    REQUIRE(final_read.record.has_value());
    CHECK(*final_read.record == replacement);
}

TEST_CASE("portable no-replace publication recovers both crash windows") {
    SUBCASE("dead pre-publish temporary is retired") {
        TempDirectory directory;
        const auto state = directory.path / "ownership";
        const auto record = record_fixture();
        const pid_t child = ::fork();
        REQUIRE(child >= 0);
        if (child == 0) {
            NdmsNativeOwnershipStoreTestHooks hooks;
            hooks.allow_current_process_owner = true;
            hooks.force_portable_linkat = true;
            hooks.fault_injector = [](const auto stage) {
                if (stage == NdmsNativeOwnershipStoreFaultStage::
                                 pre_publish_after_file_fsync) {
                    ::_exit(81);
                }
            };
            try {
                NdmsNativeOwnershipStore store(state, hooks);
                (void)store.publish(record);
            } catch (...) {
                ::_exit(91);
            }
            ::_exit(92);
        }
        CHECK(exited_child_status(child) == 81);
        REQUIRE(has_ownership_temporary(state));

        NdmsNativeOwnershipStore retry(state);
        CHECK_NOTHROW(retry.publish(record));
        CHECK_FALSE(has_ownership_temporary(state));
        const auto read = retry.read("Wireguard5");
        REQUIRE(read.record.has_value());
        CHECK(*read.record == record);
    }

    SUBCASE("linked nlink-two temporary is completed without replay") {
        TempDirectory directory;
        const auto state = directory.path / "ownership";
        const auto record = record_fixture();
        const pid_t child = ::fork();
        REQUIRE(child >= 0);
        if (child == 0) {
            NdmsNativeOwnershipStoreTestHooks hooks;
            hooks.allow_current_process_owner = true;
            hooks.force_portable_linkat = true;
            hooks.fault_injector = [](const auto stage) {
                if (stage == NdmsNativeOwnershipStoreFaultStage::
                                 post_link_before_unlink) {
                    ::_exit(82);
                }
            };
            try {
                NdmsNativeOwnershipStore store(state, hooks);
                (void)store.publish(record);
            } catch (...) {
                ::_exit(93);
            }
            ::_exit(94);
        }
        CHECK(exited_child_status(child) == 82);
        CHECK(has_ownership_temporary(state));
        CHECK(fs::exists(state / "Wireguard5"));

        NdmsNativeOwnershipStore retry(state);
        CHECK_NOTHROW(retry.publish(record));
        CHECK_FALSE(has_ownership_temporary(state));
        const auto read = retry.read("Wireguard5");
        REQUIRE(read.record.has_value());
        CHECK(*read.record == record);
    }
}

TEST_CASE("listing cleans a dead temporary and repeats the same sorted inventory") {
    TempDirectory directory;
    const auto state = directory.path / "ownership";
    NdmsNativeOwnershipStore store(state);
    auto five = record_fixture();
    auto six = five;
    six.interface_name = "Wireguard6";
    store.publish(six);
    store.publish(five);

    auto seven = five;
    seven.interface_name = "Wireguard7";
    const pid_t child = ::fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        NdmsNativeOwnershipStoreTestHooks hooks;
        hooks.allow_current_process_owner = true;
        hooks.force_portable_linkat = true;
        hooks.fault_injector = [](const auto stage) {
            if (stage == NdmsNativeOwnershipStoreFaultStage::
                             pre_publish_after_file_fsync) {
                ::_exit(83);
            }
        };
        try {
            NdmsNativeOwnershipStore child_store(state, hooks);
            (void)child_store.publish(seven);
        } catch (...) {
            ::_exit(95);
        }
        ::_exit(96);
    }
    CHECK(exited_child_status(child) == 83);
    REQUIRE(has_ownership_temporary(state));

    const auto first = store.list_claimed_interfaces();
    REQUIRE(first.readable);
    CHECK(first.interface_names ==
          (std::vector<std::string>{"Wireguard5", "Wireguard6"}));
    CHECK_FALSE(has_ownership_temporary(state));
    const auto second = store.list_claimed_interfaces();
    CHECK(second.readable);
    CHECK(second.interface_names == first.interface_names);
}

TEST_CASE("remove_exact is content-bound even across an in-place inode mutation") {
    TempDirectory directory;
    const auto state = directory.path / "ownership";
    const auto record = record_fixture();
    const auto replacement = lifecycle_record(
        record,
        NdmsNativeOwnershipLifecycle::
            active_save_acknowledged_unverified);

    bool replaced = false;
    NdmsNativeOwnershipStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    hooks.fault_injector = [&](const auto stage) {
        if (!replaced &&
            stage == NdmsNativeOwnershipStoreFaultStage::
                         before_remove_inode_recheck) {
            replaced = true;
            std::ofstream output(state / "Wireguard5",
                                 std::ios::binary | std::ios::trunc);
            output << ownership_body(replacement);
            output.close();
        }
    };
    NdmsNativeOwnershipStore store(state, hooks);
    store.publish(record);
    CHECK_FALSE(store.remove_exact(record));
    CHECK(replaced);
    const auto read = store.read("Wireguard5");
    REQUIRE(read.record.has_value());
    CHECK(*read.record == replacement);
}

TEST_CASE("legacy v2 bytes transition exactly to v3 lifecycle evidence") {
    TempDirectory directory;
    const auto state = directory.path / "ownership";
    NdmsNativeOwnershipStore seed(state);
    const auto current = record_fixture();
    seed.publish(current);

    auto legacy = current;
    legacy.schema_version = 2U;
    {
        std::ofstream output(
            state / "Wireguard5", std::ios::binary | std::ios::trunc);
        output << ownership_body(legacy);
    }
    REQUIRE(::chmod((state / "Wireguard5").c_str(), 0600) == 0);

    const auto read = seed.read("Wireguard5");
    REQUIRE(read.state == NdmsNativeOwnershipReadState::valid);
    REQUIRE(read.record.has_value());
    REQUIRE(read.revision.has_value());
    CHECK(read.record->schema_version == 2U);
    CHECK(read.record->lifecycle ==
          NdmsNativeOwnershipLifecycle::active_running_only);
    CHECK_FALSE(read.record->lifecycle_evidence.has_value());
    CHECK(read.revision->rfind("ndms-native-owner-v2-", 0U) == 0U);

    const auto tombstone = lifecycle_record(
        *read.record,
        NdmsNativeOwnershipLifecycle::
            deleted_save_acknowledged_unverified);
    const auto transitioned = seed.replace_exact(*read.record, tombstone);
    REQUIRE(transitioned.has_value());
    CHECK(transitioned->rfind(
              "ndms-native-owner-tombstone-v1-", 0U) == 0U);
    const auto final_read = seed.read("Wireguard5");
    REQUIRE(final_read.record.has_value());
    CHECK(*final_read.record == tombstone);
    CHECK_FALSE(seed.remove_exact(tombstone));
}

TEST_CASE("a v2 to v3 replacement race preserves the replacement bytes") {
    TempDirectory directory;
    const auto state = directory.path / "ownership";
    auto expected = record_fixture();
    NdmsNativeOwnershipStore seed(state);
    seed.publish(expected);
    expected.schema_version = 2U;
    {
        std::ofstream output(
            state / "Wireguard5", std::ios::binary | std::ios::trunc);
        output << ownership_body(expected);
    }
    REQUIRE(::chmod((state / "Wireguard5").c_str(), 0600) == 0);

    auto raced = expected;
    raced.target_full_revision =
        "ndms-rci-full-v1-" + std::string(64U, '9');
    const auto replacement = lifecycle_record(
        expected,
        NdmsNativeOwnershipLifecycle::
            deleted_save_acknowledged_unverified);
    bool injected = false;
    NdmsNativeOwnershipStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    hooks.fault_injector = [&](const auto stage) {
        if (!injected &&
            stage == NdmsNativeOwnershipStoreFaultStage::
                         pre_publish_after_file_fsync) {
            injected = true;
            std::ofstream output(
                state / "Wireguard5",
                std::ios::binary | std::ios::trunc);
            output << ownership_body(raced);
        }
    };
    NdmsNativeOwnershipStore store(state, hooks);
    CHECK_FALSE(store.replace_exact(expected, replacement).has_value());
    CHECK(injected);
    const auto final_read = store.read("Wireguard5");
    REQUIRE(final_read.record.has_value());
    CHECK(*final_read.record == raced);
}

TEST_CASE("v3 lifecycle numeric evidence must use canonical decimal text") {
    TempDirectory directory;
    const auto state = directory.path / "ownership";
    const auto record = lifecycle_record(
        record_fixture(),
        NdmsNativeOwnershipLifecycle::
            active_save_acknowledged_unverified);
    NdmsNativeOwnershipStore store(state);
    store.publish(record);
    auto body = ownership_body(record);
    const auto needle = std::string{"\n9\n7\n"};
    const auto position = body.find(needle);
    REQUIRE(position != std::string::npos);
    body.replace(position, needle.size(), "\n09\n7\n");
    {
        std::ofstream output(
            state / "Wireguard5", std::ios::binary | std::ios::trunc);
        output << body;
    }
    REQUIRE(::chmod((state / "Wireguard5").c_str(), 0600) == 0);
    CHECK(store.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::unreadable);
}

TEST_CASE("a visible ownership unlink is repaired before absence is trusted") {
    TempDirectory directory;
    const auto state = directory.path / "ownership";
    const auto record = record_fixture();
    NdmsNativeOwnershipStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    hooks.fault_injector = [](const auto stage) {
        if (stage == NdmsNativeOwnershipStoreFaultStage::
                         post_unlink_directory_fsync) {
            throw std::runtime_error("injected unlink fsync failure");
        }
    };
    NdmsNativeOwnershipStore interrupted(state, hooks);
    interrupted.publish(record);
    CHECK_FALSE(interrupted.remove_exact(record));
    CHECK_FALSE(fs::exists(state / "Wireguard5"));

    NdmsNativeOwnershipStore retry(state);
    CHECK(retry.ensure_absence_durable("Wireguard5"));
    CHECK(retry.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::absent);
}

TEST_CASE("unsafe ownership metadata and foreign inventory fail closed") {
    TempDirectory directory;
    const auto state = directory.path / "ownership";
    const auto file = state / "Wireguard5";
    NdmsNativeOwnershipStore store(state);
    const auto record = record_fixture();
    store.publish(record);

    REQUIRE(::chmod(file.c_str(), 0644) == 0);
    CHECK(store.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::unreadable);
    REQUIRE(::chmod(file.c_str(), 0600) == 0);

    const auto hardlink = state / "Wireguard6";
    REQUIRE(::link(file.c_str(), hardlink.c_str()) == 0);
    CHECK(store.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::unreadable);
    REQUIRE(::unlink(hardlink.c_str()) == 0);

    if (::geteuid() == 0) {
        REQUIRE(::chown(file.c_str(), 65534, 65534) == 0);
        CHECK(store.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::unreadable);
        REQUIRE(::chown(file.c_str(), ::geteuid(), ::getegid()) == 0);
    }

    {
        std::ofstream foreign(state / "notes.txt", std::ios::binary);
        foreign << "foreign";
    }
    const auto listing = store.list_claimed_interfaces();
    CHECK_FALSE(listing.readable);
    CHECK(listing.interface_names.empty());
    CHECK(store.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::unreadable);
}

TEST_CASE("ownership records require exact kind and RCI revision domains") {
    TempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    auto invalid = record_fixture();

    invalid.kind = static_cast<NdmsNativeTunnelImportKind>(99);
    CHECK_THROWS(ndms_native_ownership_revision(invalid));
    CHECK_THROWS(store.publish(invalid));

    for (const auto& revision : {
             std::string(64U, 'b'),
             std::string("other-v1-") + std::string(64U, 'b'),
             std::string("ndms-rci-full-v1-") + std::string(64U, 'A')}) {
        invalid = record_fixture();
        invalid.target_full_revision = revision;
        CHECK_THROWS(ndms_native_ownership_revision(invalid));
        CHECK_THROWS(store.publish(invalid));
    }
}

} // namespace keen_pbr3
