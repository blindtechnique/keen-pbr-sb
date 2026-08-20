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

std::string ownership_body(const NdmsNativeOwnershipRecord& record) {
    const char* kind = record.kind ==
                               NdmsNativeTunnelImportKind::amnezia_wireguard
                           ? "amnezia_wireguard"
                           : "wireguard";
    return std::string("keen-pbr-native-ownership-v2\n") +
           record.interface_name + "\n" + record.transaction_id + "\n" +
           record.marker + "\n" + kind + "\n" +
           record.snapshot_revision + "\n" +
           record.target_full_revision + "\n";
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
    auto replacement = expected;
    replacement.target_full_revision =
        "ndms-rci-full-v1-" + std::string(64U, 'd');

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
    auto replacement = record;
    replacement.target_full_revision =
        "ndms-rci-full-v1-" + std::string(64U, 'c');

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
