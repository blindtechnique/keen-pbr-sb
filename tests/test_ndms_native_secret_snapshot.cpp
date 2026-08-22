#include <doctest/doctest.h>

#include "../src/keenetic/ndms_native_import_request.hpp"
#include "../src/keenetic/ndms_native_secret_snapshot.hpp"

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <type_traits>
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
            (fs::temp_directory_path() / "keen-pbr-secret-XXXXXX").string();
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

const std::string kTransaction(32U, 'a');
const std::string kMarker = "kpbr-ni-v1-" + kTransaction;
const std::string kSecret =
    "PrivateKey = 2BJtA3H8tWH+4Wsg1CmSbdaUcVXK/HeNTIEnyZ2W3Vw=";

std::string base64_key(const char value) {
    constexpr std::string_view alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const std::string input(32U, value);
    std::string output;
    output.reserve(44U);
    for (std::size_t offset = 0U; offset < input.size(); offset += 3U) {
        const auto first = static_cast<unsigned char>(input[offset]);
        const bool second_present = offset + 1U < input.size();
        const bool third_present = offset + 2U < input.size();
        const auto second = second_present
            ? static_cast<unsigned char>(input[offset + 1U]) : 0U;
        const auto third = third_present
            ? static_cast<unsigned char>(input[offset + 2U]) : 0U;
        const auto block =
            (static_cast<unsigned int>(first) << 16U) |
            (static_cast<unsigned int>(second) << 8U) |
            static_cast<unsigned int>(third);
        output.push_back(alphabet[(block >> 18U) & 0x3fU]);
        output.push_back(alphabet[(block >> 12U) & 0x3fU]);
        output.push_back(second_present
                             ? alphabet[(block >> 6U) & 0x3fU]
                             : '=');
        output.push_back(third_present
                             ? alphabet[block & 0x3fU]
                             : '=');
    }
    return output;
}

std::string full_configuration(const bool awg) {
    std::string configuration =
        "[Interface]\n"
        "PrivateKey = " + base64_key('P') + "\n"
        "Address = 10.8.0.2/32\n"
        "DNS = 1.1.1.1\n";
    if (awg) {
        configuration +=
            "Jc = 4\nJmin = 40\nJmax = 70\n"
            "S1 = 100\nS2 = 200\nS3 = 300\nS4 = 400\n"
            "H1 = 101010101\nH2 = 202020202\n"
            "H3 = 303030303\nH4 = 404040404\n"
            "I1 = <r 8><c><t>\nI2 = <b 0x10>\n"
            "I3 = <c><t>\nI4 = <r 4>\nI5 = <b 0x20>\n";
    }
    configuration +=
        "\n[Peer]\n"
        "PublicKey = " + base64_key('K') + "\n"
        "PresharedKey = " + base64_key('S') + "\n"
        "Endpoint = vpn.example.test:443\n"
        "AllowedIPs = 0.0.0.0/0\n"
        "PersistentKeepalive = 25\n";
    return configuration;
}

std::string partial_awg_configuration(const unsigned mask) {
    std::string configuration =
        "[Interface]\n"
        "PrivateKey = " + base64_key('P') + "\n"
        "Address = 10.8.0.2/32\n"
        "Jc = 4\nJmin = 40\nJmax = 70\n"
        "S1 = 100\nS2 = 200\n"
        "H1 = 101010101\nH2 = 202020202\n"
        "H3 = 303030303\nH4 = 404040404\n";
    if ((mask & 1U) != 0U) {
        configuration += "S3 = 300\nS4 = 400\n";
    }
    constexpr const char* signatures[5]{
        "I1 = <r 8><c><t>\n",
        "I2 = \n",
        "I3 = <c><t>\n",
        "I4 = <r 4>\n",
        "I5 = <b 0x20>\n",
    };
    for (unsigned index = 0U; index < 5U; ++index) {
        if ((mask & (1U << (index + 1U))) != 0U) {
            configuration += signatures[index];
        }
    }
    configuration +=
        "\n[Peer]\n"
        "PublicKey = " + base64_key('K') + "\n"
        "Endpoint = vpn.example.test:443\n"
        "AllowedIPs = 0.0.0.0/0\n";
    return configuration;
}

NdmsNativeSecretSnapshotStore store_for(
    const TempDirectory& directory,
    NdmsNativeSecretSnapshotStoreTestHooks hooks = {}) {
    hooks.allow_current_process_owner = true;
    return NdmsNativeSecretSnapshotStore(
        directory.path / "keys" / "master.key",
        directory.path / "snapshots",
        std::move(hooks));
}

} // namespace

static_assert(!std::is_default_constructible_v<
              NdmsNativePanelDeleteSnapshot>);
static_assert(!std::is_copy_constructible_v<
              NdmsNativePanelDeleteSnapshot>);
static_assert(std::is_nothrow_move_constructible_v<
              NdmsNativePanelDeleteSnapshot>);
static_assert(!std::is_copy_constructible_v<
              NdmsNativeSecretReadResult>);
static_assert(!std::is_copy_assignable_v<
              NdmsNativeSecretReadResult>);
static_assert(std::is_nothrow_move_constructible_v<
              NdmsNativeSecretReadResult>);
static_assert(std::is_nothrow_move_assignable_v<
              NdmsNativeSecretReadResult>);

TEST_CASE("raw secret read results wipe on move overwrite and destruction") {
    reset_ndms_native_secret_result_wipe_count_for_testing();
    {
        NdmsNativeSecretReadResult source;
        source.state = NdmsNativeSecretReadState::valid;
        source.secret = std::make_unique<std::string>(
            "first plaintext private key");
        const auto* original_secret = source.secret.get();
        NdmsNativeSecretReadResult moved(std::move(source));
        CHECK(source.state == NdmsNativeSecretReadState::unreadable);
        CHECK_FALSE(source.secret);
        REQUIRE(moved.secret);
        CHECK(moved.secret.get() == original_secret);

        NdmsNativeSecretReadResult destination;
        destination.secret = std::make_unique<std::string>(
            "plaintext being overwritten");
        destination = std::move(moved);
        CHECK(moved.state == NdmsNativeSecretReadState::unreadable);
        CHECK_FALSE(moved.secret);
        REQUIRE(destination.secret);
        CHECK(destination.secret.get() == original_secret);
        CHECK(*destination.secret == "first plaintext private key");

        auto* same_destination = &destination;
        destination = std::move(*same_destination);
        REQUIRE(destination.secret);
        CHECK(*destination.secret == "first plaintext private key");
    }
    // Moving transfers the owning pointer without copying secret bytes. The
    // overwritten destination and the final owner still pass through the
    // non-optimizable wipe path.
    CHECK(ndms_native_secret_result_wipe_count_for_testing() == 2U);
}

TEST_CASE("raw secret read results preserve an empty valid payload") {
    NdmsNativeSecretReadResult source;
    source.state = NdmsNativeSecretReadState::valid;
    source.secret = std::make_unique<std::string>();

    NdmsNativeSecretReadResult moved(std::move(source));
    CHECK(source.state == NdmsNativeSecretReadState::unreadable);
    CHECK_FALSE(source.secret);
    REQUIRE(moved.secret);
    CHECK(moved.secret->empty());
}

TEST_CASE("typed panel delete snapshots preserve complete WG and AWG state") {
    TempDirectory directory;
    auto store = store_for(directory);

    SUBCASE("WireGuard preserves its PSK-bearing canonical configuration") {
        auto snapshot = make_ndms_native_panel_delete_snapshot(
            full_configuration(false), kMarker);
        REQUIRE(snapshot.kind() == NdmsNativeTunnelImportKind::wireguard);
        REQUIRE(snapshot.preshared_key_count() == 1U);
        CHECK_FALSE(snapshot.has_complete_awg_parameters());
        const auto revision = std::string(snapshot.canonical_revision());
        CHECK(snapshot.sealed_payload_bytes() > 200U);
        store.publish_panel_delete_snapshot(
            "Wireguard5", kTransaction, kMarker, std::move(snapshot));
        CHECK(snapshot.marker().empty());
        CHECK(snapshot.canonical_revision().empty());
        CHECK(snapshot.sealed_payload_bytes() == 0U);

        const auto read = store.read_panel_delete_snapshot(
            "Wireguard5", kTransaction, kMarker);
        REQUIRE(read.state == NdmsNativeSecretReadState::valid);
        REQUIRE(read.snapshot.has_value());
        CHECK(read.snapshot->kind() ==
              NdmsNativeTunnelImportKind::wireguard);
        CHECK(read.snapshot->preshared_key_count() == 1U);
        CHECK(read.snapshot->canonical_revision() == revision);
    }

    SUBCASE("AmneziaWG preserves every base and extended ASC parameter") {
        auto snapshot = make_ndms_native_panel_delete_snapshot(
            full_configuration(true), kMarker);
        REQUIRE(snapshot.kind() ==
                NdmsNativeTunnelImportKind::amnezia_wireguard);
        REQUIRE(snapshot.preshared_key_count() == 1U);
        REQUIRE(snapshot.has_complete_awg_parameters());
        const auto revision = std::string(snapshot.canonical_revision());
        store.publish_panel_delete_snapshot(
            "Wireguard6", kTransaction, kMarker, std::move(snapshot));

        const auto read = store.read_panel_delete_snapshot(
            "Wireguard6", kTransaction, kMarker);
        REQUIRE(read.state == NdmsNativeSecretReadState::valid);
        REQUIRE(read.snapshot.has_value());
        CHECK(read.snapshot->kind() ==
              NdmsNativeTunnelImportKind::amnezia_wireguard);
        CHECK(read.snapshot->preshared_key_count() == 1U);
        CHECK(read.snapshot->has_complete_awg_parameters());
        CHECK(read.snapshot->canonical_revision() == revision);
    }
}

TEST_CASE("typed panel delete snapshots preserve a chosen display name") {
    TempDirectory directory;
    auto store = store_for(directory);
    auto prepared = prepare_ndms_native_import(
        full_configuration(true), "Мой AWG");
    const auto transaction =
        std::string{prepared.request_identity().transaction_id()};
    const auto marker =
        std::string{prepared.request_identity().marker()};
    const auto revision = std::string{
        prepared.delete_snapshot_metadata().canonical_revision()};

    store.publish_panel_delete_snapshot(
        "Wireguard6", transaction, marker,
        prepared.take_delete_snapshot());

    const auto read = store.read_panel_delete_snapshot(
        "Wireguard6", transaction, marker);
    REQUIRE(read.state == NdmsNativeSecretReadState::valid);
    REQUIRE(read.snapshot.has_value());
    CHECK(read.snapshot->kind() ==
          NdmsNativeTunnelImportKind::amnezia_wireguard);
    CHECK(read.snapshot->canonical_revision() == revision);
    CHECK(read.snapshot->marker() == marker);
}

TEST_CASE("every partial extended AWG shape round-trips canonically") {
    TempDirectory directory;
    auto store = store_for(directory);
    for (unsigned mask = 0U; mask < 64U; ++mask) {
        CAPTURE(mask);
        auto snapshot = make_ndms_native_panel_delete_snapshot(
            partial_awg_configuration(mask), kMarker);
        const auto revision =
            std::string(snapshot.canonical_revision());
        const auto target = "Wireguard" + std::to_string(5U + mask);
        store.publish_panel_delete_snapshot(
            target, kTransaction, kMarker, std::move(snapshot));
        const auto read = store.read_panel_delete_snapshot(
            target, kTransaction, kMarker);
        REQUIRE(read.state == NdmsNativeSecretReadState::valid);
        REQUIRE(read.snapshot.has_value());
        CHECK(read.snapshot->kind() ==
              NdmsNativeTunnelImportKind::amnezia_wireguard);
        CHECK(read.snapshot->canonical_revision() == revision);
    }
}

TEST_CASE("legacy key-only ciphertext cannot authorize panel deletion") {
    TempDirectory directory;
    auto store = store_for(directory);
    store.publish("Wireguard5", kTransaction, kMarker, kSecret);

    const auto typed = store.read_panel_delete_snapshot(
        "Wireguard5", kTransaction, kMarker);
    CHECK(typed.state == NdmsNativeSecretReadState::unreadable);
    CHECK_FALSE(typed.snapshot.has_value());
    CHECK(store.read("Wireguard5", kTransaction, kMarker).state ==
          NdmsNativeSecretReadState::valid);
}

TEST_CASE("typed snapshot identity mismatch is refused before encryption") {
    TempDirectory directory;
    auto store = store_for(directory);
    auto snapshot = make_ndms_native_panel_delete_snapshot(
        full_configuration(true), kMarker);
    const std::string other_transaction(32U, 'b');
    const auto other_marker = "kpbr-ni-v1-" + other_transaction;

    CHECK_THROWS(store.publish_panel_delete_snapshot(
        "Wireguard5", other_transaction, other_marker,
        std::move(snapshot)));
    CHECK(store.read("Wireguard5", other_transaction, other_marker).state ==
          NdmsNativeSecretReadState::absent);
}

TEST_CASE("a sealed secret comes back only under its exact identity") {
    TempDirectory directory;
    auto store = store_for(directory);
    store.publish("Wireguard5", kTransaction, kMarker, kSecret);

    const auto read = store.read("Wireguard5", kTransaction, kMarker);
    REQUIRE(read.state == NdmsNativeSecretReadState::valid);
    CHECK(*read.secret == kSecret);

    // A different transaction, a different marker: the ciphertext is bound
    // to the identity it was sealed for, not to the file it sits in.
    const std::string other(32U, 'b');
    CHECK(store.read("Wireguard5", other, "kpbr-ni-v1-" + other).state ==
          NdmsNativeSecretReadState::unreadable);
}

TEST_CASE("a snapshot renamed onto another interface does not decrypt") {
    TempDirectory directory;
    auto store = store_for(directory);
    store.publish("Wireguard6", kTransaction, kMarker, kSecret);

    std::error_code error;
    fs::rename(directory.path / "snapshots" / "Wireguard6",
               directory.path / "snapshots" / "Wireguard5", error);
    REQUIRE_FALSE(error);
    // The name is part of the authenticated data: a copied or renamed
    // snapshot asserts a key for an interface it never held.
    CHECK(store.read("Wireguard5", kTransaction, kMarker).state ==
          NdmsNativeSecretReadState::unreadable);
}

TEST_CASE("tampered bytes and torn files read as damage, never absence") {
    TempDirectory directory;
    auto store = store_for(directory);
    store.publish("Wireguard5", kTransaction, kMarker, kSecret);
    const auto path = directory.path / "snapshots" / "Wireguard5";

    auto tamper = [&](const std::size_t offset) {
        std::fstream file(path,
                          std::ios::binary | std::ios::in | std::ios::out);
        REQUIRE(file);
        file.seekg(0, std::ios::end);
        const auto size = static_cast<std::size_t>(file.tellg());
        REQUIRE(offset < size);
        file.seekp(static_cast<std::streamoff>(offset));
        char byte = 0;
        file.seekg(static_cast<std::streamoff>(offset));
        file.read(&byte, 1);
        file.seekp(static_cast<std::streamoff>(offset));
        byte = static_cast<char>(byte ^ 0x01);
        file.write(&byte, 1);
    };

    tamper(40U);  // inside the ciphertext
    CHECK(store.read("Wireguard5", kTransaction, kMarker).state ==
          NdmsNativeSecretReadState::unreadable);

    std::ofstream torn(path, std::ios::binary | std::ios::trunc);
    torn << "keen-pbr-secret-snapshot-v1\n";
    torn.close();
    CHECK(store.read("Wireguard5", kTransaction, kMarker).state ==
          NdmsNativeSecretReadState::unreadable);
}

TEST_CASE("unsafe snapshot metadata is damage and is never followed") {
    TempDirectory directory;
    auto store = store_for(directory);
    const auto snapshots = directory.path / "snapshots";
    const auto path = snapshots / "Wireguard5";

    SUBCASE("a symlink entry is not followed") {
        store.publish("Wireguard6", kTransaction, kMarker, kSecret);
        std::error_code error;
        fs::create_symlink(snapshots / "Wireguard6", path, error);
        REQUIRE_FALSE(error);
        CHECK(store.read("Wireguard5", kTransaction, kMarker).state ==
              NdmsNativeSecretReadState::unreadable);
    }

    SUBCASE("a group-readable entry is rejected") {
        store.publish("Wireguard5", kTransaction, kMarker, kSecret);
        REQUIRE(::chmod(path.c_str(), 0640) == 0);
        CHECK(store.read("Wireguard5", kTransaction, kMarker).state ==
              NdmsNativeSecretReadState::unreadable);
    }

    SUBCASE("a multiply-linked entry is rejected") {
        store.publish("Wireguard5", kTransaction, kMarker, kSecret);
        const auto alias = directory.path / "snapshot-hardlink";
        REQUIRE(::link(path.c_str(), alias.c_str()) == 0);
        CHECK(store.read("Wireguard5", kTransaction, kMarker).state ==
              NdmsNativeSecretReadState::unreadable);
    }

    SUBCASE("an entry owned by another uid is rejected") {
        store.publish("Wireguard5", kTransaction, kMarker, kSecret);
        if (::geteuid() == 0) {
            REQUIRE(::chown(path.c_str(), 1, 1) == 0);
            CHECK(store.read("Wireguard5", kTransaction, kMarker).state ==
                  NdmsNativeSecretReadState::unreadable);
        }
    }
}

TEST_CASE("a symlinked secret state directory is fail-closed") {
    TempDirectory directory;
    const auto real = directory.path / "real-snapshots";
    REQUIRE(fs::create_directory(real));
    REQUIRE(::chmod(real.c_str(), 0700) == 0);
    std::error_code error;
    fs::create_directory_symlink(
        real, directory.path / "snapshots", error);
    REQUIRE_FALSE(error);
    auto store = store_for(directory);

    CHECK_THROWS(
        store.publish("Wireguard5", kTransaction, kMarker, kSecret));
    CHECK(store.read("Wireguard5", kTransaction, kMarker).state ==
          NdmsNativeSecretReadState::unreadable);
}

TEST_CASE("a lost master key is damage that reaches a human, not absence") {
    TempDirectory directory;
    auto store = store_for(directory);
    store.publish("Wireguard5", kTransaction, kMarker, kSecret);

    std::error_code error;
    fs::remove(directory.path / "keys" / "master.key", error);
    REQUIRE_FALSE(error);

    // The snapshot exists and its key does not. Absence here would tell a
    // mutation "proceed, there is nothing to preserve" - over a secret that
    // is still on disk and merely locked.
    CHECK(store.read("Wireguard5", kTransaction, kMarker).state ==
          NdmsNativeSecretReadState::unreadable);
    // And the key is not silently regenerated by the read.
    CHECK_FALSE(fs::exists(directory.path / "keys" / "master.key", error));
}

TEST_CASE("a corrupt master key is never replaced by publish") {
    TempDirectory directory;
    auto store = store_for(directory);
    store.publish("Wireguard5", kTransaction, kMarker, kSecret);

    std::ofstream corrupt(directory.path / "keys" / "master.key",
                          std::ios::binary | std::ios::trunc);
    corrupt << "short";
    corrupt.close();

    // Regenerating would orphan every snapshot sealed under the old key.
    CHECK_THROWS(
        store.publish("Wireguard6", kTransaction, kMarker, kSecret));
}

TEST_CASE("re-publishing the exact snapshot is immutable and idempotent") {
    TempDirectory directory;
    auto store = store_for(directory);
    store.publish("Wireguard5", kTransaction, kMarker, kSecret);
    std::string first;
    {
        std::ifstream input(directory.path / "snapshots" / "Wireguard5",
                            std::ios::binary);
        first.assign((std::istreambuf_iterator<char>(input)),
                     std::istreambuf_iterator<char>());
    }
    store.publish("Wireguard5", kTransaction, kMarker, kSecret);
    std::string second;
    {
        std::ifstream input(directory.path / "snapshots" / "Wireguard5",
                            std::ios::binary);
        second.assign((std::istreambuf_iterator<char>(input)),
                      std::istreambuf_iterator<char>());
    }
    CHECK(second == first);
}

TEST_CASE("a lost key is never regenerated while any ciphertext remains") {
    TempDirectory directory;
    auto store = store_for(directory);
    store.publish("Wireguard5", kTransaction, kMarker, "first-secret");
    std::string before;
    {
        std::ifstream input(
            directory.path / "snapshots" / "Wireguard5",
            std::ios::binary);
        before.assign((std::istreambuf_iterator<char>(input)),
                      std::istreambuf_iterator<char>());
    }
    std::error_code error;
    REQUIRE(fs::remove(
        directory.path / "keys" / "master.key", error));
    REQUIRE_FALSE(error);

    CHECK_THROWS(
        store.publish("Wireguard6", kTransaction, kMarker, "second-secret"));
    CHECK_THROWS(
        store.publish("Wireguard5", kTransaction, kMarker, "first-secret"));
    CHECK_FALSE(fs::exists(
        directory.path / "keys" / "master.key", error));
    CHECK_FALSE(fs::exists(
        directory.path / "snapshots" / "Wireguard6", error));
    std::string after;
    {
        std::ifstream input(
            directory.path / "snapshots" / "Wireguard5",
            std::ios::binary);
        after.assign((std::istreambuf_iterator<char>(input)),
                     std::istreambuf_iterator<char>());
    }
    CHECK(after == before);
}

TEST_CASE("an existing rollback snapshot cannot be replaced") {
    TempDirectory directory;
    auto store = store_for(directory);
    store.publish("Wireguard5", kTransaction, kMarker, "original-secret");

    SUBCASE("different payload under the same identity") {
        CHECK_THROWS(store.publish(
            "Wireguard5", kTransaction, kMarker, "replacement-secret"));
    }
    SUBCASE("same target under a different identity") {
        const std::string other_transaction(32U, 'b');
        const auto other_marker = "kpbr-ni-v1-" + other_transaction;
        CHECK_THROWS(store.publish(
            "Wireguard5", other_transaction, other_marker,
            "original-secret"));
    }
    const auto original = store.read(
        "Wireguard5", kTransaction, kMarker);
    REQUIRE(original.state == NdmsNativeSecretReadState::valid);
    CHECK(*original.secret == "original-secret");
}

TEST_CASE("master key and snapshot directories may not overlap") {
    TempDirectory directory;
    const auto shared = directory.path / "shared";

    CHECK_THROWS_AS(
        NdmsNativeSecretSnapshotStore(
            shared / "master.key", shared,
            NdmsNativeSecretSnapshotStoreTestHooks{}),
        std::invalid_argument);
    CHECK_THROWS_AS(
        NdmsNativeSecretSnapshotStore(
            directory.path / "state" / "keys" / "master.key",
            directory.path / "state",
            NdmsNativeSecretSnapshotStoreTestHooks{}),
        std::invalid_argument);
    CHECK_THROWS_AS(
        NdmsNativeSecretSnapshotStore(
            shared / "Wireguard5", shared,
            NdmsNativeSecretSnapshotStoreTestHooks{}),
        std::invalid_argument);
}

TEST_CASE("a post-rename key fsync failure never publishes ciphertext") {
    TempDirectory directory;
    NdmsNativeSecretSnapshotStoreTestHooks hooks;
    hooks.fault_injector = [](const auto stage) {
        if (stage == NdmsNativeSecretSnapshotStoreFaultStage::
                         post_rename_directory_fsync) {
            throw std::runtime_error("injected key directory fsync");
        }
    };
    auto store = store_for(directory, std::move(hooks));

    CHECK_THROWS(
        store.publish("Wireguard5", kTransaction, kMarker, kSecret));
    std::error_code error;
    CHECK_FALSE(fs::exists(
        directory.path / "snapshots" / "Wireguard5", error));

    // The visible key can be made durable by a clean retry; the failed call
    // itself never persisted ciphertext that could outlive its key.
    auto retry = store_for(directory);
    CHECK_NOTHROW(
        retry.publish("Wireguard5", kTransaction, kMarker, kSecret));
    CHECK(retry.read("Wireguard5", kTransaction, kMarker).state ==
          NdmsNativeSecretReadState::valid);
}

TEST_CASE("a visible snapshot after directory fsync failure is repaired by exact retry") {
    TempDirectory directory;
    auto durable = store_for(directory);
    durable.publish("Wireguard5", kTransaction, kMarker, "key-bootstrap");

    NdmsNativeSecretSnapshotStoreTestHooks hooks;
    hooks.fault_injector = [](const auto stage) {
        if (stage == NdmsNativeSecretSnapshotStoreFaultStage::
                         post_rename_directory_fsync) {
            throw std::runtime_error("injected snapshot directory fsync");
        }
    };
    auto faulted = store_for(directory, std::move(hooks));
    CHECK_THROWS(faulted.publish(
        "Wireguard6", kTransaction, kMarker, "second-secret"));
    std::error_code error;
    REQUIRE(fs::exists(
        directory.path / "snapshots" / "Wireguard6", error));
    REQUIRE_FALSE(error);

    auto retry = store_for(directory);
    CHECK_NOTHROW(retry.publish(
        "Wireguard6", kTransaction, kMarker, "second-secret"));
    const auto read = retry.read(
        "Wireguard6", kTransaction, kMarker);
    REQUIRE(read.state == NdmsNativeSecretReadState::valid);
    CHECK(*read.secret == "second-secret");
}

TEST_CASE("portable no-replace crash recovery handles key and snapshot links") {
    TempDirectory directory;

    auto crash_publish = [&](const char* target,
                             const char* secret,
                             const auto crash_stage) {
        const pid_t child = ::fork();
        REQUIRE(child >= 0);
        if (child == 0) {
            NdmsNativeSecretSnapshotStoreTestHooks hooks;
            hooks.allow_current_process_owner = true;
            hooks.force_portable_linkat = true;
            hooks.fault_injector = [crash_stage](const auto stage) {
                if (stage == crash_stage) _exit(73);
            };
            NdmsNativeSecretSnapshotStore child_store(
                directory.path / "keys" / "master.key",
                directory.path / "snapshots", std::move(hooks));
            child_store.publish(
                target, kTransaction, kMarker, secret);
            _exit(74);
        }
        int status = 0;
        REQUIRE(::waitpid(child, &status, 0) == child);
        REQUIRE(WIFEXITED(status));
        CHECK(WEXITSTATUS(status) == 73);
    };

    // First crash leaves the key target and its temporary name on one inode.
    crash_publish(
        "Wireguard5", "first-secret",
        NdmsNativeSecretSnapshotStoreFaultStage::post_link_before_unlink);
    auto recovered = store_for(directory);
    CHECK_NOTHROW(recovered.publish(
        "Wireguard5", kTransaction, kMarker, "first-secret"));
    CHECK(recovered.read(
              "Wireguard5", kTransaction, kMarker).state ==
          NdmsNativeSecretReadState::valid);

    // With the key durable, the same crash point now belongs to the snapshot.
    crash_publish(
        "Wireguard6", "second-secret",
        NdmsNativeSecretSnapshotStoreFaultStage::post_link_before_unlink);
    CHECK_NOTHROW(recovered.publish(
        "Wireguard6", kTransaction, kMarker, "second-secret"));
    CHECK(recovered.read(
              "Wireguard6", kTransaction, kMarker).state ==
          NdmsNativeSecretReadState::valid);

    for (const auto& state : {
             directory.path / "keys", directory.path / "snapshots"}) {
        for (const auto& entry : fs::directory_iterator(state)) {
            CHECK(entry.path().filename().string().rfind(
                      ".keen-pbr-secret-snapshot.", 0U) != 0U);
        }
    }
}

TEST_CASE("dead pre-publish secret temporaries are bounded and recoverable") {
    TempDirectory directory;
    const pid_t child = ::fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        NdmsNativeSecretSnapshotStoreTestHooks hooks;
        hooks.allow_current_process_owner = true;
        hooks.fault_injector = [](const auto stage) {
            if (stage == NdmsNativeSecretSnapshotStoreFaultStage::
                             pre_publish_after_file_fsync) {
                _exit(75);
            }
        };
        NdmsNativeSecretSnapshotStore child_store(
            directory.path / "keys" / "master.key",
            directory.path / "snapshots", std::move(hooks));
        child_store.publish(
            "Wireguard5", kTransaction, kMarker, "first-secret");
        _exit(76);
    }
    int status = 0;
    REQUIRE(::waitpid(child, &status, 0) == child);
    REQUIRE(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 75);

    auto recovered = store_for(directory);
    CHECK_NOTHROW(recovered.publish(
        "Wireguard5", kTransaction, kMarker, "first-secret"));
    CHECK(recovered.read(
              "Wireguard5", kTransaction, kMarker).state ==
          NdmsNativeSecretReadState::valid);
}

TEST_CASE("cross-process cold start installs exactly one durable master key") {
    TempDirectory directory;
    int start_pipe[2]{};
    REQUIRE(::pipe(start_pipe) == 0);

    auto spawn = [&](const char* target, const char* secret) {
        const pid_t child = ::fork();
        REQUIRE(child >= 0);
        if (child == 0) {
            (void)::close(start_pipe[1]);
            char token = 0;
            if (::read(start_pipe[0], &token, 1U) != 1) _exit(90);
            try {
                auto child_store = store_for(directory);
                child_store.publish(
                    target, kTransaction, kMarker, secret);
                _exit(0);
            } catch (...) {
                _exit(91);
            }
        }
        return child;
    };

    const auto first = spawn("Wireguard5", "first-secret");
    const auto second = spawn("Wireguard6", "second-secret");
    REQUIRE(::close(start_pipe[0]) == 0);
    const char tokens[2]{'a', 'b'};
    REQUIRE(::write(start_pipe[1], tokens, sizeof(tokens)) ==
            static_cast<ssize_t>(sizeof(tokens)));
    REQUIRE(::close(start_pipe[1]) == 0);
    int first_status = 0;
    int second_status = 0;
    REQUIRE(::waitpid(first, &first_status, 0) == first);
    REQUIRE(::waitpid(second, &second_status, 0) == second);
    REQUIRE(WIFEXITED(first_status));
    REQUIRE(WIFEXITED(second_status));
    CHECK(WEXITSTATUS(first_status) == 0);
    CHECK(WEXITSTATUS(second_status) == 0);

    auto store = store_for(directory);
    const auto first_read = store.read(
        "Wireguard5", kTransaction, kMarker);
    const auto second_read = store.read(
        "Wireguard6", kTransaction, kMarker);
    REQUIRE(first_read.state == NdmsNativeSecretReadState::valid);
    REQUIRE(second_read.state == NdmsNativeSecretReadState::valid);
    CHECK(*first_read.secret == "first-secret");
    CHECK(*second_read.secret == "second-secret");

    struct stat metadata {};
    REQUIRE(::lstat((directory.path / "keys" / "master.key").c_str(),
                    &metadata) == 0);
    CHECK((metadata.st_mode & 07777) == 0600U);
    CHECK(metadata.st_nlink == 1);
}

TEST_CASE("protected slots and malformed identities cannot hold secrets") {
    TempDirectory directory;
    auto store = store_for(directory);
    for (const char* name :
         {"Wireguard0", "Wireguard99", "wireguard5", "Wireguard05"}) {
        CHECK_THROWS(store.publish(name, kTransaction, kMarker, kSecret));
        CHECK(store.read(name, kTransaction, kMarker).state ==
              NdmsNativeSecretReadState::unreadable);
    }
    CHECK_THROWS(
        store.publish("Wireguard5", kTransaction, kMarker, ""));
}

TEST_CASE("snapshot removal is bound to identity and canonical content") {
    TempDirectory directory;
    auto store = store_for(directory);
    auto snapshot = make_ndms_native_panel_delete_snapshot(
        full_configuration(false), kMarker);
    const auto revision = std::string(snapshot.canonical_revision());
    store.publish_panel_delete_snapshot(
        "Wireguard5", kTransaction, kMarker, std::move(snapshot));

    const std::string other(32U, 'b');
    CHECK_FALSE(
        store.remove_panel_delete_snapshot_exact(
            "Wireguard5", other, "kpbr-ni-v1-" + other, revision));
    CHECK(store.read("Wireguard5", kTransaction, kMarker).state ==
          NdmsNativeSecretReadState::valid);

    CHECK_FALSE(store.remove_panel_delete_snapshot_exact(
        "Wireguard5", kTransaction, kMarker,
        "ndms-native-import-v1-" + std::string(64U, 'f')));
    CHECK(store.remove_panel_delete_snapshot_exact(
        "Wireguard5", kTransaction, kMarker, revision));
    CHECK(store.read("Wireguard5", kTransaction, kMarker).state ==
          NdmsNativeSecretReadState::absent);
    CHECK_FALSE(store.remove_panel_delete_snapshot_exact(
        "Wireguard5", kTransaction, kMarker, revision));
}

TEST_CASE("snapshot CAS replacement between preflight and remove survives") {
    TempDirectory directory;
    auto store = store_for(directory);
    auto original = make_ndms_native_panel_delete_snapshot(
        full_configuration(false), kMarker);
    const auto original_revision =
        std::string(original.canonical_revision());
    store.publish_panel_delete_snapshot(
        "Wireguard5", kTransaction, kMarker, std::move(original));

    NdmsNativeSecretSnapshotStoreTestHooks replacement_hooks;
    replacement_hooks.allow_current_process_owner = true;
    NdmsNativeSecretSnapshotStore replacement_store(
        directory.path / "keys" / "master.key",
        directory.path / "replacement-snapshots",
        std::move(replacement_hooks));
    auto replacement = make_ndms_native_panel_delete_snapshot(
        full_configuration(true), kMarker);
    const auto replacement_revision =
        std::string(replacement.canonical_revision());
    REQUIRE(replacement_revision != original_revision);
    replacement_store.publish_panel_delete_snapshot(
        "Wireguard5", kTransaction, kMarker, std::move(replacement));

    NdmsNativeSecretSnapshotStoreTestHooks hooks;
    hooks.fault_injector = [&](const auto stage) {
        if (stage == NdmsNativeSecretSnapshotStoreFaultStage::
                         before_remove_content_recheck) {
            std::error_code error;
            fs::rename(
                directory.path / "replacement-snapshots" / "Wireguard5",
                directory.path / "snapshots" / "Wireguard5", error);
            REQUIRE_FALSE(error);
        }
    };
    auto raced = store_for(directory, std::move(hooks));
    CHECK_FALSE(raced.remove_panel_delete_snapshot_exact(
        "Wireguard5", kTransaction, kMarker, original_revision));
    const auto after = raced.read_panel_delete_snapshot(
        "Wireguard5", kTransaction, kMarker);
    REQUIRE(after.state == NdmsNativeSecretReadState::valid);
    REQUIRE(after.snapshot.has_value());
    CHECK(after.snapshot->canonical_revision() == replacement_revision);
}

TEST_CASE("visible snapshot unlink is repaired before absence is trusted") {
    TempDirectory directory;
    auto durable = store_for(directory);
    auto snapshot = make_ndms_native_panel_delete_snapshot(
        full_configuration(false), kMarker);
    const auto revision = std::string(snapshot.canonical_revision());
    durable.publish_panel_delete_snapshot(
        "Wireguard5", kTransaction, kMarker, std::move(snapshot));

    NdmsNativeSecretSnapshotStoreTestHooks hooks;
    hooks.fault_injector = [](const auto stage) {
        if (stage == NdmsNativeSecretSnapshotStoreFaultStage::
                         post_unlink_directory_fsync) {
            throw std::runtime_error("injected snapshot unlink fsync");
        }
    };
    auto faulted = store_for(directory, std::move(hooks));
    CHECK_FALSE(faulted.remove_panel_delete_snapshot_exact(
        "Wireguard5", kTransaction, kMarker, revision));
    std::error_code error;
    REQUIRE_FALSE(fs::exists(
        directory.path / "snapshots" / "Wireguard5", error));
    REQUIRE_FALSE(error);

    auto retry = store_for(directory);
    CHECK(retry.ensure_absence_durable("Wireguard5"));
    CHECK(retry.read(
              "Wireguard5", kTransaction, kMarker).state ==
          NdmsNativeSecretReadState::absent);
}

TEST_CASE("the key and the snapshots are private on disk") {
    TempDirectory directory;
    auto store = store_for(directory);
    store.publish("Wireguard5", kTransaction, kMarker, kSecret);

    struct stat info {};
    REQUIRE(::lstat((directory.path / "keys" / "master.key").c_str(),
                    &info) == 0);
    CHECK((info.st_mode & 07777) == 0600U);
    REQUIRE(::lstat((directory.path / "snapshots" / "Wireguard5").c_str(),
                    &info) == 0);
    CHECK((info.st_mode & 07777) == 0600U);
    REQUIRE(::lstat((directory.path / "keys").c_str(), &info) == 0);
    CHECK((info.st_mode & 07777) == 0700U);
    REQUIRE(::lstat((directory.path / "snapshots").c_str(), &info) == 0);
    CHECK((info.st_mode & 07777) == 0700U);
}

} // namespace keen_pbr3
