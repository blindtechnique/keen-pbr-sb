#include <doctest/doctest.h>

#include "keenetic/ndms_native_storage_path.hpp"
#include "keenetic/ndms_native_delete_wal_store.hpp"
#include "keenetic/ndms_native_import_wal_store.hpp"
#include "keenetic/ndms_native_observation_store.hpp"
#include "keenetic/ndms_native_ownership_store.hpp"
#include "keenetic/ndms_native_secret_snapshot.hpp"
#include "keenetic/ndms_native_writer_lease.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace keen_pbr3;

TEST_CASE("native storage accepts Entware prefix ownership only above the service root") {
    const std::vector<std::string> path{"opt", "etc", "keen-pbr", "native-import-wal"};
    struct stat metadata {};
    metadata.st_mode = S_IFDIR | 0755;
    for (const uid_t owner : {0U, 1001U, 4242U}) {
        metadata.st_uid = owner;
        CHECK(ndms_native_parent_metadata_allowed(path, 0U, metadata));
        CHECK(ndms_native_parent_metadata_allowed(path, 1U, metadata));
        CHECK(ndms_native_parent_metadata_allowed(path, 2U, metadata) == (owner == 0U));
        CHECK(ndms_native_parent_metadata_allowed(path, 3U, metadata) == (owner == 0U));
    }
    metadata.st_uid = 1001;
    CHECK_FALSE(ndms_native_parent_metadata_allowed({"opt", "etc", "other", "state"}, 0U, metadata));
    CHECK_FALSE(ndms_native_parent_metadata_allowed({"tmp", "opt", "etc", "keen-pbr", "state"}, 1U, metadata));
    CHECK_FALSE(ndms_native_parent_metadata_allowed({"opt", "etc", "keen-pbr"}, 0U, metadata));
    for (const mode_t mode : {S_IFDIR | 0775, S_IFDIR | 0777, S_IFLNK | 0755, S_IFREG | 0755}) {
        metadata.st_mode = mode;
        CHECK_FALSE(ndms_native_parent_metadata_allowed(path, 0U, metadata));
    }
}

namespace {

class TemporaryRoot final {
public:
    TemporaryRoot() {
        std::string pattern = (std::filesystem::temp_directory_path() / "kpbr-entware-XXXXXX").string();
        std::vector<char> buffer(pattern.begin(), pattern.end());
        buffer.push_back('\0');
        const auto* created = ::mkdtemp(buffer.data());
        REQUIRE(created != nullptr);
        path = created;
        std::filesystem::create_directories(path / "opt/etc/keen-pbr");
    }
    ~TemporaryRoot() {
        std::error_code error;
        std::filesystem::remove_all(path, error);
    }
    std::filesystem::path path;
};

void require_child(const bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

class TestMaintenanceLease final : public MaintenanceLease {
public:
    std::uint32_t base_generation() const noexcept override { return generation_; }
    std::uint32_t reserve(const std::uint32_t expected) override {
        require_child(expected == generation_, "maintenance generation changed");
        return ++generation_;
    }
    void verify_held() override {}
private:
    std::uint32_t generation_{1U};
};

// Called ONLY in a forked child after chroot into its disposable fixture.
// No hooks relax production ownership checks; no real /opt is ever changed.
void exercise_entware_stores(const uid_t prefix_owner) {
    const std::string root = "/opt/etc/keen-pbr/";
    for (const char* parent : {"/opt", "/opt/etc"}) {
        require_child(::chown(parent, prefix_owner, prefix_owner) == 0, "fixture chown failed");
        require_child(::chmod(parent, 0755) == 0, "fixture chmod failed");
    }
    require_child(::chmod(root.c_str(), 0755) == 0, "service chmod failed");
    std::filesystem::create_directory("/dev");
    require_child(::mknod("/dev/urandom", S_IFCHR | 0600, makedev(1, 9)) == 0, "fixture random device failed");
    require_child(::mknod("/dev/null", S_IFCHR | 0600, makedev(1, 3)) == 0, "fixture null device failed");

    // The real production coordinator validates its helper BEFORE reaching
    // the native stores. A deliberately absent interpreter stops execution
    // just after that boundary, without mocking away metadata checks.
    const std::string helper = "/opt/usr/lib/keen-pbr/update-lock.sh";
    std::filesystem::create_directories("/opt/usr/lib/keen-pbr");
    for (const char* parent : {"/opt/usr", "/opt/usr/lib"}) {
        require_child(::chown(parent, prefix_owner, prefix_owner) == 0, "helper parent chown failed");
        require_child(::chmod(parent, 0755) == 0, "helper parent chmod failed");
    }
    {
        std::ofstream script(helper);
        script << "#!/missing-fixture-interpreter\n";
        require_child(script.good(), "helper fixture write failed");
    }
    require_child(::chmod(helper.c_str(), 0755) == 0, "helper fixture chmod failed");
    const auto check_helper_boundary = [](const MaintenanceLockErrorKind expected) {
        try {
            MaintenanceCoordinator coordinator("ndms-native-import");
            throw std::runtime_error("fixture helper unexpectedly executed");
        } catch (const MaintenanceLockError& error) {
            if (error.kind() != expected) {
                throw std::runtime_error(std::string("maintenance boundary: ") + error.what());
            }
        }
    };
    check_helper_boundary(MaintenanceLockErrorKind::helper_execution);
    require_child(::chown("/opt/usr/lib/keen-pbr", 4242, 4242) == 0, "helper negative chown failed");
    check_helper_boundary(MaintenanceLockErrorKind::unsafe_state);
    require_child(::chown("/opt/usr/lib/keen-pbr", 0, 0) == 0, "helper ownership restore failed");
    require_child(::chmod("/opt/usr/lib", 0777) == 0, "helper negative chmod failed");
    check_helper_boundary(MaintenanceLockErrorKind::unsafe_state);
    require_child(::chmod("/opt/usr/lib", 0755) == 0, "helper permissions restore failed");

    // Explicit empty hooks select strict production metadata policy, unlike
    // some convenience constructors used by older /tmp-based unit fixtures.
    NdmsNativeImportWalStore imports(root + "native-import-wal", {});
    NdmsNativeDeleteWalStore deletes(root + "native-delete-wal", {});
    NdmsNativeOwnershipStore ownership(root + "native-import-ownership", {});
    NdmsNativeObservationStore observations(root + "native-observations", {});
    require_child(imports.try_inventory().state == NdmsNativeImportWalInventoryState::absent, "clean import inventory refused");
    require_child(deletes.readiness() == NdmsNativeDeleteWalReadiness::clean, "clean delete inventory refused");
    require_child(ownership.inspect_bounded_read_only().readable, "absent ownership inventory refused");
    require_child(observations.read().state == NdmsNativeObservationReadState::absent, "absent observation ledger refused");

    for (const char* leaf : {"native-import-wal", "native-delete-wal", "native-import-ownership"}) {
        require_child(::mkdir((root + leaf).c_str(), 0700) == 0, "private state fixture failed");
    }
    require_child(imports.try_inventory().state == NdmsNativeImportWalInventoryState::ready, "existing import inventory refused");
    require_child(deletes.readiness() == NdmsNativeDeleteWalReadiness::clean, "existing delete inventory refused");
    require_child(ownership.inspect_bounded_read_only().readable, "existing ownership inventory refused");

    RuntimeMutationAdmission runtime;
    auto outer = runtime.try_acquire("entware-storage-test");
    require_child(outer.has_value(), "runtime lease refused");
    auto writer = admit_ndms_native_writer(observations.state_directory(),
        std::make_unique<TestMaintenanceLease>(), std::move(*outer), {});
    require_child(writer.state == NdmsNativeWriterAdmissionState::admitted, "native writer refused");
    observations.provision(writer.lease);
    require_child(observations.read().state == NdmsNativeObservationReadState::valid, "persisted observation unreadable");
    writer.lease.verify_held();

    NdmsNativeSecretSnapshotStore secrets(root + "native-import-secrets/snapshot.key", root + "native-import-snapshots", {});
    const std::string transaction(32U, 'a');
    const std::string marker = "kpbr-ni-v1-" + transaction;
    secrets.publish("Wireguard5", transaction, marker, "synthetic test secret");
    const auto restored = secrets.read("Wireguard5", transaction, marker);
    require_child(restored.state == NdmsNativeSecretReadState::valid && restored.secret &&
        *restored.secret == "synthetic test secret", "snapshot round trip failed");
    struct stat key {};
    require_child(::stat((root + "native-import-secrets/snapshot.key").c_str(), &key) == 0 &&
        key.st_uid == 0 && key.st_gid == 0 && (key.st_mode & 07777) == 0600, "key permissions changed");

    // Bad service ownership and writable shared parents must still refuse.
    require_child(::chown(root.c_str(), 4242, 4242) == 0, "negative fixture chown failed");
    require_child(imports.try_inventory().state == NdmsNativeImportWalInventoryState::unsafe_store, "non-root service directory accepted");
    require_child(::chown(root.c_str(), 0, 0) == 0, "negative fixture restore failed");
    require_child(::chmod("/opt/etc", 0777) == 0, "negative fixture chmod failed");
    require_child(deletes.readiness() == NdmsNativeDeleteWalReadiness::unsafe, "world-writable parent accepted");
    require_child(::chmod("/opt/etc", 0755) == 0, "negative fixture restore failed");
    require_child(::chmod((root + "native-import-wal").c_str(), 0755) == 0, "negative leaf chmod failed");
    require_child(imports.try_inventory().state == NdmsNativeImportWalInventoryState::unsafe_store, "non-private journal accepted");

    for (const char* parent : {"/opt", "/opt/etc"}) {
        struct stat metadata {};
        require_child(::stat(parent, &metadata) == 0 && metadata.st_uid == prefix_owner &&
            metadata.st_gid == prefix_owner && (metadata.st_mode & 07777) == 0755,
            "installation prefix metadata changed");
    }
}

} // namespace

TEST_CASE("native stores use production policy on Entware packaging-owned prefixes") {
    if (::geteuid() != 0 || ::getegid() != 0) {
        MESSAGE("Production filesystem fixture needs root and chroot; pure policy checks run unprivileged.");
        return;
    }
    for (const uid_t owner : {0U, 1001U, 4242U}) {
        CAPTURE(owner);
        TemporaryRoot fixture;
        const pid_t child = ::fork();
        REQUIRE(child >= 0);
        if (child == 0) {
            try {
                require_child(::chroot(fixture.path.c_str()) == 0 && ::chdir("/") == 0, "fixture chroot failed");
                exercise_entware_stores(owner);
                ::_exit(0);
            } catch (const std::exception& error) {
                std::fprintf(stderr, "Entware fixture: %s\n", error.what());
                ::_exit(1);
            }
        }
        int status = 0;
        REQUIRE(::waitpid(child, &status, 0) == child);
        REQUIRE(WIFEXITED(status));
        CHECK(WEXITSTATUS(status) == 0);
    }
}
