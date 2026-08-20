#include <doctest/doctest.h>

#include "keenetic/ndms_native_writer_lease.hpp"

#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <sys/stat.h>
#include <sys/wait.h>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace keen_pbr3;

namespace {

class TempDirectory final {
public:
    TempDirectory() {
        std::string pattern =
            (std::filesystem::temp_directory_path() /
             "keen-pbr-native-writer-XXXXXX")
                .string();
        std::vector<char> writable(pattern.begin(), pattern.end());
        writable.push_back('\0');
        const auto* created = ::mkdtemp(writable.data());
        REQUIRE(created != nullptr);
        root = created;
        state = root / "state";
    }

    ~TempDirectory() {
        std::error_code error;
        std::filesystem::remove_all(root, error);
    }

    std::filesystem::path root;
    std::filesystem::path state;
};

struct MaintenanceState final {
    bool held{true};
    std::size_t verify_count{0U};
    std::size_t reserve_count{0U};
    std::size_t destruction_count{0U};
};

class FakeMaintenanceLease final : public MaintenanceLease {
public:
    explicit FakeMaintenanceLease(
        std::shared_ptr<MaintenanceState> state,
        const std::uint32_t generation = 41U)
        : state_(std::move(state)), base_generation_(generation),
          current_generation_(generation) {}

    ~FakeMaintenanceLease() override { ++state_->destruction_count; }

    std::uint32_t base_generation() const noexcept override {
        return base_generation_;
    }

    std::uint32_t reserve(const std::uint32_t expected) override {
        ++state_->reserve_count;
        if (!state_->held || expected != current_generation_) {
            throw std::runtime_error("test maintenance generation mismatch");
        }
        return ++current_generation_;
    }

    void verify_held() override {
        ++state_->verify_count;
        if (!state_->held) {
            throw std::runtime_error("test maintenance lease lost");
        }
    }

private:
    std::shared_ptr<MaintenanceState> state_;
    std::uint32_t base_generation_{0U};
    std::uint32_t current_generation_{0U};
};

NdmsNativeWriterLeaseTestHooks writer_hooks() {
    NdmsNativeWriterLeaseTestHooks hooks;
    hooks.allow_current_process_owner = true;
    return hooks;
}

NdmsNativeWriterAdmission acquire_writer(
    const std::filesystem::path& state_directory,
    RuntimeMutationAdmission& runtime,
    const std::shared_ptr<MaintenanceState>& maintenance_state) {
    auto runtime_lease = runtime.try_acquire("native-test");
    REQUIRE(runtime_lease.has_value());
    return admit_ndms_native_writer(
        state_directory,
        std::make_unique<FakeMaintenanceLease>(maintenance_state),
        std::move(*runtime_lease), writer_hooks());
}

void require_exact_mode(const std::filesystem::path& path,
                        const mode_t expected,
                        const bool directory) {
    struct stat status {};
    REQUIRE(::lstat(path.c_str(), &status) == 0);
    CHECK((status.st_mode & 07777) == expected);
    CHECK(directory ? S_ISDIR(status.st_mode) : S_ISREG(status.st_mode));
    CHECK(status.st_uid == ::geteuid());
    CHECK(status.st_gid == ::getegid());
}

} // namespace

static_assert(!std::is_default_constructible_v<NdmsNativeWriterLease>);
static_assert(!std::is_copy_constructible_v<NdmsNativeWriterLease>);
static_assert(!std::is_copy_assignable_v<NdmsNativeWriterLease>);
static_assert(std::is_nothrow_move_constructible_v<NdmsNativeWriterLease>);
static_assert(std::is_nothrow_move_assignable_v<NdmsNativeWriterLease>);

TEST_CASE("native writer lease owns all guards and reports cooperative scope") {
    TempDirectory directory;
    RuntimeMutationAdmission runtime;
    const auto maintenance = std::make_shared<MaintenanceState>();

    {
        auto admitted = acquire_writer(directory.state, runtime, maintenance);
        REQUIRE(admitted.state == NdmsNativeWriterAdmissionState::admitted);
        REQUIRE(admitted.lease.held());
        CHECK(admitted.lease.scope() ==
              NdmsNativeWriterLeaseScope::keen_pbr_cooperative);
        CHECK(std::string(ndms_native_writer_lease_scope_name(
                  admitted.lease.scope())) == "keen_pbr_cooperative");
        CHECK(admitted.lease.maintenance_base_generation() == 41U);
        CHECK(admitted.lease.runtime_token() != 0U);
        CHECK(runtime.active().has_value());
        CHECK_NOTHROW(admitted.lease.verify_held());
        require_exact_mode(directory.state, 0700, true);
        require_exact_mode(directory.state / "writer.lock", 0600, false);
    }

    CHECK_FALSE(runtime.active().has_value());
    CHECK(maintenance->destruction_count == 1U);
    CHECK(maintenance->verify_count >= 3U);
}

TEST_CASE("native writer lease refuses missing or lost outer guards") {
    TempDirectory directory;
    RuntimeMutationAdmission runtime;
    const auto maintenance = std::make_shared<MaintenanceState>();

    auto missing = admit_ndms_native_writer(
        directory.state,
        std::make_unique<FakeMaintenanceLease>(maintenance),
        RuntimeMutationAdmission::Lease{}, writer_hooks());
    CHECK(missing.state ==
          NdmsNativeWriterAdmissionState::outer_guard_missing);
    CHECK_FALSE(missing.lease.held());

    maintenance->held = false;
    auto runtime_lease = runtime.try_acquire("native-lost");
    REQUIRE(runtime_lease.has_value());
    auto lost = admit_ndms_native_writer(
        directory.state,
        std::make_unique<FakeMaintenanceLease>(maintenance),
        std::move(*runtime_lease), writer_hooks());
    CHECK(lost.state == NdmsNativeWriterAdmissionState::outer_guard_lost);
    CHECK_FALSE(lost.lease.held());
    CHECK_FALSE(runtime.active().has_value());
}

TEST_CASE("native writer flock excludes another process-local admission") {
    TempDirectory directory;
    RuntimeMutationAdmission first_runtime;
    RuntimeMutationAdmission second_runtime;
    const auto first_maintenance = std::make_shared<MaintenanceState>();
    const auto second_maintenance = std::make_shared<MaintenanceState>();

    auto first = acquire_writer(
        directory.state, first_runtime, first_maintenance);
    REQUIRE(first.state == NdmsNativeWriterAdmissionState::admitted);

    auto second = acquire_writer(
        directory.state, second_runtime, second_maintenance);
    CHECK(second.state == NdmsNativeWriterAdmissionState::lease_busy);
    CHECK_FALSE(second.lease.held());
    CHECK_FALSE(second_runtime.active().has_value());

    first.lease = NdmsNativeWriterLease(std::move(second.lease));
    CHECK_FALSE(first.lease.held());

    auto retry = acquire_writer(
        directory.state, second_runtime, second_maintenance);
    CHECK(retry.state == NdmsNativeWriterAdmissionState::admitted);
}

TEST_CASE("moving native writer lease transfers exactly one ownership") {
    TempDirectory directory;
    RuntimeMutationAdmission runtime;
    const auto maintenance = std::make_shared<MaintenanceState>();
    auto admitted = acquire_writer(directory.state, runtime, maintenance);
    REQUIRE(admitted.state == NdmsNativeWriterAdmissionState::admitted);

    NdmsNativeWriterLease moved(std::move(admitted.lease));
    CHECK_FALSE(admitted.lease.held());
    CHECK(moved.held());
    CHECK_NOTHROW(moved.verify_held());
}

TEST_CASE("native writer detects a lost maintenance guard") {
    TempDirectory directory;
    RuntimeMutationAdmission runtime;
    const auto maintenance = std::make_shared<MaintenanceState>();
    auto admitted = acquire_writer(directory.state, runtime, maintenance);
    REQUIRE(admitted.state == NdmsNativeWriterAdmissionState::admitted);

    maintenance->held = false;
    CHECK_THROWS_AS(
        admitted.lease.verify_held(), std::runtime_error);
}

TEST_CASE("native writer exposes only exact maintenance generation reserve") {
    TempDirectory directory;
    RuntimeMutationAdmission runtime;
    const auto maintenance = std::make_shared<MaintenanceState>();
    auto admitted = acquire_writer(directory.state, runtime, maintenance);
    REQUIRE(admitted.state == NdmsNativeWriterAdmissionState::admitted);

    CHECK(admitted.lease.maintenance_base_generation() == 41U);
    CHECK(admitted.lease.reserve_maintenance_generation(41U) == 42U);
    CHECK(admitted.lease.maintenance_base_generation() == 41U);
    CHECK_THROWS_AS(
        admitted.lease.reserve_maintenance_generation(41U),
        std::runtime_error);
    CHECK(admitted.lease.reserve_maintenance_generation(42U) == 43U);
    CHECK(maintenance->reserve_count == 3U);

    maintenance->held = false;
    CHECK_THROWS_AS(
        admitted.lease.reserve_maintenance_generation(43U),
        std::runtime_error);
    CHECK(maintenance->reserve_count == 3U);
}

TEST_CASE("native writer rejects a symlinked state directory") {
    TempDirectory directory;
    const auto real = directory.root / "real";
    REQUIRE(std::filesystem::create_directory(real));
    std::filesystem::create_directory_symlink(real, directory.state);
    REQUIRE(std::filesystem::is_symlink(directory.state));
    RuntimeMutationAdmission runtime;
    const auto maintenance = std::make_shared<MaintenanceState>();

    auto admitted = acquire_writer(directory.state, runtime, maintenance);
    CHECK(admitted.state ==
          NdmsNativeWriterAdmissionState::state_directory_unsafe);
    CHECK_FALSE(admitted.lease.held());
}

TEST_CASE("a crashed native writer releases the kernel flock") {
    TempDirectory directory;
    int ready_pipe[2] {-1, -1};
    int release_pipe[2] {-1, -1};
    REQUIRE(::pipe(ready_pipe) == 0);
    REQUIRE(::pipe(release_pipe) == 0);

    const pid_t child = ::fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        (void)::close(ready_pipe[0]);
        (void)::close(release_pipe[1]);
        RuntimeMutationAdmission runtime;
        auto runtime_lease = runtime.try_acquire("child-native-writer");
        if (!runtime_lease.has_value()) {
            const char ready = '0';
            if (::write(ready_pipe[1], &ready, 1U) != 1) {
                ::_exit(2);
            }
            ::_exit(1);
        }
        const auto maintenance = std::make_shared<MaintenanceState>();
        auto admitted = admit_ndms_native_writer(
            directory.state,
            std::make_unique<FakeMaintenanceLease>(maintenance),
            std::move(*runtime_lease), writer_hooks());
        const char ready = admitted.state ==
                                   NdmsNativeWriterAdmissionState::admitted
            ? '1' : '0';
        if (::write(ready_pipe[1], &ready, 1U) != 1) {
            ::_exit(2);
        }
        char release = 0;
        if (::read(release_pipe[0], &release, 1U) != 1) {
            ::_exit(3);
        }
        ::_exit(0);
    }

    (void)::close(ready_pipe[1]);
    (void)::close(release_pipe[0]);
    char ready = 0;
    REQUIRE(::read(ready_pipe[0], &ready, 1U) == 1);
    REQUIRE(ready == '1');

    RuntimeMutationAdmission runtime;
    const auto maintenance = std::make_shared<MaintenanceState>();
    auto busy = acquire_writer(directory.state, runtime, maintenance);
    CHECK(busy.state == NdmsNativeWriterAdmissionState::lease_busy);

    const char release = 'x';
    REQUIRE(::write(release_pipe[1], &release, 1U) == 1);
    int status = 0;
    REQUIRE(::waitpid(child, &status, 0) == child);
    REQUIRE(WIFEXITED(status));

    auto after_crash = acquire_writer(directory.state, runtime, maintenance);
    CHECK(after_crash.state == NdmsNativeWriterAdmissionState::admitted);

    (void)::close(ready_pipe[0]);
    (void)::close(release_pipe[1]);
}
