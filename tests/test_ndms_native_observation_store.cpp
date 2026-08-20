#include <doctest/doctest.h>

#include "keenetic/ndms_native_observation_store.hpp"

#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace keen_pbr3;

namespace {

constexpr char kAuthority[] = "0123456789abcdef0123456789abcdef";

class TempDirectory final {
public:
    TempDirectory() {
        std::string pattern =
            (std::filesystem::temp_directory_path() /
             "keen-pbr-native-observation-XXXXXX")
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

class FakeMaintenanceLease final : public MaintenanceLease {
public:
    std::uint32_t base_generation() const noexcept override { return 41U; }
    std::uint32_t reserve(const std::uint32_t expected) override {
        if (expected != 41U) throw std::runtime_error("generation mismatch");
        return 42U;
    }
    void verify_held() override {}
};

NdmsNativeWriterLeaseTestHooks writer_hooks() {
    NdmsNativeWriterLeaseTestHooks hooks;
    hooks.allow_current_process_owner = true;
    return hooks;
}

NdmsNativeObservationStoreTestHooks observation_hooks() {
    NdmsNativeObservationStoreTestHooks hooks;
    hooks.allow_current_process_owner = true;
    hooks.authority_id_factory = [] { return std::string{kAuthority}; };
    return hooks;
}

NdmsNativeWriterAdmission acquire_writer(
    const std::filesystem::path& path,
    RuntimeMutationAdmission& runtime) {
    auto runtime_lease = runtime.try_acquire("native-observation-test");
    REQUIRE(runtime_lease.has_value());
    return admit_ndms_native_writer(
        path, std::make_unique<FakeMaintenanceLease>(),
        std::move(*runtime_lease), writer_hooks());
}

std::string catalog_revision(const char digit) {
    return std::string{kNdmsNativeObservationCatalogRevisionPrefix} +
           std::string(64U, digit);
}

std::size_t temporary_count(const std::filesystem::path& state) {
    std::size_t count = 0U;
    for (const auto& item : std::filesystem::directory_iterator(state)) {
        if (item.path().filename().string().rfind(".observation.tmp.", 0U) ==
            0U) {
            ++count;
        }
    }
    return count;
}

} // namespace

TEST_CASE("observation authority provisions once and survives reconstruction") {
    TempDirectory directory;
    NdmsNativeObservationStore before(directory.state, observation_hooks());
    CHECK(before.read().state == NdmsNativeObservationReadState::absent);

    RuntimeMutationAdmission runtime;
    auto admitted = acquire_writer(directory.state, runtime);
    REQUIRE(admitted.state == NdmsNativeWriterAdmissionState::admitted);
    const auto provisioned = before.provision(admitted.lease);
    CHECK(provisioned.authority_id == kAuthority);
    CHECK(provisioned.sequence == 0U);
    CHECK(provisioned.mutation_epoch == 0U);
    CHECK_FALSE(provisioned.last_catalog_revision.has_value());
    CHECK(provisioned.integrity ==
          ndms_native_observation_integrity(provisioned));
    CHECK(before.provision(admitted.lease) == provisioned);

    NdmsNativeObservationStore after(directory.state, observation_hooks());
    const auto restarted = after.read();
    REQUIRE(restarted.state == NdmsNativeObservationReadState::valid);
    REQUIRE(restarted.ledger.has_value());
    CHECK(*restarted.ledger == provisioned);

    struct stat status {};
    REQUIRE(::lstat(
                (directory.state /
                 kNdmsNativeObservationStateFilename).c_str(),
                &status) == 0);
    CHECK(S_ISREG(status.st_mode));
    CHECK((status.st_mode & 07777) == 0600);
    CHECK(status.st_nlink == 1);
}

TEST_CASE("observation sequence and mutation epoch remain authoritative across restart") {
    TempDirectory directory;
    NdmsNativeMutationEpoch mutation;
    NdmsNativeObservationBinding binding;
    NdmsNativeObservationStamp earlier;
    {
        RuntimeMutationAdmission first_runtime;
        auto first_writer = acquire_writer(directory.state, first_runtime);
        REQUIRE(first_writer.state == NdmsNativeWriterAdmissionState::admitted);
        NdmsNativeObservationStore first(directory.state, observation_hooks());
        first.provision(first_writer.lease);
        const auto baseline = first.record_observation(
            first_writer.lease, catalog_revision('a'));
        REQUIRE(baseline.sequence == 1U);
        REQUIRE(baseline.mutation_epoch == 0U);
        mutation = first.begin_mutation(first_writer.lease, baseline);
        CHECK(mutation.authority_id == kAuthority);
        CHECK(mutation.baseline_sequence == 1U);
        CHECK(mutation.mutation_epoch == 1U);
        binding = ndms_native_observation_binding(mutation);

        earlier = first.record_recovery_observation(
            first_writer.lease, binding, catalog_revision('b'));
        CHECK(earlier.sequence == 2U);
        CHECK(earlier.mutation_epoch == 1U);
    }

    RuntimeMutationAdmission restarted_runtime;
    auto restarted_writer = acquire_writer(
        directory.state, restarted_runtime);
    REQUIRE(restarted_writer.state ==
            NdmsNativeWriterAdmissionState::admitted);
    NdmsNativeObservationStore restarted(
        directory.state, observation_hooks());
    const auto loaded = restarted.read();
    REQUIRE(loaded.state == NdmsNativeObservationReadState::valid);
    REQUIRE(loaded.ledger.has_value());
    CHECK(loaded.ledger->authority_id == mutation.authority_id);
    CHECK(loaded.ledger->sequence == earlier.sequence);
    CHECK(loaded.ledger->mutation_epoch == mutation.mutation_epoch);

    const auto later = restarted.record_recovery_observation(
        restarted_writer.lease, binding, catalog_revision('b'));
    CHECK(later.sequence == 3U);
    CHECK(later.sequence > earlier.sequence);
    CHECK(later.mutation_epoch == earlier.mutation_epoch);
    CHECK(later.catalog_revision == earlier.catalog_revision);

    auto foreign_authority = binding;
    foreign_authority.authority_id = std::string(32U, '9');
    CHECK_THROWS_AS(
        restarted.record_recovery_observation(
            restarted_writer.lease, foreign_authority,
            catalog_revision('c')),
        NdmsNativeObservationStoreError);
    auto foreign_epoch = binding;
    ++foreign_epoch.mutation_epoch;
    CHECK_THROWS_AS(
        restarted.record_recovery_observation(
            restarted_writer.lease, foreign_epoch,
            catalog_revision('c')),
        NdmsNativeObservationStoreError);
    auto future_baseline = binding;
    future_baseline.baseline_sequence = later.sequence + 1U;
    CHECK_THROWS_AS(
        restarted.record_recovery_observation(
            restarted_writer.lease, future_baseline,
            catalog_revision('c')),
        NdmsNativeObservationStoreError);
}

TEST_CASE("begin mutation is an exact CAS over the baseline stamp") {
    TempDirectory directory;
    RuntimeMutationAdmission runtime;
    auto writer = acquire_writer(directory.state, runtime);
    REQUIRE(writer.state == NdmsNativeWriterAdmissionState::admitted);
    NdmsNativeObservationStore store(directory.state, observation_hooks());
    store.provision(writer.lease);
    const auto stale = store.record_observation(
        writer.lease, catalog_revision('a'));
    const auto current = store.record_observation(
        writer.lease, catalog_revision('b'));

    CHECK_THROWS_AS(
        store.begin_mutation(writer.lease, stale),
        NdmsNativeObservationStoreError);
    const auto mutation = store.begin_mutation(writer.lease, current);
    CHECK(mutation.baseline_sequence == current.sequence);
    CHECK(mutation.mutation_epoch == current.mutation_epoch + 1U);
    const auto binding = ndms_native_observation_binding(mutation);
    CHECK(valid_ndms_native_observation_binding(binding));
    CHECK(binding.authority_id == mutation.authority_id);
    CHECK(binding.mutation_epoch == mutation.mutation_epoch);
    CHECK(binding.baseline_sequence == mutation.baseline_sequence);

    const auto next_baseline = store.record_mutation_observation(
        writer.lease, mutation, catalog_revision('c'));
    const auto next_mutation = store.begin_mutation(
        writer.lease, next_baseline);
    CHECK(next_mutation.mutation_epoch == mutation.mutation_epoch + 1U);
    CHECK_THROWS_AS(
        store.record_mutation_observation(
            writer.lease, mutation, catalog_revision('d')),
        NdmsNativeObservationStoreError);
}

TEST_CASE("corrupt observation state is unreadable and never regenerated") {
    TempDirectory directory;
    RuntimeMutationAdmission runtime;
    NdmsNativeObservationStore store(directory.state, observation_hooks());
    {
        auto writer = acquire_writer(directory.state, runtime);
        REQUIRE(writer.state == NdmsNativeWriterAdmissionState::admitted);
        store.provision(writer.lease);
        store.record_observation(writer.lease, catalog_revision('a'));
    }

    const auto state_path =
        directory.state / kNdmsNativeObservationStateFilename;
    std::fstream file(state_path, std::ios::in | std::ios::out |
                                      std::ios::binary);
    REQUIRE(file);
    file.seekp(40);
    file.put('f');
    file.flush();
    file.close();

    CHECK(store.read().state == NdmsNativeObservationReadState::unreadable);
    auto retry_writer = acquire_writer(directory.state, runtime);
    REQUIRE(retry_writer.state == NdmsNativeWriterAdmissionState::admitted);
    CHECK_THROWS_AS(
        store.provision(retry_writer.lease),
        NdmsNativeObservationStoreError);
}

TEST_CASE("fault before atomic replace preserves the previous ledger") {
    TempDirectory directory;
    bool fail = false;
    auto hooks = observation_hooks();
    hooks.fault_injector = [&fail](
        const NdmsNativeObservationStoreFaultStage stage) {
        if (fail && stage ==
                        NdmsNativeObservationStoreFaultStage::
                            after_temporary_file_fsync) {
            fail = false;
            throw std::runtime_error("injected pre-replace fault");
        }
    };
    RuntimeMutationAdmission runtime;
    auto writer = acquire_writer(directory.state, runtime);
    REQUIRE(writer.state == NdmsNativeWriterAdmissionState::admitted);
    NdmsNativeObservationStore store(directory.state, hooks);
    store.provision(writer.lease);
    const auto baseline = store.record_observation(
        writer.lease, catalog_revision('a'));

    fail = true;
    CHECK_THROWS_AS(
        store.record_observation(writer.lease, catalog_revision('b')),
        std::runtime_error);
    const auto retained = store.read();
    REQUIRE(retained.state == NdmsNativeObservationReadState::valid);
    REQUIRE(retained.ledger.has_value());
    CHECK(retained.ledger->sequence == baseline.sequence);
    CHECK(retained.ledger->last_catalog_revision ==
          std::optional<std::string>{baseline.catalog_revision});
    CHECK(temporary_count(directory.state) == 0U);
}

TEST_CASE("fault after rename leaves one complete restart-readable ledger") {
    TempDirectory directory;
    bool fail = false;
    auto hooks = observation_hooks();
    hooks.fault_injector = [&fail](
        const NdmsNativeObservationStoreFaultStage stage) {
        if (fail && stage ==
                        NdmsNativeObservationStoreFaultStage::
                            after_replace_rename_before_directory_fsync) {
            fail = false;
            throw std::runtime_error("injected post-rename fault");
        }
    };
    RuntimeMutationAdmission runtime;
    auto writer = acquire_writer(directory.state, runtime);
    REQUIRE(writer.state == NdmsNativeWriterAdmissionState::admitted);
    NdmsNativeObservationStore store(directory.state, hooks);
    store.provision(writer.lease);
    store.record_observation(writer.lease, catalog_revision('a'));

    fail = true;
    CHECK_THROWS_AS(
        store.record_observation(writer.lease, catalog_revision('b')),
        std::runtime_error);
    const auto visible = store.read();
    REQUIRE(visible.state == NdmsNativeObservationReadState::valid);
    REQUIRE(visible.ledger.has_value());
    CHECK(visible.ledger->sequence == 2U);
    CHECK(visible.ledger->last_catalog_revision ==
          std::optional<std::string>{catalog_revision('b')});
    CHECK(temporary_count(directory.state) == 0U);
}

TEST_CASE("restart repairs an initial-publication crash without changing authority") {
    TempDirectory directory;
    const pid_t child = ::fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        RuntimeMutationAdmission runtime;
        auto runtime_lease = runtime.try_acquire("observation-crash-child");
        if (!runtime_lease.has_value()) ::_exit(70);
        auto writer = admit_ndms_native_writer(
            directory.state, std::make_unique<FakeMaintenanceLease>(),
            std::move(*runtime_lease), writer_hooks());
        if (writer.state != NdmsNativeWriterAdmissionState::admitted) {
            ::_exit(71);
        }
        auto hooks = observation_hooks();
        hooks.fault_injector = [](
            const NdmsNativeObservationStoreFaultStage stage) {
            if (stage ==
                NdmsNativeObservationStoreFaultStage::
                    after_initial_link_before_temporary_unlink) {
                ::_exit(77);
            }
        };
        NdmsNativeObservationStore store(directory.state, hooks);
        (void)store.provision(writer.lease);
        ::_exit(72);
    }

    int status = 0;
    REQUIRE(::waitpid(child, &status, 0) == child);
    REQUIRE(WIFEXITED(status));
    REQUIRE(WEXITSTATUS(status) == 77);

    NdmsNativeObservationStore store(
        directory.state, observation_hooks());
    CHECK(store.read().state == NdmsNativeObservationReadState::unreadable);
    RuntimeMutationAdmission runtime;
    auto writer = acquire_writer(directory.state, runtime);
    REQUIRE(writer.state == NdmsNativeWriterAdmissionState::admitted);
    const auto recovered = store.provision(writer.lease);
    CHECK(recovered.authority_id == kAuthority);
    CHECK(recovered.sequence == 0U);
    CHECK(recovered.mutation_epoch == 0U);
    CHECK(temporary_count(directory.state) == 0U);
    CHECK(store.read().state == NdmsNativeObservationReadState::valid);
}

TEST_CASE("observation store refuses a writer for a different directory") {
    TempDirectory first;
    TempDirectory second;
    RuntimeMutationAdmission runtime;
    auto writer = acquire_writer(first.state, runtime);
    REQUIRE(writer.state == NdmsNativeWriterAdmissionState::admitted);
    NdmsNativeObservationStore store(second.state, observation_hooks());
    CHECK_THROWS_AS(
        store.provision(writer.lease),
        NdmsNativeObservationStoreError);
}

TEST_CASE("observation catalog revisions are a closed digest vocabulary") {
    CHECK(valid_ndms_native_observation_catalog_revision(
        catalog_revision('a')));
    CHECK_FALSE(valid_ndms_native_observation_catalog_revision(
        std::string(64U, 'a')));
    CHECK_FALSE(valid_ndms_native_observation_catalog_revision(
        std::string{kNdmsNativeObservationCatalogRevisionPrefix} +
        std::string(64U, 'A')));
}
