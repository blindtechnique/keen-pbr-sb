#include <doctest/doctest.h>

#include "../src/update/component_transaction_journal.hpp"

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <system_error>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {

namespace {

namespace fs = std::filesystem;

class TempDirectory {
public:
    TempDirectory() {
        std::string pattern =
            (fs::temp_directory_path() / "keen-pbr-ctj-XXXXXX").string();
        std::vector<char> writable(pattern.begin(), pattern.end());
        writable.push_back('\0');
        const char* created = ::mkdtemp(writable.data());
        if (created == nullptr)
            throw std::system_error(errno, std::generic_category(), "mkdtemp");
        path = created;
    }

    ~TempDirectory() {
        std::error_code error;
        fs::permissions(path,
                        fs::perms::owner_all,
                        fs::perm_options::add,
                        error);
        fs::remove_all(path, error);
    }

    fs::path path;
};

ComponentTransactionRecord sample_record() {
    ComponentTransactionRecord record;
    record.component = "nfqws2-keenetic";
    record.operation = "upgrade";
    record.phase = ComponentTransactionPhase::mutating;
    record.started_at = 1786500000;
    record.binary_sha256 = std::string(64, 'a');
    record.config_sha256 = std::string(64, 'b');
    record.runtime_was_running = true;
    return record;
}

void write_raw(const fs::path& path, const std::string& body) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    REQUIRE(output);
    output << body;
}

} // namespace

TEST_CASE("no record means nothing was in flight") {
    TempDirectory directory;
    const auto status =
        read_component_transaction(directory.path / "absent.json");
    CHECK(status.state == ComponentTransactionState::none);
    CHECK_FALSE(status.record.has_value());
}

TEST_CASE("a record this process owns is running, not abandoned") {
    // The regression this case exists for: without an owner, every record read
    // as "did not finish", so the panel told the operator their upgrade had
    // failed for the whole time it was correctly running. A warning that fires
    // during the normal case is one that stops being read before the abnormal
    // case arrives.
    TempDirectory directory;
    const auto path = directory.path / "transaction.json";
    write_component_transaction(path, sample_record());

    const auto status = read_component_transaction(path);
    CHECK(status.state == ComponentTransactionState::in_flight);
    REQUIRE(status.record.has_value());
    CHECK(status.record->owner_pid == static_cast<std::int64_t>(::getpid()));
    CHECK_FALSE(status.record->owner_start.empty());
}

TEST_CASE("a record whose owner is gone is abandoned") {
    TempDirectory directory;
    const auto path = directory.path / "transaction.json";
    auto record = sample_record();
    // This process, with somebody else's start time. Alive, so liveness alone
    // would call it running; the start time is what says otherwise.
    //
    // That distinction is not decoration. Pids are reused, and a reboot makes
    // reuse near-certain: without this check any process that happened to land
    // on the recorded number would make an interrupted operation look like a
    // running one, and the operator would be told to wait for something that
    // is never going to finish.
    //
    // An earlier version of this case used pid 1, which proves nothing: it is
    // rejected by the pid<=1 guard before the start time is ever compared, and
    // a mutation deleting the comparison passed the suite.
    record.owner_pid = static_cast<std::int64_t>(::getpid());
    record.owner_start = "999999999";
    write_component_transaction(path, record);
    CHECK(read_component_transaction(path).state ==
          ComponentTransactionState::abandoned);

    // And pid 1 for the guard that does reject it: init is alive, and is not
    // the owner of anything we wrote.
    record.owner_pid = 1;
    record.owner_start = "1";
    write_component_transaction(path, record);
    CHECK(read_component_transaction(path).state ==
          ComponentTransactionState::abandoned);

    // A pid that can own nothing, written raw: the writer substitutes this
    // process when the caller names none, so this state cannot be produced
    // through it - and that substitution is deliberate, since the process
    // writing the record is by definition the one doing the work.
    write_raw(path,
              "{\"version\":1,\"component\":\"nfqws2-keenetic\","
              "\"operation\":\"upgrade\",\"phase\":\"mutating\","
              "\"owner_pid\":0,\"owner_start\":\"1\"}");
    CHECK(read_component_transaction(path).state ==
          ComponentTransactionState::abandoned);
}

TEST_CASE("a record from before owners were written is abandoned, not running") {
    // An older keen-pbr wrote no owner. Reading that as "running" would let a
    // genuinely interrupted operation hide behind the benign state.
    TempDirectory directory;
    const auto path = directory.path / "old.json";
    write_raw(path,
              "{\"version\":1,\"component\":\"nfqws2-keenetic\","
              "\"operation\":\"upgrade\",\"phase\":\"mutating\"}");
    CHECK(read_component_transaction(path).state ==
          ComponentTransactionState::abandoned);
}

TEST_CASE("a written record survives and reads back exactly") {
    TempDirectory directory;
    const auto path = directory.path / "nested" / "transaction.json";
    const auto written = sample_record();
    write_component_transaction(path, written);

    const auto status = read_component_transaction(path);
    REQUIRE(status.state == ComponentTransactionState::in_flight);
    REQUIRE(status.record.has_value());
    CHECK(status.record->component == written.component);
    CHECK(status.record->operation == written.operation);
    CHECK(status.record->phase == written.phase);
    CHECK(status.record->started_at == written.started_at);
    CHECK(status.record->binary_sha256 == written.binary_sha256);
    CHECK(status.record->config_sha256 == written.config_sha256);
    CHECK(status.record->runtime_was_running);
    // The record is private: it names what was installed and can be read to
    // learn what an interrupted upgrade was doing.
    struct stat info {};
    REQUIRE(::lstat(path.c_str(), &info) == 0);
    CHECK((info.st_mode & 07777) == 0600U);
}

TEST_CASE("every phase round-trips through its name") {
    TempDirectory directory;
    const auto path = directory.path / "phase.json";
    for (const auto phase : {ComponentTransactionPhase::started,
                             ComponentTransactionPhase::mutating,
                             ComponentTransactionPhase::verifying}) {
        auto record = sample_record();
        record.phase = phase;
        write_component_transaction(path, record);
        const auto status = read_component_transaction(path);
        REQUIRE(status.record.has_value());
        CHECK(status.record->phase == phase);
    }
}

TEST_CASE("a record that cannot be read is never reported as absent") {
    // The one case where assuming "nothing happened" is most likely wrong: a
    // torn or truncated journal is itself evidence of an interruption. If this
    // answered `none`, the next upgrade would run a package manager over
    // exactly the state nobody can describe.
    TempDirectory directory;
    const auto path = directory.path / "damaged.json";

    write_raw(path, "{\"version\":1,\"component\":\"nfqws2-keeneti");
    CHECK(read_component_transaction(path).state ==
          ComponentTransactionState::unreadable);

    write_raw(path, "");
    CHECK(read_component_transaction(path).state ==
          ComponentTransactionState::unreadable);

    write_raw(path, "[]");
    CHECK(read_component_transaction(path).state ==
          ComponentTransactionState::unreadable);

    // A future version is not this version. Guessing at fields we do not know
    // would be worse than admitting we cannot read it.
    write_raw(path,
              "{\"version\":2,\"component\":\"c\",\"operation\":\"upgrade\","
              "\"phase\":\"mutating\"}");
    CHECK(read_component_transaction(path).state ==
          ComponentTransactionState::unreadable);

    // An unknown phase name, an empty component, a missing field.
    write_raw(path,
              "{\"version\":1,\"component\":\"c\",\"operation\":\"upgrade\","
              "\"phase\":\"teleporting\"}");
    CHECK(read_component_transaction(path).state ==
          ComponentTransactionState::unreadable);
    write_raw(path,
              "{\"version\":1,\"component\":\"\",\"operation\":\"upgrade\","
              "\"phase\":\"mutating\"}");
    CHECK(read_component_transaction(path).state ==
          ComponentTransactionState::unreadable);
    write_raw(path, "{\"version\":1,\"component\":\"c\"}");
    CHECK(read_component_transaction(path).state ==
          ComponentTransactionState::unreadable);
}

TEST_CASE("optional detail is allowed to be missing without losing the record") {
    // The fields that describe the pre-upgrade world are useful, not load
    // bearing. Refusing to read a record because one of them is absent would
    // turn a known interruption into an unreadable one for no gain.
    TempDirectory directory;
    const auto path = directory.path / "minimal.json";
    write_raw(path,
              "{\"version\":1,\"component\":\"nfqws2-keenetic\","
              "\"operation\":\"upgrade\",\"phase\":\"started\"}");
    const auto status = read_component_transaction(path);
    // Readable, so a record - abandoned rather than running, because no owner
    // was named. Which of the two it is does not change that it was read.
    REQUIRE(status.state == ComponentTransactionState::abandoned);
    REQUIRE(status.record.has_value());
    CHECK(status.record->started_at == 0);
    CHECK(status.record->binary_sha256.empty());
    CHECK_FALSE(status.record->runtime_was_running);
}

TEST_CASE("clearing is confirmed by looking, not by trusting the call") {
    TempDirectory directory;
    const auto path = directory.path / "transaction.json";
    write_component_transaction(path, sample_record());
    REQUIRE(read_component_transaction(path).state ==
            ComponentTransactionState::in_flight);

    CHECK(clear_component_transaction(path));
    CHECK(read_component_transaction(path).state ==
          ComponentTransactionState::none);
    // Clearing an absent record is not a failure; the desired end state is
    // "no record", and it is already true.
    CHECK(clear_component_transaction(path));
}

TEST_CASE("a record that could not be removed is reported as still present") {
    // Made to fail by a means that works under root as well. Withdrawing the
    // directory's write bit does not: root ignores it, so that version of this
    // test passed by skipping its own body in exactly the environment the
    // suite runs in - zero assertions, and a mutation that removed the check
    // sailed through it.
    //
    // A non-empty directory cannot be unlinked by anybody.
    TempDirectory directory;
    const auto path = directory.path / "transaction.json";
    fs::create_directories(path);
    write_raw(path / "occupant", "in the way\n");

    // Silently reporting success here would let the next upgrade run while the
    // record still says a transaction is open.
    CHECK_FALSE(clear_component_transaction(path));
    std::error_code error;
    CHECK(fs::exists(path, error));
}

TEST_CASE("every journal name is distinct and stable") {
    std::set<std::string> names;
    for (const auto phase : {ComponentTransactionPhase::started,
                             ComponentTransactionPhase::mutating,
                             ComponentTransactionPhase::verifying}) {
        CHECK(names.insert(component_transaction_phase_name(phase)).second);
    }
    std::set<std::string> states;
    for (const auto state : {ComponentTransactionState::none,
                             ComponentTransactionState::in_flight,
                             ComponentTransactionState::abandoned,
                             ComponentTransactionState::unreadable}) {
        CHECK(states.insert(component_transaction_state_name(state)).second);
    }
}

} // namespace keen_pbr3
