#include "../src/util/nfqws_rotator_state.hpp"

#include <doctest/doctest.h>

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {
namespace {

namespace fs = std::filesystem;

constexpr NfqwsProcessGeneration kGeneration{321, 987654};

std::string snapshot(std::uint64_t sequence,
                     std::int64_t observed_at,
                     const std::string& pools,
                     std::uint64_t pool_count,
                     std::uint64_t tracked_total,
                     bool truncated = false,
                     NfqwsProcessGeneration generation = kGeneration) {
    return "V1\t" + std::to_string(sequence) + "\t" +
           std::to_string(generation.pid) + "\t" +
           std::to_string(generation.start_ticks) + "\t" +
           std::to_string(observed_at) + "\t" +
           (truncated ? "1\n" : "0\n") + pools + "END\t" +
           std::to_string(sequence) + "\t" +
           std::to_string(pool_count) + "\t" +
           std::to_string(tracked_total) + "\n";
}

NfqwsRotatorStateSelection selection_at(std::int64_t now) {
    NfqwsRotatorStateSelection selection;
    selection.reporter_expected = true;
    selection.process_generation = kGeneration;
    selection.process_age_seconds = 60;
    selection.now_unix = now;
    return selection;
}

struct TemporaryDirectory {
    fs::path path;

    TemporaryDirectory() {
        char pattern[] = "/tmp/keen-pbr-rotator-state-XXXXXX";
        const auto created = ::mkdtemp(pattern);
        if (!created) throw std::runtime_error("mkdtemp failed");
        path = created;
    }

    ~TemporaryDirectory() {
        std::error_code error;
        fs::remove_all(path, error);
    }
};

void write_file(const fs::path& path, const std::string& content) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    REQUIRE(output.good());
    output << content;
    output.close();
    REQUIRE(output.good());
    REQUIRE(::chmod(path.c_str(), 0644) == 0);
}

} // namespace

TEST_CASE("nfqws rotator snapshot exposes a slot only for a unanimous pool") {
    const auto parsed = parse_nfqws_rotator_snapshot(snapshot(
        7, 1000,
        "P\t79745f746370\t3\t3=3\t9=3\t0=2,1=1\n",
        1, 3));

    REQUIRE_MESSAGE(parsed.snapshot.has_value(), parsed.error);
    REQUIRE(parsed.snapshot->pools.size() == 1U);
    const auto& pool = parsed.snapshot->pools.front();
    CHECK(pool.key == "yt_tcp");
    CHECK(pool.tracked_targets == 3U);
    CHECK(pool.unanimous_slot() == 3U);
    CHECK(pool.unanimous_slot_count() == 9U);
    CHECK_FALSE(pool.unanimous_pending_failures().has_value());
    CHECK(pool.max_pending_failures() == 1U);
    CHECK(pool.pending_failure_histogram ==
          std::map<std::uint32_t, std::uint64_t>{{0U, 2U}, {1U, 1U}});
}

TEST_CASE("nfqws rotator snapshot preserves divergent host-level slots") {
    const auto parsed = parse_nfqws_rotator_snapshot(snapshot(
        8, 1000,
        "P\t6d61696e5f746370\t3\t1=2,3=1\t9=3\t0=1,1=2\n"
        "P\t79745f71756963\t2\t2=2\t7=1,9=1\t0=2\n",
        2, 5));

    REQUIRE_MESSAGE(parsed.snapshot.has_value(), parsed.error);
    REQUIRE(parsed.snapshot->pools.size() == 2U);
    const auto& main = parsed.snapshot->pools[0];
    CHECK(main.key == "main_tcp");
    CHECK_FALSE(main.unanimous_slot().has_value());
    CHECK(main.slot_histogram ==
          std::map<std::uint32_t, std::uint64_t>{{1U, 2U}, {3U, 1U}});
    CHECK(main.unanimous_slot_count() == 9U);

    const auto& youtube = parsed.snapshot->pools[1];
    CHECK(youtube.unanimous_slot() == 2U);
    CHECK_FALSE(youtube.unanimous_slot_count().has_value());
}

TEST_CASE("nfqws rotator aggregate validation does not pair unrelated hosts") {
    // Host A may validly be on slot 2 of 2 while host B is on slot 3 of 4.
    // Separate aggregate histograms intentionally cannot preserve that
    // pairing, so comparing max(slot) with min(slot_count) would reject a
    // truthful snapshot.
    const auto parsed = parse_nfqws_rotator_snapshot(snapshot(
        9, 1000,
        "P\t6d61696e5f71756963\t2\t2=1,3=1\t2=1,4=1\t0=2\n",
        1, 2));

    REQUIRE_MESSAGE(parsed.snapshot.has_value(), parsed.error);
    REQUIRE(parsed.snapshot->pools.size() == 1U);
    CHECK_FALSE(parsed.snapshot->pools.front().unanimous_slot().has_value());
    CHECK_FALSE(
        parsed.snapshot->pools.front().unanimous_slot_count().has_value());
}

TEST_CASE("nfqws rotator state chooses the newest complete double buffer") {
    auto selection = selection_at(1010);
    selection.snapshot_candidates = {
        snapshot(11, 1008,
                 "P\t79745f746370\t1\t2=1\t9=1\t0=1\n", 1, 1),
        "V1\t12\t321\t987654\t1009\t0\n"
        "P\t79745f746370\t1\t3=1\t9=1\t0=1\n",
    };

    const auto state = select_nfqws_rotator_state(selection);
    CHECK(state.status == NfqwsRotatorStateStatus::ready);
    REQUIRE(state.snapshot.has_value());
    CHECK(state.snapshot->sequence == 11U);
    CHECK(state.snapshot->pools.front().unanimous_slot() == 2U);
}

TEST_CASE("nfqws rotator state fences snapshots by pid and start ticks") {
    auto selection = selection_at(1010);
    selection.process_age_seconds = 5;
    selection.snapshot_candidates = {
        snapshot(9, 1009, {}, 0, 0, false, {322, 987654}),
        snapshot(10, 1009, {}, 0, 0, false, {321, 987655}),
    };

    auto state = select_nfqws_rotator_state(selection);
    CHECK(state.status == NfqwsRotatorStateStatus::warming_up);
    CHECK_FALSE(state.snapshot.has_value());

    selection.process_age_seconds = 60;
    state = select_nfqws_rotator_state(selection);
    CHECK(state.status == NfqwsRotatorStateStatus::stale);
    CHECK_FALSE(state.snapshot.has_value());
}

TEST_CASE("nfqws rotator state distinguishes unsupported warming and stale") {
    auto selection = selection_at(1100);
    selection.reporter_expected = false;
    CHECK(select_nfqws_rotator_state(selection).status ==
          NfqwsRotatorStateStatus::unsupported);

    selection.reporter_expected = true;
    selection.process_generation.reset();
    CHECK(select_nfqws_rotator_state(selection).status ==
          NfqwsRotatorStateStatus::stale);

    selection.process_generation = kGeneration;
    selection.process_age_seconds = 3;
    CHECK(select_nfqws_rotator_state(selection).status ==
          NfqwsRotatorStateStatus::warming_up);

    selection.process_age_seconds = 60;
    selection.snapshot_candidates = {snapshot(4, 1000, {}, 0, 0)};
    const auto stale = select_nfqws_rotator_state(selection);
    CHECK(stale.status == NfqwsRotatorStateStatus::stale);
    REQUIRE(stale.snapshot.has_value());
    CHECK(stale.snapshot->sequence == 4U);
}

TEST_CASE("nfqws rotator snapshot carries an explicit bounded truncation flag") {
    const auto parsed = parse_nfqws_rotator_snapshot(
        snapshot(3, 1000, {}, 0, 0, true));
    REQUIRE_MESSAGE(parsed.snapshot.has_value(), parsed.error);
    CHECK(parsed.snapshot->truncated);
}

TEST_CASE("nfqws rotator snapshot rejects malformed and partial publications") {
    CHECK_FALSE(parse_nfqws_rotator_snapshot(
                    "V1\t1\t321\t987654\t1000\t0\n")
                    .snapshot.has_value());
    CHECK_FALSE(parse_nfqws_rotator_snapshot(snapshot(
                    1, 1000,
                    "P\t79745f746370\t2\t1=2\t9=2\t0=1\n",
                    1, 2))
                    .snapshot.has_value());
    CHECK_FALSE(parse_nfqws_rotator_snapshot(
                    "V1\t1\t321\t987654\t1000\t0\n"
                    "P\t79745f746370\t1\t1=1\t9=1\t0=1\n"
                    "END\t2\t1\t1\n")
                    .snapshot.has_value());
    CHECK_FALSE(parse_nfqws_rotator_snapshot(snapshot(
                    1, 1000,
                    "P\t79745f746370\t1\t1=1\t9=1\t0=1\n"
                    "P\t79745f746370\t1\t1=1\t9=1\t0=1\n",
                    2, 2))
                    .snapshot.has_value());

    const std::string oversized(kMaxNfqwsRotatorSnapshotSize + 1U, 'x');
    CHECK_FALSE(parse_nfqws_rotator_snapshot(oversized).snapshot.has_value());
}

TEST_CASE("nfqws process generation parser fences pid and start ticks") {
    const std::string process_stat =
        "321 (nfqws2 worker) S 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 "
        "19 20 21 987654 23 24\n";
    CHECK(parse_nfqws_process_stat(process_stat, 321) == kGeneration);
    CHECK_FALSE(parse_nfqws_process_stat(process_stat, 322).has_value());
    CHECK_FALSE(parse_nfqws_process_stat("321 (broken) S 1 2", 321)
                    .has_value());
}

TEST_CASE("nfqws snapshot reader accepts only bounded regular owned leaves") {
    TemporaryDirectory temporary;
    const auto valid = snapshot(1, 1000, {}, 0, 0);
    write_file(temporary.path / "rotator-state.1", valid);
    write_file(temporary.path / "ignored", valid);

    auto candidates = read_nfqws_rotator_snapshot_candidates(
        temporary.path.string());
    REQUIRE(candidates.size() == 1U);
    CHECK(candidates.front() == valid);

    fs::create_symlink(
        temporary.path / "rotator-state.1",
        temporary.path / "rotator-state.0");
    REQUIRE(fs::is_symlink(temporary.path / "rotator-state.0"));
    candidates = read_nfqws_rotator_snapshot_candidates(
        temporary.path.string());
    CHECK(candidates.size() == 1U);

    REQUIRE(fs::remove(temporary.path / "rotator-state.0"));
    fs::create_hard_link(
        temporary.path / "rotator-state.1",
        temporary.path / "rotator-state.0");
    REQUIRE(fs::hard_link_count(temporary.path / "rotator-state.1") == 2U);
    candidates = read_nfqws_rotator_snapshot_candidates(
        temporary.path.string());
    CHECK(candidates.empty());
}

TEST_CASE("nfqws snapshot reader rejects oversize non-regular and unsafe paths") {
    TemporaryDirectory temporary;
    const auto state_zero = temporary.path / "rotator-state.0";
    const auto state_one = temporary.path / "rotator-state.1";
    write_file(
        state_zero,
        std::string(kMaxNfqwsRotatorSnapshotSize + 1U, 'x'));
    REQUIRE(::mkfifo(state_one.c_str(), 0600) == 0);
    CHECK(read_nfqws_rotator_snapshot_candidates(temporary.path.string())
              .empty());

    const auto link = temporary.path.parent_path() /
                      (temporary.path.filename().string() + "-link");
    fs::create_directory_symlink(temporary.path, link);
    REQUIRE(fs::is_symlink(link));
    CHECK(read_nfqws_rotator_snapshot_candidates(link.string()).empty());
    REQUIRE(fs::remove(link));

    REQUIRE(::chmod(temporary.path.c_str(), 0777) == 0);
    CHECK(read_nfqws_rotator_snapshot_candidates(temporary.path.string())
              .empty());
}

} // namespace keen_pbr3
