#include "../src/log/notification_state.hpp"

#include <doctest/doctest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {
namespace {

class NotificationDirectory {
public:
    NotificationDirectory() {
        std::array<char, 64> pattern{};
        const std::string path = "/tmp/kpbr-notification-test-XXXXXX";
        std::copy(path.begin(), path.end(), pattern.begin());
        const auto result = ::mkdtemp(pattern.data());
        if (!result) throw std::runtime_error("mkdtemp failed");
        path_ = result;
    }
    ~NotificationDirectory() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }
    std::string file(const std::string& name = "notifications.json") const {
        return (path_ / name).string();
    }
private:
    std::filesystem::path path_;
};

std::string notification_file_text(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

void write_notification_fixture(const std::string& path, const std::string& text) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << text;
    if (!output.good()) throw std::runtime_error("fixture write failed");
}

std::vector<std::string> numbered_ids(std::size_t first, std::size_t count) {
    std::vector<std::string> ids;
    for (std::size_t index = first; index < first + count; ++index) {
        ids.push_back("id:" + std::to_string(index));
    }
    return ids;
}

nlohmann::json notification_document() {
    return {{"version", 1}, {"revision", 3},
            {"log_ids", {"log:known"}}, {"update_ids", {"update:known"}}};
}

} // namespace

TEST_CASE("notification dismissals: a missing file is an ordinary empty state") {
    NotificationDirectory directory;
    std::string error = "old error";
    NotificationStateStore store(directory.file(), &error);
    CHECK(error.empty());
    CHECK(store.snapshot().revision == 0U);
    CHECK(store.snapshot().log_ids.empty());
    CHECK(store.snapshot().update_ids.empty());
    CHECK_FALSE(std::filesystem::exists(directory.file()));
    CHECK(store.dismiss({}, {}, error));
    CHECK(error.empty());
    CHECK_FALSE(std::filesystem::exists(directory.file()));
}

TEST_CASE("notification dismissals: stale PC and phone clears merge with recent ordering") {
    NotificationDirectory directory;
    NotificationStateStore store(directory.file());
    std::string error;
    REQUIRE(store.dismiss({"log:pc", "log:shared"}, {"update:pc"}, error));
    REQUIRE(store.dismiss({"log:phone", "log:shared", "log:phone"}, {"update:phone"}, error));
    const auto state = store.snapshot();
    CHECK(state.revision == 2U);
    CHECK(state.log_ids == std::vector<std::string>{"log:pc", "log:shared", "log:phone"});
    CHECK(state.update_ids == std::vector<std::string>{"update:pc", "update:phone"});
    const auto persisted = notification_file_text(directory.file());
    REQUIRE(store.dismiss({"log:phone"}, {}, error));
    CHECK(store.snapshot().revision == state.revision);
    CHECK(notification_file_text(directory.file()) == persisted);
    REQUIRE(store.dismiss({"log:pc"}, {}, error));
    CHECK(store.snapshot().log_ids ==
          std::vector<std::string>{"log:shared", "log:phone", "log:pc"});
    CHECK(store.snapshot().revision == 3U);
}

TEST_CASE("notification dismissals: restart restores IDs and private file mode") {
    NotificationDirectory directory;
    std::string error;
    NotificationStateStore first(directory.file());
    REQUIRE(first.dismiss({"log:one"}, {"update:one"}, error));
    NotificationStateStore restarted(directory.file(), &error);
    CHECK(error.empty());
    CHECK(restarted.snapshot().revision == first.snapshot().revision);
    CHECK(restarted.snapshot().log_ids == first.snapshot().log_ids);
    CHECK(restarted.snapshot().update_ids == first.snapshot().update_ids);
    struct stat metadata {};
    REQUIRE(::stat(directory.file().c_str(), &metadata) == 0);
    CHECK((metadata.st_mode & 0777) == 0600);
    REQUIRE(::chmod(directory.file().c_str(), 0644) == 0);
    REQUIRE(restarted.dismiss({"log:two"}, {}, error));
    REQUIRE(::stat(directory.file().c_str(), &metadata) == 0);
    CHECK((metadata.st_mode & 0777) == 0600);
}

TEST_CASE("notification dismissals: shared store serializes simultaneous clients") {
    NotificationDirectory directory;
    NotificationStateStore store(directory.file());
    std::atomic<unsigned> failures{0};
    std::vector<std::thread> clients;
    for (unsigned index = 0; index < 8; ++index) {
        clients.emplace_back([&store, &failures, index] {
            std::string error;
            if (!store.dismiss({"log:" + std::to_string(index)}, {}, error)) ++failures;
        });
    }
    for (auto& client : clients) client.join();
    CHECK(failures.load() == 0U);
    CHECK(store.snapshot().revision == 8U);
    CHECK(store.snapshot().log_ids.size() == 8U);
    NotificationStateStore restarted(directory.file());
    CHECK(restarted.snapshot().log_ids == store.snapshot().log_ids);
    CHECK(restarted.snapshot().revision == store.snapshot().revision);
}

TEST_CASE("notification dismissals: count bounds retain recent IDs independently") {
    NotificationDirectory directory;
    NotificationStateStore store(directory.file());
    std::string error;
    for (std::size_t index = 0; index < 600; index += 200) {
        REQUIRE(store.dismiss(numbered_ids(index, 200), {}, error));
    }
    for (std::size_t index = 0; index < 600; index += 200) {
        REQUIRE(store.dismiss({}, numbered_ids(index, 200), error));
    }
    const auto state = store.snapshot();
    CHECK(state.log_ids == numbered_ids(88, 512));
    CHECK(state.update_ids == numbered_ids(88, 512));
    CHECK(std::filesystem::file_size(directory.file()) <= kNotificationStateMaxBytes);
    NotificationStateStore restarted(directory.file(), &error);
    CHECK(error.empty());
    CHECK(restarted.snapshot().log_ids == state.log_ids);
    CHECK(restarted.snapshot().update_ids == state.update_ids);
}

TEST_CASE("notification dismissals: escaped IDs also respect the serialized byte limit") {
    NotificationDirectory directory;
    NotificationStateStore store(directory.file());
    std::string error;
    std::string newest;
    for (std::size_t first = 0; first < 600; first += 200) {
        auto ids = numbered_ids(first, 200);
        for (auto& id : ids) id.append(kNotificationIdLengthLimit - id.size(), '"');
        newest = ids.back();
        REQUIRE(store.dismiss(ids, {}, error));
    }
    auto update_ids = numbered_ids(0, kNotificationUpdateIdLimit);
    for (auto& id : update_ids) id.append(kNotificationIdLengthLimit - id.size(), '"');
    REQUIRE(store.dismiss({}, update_ids, error));
    const auto state = store.snapshot();
    CHECK(state.log_ids.size() < kNotificationLogIdLimit);
    REQUIRE_FALSE(state.log_ids.empty());
    CHECK(state.log_ids.back() == newest);
    CHECK(std::filesystem::file_size(directory.file()) <= kNotificationStateMaxBytes);
    NotificationStateStore restarted(directory.file(), &error);
    CHECK(error.empty());
    CHECK(restarted.snapshot().log_ids == state.log_ids);
    CHECK(restarted.snapshot().update_ids == state.update_ids);
}

TEST_CASE("notification dismissals: invalid requests preserve existing state and file") {
    NotificationDirectory directory;
    NotificationStateStore store(directory.file());
    std::string error;
    REQUIRE(store.dismiss({"log:existing"}, {}, error));
    const auto persisted = notification_file_text(directory.file());
    const std::vector<std::vector<std::string>> invalid_logs = {
        {""}, {std::string(129, 'x')}, {std::string("a\0b", 3)}, {"a\nb"},
        {std::string(1, '\x7f')}, numbered_ids(0, 201)};
    for (const auto& ids : invalid_logs) {
        CHECK_FALSE(valid_notification_dismissal(ids, {}));
        CHECK_FALSE(store.dismiss(ids, {}, error));
        CHECK_FALSE(error.empty());
    }
    CHECK_FALSE(valid_notification_dismissal({}, numbered_ids(0, 513)));
    CHECK_FALSE(store.dismiss({}, numbered_ids(0, 513), error));
    CHECK_FALSE(store.dismiss({}, {""}, error));
    CHECK(valid_notification_dismissal({std::string(128, 'x')}, {"opaque:update"}));
    CHECK(store.snapshot().revision == 1U);
    CHECK(store.snapshot().log_ids == std::vector<std::string>{"log:existing"});
    CHECK(notification_file_text(directory.file()) == persisted);
}

TEST_CASE("notification dismissals: malformed persisted data is reported without partial load") {
    NotificationDirectory directory;
    std::vector<nlohmann::json> malformed = {nullptr, nlohmann::json::array()};
    auto value = notification_document();
    value["version"] = 2;
    malformed.push_back(value);
    for (const auto& revision : std::vector<nlohmann::json>{-1, 1.5, "3", nullptr}) {
        value = notification_document();
        value["revision"] = revision;
        malformed.push_back(value);
    }
    for (const auto& ids : std::vector<nlohmann::json>{
             nullptr, "wrong", {"duplicate", "duplicate"}, {std::string(129, 'x')},
             {"a\nb"}, numbered_ids(0, 513)}) {
        value = notification_document();
        value["log_ids"] = ids;
        malformed.push_back(value);
    }
    value = notification_document();
    value["update_ids"] = numbered_ids(0, 513);
    malformed.push_back(value);
    value = notification_document();
    value.erase("update_ids");
    malformed.push_back(value);
    std::vector<std::string> bodies = {"not json", "{"};
    for (const auto& document : malformed) bodies.push_back(document.dump());
    for (const auto& body : bodies) {
        INFO(body);
        write_notification_fixture(directory.file(), body);
        std::string error;
        NotificationStateStore store(directory.file(), &error);
        CHECK_FALSE(error.empty());
        CHECK(store.snapshot().revision == 0U);
        CHECK(store.snapshot().log_ids.empty());
        CHECK(store.snapshot().update_ids.empty());
        CHECK(notification_file_text(directory.file()) == body);
    }
}

TEST_CASE("notification dismissals: read failures are bounded and differ from missing state") {
    NotificationDirectory directory;
    std::string error;
    REQUIRE(std::filesystem::create_directory(directory.file("not-a-file")));
    NotificationStateStore unreadable(directory.file("not-a-file"), &error);
    CHECK_FALSE(error.empty());
    CHECK(unreadable.snapshot().revision == 0U);
    write_notification_fixture(directory.file(), std::string(kNotificationStateReadMaxBytes + 1, ' '));
    NotificationStateStore oversized(directory.file(), &error);
    CHECK_FALSE(error.empty());
    CHECK(oversized.snapshot().log_ids.empty());
    NotificationStateStore missing(directory.file("missing"), &error);
    CHECK(error.empty());
}

TEST_CASE("notification dismissals: state is loaded once and a failed write keeps it intact") {
    NotificationDirectory directory;
    std::string error;
    NotificationStateStore store(directory.file());
    REQUIRE(store.dismiss({"log:old"}, {"update:old"}, error));
    const auto persisted = notification_file_text(directory.file());
    write_notification_fixture(directory.file(), "broken externally");
    CHECK(store.snapshot().log_ids == std::vector<std::string>{"log:old"});
    NotificationStateStore damaged_restart(directory.file(), &error);
    CHECK_FALSE(error.empty());
    CHECK(damaged_restart.snapshot().log_ids.empty());
    write_notification_fixture(directory.file(), persisted);
    std::filesystem::rename(directory.file(), directory.file("saved.json"));
    REQUIRE(std::filesystem::create_directory(directory.file()));
    CHECK_FALSE(store.dismiss({"log:new"}, {"update:new"}, error));
    CHECK_FALSE(error.empty());
    CHECK(store.snapshot().revision == 1U);
    CHECK(store.snapshot().log_ids == std::vector<std::string>{"log:old"});
    CHECK(store.snapshot().update_ids == std::vector<std::string>{"update:old"});
    CHECK(notification_file_text(directory.file("saved.json")) == persisted);
}

TEST_CASE("notification dismissals: log IDs are stable across query windows and distinguish events") {
    const std::string line = "2026-09-05 12:00:00.001 [E] operation failed";
    const auto first = notification_log_id(line, 8, 900, 1234);
    CHECK(first.size() == 68U);
    CHECK(first.substr(0, 4) == "log:");
    CHECK(first.find(line) == std::string::npos);
    CHECK(std::all_of(first.begin() + 4, first.end(), [](char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    }));
    CHECK(first == notification_log_id(line, 8, 900, 1234));
    CHECK(first == notification_log_id(line, 8, 900, 1290));
    CHECK(first != notification_log_id("2026-09-05 12:00:00.002 [E] operation failed", 8, 900, 1234));
    CHECK(first != notification_log_id(line, 8, 901, 1234));
    CHECK(first != notification_log_id(line, 9, 900, 1234));
    CHECK(first != notification_log_id(line + " again", 8, 900, 1234));
    // Looking at more/fewer neighboring log entries does not alter this event.
    notification_log_id("earlier line", 8, 900, 1000);
    notification_log_id("later line", 8, 900, 1500);
    CHECK(first == notification_log_id(line, 8, 900, 1234));
}

TEST_CASE("notification dismissals: retained lines stay dismissed after in-place age compaction") {
    NotificationDirectory directory;
    const std::string expired = "2026-09-01 12:00:00.001 [W] old warning\n";
    const std::string retained = "2026-09-06 12:00:00.001 [W] retained warning";
    const auto log_path = directory.file("keen-pbr.log");
    write_notification_fixture(log_path, expired + retained + "\n");
    struct stat before {};
    REQUIRE(::stat(log_path.c_str(), &before) == 0);
    const auto original_id = notification_log_id(retained, before.st_dev, before.st_ino, expired.size());
    NotificationStateStore store(directory.file());
    std::string error;
    REQUIRE(store.dismiss({original_id}, {}, error));

    // The age-cleanup writer compacts the existing file, not a replacement
    // inode. The retained line now starts at byte zero.
    write_notification_fixture(log_path, retained + "\n");
    struct stat after {};
    REQUIRE(::stat(log_path.c_str(), &after) == 0);
    REQUIRE(before.st_ino == after.st_ino);
    REQUIRE(before.st_dev == after.st_dev);
    const auto compacted_id = notification_log_id(retained, after.st_dev, after.st_ino, 0);
    CHECK(compacted_id == original_id);
    NotificationStateStore restarted(directory.file());
    CHECK(restarted.snapshot().log_ids == std::vector<std::string>{compacted_id});
}

} // namespace keen_pbr3
