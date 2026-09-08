#ifdef WITH_API

#include <doctest/doctest.h>
#include <nlohmann/json.hpp>

#include "../src/api/handler_logs.hpp"
#include "../src/api/server.hpp"
#include "../src/api/status_stream.hpp"
#include "../src/log/notification_state.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {
namespace {

class NotificationApiDirectory {
public:
    NotificationApiDirectory() {
        char pattern[] = "/tmp/keen-pbr-notifications-api-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path = created;
        if (const char* previous = std::getenv("KEEN_PBR_TEST_LOG_FILE")) {
            previous_log_file_ = previous;
        }
        REQUIRE(::setenv("KEEN_PBR_TEST_LOG_FILE", log_path().c_str(), 1) == 0);
    }
    ~NotificationApiDirectory() {
        if (previous_log_file_) {
            (void)::setenv("KEEN_PBR_TEST_LOG_FILE", previous_log_file_->c_str(), 1);
        } else {
            (void)::unsetenv("KEEN_PBR_TEST_LOG_FILE");
        }
        std::error_code error;
        std::filesystem::remove_all(path, error);
    }
    std::string log_path() const { return (path / "daemon.log").string(); }
    std::string config_path() const { return (path / "config.json").string(); }
    void write_log(const std::string& text, bool append = false) const {
        std::ofstream output(log_path(), std::ios::binary |
            (append ? std::ios::app : std::ios::trunc));
        REQUIRE(output.good());
        output << text;
        output.close();
        REQUIRE(output.good());
    }
    std::filesystem::path path;
private:
    std::optional<std::string> previous_log_file_;
};

// Exercise the exact production route callbacks, the real persistence store
// and the shared SSE. HTTP authentication belongs to the existing server tests.
class NotificationApiHarness {
public:
    explicit NotificationApiHarness(const std::string& config_path,
                                    StatusStream* stream = nullptr,
                                    std::function<nlohmann::json()> sources = {})
        : handlers(make_notification_handlers(stream, config_path, std::move(sources))) {}
    nlohmann::json get() {
        return nlohmann::json::parse(handlers.get());
    }
    nlohmann::json dismiss(const nlohmann::json& body) {
        return nlohmann::json::parse(handlers.dismiss(body.dump()));
    }
    void expect_dismiss_failure(const std::string& body, int status) {
        bool failed = false;
        try {
            (void)handlers.dismiss(body);
        } catch (const ApiError& error) {
            failed = true;
            CHECK(error.status() == status);
            CHECK_FALSE(std::string(error.what()).empty());
        }
        CHECK(failed);
    }
    NotificationHandlers handlers;
};

StatusSnapshot notification_snapshot() {
    StatusSnapshot snapshot;
    snapshot.service.version = "test";
    snapshot.service.build = "test";
    snapshot.service.status = api::HealthResponseStatus::RUNNING;
    snapshot.service.runtime_state = api::RuntimeState::RUNNING;
    snapshot.service.runtime_state_reason = "test";
    snapshot.service.os_type = "linux";
    snapshot.service.os_version = "test";
    snapshot.service.build_variant = "test";
    snapshot.service.resolver_live_status = api::ResolverLiveStatus::HEALTHY;
    snapshot.service.config_is_draft = false;
    return snapshot;
}

std::string notification_pop(const SseBroadcaster::SubscriptionPtr& subscription) {
    KPBR_LOCK_GUARD(subscription->mutex);
    REQUIRE_FALSE(subscription->messages.empty());
    auto frame = std::move(subscription->messages.front());
    subscription->messages.pop_front();
    return frame;
}

std::size_t notification_queued(const SseBroadcaster::SubscriptionPtr& subscription) {
    KPBR_LOCK_GUARD(subscription->mutex);
    return subscription->messages.size();
}

nlohmann::json notification_state(std::uint64_t revision,
                                const std::vector<std::string>& log_ids = {}) {
    return {{"revision", revision}, {"log_ids", log_ids},
            {"update_ids", nlohmann::json::array()}};
}

} // namespace

TEST_CASE("notifications returns bounded stable IDs as the tail window advances") {
    NotificationApiDirectory directory;
    std::string log;
    for (int index = 0; index < 205; ++index) {
        log += "[W] line " + std::to_string(index) + "\n";
    }
    directory.write_log(log);
    NotificationApiHarness api(directory.config_path());
    const auto initial = api.get();
    REQUIRE(initial.at("lines").size() == 200);
    REQUIRE(initial.at("line_ids").size() == 200);
    CHECK(initial.at("lines").front() == "[W] line 5");
    CHECK(initial.at("state") == notification_state(0));
    struct stat metadata {};
    REQUIRE(::stat(directory.log_path().c_str(), &metadata) == 0);
    const auto first_offset = log.find("[W] line 5\n");
    CHECK(initial.at("line_ids").front() == notification_log_id(
        "[W] line 5", metadata.st_dev, metadata.st_ino, first_offset));

    directory.write_log("[W] new line\n", true);
    const auto advanced = api.get();
    REQUIRE(advanced.at("line_ids").size() == 200);
    CHECK(advanced.at("line_ids").front() == initial.at("line_ids").at(1));
    CHECK(advanced.at("line_ids").at(198) == initial.at("line_ids").back());
}

TEST_CASE("notification IDs coalesce exact same-millisecond lines but separate times and generations") {
    NotificationApiDirectory directory;
    const std::string repeated = "2026-09-06 12:00:00.001 [W] repeat\n";
    const std::string later = "2026-09-06 12:00:00.002 [W] repeat\n";
    directory.write_log(repeated + repeated + later);
    NotificationApiHarness api(directory.config_path());
    const auto first = api.get();
    REQUIRE(first.at("line_ids").size() == 3);
    CHECK(first.at("line_ids").at(0) == first.at("line_ids").at(1));
    CHECK(first.at("line_ids").at(0) != first.at("line_ids").at(2));
    std::filesystem::rename(directory.log_path(), directory.path / "daemon.log.1");
    directory.write_log(repeated + repeated + later);
    const auto rotated = api.get();
    CHECK(rotated.at("lines") == first.at("lines"));
    CHECK(rotated.at("line_ids").at(0) != first.at("line_ids").at(0));
}

TEST_CASE("notification tail keeps absolute offsets after the byte limit") {
    NotificationApiDirectory directory;
    const std::string prefix(600U * 1024U, 'x');
    directory.write_log(prefix + "\n[W] after a long line\n");
    NotificationApiHarness api(directory.config_path());
    const auto response = api.get();
    REQUIRE(response.at("lines").size() == 1);
    struct stat metadata {};
    REQUIRE(::stat(directory.log_path().c_str(), &metadata) == 0);
    CHECK(response.at("line_ids").front() == notification_log_id(
        "[W] after a long line", metadata.st_dev, metadata.st_ino, prefix.size() + 1));
}

TEST_CASE("notification dismissals merge across clients persist and do not delete logs") {
    NotificationApiDirectory directory;
    const std::string original = "[W] first\n[E] second\n";
    directory.write_log(original);
    nlohmann::json persisted;
    {
        NotificationApiHarness api(directory.config_path());
        const auto before = api.get();
        const auto first_id = before.at("line_ids").at(0).get<std::string>();
        const auto second_id = before.at("line_ids").at(1).get<std::string>();
        const auto first = api.dismiss({{"log_ids", {first_id}}});
        CHECK(first.at("revision") == 1);
        persisted = api.dismiss({{"log_ids", {second_id}},
                                  {"update_ids", {"update:keen-pbr:next"}}});
        CHECK(persisted.at("revision") == 2);
        CHECK(persisted.at("log_ids") == nlohmann::json({first_id, second_id}));
        const auto after = api.get();
        CHECK(after.at("lines") == before.at("lines"));
        CHECK(after.at("line_ids") == before.at("line_ids"));
        CHECK(after.at("state") == persisted);
        CHECK(api.dismiss(nlohmann::json::object()) == persisted);
    }
    NotificationApiHarness restarted(directory.config_path());
    CHECK(restarted.get().at("state") == persisted);
    CHECK(std::filesystem::file_size(directory.log_path()) == original.size());
}

TEST_CASE("notifications reject malformed dismissals without changing state") {
    NotificationApiDirectory directory;
    NotificationApiHarness api(directory.config_path());
    auto many = nlohmann::json::array();
    for (int index = 0; index < 201; ++index) many.push_back("log:" + std::to_string(index));
    auto updates = nlohmann::json::array();
    for (int index = 0; index < 513; ++index) updates.push_back("update:" + std::to_string(index));
    const std::vector<nlohmann::json> invalid{
        nullptr, nlohmann::json::array(), {{"log_ids", nullptr}},
        {{"log_ids", {1}}}, {{"log_ids", {std::string(129, 'x')}}},
        {{"log_ids", {"contains\nnewline"}}}, {{"log_ids", many}},
        {{"update_ids", updates}}};
    for (const auto& body : invalid) {
        api.expect_dismiss_failure(body.dump(), 400);
    }
    api.expect_dismiss_failure("{", 400);
    CHECK(api.get().at("state") == notification_state(0));
    CHECK_FALSE(std::filesystem::exists(directory.path / "notifications.json"));
}

TEST_CASE("notification source callback derives new-server notices and persists their dismissal") {
    NotificationApiDirectory directory;
    directory.write_log("[W] ordinary warning\n");
    const auto sources = [] {
        return nlohmann::json::array({{
            {"id", "source-one"}, {"name", "My provider"},
            {"pending_new_servers_count", 2}, {"pending_servers_revision", "pending-v1"},
            {"url", "https://provider.example/private-source-token"},
            {"_bindings", nlohmann::json::array({{{"fingerprint", "private-fingerprint"}}})}}});
    };
    std::string notice_id;
    nlohmann::json dismissed;
    {
        NotificationApiHarness api(directory.config_path(), nullptr, sources);
        const auto response = api.get();
        REQUIRE(response.at("subscription_notices").size() == 1);
        const auto& notice = response.at("subscription_notices").front();
        CHECK(notice.at("kind") == "new_servers");
        CHECK(notice.at("subscription_id") == "source-one");
        CHECK(notice.at("name") == "My provider");
        CHECK(notice.at("count") == 2);
        CHECK_FALSE(response.value("subscription_notices_error", false));
        CHECK(response.at("lines") == nlohmann::json::array({"[W] ordinary warning"}));
        CHECK(response.dump().find("private-source-token") == std::string::npos);
        CHECK(response.dump().find("private-fingerprint") == std::string::npos);
        notice_id = notice.at("id").get<std::string>();
        CHECK(valid_notification_dismissal({}, {notice_id}));
        dismissed = api.dismiss({{"update_ids", {notice_id}}});
        CHECK(dismissed.at("update_ids") == nlohmann::json::array({notice_id}));
    }
    NotificationApiHarness recreated(directory.config_path(), nullptr, sources);
    const auto reloaded = recreated.get();
    CHECK(reloaded.at("state") == dismissed);
    CHECK(reloaded.at("subscription_notices").front().at("id") == notice_id);
}

TEST_CASE("notification source callback failure keeps ordinary log and dismissal state available") {
    NotificationApiDirectory directory;
    directory.write_log("[E] ordinary error\n");
    NotificationApiHarness api(directory.config_path(), nullptr, []() -> nlohmann::json {
        throw std::runtime_error("private-source-token must not reach response");
    });
    const auto state = api.dismiss({{"update_ids", {"system-update-test"}}});
    const auto response = api.get();
    CHECK(response.at("subscription_notices_error") == true);
    CHECK(response.at("subscription_notices").empty());
    CHECK(response.at("lines") == nlohmann::json::array({"[E] ordinary error"}));
    CHECK(response.at("line_ids").size() == 1);
    CHECK(response.at("state") == state);
    CHECK(response.dump().find("private-source-token") == std::string::npos);
}

TEST_CASE("notification persistence failure returns an API failure and preserves state") {
    NotificationApiDirectory directory;
    std::filesystem::create_directory(directory.path / "notifications.json");
    NotificationApiHarness api(directory.config_path());
    api.expect_dismiss_failure(R"({"log_ids":["log:failed"]})", 500);
    CHECK(api.get().at("state") == notification_state(0));
}

TEST_CASE("notifications handle an absent log and replace invalid UTF8 without changing ID") {
    NotificationApiDirectory directory;
    NotificationApiHarness api(directory.config_path());
    CHECK(api.get().at("lines").empty());
    std::string line = "[W] invalid ";
    line.push_back(static_cast<char>(0x8b));
    directory.write_log(line + "\n");
    const auto response = api.get();
    REQUIRE(response.at("lines").size() == 1);
    CHECK(response.at("lines").front().get<std::string>().find(
        static_cast<char>(0x8b)) == std::string::npos);
    struct stat metadata {};
    REQUIRE(::stat(directory.log_path().c_str(), &metadata) == 0);
    CHECK(response.at("line_ids").front() == notification_log_id(
        line, metadata.st_dev, metadata.st_ino, 0));
}

TEST_CASE("notification state replays initial zero and only newer revisions") {
    StatusStream stream([] { return notification_snapshot(); });
    stream.publish_notification_state(notification_state(0));
    auto first = stream.subscribe();
    (void)notification_pop(first);
    CHECK(notification_pop(first) == make_named_sse_frame("notification_state",
        nlohmann::json{{"type", "notification_state"},
                       {"data", notification_state(0)}}.dump()));
    stream.publish_notification_state(notification_state(2, {"log:new"}));
    CHECK(notification_pop(first).find("log:new") != std::string::npos);
    stream.publish_notification_state(notification_state(1, {"log:old"}));
    stream.publish_notification_state(notification_state(2, {"log:conflicting"}));
    stream.publish_notification_state({{"revision", -1}});
    CHECK(notification_queued(first) == 0);
    auto second = stream.subscribe();
    (void)notification_pop(second);
    const auto replay = notification_pop(second);
    CHECK(replay.find("log:new") != std::string::npos);
    CHECK(replay.find("log:old") == std::string::npos);
}

TEST_CASE("notification dismiss API publishes to both existing and reconnecting subscribers") {
    NotificationApiDirectory directory;
    StatusStream stream([] { return notification_snapshot(); });
    NotificationApiHarness api(directory.config_path(), &stream);
    auto first = stream.subscribe();
    (void)notification_pop(first);
    (void)notification_pop(first);
    const auto state = api.dismiss({{"update_ids", {"update:nfqws:1.2.5"}}});
    const auto expected = make_named_sse_frame("notification_state",
        nlohmann::json{{"type", "notification_state"}, {"data", state}}.dump());
    CHECK(notification_pop(first) == expected);
    auto second = stream.subscribe();
    (void)notification_pop(second);
    CHECK(notification_pop(second) == expected);
    CHECK(api.dismiss({{"update_ids", {"update:nfqws:1.2.5"}}}) == state);
    CHECK(notification_queued(first) == 0);
    CHECK(notification_queued(second) == 0);
}

} // namespace keen_pbr3

#endif
