#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "api_context_test_support.hpp"
#include "api/handler_reload.hpp"
#include "api/sse_broadcaster.hpp"
#include "runtime/lifecycle_operation.hpp"
#include "runtime/runtime_mutation_admission.hpp"

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

class ReloadApiFixture {
public:
    explicit ReloadApiFixture(int port)
        : auth_file("KEEN_PBR_AUTH_FILE",
                    test_support::missing_auth_path(port))
        , context(test_support::make_minimal_api_context(
              broadcaster, "/tmp/keen-pbr-reload-test.json"))
        , server(make_config(port)) {
        context.lifecycle_operations = &coordinator;
        register_reload_handler(server, context);
        server.start();
        client = std::make_unique<httplib::Client>(
            "127.0.0.1", port);
    }

    ~ReloadApiFixture() {
        server.stop();
    }

    static ApiConfig make_config(int port) {
        ApiConfig config;
        config.listen = "127.0.0.1:" + std::to_string(port);
        return config;
    }

    SseBroadcaster broadcaster;
    test_support::EnvironmentVariableGuard auth_file;
    LifecycleOperationStore store;
    LifecycleOperationCoordinator coordinator{store};
    ApiContext context;
    ApiServer server;
    std::unique_ptr<httplib::Client> client;
};

} // namespace

TEST_CASE("service lifecycle endpoints invoke exactly one matching action") {
    std::vector<std::string> actions;
    ReloadApiFixture fixture(test_support::isolated_api_port(1));
    fixture.context.start_runtime_fn = [&] { actions.push_back("start"); };
    fixture.context.stop_runtime_fn = [&] { actions.push_back("stop"); };
    fixture.context.restart_runtime_fn = [&] {
        actions.push_back("restart");
    };

    const auto start = fixture.client->Post(
        "/api/service/start", "", "application/json");
    const auto stop = fixture.client->Post(
        "/api/service/stop", "", "application/json");
    const auto restart = fixture.client->Post(
        "/api/service/restart", "", "application/json");

    REQUIRE(start != nullptr);
    REQUIRE(stop != nullptr);
    REQUIRE(restart != nullptr);
    CHECK(start->status == 200);
    CHECK(stop->status == 200);
    CHECK(restart->status == 200);
    const std::vector<std::string> expected_actions{
        "start", "stop", "restart"};
    CHECK(actions == expected_actions);

    const auto snapshot = fixture.store.snapshot();
    REQUIRE(snapshot.has_value());
    CHECK(snapshot->type == LifecycleOperationType::Restart);
    CHECK(snapshot->result == LifecycleOperationResult::Succeeded);
    REQUIRE(snapshot->stages.size() == 1);
    CHECK(snapshot->stages.front().id == "restart_routing");
    CHECK(snapshot->stages.front().status ==
          LifecycleOperationStatus::Succeeded);
}

TEST_CASE("failed service lifecycle action is terminal and releases the guard") {
    std::size_t calls = 0;
    ReloadApiFixture fixture(test_support::isolated_api_port(2));
    fixture.context.start_runtime_fn = [&] {
        ++calls;
        throw std::runtime_error("injected start failure");
    };

    const auto failed = fixture.client->Post(
        "/api/service/start", "", "application/json");
    REQUIRE(failed != nullptr);
    CHECK(failed->status == 500);
    CHECK(calls == 1);

    auto snapshot = fixture.store.snapshot();
    REQUIRE(snapshot.has_value());
    CHECK(snapshot->result == LifecycleOperationResult::Failed);
    CHECK(snapshot->error == "injected start failure");
    REQUIRE(snapshot->stages.size() == 1);
    CHECK(snapshot->stages.front().status ==
          LifecycleOperationStatus::Failed);

    fixture.context.start_runtime_fn = [&] { ++calls; };
    const auto recovered = fixture.client->Post(
        "/api/service/start", "", "application/json");
    REQUIRE(recovered != nullptr);
    CHECK(recovered->status == 200);
    CHECK(calls == 2);
    snapshot = fixture.store.snapshot();
    REQUIRE(snapshot.has_value());
    CHECK(snapshot->result == LifecycleOperationResult::Succeeded);
}

TEST_CASE("service lifecycle rejects overlap before invoking runtime") {
    std::size_t restart_calls = 0;
    ReloadApiFixture fixture(test_support::isolated_api_port(3));
    fixture.context.restart_runtime_fn = [&] { ++restart_calls; };

    LifecycleOperationSnapshot active;
    REQUIRE_FALSE(fixture.coordinator.begin(
        LifecycleOperationType::ApplyConfig,
        {{"apply", "Apply configuration"}},
        active));

    const auto rejected = fixture.client->Post(
        "/api/service/restart", "", "application/json");
    REQUIRE(rejected != nullptr);
    CHECK(rejected->status == 409);
    CHECK(restart_calls == 0);
    const auto body = nlohmann::json::parse(rejected->body);
    CHECK(body["active_operation_id"] == active.id);

    fixture.coordinator.finish(active.id);
}

TEST_CASE("runtime mutation admission rejects before lifecycle projection") {
    std::size_t start_calls = 0;
    ReloadApiFixture fixture(test_support::isolated_api_port(4));
    RuntimeMutationAdmission admission;
    fixture.context.acquire_runtime_mutation_fn =
        [&admission](std::string label, bool, bool) {
            auto lease = admission.try_acquire(std::move(label));
            if (!lease.has_value()) {
                throw ApiError("runtime mutation busy", 409);
            }
            return std::move(*lease);
        };
    fixture.context.start_runtime_fn = [&] { ++start_calls; };

    auto blocker = admission.try_acquire("sighup-reload");
    REQUIRE(blocker.has_value());

    const auto rejected = fixture.client->Post(
        "/api/service/start", "", "application/json");
    REQUIRE(rejected != nullptr);
    CHECK(rejected->status == 409);
    CHECK(start_calls == 0);
    CHECK_FALSE(fixture.store.snapshot().has_value());

    blocker->release();
    const auto accepted = fixture.client->Post(
        "/api/service/start", "", "application/json");
    REQUIRE(accepted != nullptr);
    CHECK(accepted->status == 200);
    CHECK(start_calls == 1);
    const auto lifecycle = fixture.store.snapshot();
    REQUIRE(lifecycle.has_value());
    CHECK(lifecycle->result == LifecycleOperationResult::Succeeded);
}

TEST_CASE("API mutation guard hands off its production lease without releasing admission") {
    RuntimeMutationAdmission admission;
    SseBroadcaster broadcaster;
    auto context = test_support::make_minimal_api_context(
        broadcaster, "/tmp/keen-pbr-reload-lease-handoff-test.json");
    context.acquire_runtime_mutation_fn =
        [&admission](std::string label, bool, bool) {
            auto lease = admission.try_acquire(std::move(label));
            if (!lease.has_value()) {
                throw ApiError("runtime mutation busy", 409);
            }
            return std::move(*lease);
        };

    std::optional<RuntimeMutationAdmission::Lease> transferred;
    {
        ApiRuntimeMutationGuard mutation(
            context, "restart-runtime", true, false);
        const auto active = admission.active();
        REQUIRE(active.has_value());
        CHECK(active->label == "restart-runtime");
        transferred.emplace(mutation.take_lease());
    }

    REQUIRE(transferred.has_value());
    CHECK(static_cast<bool>(*transferred));
    CHECK(admission.active().has_value());
    transferred->release();
    CHECK_FALSE(admission.active().has_value());
}

TEST_CASE("restart endpoint hands the exact production lease to its tail callback") {
    RuntimeMutationAdmission admission;
    ReloadApiFixture fixture(test_support::isolated_api_port(5));
    fixture.context.acquire_runtime_mutation_fn =
        [&admission](std::string label, bool, bool) {
            auto lease = admission.try_acquire(std::move(label));
            if (!lease.has_value()) {
                throw ApiError("runtime mutation busy", 409);
            }
            return std::move(*lease);
        };

    std::optional<RuntimeMutationAdmission::Lease> transferred;
    std::size_t legacy_restart_calls = 0U;
    fixture.context.restart_runtime_fn = [&] {
        ++legacy_restart_calls;
    };
    fixture.context.restart_runtime_with_lease_fn =
        [&](RuntimeMutationAdmission::Lease lease) {
            transferred.emplace(std::move(lease));
        };

    const auto response = fixture.client->Post(
        "/api/service/restart", "", "application/json");
    REQUIRE(response != nullptr);
    CHECK(response->status == 200);
    CHECK(legacy_restart_calls == 0U);
    REQUIRE(transferred.has_value());
    CHECK(static_cast<bool>(*transferred));
    const auto active = admission.active();
    REQUIRE(active.has_value());
    CHECK(active->label == "restart-runtime");
    CHECK(transferred->token() == active->token);

    transferred->release();
    CHECK_FALSE(admission.active().has_value());
}

TEST_CASE("start endpoint hands the exact production lease to its tail callback") {
    RuntimeMutationAdmission admission;
    ReloadApiFixture fixture(test_support::isolated_api_port(6));
    bool require_running = true;
    bool require_stopped = false;
    fixture.context.acquire_runtime_mutation_fn =
        [&admission, &require_running, &require_stopped](
            std::string label,
            bool requested_running,
            bool requested_stopped) {
            require_running = requested_running;
            require_stopped = requested_stopped;
            auto lease = admission.try_acquire(std::move(label));
            if (!lease.has_value()) {
                throw ApiError("runtime mutation busy", 409);
            }
            return std::move(*lease);
        };

    std::optional<RuntimeMutationAdmission::Lease> transferred;
    std::size_t legacy_start_calls = 0U;
    fixture.context.start_runtime_fn = [&] {
        ++legacy_start_calls;
    };
    fixture.context.start_runtime_with_lease_fn =
        [&](RuntimeMutationAdmission::Lease lease) {
            transferred.emplace(std::move(lease));
        };

    const auto response = fixture.client->Post(
        "/api/service/start", "", "application/json");
    REQUIRE(response != nullptr);
    CHECK(response->status == 200);
    CHECK(legacy_start_calls == 0U);
    CHECK_FALSE(require_running);
    CHECK(require_stopped);
    REQUIRE(transferred.has_value());
    CHECK(static_cast<bool>(*transferred));
    const auto active = admission.active();
    REQUIRE(active.has_value());
    CHECK(active->label == "start-runtime");
    CHECK(transferred->token() == active->token);

    transferred->release();
    CHECK_FALSE(admission.active().has_value());
}

TEST_CASE("start endpoint releases its exact lease when tail handoff throws") {
    RuntimeMutationAdmission admission;
    ReloadApiFixture fixture(test_support::isolated_api_port(7));
    fixture.context.acquire_runtime_mutation_fn =
        [&admission](std::string label, bool, bool) {
            auto lease = admission.try_acquire(std::move(label));
            if (!lease.has_value()) {
                throw ApiError("runtime mutation busy", 409);
            }
            return std::move(*lease);
        };
    fixture.context.start_runtime_with_lease_fn =
        [](RuntimeMutationAdmission::Lease lease) {
            CHECK(static_cast<bool>(lease));
            throw std::runtime_error("typed start handoff failed");
        };

    const auto response = fixture.client->Post(
        "/api/service/start", "", "application/json");
    REQUIRE(response != nullptr);
    CHECK(response->status == 500);
    CHECK(response->body.find("typed start handoff failed") !=
          std::string::npos);
    CHECK_FALSE(admission.active().has_value());
    const auto lifecycle = fixture.store.snapshot();
    REQUIRE(lifecycle.has_value());
    CHECK(lifecycle->result == LifecycleOperationResult::Failed);
    CHECK(lifecycle->error == "typed start handoff failed");
}

} // namespace keen_pbr3

#endif // WITH_API
