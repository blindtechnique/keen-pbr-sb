#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>

#include "api_context_test_support.hpp"
#include "api/handler_dns_test.hpp"
#include "api/server.hpp"
#include "api/sse_broadcaster.hpp"

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <thread>

namespace keen_pbr3 {
namespace {

using namespace std::chrono_literals;

constexpr char kDnsHelloFrame[] = "data: {\"type\":\"HELLO\"}\n\n";

template <typename Predicate>
bool wait_until(std::chrono::milliseconds timeout, Predicate predicate) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    do {
        if (predicate()) {
            return true;
        }
        std::this_thread::sleep_for(10ms);
    } while (std::chrono::steady_clock::now() < deadline);
    return predicate();
}

void configure_client(httplib::Client& client) {
    client.set_connection_timeout(1, 0);
    client.set_read_timeout(5, 0);
    client.set_write_timeout(2, 0);
}

class DnsSseApiFixture {
public:
    explicit DnsSseApiFixture(int port_value)
        : port(port_value)
        , broadcaster(128, 1)
        , auth_file("KEEN_PBR_AUTH_FILE",
                    test_support::missing_auth_path(port))
        , context(test_support::make_minimal_api_context(
              broadcaster, "/tmp/keen-pbr-dns-sse-test.json"))
        , server(make_config(port)) {
        register_dns_test_handler(server, context);
        server.start();
    }

    ~DnsSseApiFixture() {
        stop();
    }

    void stop() {
        if (!stopped_) {
            stopped_ = true;
            server.stop();
        }
    }

    static ApiConfig make_config(int port) {
        ApiConfig config;
        config.listen = "127.0.0.1:" + std::to_string(port);
        return config;
    }

    int port;
    SseBroadcaster broadcaster;
    test_support::EnvironmentVariableGuard auth_file;
    ApiContext context;
    ApiServer server;

private:
    bool stopped_{false};
};

} // namespace

TEST_CASE("DNS SSE disconnect releases its slot and admits a replacement") {
    DnsSseApiFixture fixture(test_support::isolated_api_port(7));

    std::promise<void> first_frame_ready;
    auto first_frame_future = first_frame_ready.get_future();
    std::promise<void> release_first_frame;
    const auto release_future = release_first_frame.get_future().share();
    std::atomic_bool first_frame_signaled{false};
    int first_status = 0;
    std::string first_content_type;
    std::string first_body;

    auto first_client = std::make_shared<httplib::Client>(
        "127.0.0.1", fixture.port);
    configure_client(*first_client);
    auto first_request = std::async(std::launch::async, [&, first_client] {
        return first_client->Get(
            "/api/dns/test",
            [&](const httplib::Response& response) {
                first_status = response.status;
                first_content_type =
                    response.get_header_value("Content-Type");
                return true;
            },
            [&](const char* data, size_t length) {
                first_body.append(data, length);
                if (first_body.size() >= sizeof(kDnsHelloFrame) - 1 &&
                    !first_frame_signaled.exchange(
                        true, std::memory_order_acq_rel)) {
                    first_frame_ready.set_value();
                    release_future.wait();
                    return false;
                }
                return true;
            });
    });

    const bool first_frame_arrived =
        first_frame_future.wait_for(3s) == std::future_status::ready;
    const bool first_slot_admitted = first_frame_arrived &&
        wait_until(1s, [&] {
            return fixture.broadcaster.active_subscriptions() == 1;
        });

    bool cap_rejected = false;
    if (first_slot_admitted) {
        httplib::Client capped_client("127.0.0.1", fixture.port);
        configure_client(capped_client);
        const auto capped_response = capped_client.Get("/api/dns/test");
        cap_rejected = capped_response &&
            capped_response->status == 503 &&
            capped_response->get_header_value("Retry-After") == "5";
    }

    // Never assert while the first client callback owns this barrier. Test
    // cleanup must remain bounded even when the endpoint regresses.
    release_first_frame.set_value();
    auto first_completion = first_request.wait_for(5s);
    if (first_completion != std::future_status::ready) {
        first_client->stop();
        fixture.stop();
        first_completion = first_request.wait_for(5s);
    }
    const bool first_completed =
        first_completion == std::future_status::ready;
    if (first_completed) {
        (void)first_request.get();
    }

    const bool first_slot_released = first_completed &&
        wait_until(5s, [&] {
            return fixture.broadcaster.active_subscriptions() == 0;
        });

    int replacement_status = 0;
    std::string replacement_content_type;
    std::string replacement_body;
    bool replacement_attempted = false;
    if (first_slot_released) {
        replacement_attempted = true;
        httplib::Client replacement_client(
            "127.0.0.1", fixture.port);
        configure_client(replacement_client);
        (void)replacement_client.Get(
            "/api/dns/test",
            [&](const httplib::Response& response) {
                replacement_status = response.status;
                replacement_content_type =
                    response.get_header_value("Content-Type");
                return true;
            },
            [&](const char* data, size_t length) {
                replacement_body.append(data, length);
                return replacement_body.size() <
                       sizeof(kDnsHelloFrame) - 1;
            });
    }

    const bool replacement_slot_released = replacement_attempted &&
        wait_until(5s, [&] {
            return fixture.broadcaster.active_subscriptions() == 0;
        });
    fixture.stop();

    CHECK(first_frame_arrived);
    CHECK(first_status == 200);
    CHECK(first_content_type.find("text/event-stream") !=
          std::string::npos);
    CHECK(first_body.rfind(kDnsHelloFrame, 0) == 0);
    CHECK(first_slot_admitted);
    CHECK(cap_rejected);
    CHECK(first_completed);
    CHECK(first_slot_released);
    CHECK(replacement_attempted);
    CHECK(replacement_status == 200);
    CHECK(replacement_content_type.find("text/event-stream") !=
          std::string::npos);
    CHECK(replacement_body.rfind(kDnsHelloFrame, 0) == 0);
    CHECK(replacement_slot_released);
}

} // namespace keen_pbr3

#endif // WITH_API
