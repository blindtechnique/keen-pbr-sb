#ifdef WITH_API

#include "handler_dns_test.hpp"

#include "../log/logger.hpp"

#include <chrono>
#include <httplib.h>
#include <nlohmann/json.hpp>

namespace keen_pbr3 {

namespace {

std::string make_sse_frame(const std::string& payload) {
    return "data: " + payload + "\n\n";
}

std::string make_hello_payload() {
    nlohmann::json payload = {
        {"type", "HELLO"}
    };
    return payload.dump();
}

} // namespace

void register_dns_test_handler(ApiServer& server, ApiContext& ctx) {
    server.get_stream("/api/dns/test",
                      [&ctx](const httplib::Request&, httplib::Response& res) {
        auto subscription = ctx.dns_test_broadcaster.subscribe();
        if (!subscription) {
            res.status = 503;
            res.set_header("Retry-After", "5");
            res.set_content(
                R"({"error":"too many active DNS test streams"})",
                "application/json");
            return;
        }
        Logger::instance().trace("sse_open", "path=/api/dns/test");
        res.set_header("Cache-Control", "no-cache");
        res.set_header("Connection", "keep-alive");
        res.set_header("X-Accel-Buffering", "no");
        res.set_chunked_content_provider(
            "text/event-stream",
            [subscription, hello_sent = false](size_t, httplib::DataSink& sink) mutable -> bool {
                if (!hello_sent) {
                    hello_sent = true;
                    const auto hello = make_sse_frame(make_hello_payload());
                    Logger::instance().trace("sse_hello", "path=/api/dns/test bytes={}", hello.size());
                    if (!sink.write(hello.data(), hello.size())) {
                        return false;
                    }
                    return true;
                }

                auto result = wait_for_sse_subscription(
                    subscription,
                    std::chrono::seconds(15),
                    std::chrono::seconds(1),
                    [&sink] {
                        return !sink.is_writable || sink.is_writable();
                    });
                switch (result.status) {
                    case SseSubscriptionWaitStatus::CLOSED:
                        Logger::instance().trace("sse_done", "path=/api/dns/test");
                        sink.done();
                        return true;
                    case SseSubscriptionWaitStatus::PEER_DISCONNECTED:
                        return false;
                    case SseSubscriptionWaitStatus::HEARTBEAT: {
                        static constexpr char kHeartbeat[] = ": heartbeat\n\n";
                        return sink.write(kHeartbeat, sizeof(kHeartbeat) - 1);
                    }
                    case SseSubscriptionWaitStatus::MESSAGE: {
                        const auto frame = make_sse_frame(result.message);
                        Logger::instance().trace(
                            "sse_event", "path=/api/dns/test bytes={}", frame.size());
                        return sink.write(frame.data(), frame.size());
                    }
                }
                return false;
            },
            [&ctx, subscription](bool) {
                Logger::instance().trace("sse_close", "path=/api/dns/test");
                ctx.dns_test_broadcaster.unsubscribe(subscription);
            });
    });
}

} // namespace keen_pbr3

#endif // WITH_API
