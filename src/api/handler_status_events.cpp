#ifdef WITH_API

#include "handler_status_events.hpp"
#include "handlers.hpp"
#include "status_stream.hpp"

#include <chrono>
#include <httplib.h>
#include <utility>

namespace keen_pbr3 {

void register_status_events_handler(ApiServer& server, ApiContext& ctx) {
    if (ctx.status_stream) {
        server.on_auth_sessions_revoked(
            [stream = ctx.status_stream] {
                stream->revoke_active_subscriptions();
            });
    }
    server.get_stream("/api/status/events",
                      [&ctx, &server](const httplib::Request& req,
                                      httplib::Response& res) {
        auto authorization_is_current =
            server.make_stream_authorization_probe(req);
        auto subscription = ctx.status_stream->subscribe();
        if (!subscription) {
            res.status = 503;
            res.set_header("Retry-After", "5");
            res.set_content(
                R"({"error":"too many active status streams"})",
                "application/json");
            return;
        }
        res.set_header("Cache-Control", "no-cache");
        res.set_header("Connection", "keep-alive");
        res.set_header("X-Accel-Buffering", "no");
        res.set_chunked_content_provider(
            "text/event-stream",
            [subscription,
             authorization_is_current =
                 std::move(authorization_is_current)](
                size_t, httplib::DataSink& sink) -> bool {
                auto result = wait_for_sse_subscription(
                    subscription,
                    std::chrono::seconds(15),
                    std::chrono::seconds(1),
                    [&sink] {
                        return !sink.is_writable || sink.is_writable();
                    },
                    authorization_is_current);
                switch (result.status) {
                    case SseSubscriptionWaitStatus::MESSAGE:
                        return sink.write(
                            result.message.data(), result.message.size());
                    case SseSubscriptionWaitStatus::CLOSED:
                        sink.done();
                        return true;
                    case SseSubscriptionWaitStatus::PEER_DISCONNECTED:
                        return false;
                    case SseSubscriptionWaitStatus::HEARTBEAT:
                        static constexpr char kHeartbeat[] = ": heartbeat\n\n";
                        return sink.write(
                            kHeartbeat, sizeof(kHeartbeat) - 1);
                }
                return false;
            },
            [&ctx, subscription](bool) {
                ctx.status_stream->unsubscribe(subscription);
            });
    });
}

} // namespace keen_pbr3

#endif
