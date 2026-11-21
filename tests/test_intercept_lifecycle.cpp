#include <ostream>
#include <doctest/doctest.h>
#include "../src/intercept/intercept_service.hpp"
#include "../src/intercept/intercept_snapshot.hpp"
#include "../src/intercept/intercept_runtime.hpp"

#include <condition_variable>
#include <stdexcept>

using namespace keen_pbr3;

namespace keen_pbr3 {
struct InterceptServiceTestAccess {
    static void bind_for_health_test(InterceptService& service, bool fail_open) {
        service.dns_bound_.store(true);
        service.l7_bound_.store(true);
        service.listener_probe_.nfqueue = nfnl::make_probe_result(nfnl::ProbeStatus::ok);
        service.listener_probe_.nflog = nfnl::make_probe_result(nfnl::ProbeStatus::ok);
        service.listener_probe_.fail_open = nfnl::make_probe_result(
            fail_open ? nfnl::ProbeStatus::ok : nfnl::ProbeStatus::unsupported, "test kernel");
    }
    static void fail_for_health_test(InterceptService& service) {
        service.failed_.store(true);
        service.l7_degraded_.store(true);
    }
    static void count_for_health_test(InterceptService& service) {
        service.counters_->dns_packets.fetch_add(1);
        service.counters_->l7_matched.fetch_add(1);
    }
    static bool write_admitted(InterceptService& service) {
        if (!service.dns_writes_.enter()) return false;
        service.dns_writes_.leave();
        return true;
    }
    static bool cleanup_enabled(const InterceptService& service) {
        return service.cleanup_queue_.enabled_.load();
    }
    static void request_cleanup(InterceptService& service) {
        service.cleanup_queue_.request(service.current_snapshot(), 4, {192, 0, 2, 1}, {203, 0, 113, 1});
    }
    static void dispatch_cleanup(InterceptService& service,
                                 const std::shared_ptr<const InterceptSnapshot>& snapshot) {
        service.run_cleanup({{snapshot, 4, {192, 0, 2, 1}, {203, 0, 113, 1}}});
    }
};
}

namespace {
class FakeWriter : public nfnl::DynamicSetWriter {
public:
    bool add(const nfnl::SetAdd*, nfnl::SetAddResult*, std::size_t, int) override { return true; }
    int last_errno() const override { return 0; }
};
class RecordingCleanup final : public ConntrackCleanupSink {
public:
    void request(const std::shared_ptr<const InterceptSnapshot>& snapshot,
                 uint8_t family, const std::array<uint8_t, 16>& client,
                 const std::array<uint8_t, 16>& dst) override {
        std::lock_guard<std::mutex> lock(mutex);
        last_family = family;
        last_client = client;
        last_dst = dst;
        last_snapshot = snapshot;
        ++requests;
        cv.notify_all();
    }
    bool wait() {
        std::unique_lock<std::mutex> lock(mutex);
        return cv.wait_for(lock, std::chrono::seconds(2), [this] { return requests != 0; });
    }
    std::mutex mutex;
    std::condition_variable cv;
    unsigned requests{0};
    uint8_t last_family{0};
    std::array<uint8_t, 16> last_client{}, last_dst{};
    std::shared_ptr<const InterceptSnapshot> last_snapshot;
};
}

TEST_CASE("intercept lifecycle: null writer is rejected before dereference") {
    CHECK_THROWS_AS(InterceptService(nullptr), std::invalid_argument);
}

TEST_CASE("interception health: active hooks require confirmed fail-open and a committed snapshot") {
    for (const bool fail_open : {false, true}) {
        InterceptService* current = nullptr;
        unsigned starts = 0;
        InterceptRuntime runtime([&] {
            auto service = std::make_unique<InterceptService>(std::make_unique<FakeWriter>());
            current = service.get();
            return service;
        }, [&](InterceptService& service, const InterceptServiceOptions&) {
            ++starts;
            service.start({}, nullptr);
            InterceptServiceTestAccess::bind_for_health_test(service, fail_open);
        });
        const std::vector<InterceptListBinding> targets{{"list", "v1", {"v4", "", 60}}};
        auto pending = runtime.begin_update();
        const auto hooks = pending->prepare(targets, {},
            [](const auto&, const auto& consume) { consume("example.org"); return true; },
            false, {true, true, {"br0"}});
        CHECK(hooks.dns == fail_open);
        CHECK(hooks.l7);
        CHECK(runtime.health().dns_state == "applying");
        pending->commit();
        CHECK(runtime.health().dns_state == (fail_open ? "active" : "fail_open_unconfirmed"));
        CHECK(runtime.health().l7_state == "active");
        CHECK(runtime.health().fail_open == (fail_open ? "ok" : "unsupported"));
        std::thread observer([&] {
            for (int i = 0; i < 500; ++i) (void)runtime.health();
        });
        for (int i = 0; i < 100; ++i)
            InterceptServiceTestAccess::count_for_health_test(*current);
        observer.join();
        CHECK(runtime.health().dns_packets == 100);
        CHECK(runtime.health().l7_matched == 100);
        InterceptServiceTestAccess::fail_for_health_test(*current);
        CHECK(runtime.health().l7_state == "unavailable");
        CHECK(starts == 1);
        runtime.stop();
        CHECK(runtime.health().dns_state == "stopped");
        CHECK(runtime.health().l7_state == "stopped");
    }
}

TEST_CASE("intercept lifecycle: counters outlive the writers which borrow them") {
    auto counters = std::make_shared<InterceptCounters>();
    const std::weak_ptr<InterceptCounters> weak = counters;
    bool lived = false;
    struct BorrowingWriter : FakeWriter {
        BorrowingWriter(std::weak_ptr<InterceptCounters> value, bool& result)
            : weak(std::move(value)), lived(result) {}
        ~BorrowingWriter() override {
            lived = !weak.expired();
            if (lived && borrowed) borrowed->fetch_add(1);
        }
        void set_slow_write_counter(std::atomic<uint64_t>* counter) override { borrowed = counter; }
        std::weak_ptr<InterceptCounters> weak;
        bool& lived;
        std::atomic<uint64_t>* borrowed{nullptr};
    };
    {
        InterceptService service(std::make_unique<BorrowingWriter>(weak, lived), nullptr,
                                 std::move(counters));
    }
    CHECK(lived);
    CHECK(weak.expired());
}

TEST_CASE("intercept lifecycle: STOP clears readiness and permits explicit restart") {
    InterceptService service(std::make_unique<FakeWriter>());
    const auto snapshot = build_intercept_snapshot({}, {}, {});
    service.start({}, snapshot);  // no sockets/listeners requested
    CHECK(service.running());
    CHECK(service.snapshot_ready());
    CHECK_FALSE(service.dns_bound());
    CHECK_FALSE(service.l7_bound());
    service.update_snapshot(nullptr);
    CHECK_FALSE(service.snapshot_ready());
    service.update_snapshot(snapshot);
    CHECK(service.snapshot_ready());
    service.stop();
    CHECK_FALSE(service.running());
    CHECK_FALSE(service.snapshot_ready());
    CHECK_FALSE(service.current_snapshot());
    service.stop();  // idempotent
    service.start({}, snapshot);  // explicit user request, no automatic retry loop
    CHECK(service.running());
    service.stop();
}

TEST_CASE("intercept lifecycle: nested publication pauses release independently") {
    InterceptService service(std::make_unique<FakeWriter>());
    service.start({}, build_intercept_snapshot({}, {}, {}));
    CHECK(InterceptServiceTestAccess::write_admitted(service));
    {
        auto outer = service.pause_writes();
        {
            auto inner = service.pause_writes();
            CHECK_FALSE(InterceptServiceTestAccess::write_admitted(service));
        }
        CHECK_FALSE(InterceptServiceTestAccess::write_admitted(service));
        service.stop();  // must not wait for a pause handle
        CHECK_FALSE(service.running());
    }
    CHECK(InterceptServiceTestAccess::write_admitted(service));
}

TEST_CASE("intercept lifecycle: cleanup requires explicit opt-in AND a routing owner") {
    CHECK_FALSE(InterceptServiceOptions{}.conntrack_cleanup);
    auto sink = std::make_shared<RecordingCleanup>();
    InterceptService service(std::make_unique<FakeWriter>(), nullptr, nullptr, sink);
    service.start({}, nullptr);
    CHECK_FALSE(InterceptServiceTestAccess::cleanup_enabled(service));
    InterceptServiceTestAccess::request_cleanup(service);
    service.stop();
    CHECK(sink->requests == 0);

    InterceptServiceOptions opt_in;
    opt_in.conntrack_cleanup = true;
    InterceptService no_owner(std::make_unique<FakeWriter>());
    no_owner.start(opt_in, nullptr);
    CHECK_FALSE(InterceptServiceTestAccess::cleanup_enabled(no_owner));
    no_owner.stop();

    const auto snapshot = build_intercept_snapshot({}, {}, {});
    service.start(opt_in, snapshot);
    CHECK(InterceptServiceTestAccess::cleanup_enabled(service));
    InterceptServiceTestAccess::request_cleanup(service);
    REQUIRE(sink->wait());
    service.stop();
    CHECK(sink->requests == 1);
    CHECK(sink->last_snapshot == snapshot);
    CHECK(sink->last_family == 4);
    CHECK(sink->last_client == std::array<uint8_t, 16>{192, 0, 2, 1});
    CHECK(sink->last_dst == std::array<uint8_t, 16>{203, 0, 113, 1});
    CHECK(service.counters().conntrack_deleted == 0);
}

TEST_CASE("intercept lifecycle: cleanup intents cannot outlive their routing snapshot") {
    auto sink = std::make_shared<RecordingCleanup>();
    InterceptService service(std::make_unique<FakeWriter>(), nullptr, nullptr, sink);
    InterceptServiceOptions options;
    options.conntrack_cleanup = true;
    const auto old = build_intercept_snapshot({}, {}, {});
    const auto current = build_intercept_snapshot({}, {}, {});
    service.start(options, old);
    service.update_snapshot(current);
    InterceptServiceTestAccess::dispatch_cleanup(service, old);
    CHECK(sink->requests == 0);
    InterceptServiceTestAccess::dispatch_cleanup(service, current);
    CHECK(sink->requests == 1);
    CHECK(sink->last_snapshot == current);
    service.stop();
    InterceptServiceTestAccess::dispatch_cleanup(service, current);
    CHECK(sink->requests == 1);
}
