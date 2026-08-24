#include <doctest/doctest.h>

#include "../src/daemon/runtime_state_store.hpp"

#include <string>
#include <thread>
#include <vector>

namespace keen_pbr3 {

namespace {

// Two payloads that disagree in every field a reader can check, so a reader
// that observes a mixture of them has observed a torn snapshot rather than
// either publish.
RuntimeStateSnapshot payload_a() {
    RuntimeStateSnapshot snapshot;
    snapshot.resolver_config_hash = "aaaa";
    snapshot.runtime_state_reason = "reason-a";
    snapshot.route_specs.resize(1);
    snapshot.policy_rule_specs.resize(1);
    return snapshot;
}

RuntimeStateSnapshot payload_b() {
    RuntimeStateSnapshot snapshot;
    snapshot.resolver_config_hash = "bbbbbbbb";
    snapshot.runtime_state_reason = "reason-b";
    snapshot.route_specs.resize(7);
    snapshot.policy_rule_specs.resize(7);
    return snapshot;
}

bool payload_is_coherent(const RuntimeStateSnapshot& snapshot) {
    if (snapshot.resolver_config_hash == "aaaa") {
        return snapshot.runtime_state_reason == "reason-a" &&
               snapshot.route_specs.size() == 1U &&
               snapshot.policy_rule_specs.size() == 1U;
    }
    if (snapshot.resolver_config_hash == "bbbbbbbb") {
        return snapshot.runtime_state_reason == "reason-b" &&
               snapshot.route_specs.size() == 7U &&
               snapshot.policy_rule_specs.size() == 7U;
    }
    return false;
}

} // namespace

TEST_CASE("the store answers routing_runtime_active without copying a snapshot") {
    RuntimeStateStore store;
    // The default is "active": a daemon that has not published yet must not
    // report routing as down and have callers act on it.
    CHECK(store.routing_runtime_active());
    CHECK(store.snapshot().routing_runtime_active);

    store.set_routing_runtime_active(false);
    CHECK_FALSE(store.routing_runtime_active());
    // The cheap read and the snapshot are one value, not two that agree.
    CHECK_FALSE(store.snapshot().routing_runtime_active);
}

TEST_CASE("setting the flag leaves the rest of the published state alone") {
    // The daemon flips this between full publishes; a setter that rebuilt or
    // reset the snapshot would drop the resolver hash and the route specs
    // every time routing went up or down.
    RuntimeStateStore store;
    store.publish(payload_b());

    store.set_routing_runtime_active(false);

    const auto after = store.snapshot();
    CHECK_FALSE(after.routing_runtime_active);
    CHECK(after.resolver_config_hash == "bbbbbbbb");
    CHECK(after.runtime_state_reason == "reason-b");
    CHECK(after.route_specs.size() == 7U);
}

TEST_CASE("a publish cannot answer for routing_runtime_active") {
    // This is the property the whole deduplication rests on. A publish
    // rebuilds the snapshot from the daemon's own fields, and the struct's
    // default for this flag is `true` - so a publish that honoured its
    // argument would quietly reset a stopped runtime to "routing is fine" at
    // any of the sites that publish for an unrelated reason. The store keeps
    // the value it was told directly, whatever the incoming snapshot says.
    RuntimeStateStore store;
    store.set_routing_runtime_active(false);

    auto rebuilt = payload_a();
    rebuilt.routing_runtime_active = true;  // the struct default, and a lie
    store.publish(std::move(rebuilt));

    CHECK_FALSE(store.routing_runtime_active());
    CHECK_FALSE(store.snapshot().routing_runtime_active);
    // Everything else the publish carried did land.
    CHECK(store.snapshot().resolver_config_hash == "aaaa");

    // And the other direction: a publish must not clear a flag that is set.
    store.set_routing_runtime_active(true);
    auto second = payload_b();
    second.routing_runtime_active = false;
    store.publish(std::move(second));
    CHECK(store.routing_runtime_active());
    CHECK(store.snapshot().resolver_config_hash == "bbbbbbbb");
}

TEST_CASE("a reader never sees a snapshot mixed from two publishes") {
    // The control loop publishes whole snapshots while the API thread reads
    // them, and the flag is written from a third place. Without the store's
    // lock a reader can copy a struct mid-assignment and see one publish's
    // hash beside another's route specs; the payloads here disagree in every
    // checked field so that mixture is detectable rather than plausible.
    RuntimeStateStore store;
    store.publish(payload_a());

    std::thread publisher([&store] {
        for (int index = 0; index < 2000; ++index) {
            store.publish(index % 2 == 0 ? payload_a() : payload_b());
        }
    });
    std::thread flipper([&store] {
        for (int index = 0; index < 2000; ++index) {
            store.set_routing_runtime_active(index % 2 == 0);
        }
    });

    std::size_t incoherent = 0;
    std::vector<std::thread> readers;
    for (int reader = 0; reader < 3; ++reader) {
        readers.emplace_back([&store, &incoherent] {
            std::size_t local = 0;
            for (int index = 0; index < 2000; ++index) {
                if (!payload_is_coherent(store.snapshot())) ++local;
                // The cheap read runs against the same lock; what it must
                // never do is wedge or crash the store.
                (void)store.routing_runtime_active();
            }
            if (local != 0) incoherent += local;
        });
    }
    publisher.join();
    flipper.join();
    for (auto& reader : readers) reader.join();

    CHECK(incoherent == 0U);
    // The store is still usable, and the flag still answers directly.
    store.set_routing_runtime_active(true);
    CHECK(store.routing_runtime_active());
}

} // namespace keen_pbr3
