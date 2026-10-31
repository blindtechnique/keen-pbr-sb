#include <ostream>
#include <doctest/doctest.h>
#include "../src/intercept/intercept_snapshot.hpp"
#include "../src/util/log_escape.hpp"

using namespace keen_pbr3;

namespace {
std::vector<InterceptListBinding> bindings() {
    return {{"a", "source-a-v1", {"kpbr4d_a", "kpbr6d_a", 120}},
            {"b", "source-b-v1", {"kpbr4d_b", "kpbr6d_b", 60}}};
}
InterceptDomainReader reader = [](const auto& binding, const auto& consume) {
    consume(binding.name + ".example");
    return true;
};
}

TEST_CASE("intercept snapshot: streamed domains and policy produce aligned targets") {
    const auto snapshot = build_intercept_snapshot(bindings(), {}, reader);
    REQUIRE(snapshot->index);
    CHECK(snapshot->marker_domain.empty());
    CHECK(snapshot->index->domain_count() == 2);
    std::vector<DomainIndex::ListId> matches;
    snapshot->index->lookup("www.A.example.", matches);
    REQUIRE(matches.size() == 1);
    CHECK(snapshot->targets[matches[0]].set_v4 == "kpbr4d_a");
    CHECK(snapshot->list_signatures[matches[0]] == "source-a-v1");
    CHECK(snapshot->targets[0].min_ttl_s == 120);
}

TEST_CASE("intercept snapshot: rebind removes a list without mutating the published index") {
    const auto initial = build_intercept_snapshot(bindings(), {}, reader);
    auto updated = bindings();
    updated.erase(updated.begin());
    updated[0].target.set_v4 = "kpbr4d_new_b";
    const auto rebound = rebind_intercept_snapshot(initial, updated, {});
    CHECK(rebound->index == initial->index);
    REQUIRE(rebound->targets.size() == 2);
    CHECK(rebound->targets[0].set_v4.empty());
    CHECK(rebound->targets[0].set_v6.empty());
    CHECK(rebound->targets[1].set_v4 == "kpbr4d_new_b");
    CHECK(initial->targets[0].set_v4 == "kpbr4d_a");
    CHECK(initial->targets[1].set_v4 == "kpbr4d_b");
}

TEST_CASE("intercept snapshot: repeated rebind cannot revive changed source content") {
    const auto initial = build_intercept_snapshot(bindings(), {}, reader);
    auto updated = bindings();
    updated[0].content_signature = "source-a-v2";
    auto rebound = rebind_intercept_snapshot(initial, updated, {});
    CHECK(rebound->targets[0].set_v4.empty());
    CHECK(rebound->list_signatures[0] == "source-a-v1");
    rebound = rebind_intercept_snapshot(rebound, updated, {});
    CHECK(rebound->targets[0].set_v4.empty());
    const auto rebuilt = build_intercept_snapshot(updated, {}, reader);
    CHECK(rebuilt->targets[0].set_v4 == "kpbr4d_a");
    CHECK(rebuilt->list_signatures[0] == "source-a-v2");
}

TEST_CASE("intercept snapshot: failed source is not an empty successful generation") {
    auto published = build_intercept_snapshot(bindings(), {}, reader);
    const auto old = published;
    auto failing = [](const auto& binding, const auto& consume) {
        consume("partial.example");
        return binding.name != "b";
    };
    CHECK_THROWS_AS(published = build_intercept_snapshot(bindings(), {}, failing), std::runtime_error);
    CHECK(published == old);
    CHECK(published->index->domain_count() == 2);
}

TEST_CASE("intercept snapshot: new policy disables IPv6 and L7 without rebuilding domains") {
    const auto initial = build_intercept_snapshot(bindings(), {}, reader);
    InterceptSnapshotPolicy policy;
    policy.ipv6_enabled = policy.tls = policy.http = policy.quic = false;
    policy.max_ttl_s = 600;
    policy.marker_domain = "test.invalid";
    const auto rebound = rebind_intercept_snapshot(initial, bindings(), policy);
    CHECK_FALSE(rebound->ipv6_enabled);
    CHECK_FALSE(rebound->tls);
    CHECK_FALSE(rebound->http);
    CHECK_FALSE(rebound->quic);
    CHECK(rebound->targets[0].set_v6.empty());
    CHECK(rebound->targets[1].set_v6.empty());
    CHECK(rebound->max_ttl_s == 600);
    CHECK(rebound->marker_domain == "test.invalid");
    CHECK(initial->ipv6_enabled);
}

TEST_CASE("intercept snapshot: missing signatures never authorize old content") {
    auto old = std::make_shared<InterceptSnapshot>();
    old->index = build_intercept_snapshot(bindings(), {}, reader)->index;
    const auto rebound = rebind_intercept_snapshot(old, bindings(), {});
    REQUIRE(rebound->targets.size() == 2);
    CHECK(rebound->targets[0].set_v4.empty());
    CHECK(rebound->targets[1].set_v4.empty());
    CHECK_FALSE(rebind_intercept_snapshot(nullptr, bindings(), {}));
}

TEST_CASE("intercept snapshot: invalid and ambiguous bindings rejected before reading") {
    auto invalid = bindings();
    invalid[0].content_signature.clear();
    CHECK_THROWS_AS(build_intercept_snapshot(invalid, {}, reader), std::invalid_argument);
    invalid = bindings();
    invalid[0].name.clear();
    CHECK_THROWS_AS(build_intercept_snapshot(invalid, {}, reader), std::invalid_argument);
    invalid = bindings();
    invalid.push_back(invalid[0]);
    CHECK_THROWS_AS(build_intercept_snapshot(invalid, {}, reader), std::invalid_argument);
    CHECK_THROWS_AS(build_intercept_snapshot(bindings(), {}, {}), std::invalid_argument);
    const auto empty = build_intercept_snapshot({}, {}, {});
    CHECK(empty->index->empty());
    CHECK(empty->targets.empty());
}

TEST_CASE("domain index: empty default and invalid list ids are deterministic") {
    DomainIndex index;
    CHECK(index.domain_count() == 0);
    CHECK(index.empty());
    DomainIndex::Builder builder;
    CHECK_THROWS_AS(builder.add_domain(0, "wrong.example"), std::out_of_range);
    builder.add_list("a");
    CHECK_THROWS_AS(builder.add_domain(1, "wrong.example"), std::out_of_range);
}

TEST_CASE("intercept diagnostics: traffic cannot inject log lines or control characters") {
    const char raw[] = {'a', '\n', '\r', '\0', '\x1b', '\\', static_cast<char>(0xff)};
    CHECK(log_escape(std::string_view(raw, sizeof(raw))) == "a\\x0a\\x0d\\x00\\x1b\\\\\\xff");
    CHECK(log_escape(std::string(260, 'a')) == std::string(255, 'a') + "...");
    CHECK(log_escape("example.com") == "example.com");
}
