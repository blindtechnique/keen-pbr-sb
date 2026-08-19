#include <doctest/doctest.h>

#include "keenetic/ndms_native_exact_mutation_transport.hpp"

#include <new>
#include <string>
#include <type_traits>
#include <utility>

using namespace keen_pbr3;

namespace {

class FakeGuard final
    : public NdmsNativeExactMutationPreDispatchGuard {
public:
    bool authorize_dispatch() noexcept override {
        ++calls;
        return authorize;
    }

    bool authorize{true};
    std::size_t calls{0U};
};

class FakeBackend final : public NdmsNativeExactMutationBackend {
private:
    NdmsNativeExactMutationRawResponse post_fixed_loopback_once(
        NdmsNativeExactMutationDispatchCapability&&,
        NdmsNativeSecretBuffer&& request_body,
        NdmsNativeExactMutationPreDispatchGuard& guard,
        NdmsNativeExactMutationBackendTrace& trace) override {
        ++calls;
        captured_request.assign(
            request_body.view().data(), request_body.view().size());
        NdmsNativeExactMutationRawResponse response;
        trace.pre_dispatch_guard_evaluated = true;
        if (!guard.authorize_dispatch()) return response;
        trace.pre_dispatch_guard_passed = true;
        trace.perform_started = true;
        ++perform_calls;
        response.request_may_have_been_dispatched = may_have_dispatched;
        response.transport_ok = transport_ok;
        response.status_code = status_code;
        response.content_type_seen = content_type_seen;
        response.content_type_is_json = content_type_is_json;
        response.content_type_ambiguous = content_type_ambiguous;
        response.callback_failed = callback_failed;
        CHECK(response.body.write_secret_body_chunk(response_body));
        return response;
    }

public:
    std::size_t calls{0U};
    std::size_t perform_calls{0U};
    std::string captured_request;
    bool may_have_dispatched{true};
    bool transport_ok{true};
    int status_code{200};
    bool content_type_seen{true};
    bool content_type_is_json{true};
    bool content_type_ambiguous{false};
    bool callback_failed{false};
    std::string response_body{"{}"};
};

class SetupThrowingBackend final
    : public NdmsNativeExactMutationBackend {
private:
    NdmsNativeExactMutationRawResponse post_fixed_loopback_once(
        NdmsNativeExactMutationDispatchCapability&&,
        NdmsNativeSecretBuffer&&,
        NdmsNativeExactMutationPreDispatchGuard&,
        NdmsNativeExactMutationBackendTrace&) override {
        ++calls;
        throw std::bad_alloc{};
    }

public:
    std::size_t calls{0U};
};

class PerformThrowingBackend final
    : public NdmsNativeExactMutationBackend {
private:
    NdmsNativeExactMutationRawResponse post_fixed_loopback_once(
        NdmsNativeExactMutationDispatchCapability&&,
        NdmsNativeSecretBuffer&&,
        NdmsNativeExactMutationPreDispatchGuard& guard,
        NdmsNativeExactMutationBackendTrace& trace) override {
        ++calls;
        trace.pre_dispatch_guard_evaluated = true;
        if (!guard.authorize_dispatch()) {
            return NdmsNativeExactMutationRawResponse{};
        }
        trace.pre_dispatch_guard_passed = true;
        trace.perform_started = true;
        throw std::bad_alloc{};
    }

public:
    std::size_t calls{0U};
};

NdmsNativeExactMutationTransportResult post_for_test(
    NdmsNativeExactMutationRequest request,
    NdmsNativeExactMutationPreDispatchGuard& guard,
    NdmsNativeExactMutationBackend& backend) {
    auto capability =
        NdmsNativeExactMutationDispatchCapabilityTestIssuer::issue();
    return post_ndms_native_exact_mutation_once(
        std::move(capability), std::move(request), guard, backend);
}

} // namespace

static_assert(!std::is_default_constructible_v<
              NdmsNativeExactMutationRequest>);
static_assert(!std::is_copy_constructible_v<
              NdmsNativeExactMutationRequest>);
static_assert(std::is_nothrow_move_constructible_v<
              NdmsNativeExactMutationRequest>);
static_assert(!std::is_default_constructible_v<
              NdmsNativeExactMutationDispatchCapability>);
static_assert(!std::is_copy_constructible_v<
              NdmsNativeExactMutationDispatchCapability>);
static_assert(std::is_nothrow_move_constructible_v<
              NdmsNativeExactMutationDispatchCapability>);

TEST_CASE("exact native delete request has a closed canonical grammar") {
    auto request =
        NdmsNativeExactMutationRequest::delete_managed_interface(
            "Wireguard5");
    CHECK(request.kind() ==
          NdmsNativeExactMutationKind::delete_managed_interface);
    CHECK(request.target() == "Wireguard5");

    NdmsNativeSecretBuffer body(request.content_length());
    CHECK(request.write_body_once(body));
    CHECK(body.view() ==
          R"({"interface":{"name":"Wireguard5","no":true}})");
    CHECK(request.target().empty());
    CHECK(request.content_length() == 0U);
    CHECK_FALSE(request.write_body_once(body));
}

TEST_CASE("exact native save request has a closed canonical grammar") {
    auto request =
        NdmsNativeExactMutationRequest::save_configuration();
    CHECK(request.kind() ==
          NdmsNativeExactMutationKind::save_configuration);
    CHECK(request.target().empty());

    NdmsNativeSecretBuffer body(request.content_length());
    CHECK(request.write_body_once(body));
    CHECK(body.view() ==
          R"({"system":{"configuration":{"save":{}}}})");
    CHECK(request.content_length() == 0U);
}

TEST_CASE("exact mutation request move invalidates the source") {
    auto source =
        NdmsNativeExactMutationRequest::delete_managed_interface(
            "Wireguard98");
    auto moved = std::move(source);
    CHECK(source.content_length() == 0U);
    CHECK(source.target().empty());

    NdmsNativeSecretBuffer body(moved.content_length());
    CHECK(moved.write_body_once(body));
    CHECK(body.view() ==
          R"({"interface":{"name":"Wireguard98","no":true}})");
}

TEST_CASE("exact delete rejects protected and noncanonical targets") {
    for (const char* target : {
             "Wireguard0", "Wireguard4", "Wireguard99",
             "Wireguard126", "Wireguard05", "AmneziaWireguard5",
             "Wireguard5/../Wireguard6"}) {
        CHECK_THROWS_AS(
            NdmsNativeExactMutationRequest::delete_managed_interface(
                target),
            NdmsNativeExactMutationTransportError);
    }
}

TEST_CASE("exact mutation transport posts delete once and returns no body") {
    FakeBackend backend;
    FakeGuard guard;

    const auto result = post_for_test(
        NdmsNativeExactMutationRequest::delete_managed_interface(
            "Wireguard5"),
        guard, backend);

    CHECK(backend.calls == 1U);
    CHECK(backend.perform_calls == 1U);
    CHECK(backend.captured_request ==
          R"({"interface":{"name":"Wireguard5","no":true}})");
    CHECK(result.kind ==
          NdmsNativeExactMutationKind::delete_managed_interface);
    CHECK(result.backend_call_confirmed);
    CHECK(result.pre_dispatch_guard_evaluated);
    CHECK(result.pre_dispatch_guard_passed);
    CHECK(result.perform_started);
    CHECK(result.request_may_have_been_dispatched);
    CHECK(result.response_manifest.acknowledged_needs_observation());
    CHECK(result.response_manifest.body_bytes == 2U);
}

TEST_CASE("exact mutation transport posts save once") {
    FakeBackend backend;
    FakeGuard guard;

    const auto result = post_for_test(
        NdmsNativeExactMutationRequest::save_configuration(),
        guard, backend);

    CHECK(backend.calls == 1U);
    CHECK(backend.perform_calls == 1U);
    CHECK(backend.captured_request ==
          R"({"system":{"configuration":{"save":{}}}})");
    CHECK(result.kind ==
          NdmsNativeExactMutationKind::save_configuration);
    CHECK(result.response_manifest.acknowledged_needs_observation());
}

TEST_CASE("pre-dispatch guard blocks the exact mutation before perform") {
    FakeBackend backend;
    FakeGuard guard;
    guard.authorize = false;

    const auto result = post_for_test(
        NdmsNativeExactMutationRequest::delete_managed_interface(
            "Wireguard5"),
        guard, backend);

    CHECK(guard.calls == 1U);
    CHECK(backend.calls == 1U);
    CHECK(backend.perform_calls == 0U);
    CHECK(result.pre_dispatch_guard_evaluated);
    CHECK_FALSE(result.pre_dispatch_guard_passed);
    CHECK_FALSE(result.perform_started);
    CHECK_FALSE(result.request_may_have_been_dispatched);
    CHECK(result.response_manifest.outcome ==
          NdmsNativeExactMutationResponseOutcome::guard_rejected);
}

TEST_CASE("exact mutation capability cannot replay a request") {
    FakeBackend backend;
    FakeGuard guard;
    auto capability =
        NdmsNativeExactMutationDispatchCapabilityTestIssuer::issue();

    const auto first = post_ndms_native_exact_mutation_once(
        std::move(capability),
        NdmsNativeExactMutationRequest::save_configuration(),
        guard, backend);
    REQUIRE(first.perform_started);
    REQUIRE(backend.calls == 1U);

    CHECK_THROWS_AS(
        post_ndms_native_exact_mutation_once(
            std::move(capability),
            NdmsNativeExactMutationRequest::save_configuration(),
            guard, backend),
        NdmsNativeExactMutationTransportError);
    CHECK(backend.calls == 1U);
    CHECK(backend.perform_calls == 1U);
}

TEST_CASE("exact response acknowledgement grammar is deliberately narrow") {
    FakeBackend backend;
    FakeGuard guard;

    SUBCASE("empty object is acknowledged but still needs observation") {
        backend.response_body = " \n { } \t";
        const auto result = post_for_test(
            NdmsNativeExactMutationRequest::save_configuration(),
            guard, backend);
        CHECK(result.response_manifest.acknowledged_needs_observation());
    }

    SUBCASE("exact status ok is acknowledged but still needs observation") {
        backend.response_body = R"( { "status" : "ok" } )";
        const auto result = post_for_test(
            NdmsNativeExactMutationRequest::save_configuration(),
            guard, backend);
        CHECK(result.response_manifest.acknowledged_needs_observation());
    }

    SUBCASE("an extra field is not accepted") {
        backend.response_body = R"({"status":"ok","extra":true})";
        const auto result = post_for_test(
            NdmsNativeExactMutationRequest::save_configuration(),
            guard, backend);
        CHECK(result.response_manifest.outcome ==
              NdmsNativeExactMutationResponseOutcome::
                  shape_not_acknowledged);
    }

    SUBCASE("an explicit error is not accepted") {
        backend.response_body =
            R"({"status":"error","message":"denied"})";
        const auto result = post_for_test(
            NdmsNativeExactMutationRequest::save_configuration(),
            guard, backend);
        CHECK(result.response_manifest.outcome ==
              NdmsNativeExactMutationResponseOutcome::
                  shape_not_acknowledged);
    }

    SUBCASE("a batch response is not accepted for the single command") {
        backend.response_body = "[{}]";
        const auto result = post_for_test(
            NdmsNativeExactMutationRequest::save_configuration(),
            guard, backend);
        CHECK(result.response_manifest.outcome ==
              NdmsNativeExactMutationResponseOutcome::
                  shape_not_acknowledged);
    }
}

TEST_CASE("exact mutation response gates are bounded and fail closed") {
    FakeBackend backend;
    FakeGuard guard;

    SUBCASE("transport failure remains ambiguous after perform") {
        backend.transport_ok = false;
        backend.status_code = 0;
        backend.response_body.clear();
        const auto result = post_for_test(
            NdmsNativeExactMutationRequest::save_configuration(),
            guard, backend);
        CHECK(result.request_may_have_been_dispatched);
        CHECK(result.response_manifest.outcome ==
              NdmsNativeExactMutationResponseOutcome::transport_failed);
    }

    SUBCASE("non-200 is rejected") {
        backend.status_code = 409;
        const auto result = post_for_test(
            NdmsNativeExactMutationRequest::save_configuration(),
            guard, backend);
        CHECK(result.response_manifest.outcome ==
              NdmsNativeExactMutationResponseOutcome::
                  http_status_not_200);
    }

    SUBCASE("missing JSON content type is rejected") {
        backend.content_type_seen = false;
        backend.content_type_is_json = false;
        const auto result = post_for_test(
            NdmsNativeExactMutationRequest::save_configuration(),
            guard, backend);
        CHECK(result.response_manifest.outcome ==
              NdmsNativeExactMutationResponseOutcome::
                  content_type_not_json);
    }

    SUBCASE("ambiguous JSON content type is rejected") {
        backend.content_type_ambiguous = true;
        const auto result = post_for_test(
            NdmsNativeExactMutationRequest::save_configuration(),
            guard, backend);
        CHECK(result.response_manifest.outcome ==
              NdmsNativeExactMutationResponseOutcome::
                  content_type_not_json);
    }

    SUBCASE("empty body is rejected") {
        backend.response_body.clear();
        const auto result = post_for_test(
            NdmsNativeExactMutationRequest::save_configuration(),
            guard, backend);
        CHECK(result.response_manifest.outcome ==
              NdmsNativeExactMutationResponseOutcome::body_empty);
    }

    SUBCASE("oversized body is rejected before structural inspection") {
        backend.response_body.assign(
            kNdmsNativeExactMutationMaximumResponseBytes + 1U, 'x');
        const auto result = post_for_test(
            NdmsNativeExactMutationRequest::save_configuration(),
            guard, backend);
        CHECK(result.response_manifest.body_bytes ==
              kNdmsNativeExactMutationMaximumResponseBytes + 1U);
        CHECK(result.response_manifest.outcome ==
              NdmsNativeExactMutationResponseOutcome::body_too_large);
    }
}

TEST_CASE("backend exceptions preserve exact mutation ambiguity markers") {
    FakeGuard guard;

    SUBCASE("setup exception is known not dispatched") {
        SetupThrowingBackend backend;
        const auto result = post_for_test(
            NdmsNativeExactMutationRequest::save_configuration(),
            guard, backend);
        CHECK(backend.calls == 1U);
        CHECK(result.backend_call_confirmed);
        CHECK_FALSE(result.pre_dispatch_guard_evaluated);
        CHECK_FALSE(result.perform_started);
        CHECK_FALSE(result.request_may_have_been_dispatched);
        CHECK(result.response_manifest.outcome ==
              NdmsNativeExactMutationResponseOutcome::transport_failed);
    }

    SUBCASE("exception after perform marker is ambiguous") {
        PerformThrowingBackend backend;
        const auto result = post_for_test(
            NdmsNativeExactMutationRequest::save_configuration(),
            guard, backend);
        CHECK(backend.calls == 1U);
        CHECK(result.pre_dispatch_guard_evaluated);
        CHECK(result.pre_dispatch_guard_passed);
        CHECK(result.perform_started);
        CHECK(result.request_may_have_been_dispatched);
        CHECK(result.response_manifest.outcome ==
              NdmsNativeExactMutationResponseOutcome::transport_failed);
    }
}
