#include <doctest/doctest.h>

#include "keenetic/ndms_native_import_transport.hpp"

#include <string>
#include <new>
#include <stdexcept>
#include <type_traits>
#include <utility>

using namespace keen_pbr3;

namespace {

constexpr const char* kPrivateKey =
    "UFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFA=";
constexpr const char* kPublicKey =
    "S0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0s=";

std::string plain_wireguard_config() {
    return std::string{"[Interface]\nPrivateKey = "} + kPrivateKey +
           "\nAddress = 10.7.0.2/32\n\n[Peer]\nPublicKey = " +
           kPublicKey +
           "\nEndpoint = vpn.example:51820\nAllowedIPs = 0.0.0.0/0\n";
}

std::string amnezia_wireguard_config() {
    auto config = plain_wireguard_config();
    const auto peer = config.find("\n\n[Peer]");
    if (peer == std::string::npos) {
        throw std::runtime_error("invalid AWG transport fixture");
    }
    config.insert(
        peer,
        "\nJc = 4\nJmin = 40\nJmax = 70\n"
        "S1 = 100\nS2 = 200\n"
        "H1 = 101\nH2 = 202\nH3 = 303\nH4 = 404\n");
    return config;
}

class FakeBackend final : public NdmsNativeLoopbackRciPostBackend {
private:
    NdmsNativeImportRawTransportResponse post_fixed_loopback_once(
        NdmsNativeImportDispatchCapability&&,
        NdmsNativeSecretBuffer&& request_body,
        NdmsNativeImportPreDispatchGuard& guard,
        NdmsNativeImportBackendTrace& trace) override {
        ++calls;
        saw_nonempty_request = !request_body.empty();
        request_size = request_body.size();
        NdmsNativeImportRawTransportResponse response;
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
        response.callback_failed = callback_failed;
        CHECK(response.body.write_secret_body_chunk(response_body));
        return response;
    }

public:
    bool saw_nonempty_request{false};
    std::size_t calls{0U};
    std::size_t perform_calls{0U};
    std::size_t request_size{0U};
    bool may_have_dispatched{true};
    bool transport_ok{true};
    int status_code{200};
    bool content_type_seen{true};
    bool content_type_is_json{true};
    bool callback_failed{false};
    std::string response_body{
        R"([{"interface":{"wireguard":{"import":{"created":"Wireguard5","intersects":""}}}}])"};
};

class FakePreDispatchGuard final
    : public NdmsNativeImportPreDispatchGuard {
public:
    bool authorize_dispatch() noexcept override {
        ++calls;
        return authorize;
    }

    bool authorize{true};
    std::size_t calls{0U};
};

class ThrowingBackend final : public NdmsNativeLoopbackRciPostBackend {
private:
    NdmsNativeImportRawTransportResponse post_fixed_loopback_once(
        NdmsNativeImportDispatchCapability&&,
        NdmsNativeSecretBuffer&&,
        NdmsNativeImportPreDispatchGuard& guard,
        NdmsNativeImportBackendTrace& trace) override {
        ++calls;
        trace.pre_dispatch_guard_evaluated = true;
        if (!guard.authorize_dispatch()) {
            return NdmsNativeImportRawTransportResponse{};
        }
        trace.pre_dispatch_guard_passed = true;
        trace.perform_started = true;
        ++perform_calls;
        throw std::bad_alloc{};
    }

public:
    std::size_t calls{0U};
    std::size_t perform_calls{0U};
};

class SetupThrowingBackend final
    : public NdmsNativeLoopbackRciPostBackend {
private:
    NdmsNativeImportRawTransportResponse post_fixed_loopback_once(
        NdmsNativeImportDispatchCapability&&,
        NdmsNativeSecretBuffer&&,
        NdmsNativeImportPreDispatchGuard&,
        NdmsNativeImportBackendTrace&) override {
        ++calls;
        throw std::bad_alloc{};
    }

public:
    std::size_t calls{0U};
};

NdmsNativeImportTransportResult post_for_test(
    NdmsNativeWireguardImportRequest request,
    const std::string& expected_created_interface,
    NdmsNativeImportPreDispatchGuard& guard,
    NdmsNativeLoopbackRciPostBackend& backend) {
    auto capability =
        NdmsNativeImportDispatchCapabilityTestIssuer::issue();
    return post_ndms_native_import_once(
        std::move(capability),
        std::move(request),
        expected_created_interface,
        guard,
        backend);
}

} // namespace

static_assert(!std::is_default_constructible_v<
              NdmsNativeImportDispatchCapability>);
static_assert(!std::is_copy_constructible_v<
              NdmsNativeImportDispatchCapability>);
static_assert(std::is_nothrow_move_constructible_v<
              NdmsNativeImportDispatchCapability>);

TEST_CASE("native import transport exposes only a redacted response manifest") {
    auto request = make_ndms_native_wireguard_import_request(
        plain_wireguard_config());
    const auto expected_request_size = request.content_length();
    FakeBackend backend;
    FakePreDispatchGuard guard;

    const auto result = post_for_test(
        std::move(request), "Wireguard5", guard, backend);

    CHECK(result.backend_call_confirmed);
    CHECK(result.pre_dispatch_guard_evaluated);
    CHECK(result.pre_dispatch_guard_passed);
    CHECK(result.perform_started);
    CHECK(backend.saw_nonempty_request);
    CHECK(backend.request_size == expected_request_size);
    CHECK(result.request_may_have_been_dispatched);
    CHECK(result.response_manifest.success());
    const auto safe = serialize_ndms_native_import_response_manifest_v3(
        result.response_manifest);
    CHECK(safe.find(kPrivateKey) == std::string::npos);
    CHECK(safe.find(kPublicKey) == std::string::npos);
}

TEST_CASE("native import transport preserves AWG kind through redacted inspection") {
    auto request = make_ndms_native_wireguard_import_request(
        amnezia_wireguard_config());
    FakeBackend backend;
    FakePreDispatchGuard guard;

    const auto result = post_for_test(
        std::move(request), "Wireguard5", guard, backend);

    REQUIRE(result.response_manifest.success());
    CHECK(result.response_manifest.request_kind ==
          NdmsNativeTunnelImportKind::amnezia_wireguard);
    const auto safe = serialize_ndms_native_import_response_manifest_v3(
        result.response_manifest);
    CHECK(safe.find("kind=amnezia_wireguard") != std::string::npos);
    CHECK(safe.find(kPrivateKey) == std::string::npos);
    CHECK(safe.find("Jc = 4") == std::string::npos);
}

TEST_CASE("native import transport never upgrades an ambiguous failure") {
    auto request = make_ndms_native_wireguard_import_request(
        plain_wireguard_config());
    FakeBackend backend;
    FakePreDispatchGuard guard;
    backend.transport_ok = false;
    backend.status_code = 0;
    backend.response_body.clear();

    const auto result = post_for_test(
        std::move(request), "Wireguard5", guard, backend);

    CHECK(result.request_may_have_been_dispatched);
    CHECK_FALSE(result.response_manifest.success());
    CHECK(result.response_manifest.outcome ==
          NdmsNativeImportResponseOutcome::transport_failed);
}

TEST_CASE("unknown response shape is not decoded into ordinary DOM strings") {
    auto request = make_ndms_native_wireguard_import_request(
        plain_wireguard_config());
    FakeBackend backend;
    FakePreDispatchGuard guard;
    const std::string response_secret{"do-not-copy-private-material"};
    backend.response_body =
        std::string{
            "[{\"interface\":{\"wireguard\":{\"import\":{"
            "\"created\":\"Wireguard5\",\"intersects\":\"\","
            "\"status\":[{\"status\":\"ok\",\"message\":\""} +
        response_secret + "\"}]}}}}]";

    const auto result = post_for_test(
        std::move(request), "Wireguard5", guard, backend);
    const auto safe = serialize_ndms_native_import_response_manifest_v3(
        result.response_manifest);

    CHECK_FALSE(result.response_manifest.success());
    CHECK(result.response_manifest.outcome ==
          NdmsNativeImportResponseOutcome::shape_mismatch);
    CHECK(safe.find(response_secret) == std::string::npos);
}

TEST_CASE("callback failure remains an ambiguous transport failure") {
    auto request = make_ndms_native_wireguard_import_request(
        plain_wireguard_config());
    FakeBackend backend;
    FakePreDispatchGuard guard;
    backend.callback_failed = true;

    const auto result = post_for_test(
        std::move(request), "Wireguard5", guard, backend);

    CHECK(result.request_may_have_been_dispatched);
    CHECK_FALSE(result.response_manifest.success());
    CHECK(result.response_manifest.outcome ==
          NdmsNativeImportResponseOutcome::transport_failed);
}

TEST_CASE("backend exception remains an ambiguous transport failure") {
    auto request = make_ndms_native_wireguard_import_request(
        plain_wireguard_config());
    ThrowingBackend backend;
    FakePreDispatchGuard guard;

    const auto result = post_for_test(
        std::move(request), "Wireguard5", guard, backend);

    CHECK(backend.calls == 1U);
    CHECK(result.backend_call_confirmed);
    CHECK(result.pre_dispatch_guard_evaluated);
    CHECK(result.pre_dispatch_guard_passed);
    CHECK(result.perform_started);
    CHECK(result.request_may_have_been_dispatched);
    CHECK_FALSE(result.response_manifest.success());
    CHECK(result.response_manifest.outcome ==
          NdmsNativeImportResponseOutcome::transport_failed);
}

TEST_CASE("backend setup failure is distinct from a denied guard") {
    auto request = make_ndms_native_wireguard_import_request(
        plain_wireguard_config());
    SetupThrowingBackend backend;
    FakePreDispatchGuard guard;

    const auto result = post_for_test(
        std::move(request), "Wireguard5", guard, backend);

    CHECK(backend.calls == 1U);
    CHECK(guard.calls == 0U);
    CHECK(result.backend_call_confirmed);
    CHECK_FALSE(result.pre_dispatch_guard_evaluated);
    CHECK_FALSE(result.pre_dispatch_guard_passed);
    CHECK_FALSE(result.perform_started);
    CHECK_FALSE(result.request_may_have_been_dispatched);
    CHECK(result.response_manifest.outcome ==
          NdmsNativeImportResponseOutcome::transport_failed);
}

TEST_CASE("ineligible target is rejected before request dispatch") {
    auto request = make_ndms_native_wireguard_import_request(
        plain_wireguard_config());
    FakeBackend backend;
    FakePreDispatchGuard guard;

    CHECK_THROWS_AS(
        post_for_test(
            std::move(request), "Wireguard4", guard, backend),
        NdmsNativeImportTransportError);
    CHECK(backend.calls == 0U);
}

TEST_CASE("exact response accepts whitespace and either field order") {
    auto request = make_ndms_native_wireguard_import_request(
        plain_wireguard_config());
    FakeBackend backend;
    FakePreDispatchGuard guard;
    backend.response_body =
        " [ { \"interface\" : { \"wireguard\" : { \"import\" : { "
        "\"intersects\" : \"\" , \"created\" : \"Wireguard5\" } } } } ] ";

    const auto result = post_for_test(
        std::move(request), "Wireguard5", guard, backend);
    CHECK(result.response_manifest.success());
}

TEST_CASE("pre-dispatch guard runs after setup and blocks perform") {
    auto request = make_ndms_native_wireguard_import_request(
        plain_wireguard_config());
    FakeBackend backend;
    FakePreDispatchGuard guard;
    guard.authorize = false;

    const auto result = post_for_test(
        std::move(request), "Wireguard5", guard, backend);

    CHECK(guard.calls == 1U);
    CHECK(result.backend_call_confirmed);
    CHECK(result.pre_dispatch_guard_evaluated);
    CHECK_FALSE(result.pre_dispatch_guard_passed);
    CHECK_FALSE(result.perform_started);
    CHECK_FALSE(result.request_may_have_been_dispatched);
    CHECK(backend.calls == 1U);
    CHECK(backend.perform_calls == 0U);
    CHECK_FALSE(result.response_manifest.success());
}

TEST_CASE("dispatch capability is consumed and cannot authorize a replay") {
    FakeBackend backend;
    FakePreDispatchGuard guard;
    auto capability =
        NdmsNativeImportDispatchCapabilityTestIssuer::issue();

    const auto first = post_ndms_native_import_once(
        std::move(capability),
        make_ndms_native_wireguard_import_request(
            plain_wireguard_config()),
        "Wireguard5",
        guard,
        backend);
    REQUIRE(first.perform_started);
    REQUIRE(backend.calls == 1U);

    CHECK_THROWS_AS(
        post_ndms_native_import_once(
            std::move(capability),
            make_ndms_native_wireguard_import_request(
                plain_wireguard_config()),
            "Wireguard5",
            guard,
            backend),
        NdmsNativeImportTransportError);
    CHECK(backend.calls == 1U);
    CHECK(backend.perform_calls == 1U);
}

TEST_CASE("native secret buffer rejects overflow") {
    NdmsNativeSecretBuffer buffer(4U);
    CHECK(buffer.write_secret_body_chunk("abc"));
    CHECK_FALSE(buffer.write_secret_body_chunk("de"));
    CHECK(buffer.view() == "abc");
    buffer.clear();
    CHECK(buffer.empty());
}
