#include <doctest/doctest.h>

#include "../src/http/http_client.hpp"
#include "../src/http/curl_runtime.hpp"
#include "../src/health/url_tester.hpp"

#include <string>
#include <vector>
#include <cstdlib>
#include <optional>

namespace {

class FakeTransport final : public keen_pbr3::HttpTransport {
public:
    keen_pbr3::HttpTransportRequest request;
    keen_pbr3::HttpTransportResponse response;
    bool fail{false};
    bool bind_fail{false};
    int calls{0};
    keen_pbr3::HttpTransportResponse perform(const keen_pbr3::HttpTransportRequest& value) override {
        request = value;
        ++calls;
        if (bind_fail) {
            throw keen_pbr3::HttpTransportBindError(
                "SO_BINDTODEVICE(nwg1) failed");
        }
        if (fail) throw keen_pbr3::HttpTransportError("transport unavailable");
        return response;
    }
};

class EnvironmentVariableGuard {
public:
    EnvironmentVariableGuard(const char* name, const std::string& value)
        : name_(name) {
        if (const char* previous = std::getenv(name)) previous_ = previous;
        REQUIRE(::setenv(name, value.c_str(), 1) == 0);
    }

    ~EnvironmentVariableGuard() {
        if (previous_) {
            (void)::setenv(name_.c_str(), previous_->c_str(), 1);
        } else {
            (void)::unsetenv(name_.c_str());
        }
    }

private:
    std::string name_;
    std::optional<std::string> previous_;
};

constexpr const char* kReadmeUrl =
    "https://raw.githubusercontent.com/maksimkurb/keen-pbr/refs/heads/main/README.md";

bool is_network_unavailable(const keen_pbr3::HttpError& error) {
    const std::string message = error.what();
    return message.find("Couldn't resolve host name") != std::string::npos ||
           message.find("Could not resolve host") != std::string::npos ||
           message.find("Couldn't connect to server") != std::string::npos ||
           message.find("Timeout was reached") != std::string::npos;
}

} // namespace

TEST_CASE("http client rejects non-HTTP initial protocols") {
    keen_pbr3::CurlRuntime curl_runtime;
    keen_pbr3::HttpClient client;
    CHECK_THROWS_AS(client.download("file:///etc/hosts"), keen_pbr3::HttpError);
    CHECK_THROWS_AS(client.download_conditional("file:///etc/hosts"), keen_pbr3::HttpError);
}

TEST_CASE("http client enforces configured max response size for remote file [network]") {
    keen_pbr3::CurlRuntime curl_runtime;

    SUBCASE("download fails when limit is 30 bytes") {
        keen_pbr3::HttpClient client;
        client.set_timeout(std::chrono::seconds(15));
        client.set_max_response_size(30);

        try {
            (void)client.download(kReadmeUrl);
            FAIL("Expected HttpError");
        } catch (const keen_pbr3::HttpError& error) {
            if (is_network_unavailable(error)) {
                INFO("Skipping network-dependent assertion");
                INFO(error.what());
                return;
            }
        }
    }

    SUBCASE("download succeeds when limit is 10 MiB") {
        keen_pbr3::HttpClient client;
        client.set_timeout(std::chrono::seconds(15));
        client.set_max_response_size(10 * 1024 * 1024);

        std::string body;
        try {
            body = client.download(kReadmeUrl);
        } catch (const keen_pbr3::HttpError& error) {
            if (is_network_unavailable(error)) {
                INFO("Skipping network-dependent assertion");
                INFO(error.what());
                return;
            }
            throw;
        }

        CHECK_FALSE(body.empty());
        CHECK(body.size() > 30);
    }
}

TEST_CASE("conditional download captures validators only from final redirect response") {
    std::string etag;
    std::string last_modified;
    keen_pbr3::detail::capture_response_header_line("HTTP/1.1 302 Found\r\n", etag, last_modified);
    keen_pbr3::detail::capture_response_header_line("ETag: \"redirect-poison\"\r\n", etag, last_modified);
    keen_pbr3::detail::capture_response_header_line("Last-Modified: Mon, 01 Jan 2024 00:00:00 GMT\r\n", etag, last_modified);
    keen_pbr3::detail::capture_response_header_line("HTTP/1.1 200 OK\r\n", etag, last_modified);
    keen_pbr3::detail::capture_response_header_line("ETag: \"final\"\r\n", etag, last_modified);

    CHECK(etag == "\"final\"");
    CHECK(last_modified.empty());
}

TEST_CASE("http client builds conditional transport request and maps errors") {
    auto transport = std::make_shared<FakeTransport>();
    transport->response = {304, {}, {{"etag", "new"}, {"last-modified", "now"}}, std::chrono::milliseconds(7)};
    keen_pbr3::HttpClient client(transport);
    client.set_timeout(std::chrono::seconds(3));
    client.set_user_agent("test-agent");
    const auto result = client.download_conditional("https://example.test/a", "old", "yesterday", {42});
    CHECK(result.not_modified);
    CHECK(result.etag == "new");
    CHECK(transport->request.timeout_ms == 3000);
    CHECK(transport->request.fwmark == 42);
    CHECK(transport->request.headers.size() == 2);
    transport->fail = true;
    CHECK_THROWS_AS(client.download("https://example.test/a"), keen_pbr3::HttpError);
}

TEST_CASE("a destination filter reaches the transport on both download paths") {
    auto transport = std::make_shared<FakeTransport>();
    keen_pbr3::HttpClient client(transport);
    keen_pbr3::HttpRequestOptions options;
    options.destination_filter = [](const std::string&) { return true; };

    (void)client.download("https://example.test/a", options);
    CHECK(static_cast<bool>(transport->request.destination_filter));

    transport->request = {};
    (void)client.download_conditional(
        "https://example.test/a", "", "", options);
    CHECK(static_cast<bool>(transport->request.destination_filter));

    // Unset stays unset: list and catalog downloads go to addresses the
    // operator configured, and filtering them would be a behaviour change
    // dressed up as a security one.
    transport->request = {};
    (void)client.download("https://example.test/a");
    CHECK_FALSE(static_cast<bool>(transport->request.destination_filter));
}

TEST_CASE("http client preserves a typed interface bind failure") {
    auto transport = std::make_shared<FakeTransport>();
    transport->bind_fail = true;
    keen_pbr3::HttpClient client(transport);

    CHECK_THROWS_AS(
        client.download("https://example.test/a"),
        keen_pbr3::HttpBindError);
}

TEST_CASE("the destination filter judges the address curl resolved") {
    // Runs against loopback with no listener: the filter fires before connect,
    // so nothing has to be listening for the refusal to be observable, and the
    // accepted case reaching a connection failure is what proves the filter is
    // deciding rather than failing everything.
    keen_pbr3::CurlRuntime curl_runtime;

    SUBCASE("a refused address fails the request and says so") {
        std::vector<std::string> seen;
        keen_pbr3::HttpClient client;
        client.set_timeout(std::chrono::seconds(5));
        keen_pbr3::HttpRequestOptions options;
        options.destination_filter = [&seen](const std::string& address) {
            seen.push_back(address);
            return false;
        };
        try {
            (void)client.download("http://127.0.0.1:9/", options);
            FAIL("Expected the destination filter to refuse");
        } catch (const keen_pbr3::HttpError& error) {
            const std::string message = error.what();
            CHECK(message.find("destination policy") != std::string::npos);
            CHECK(message.find("127.0.0.1") != std::string::npos);
        }
        REQUIRE(seen.size() == 1U);
        CHECK(seen.front() == "127.0.0.1");
    }

    SUBCASE("an accepted address is not refused by the filter") {
        std::vector<std::string> seen;
        keen_pbr3::HttpClient client;
        client.set_timeout(std::chrono::seconds(5));
        keen_pbr3::HttpRequestOptions options;
        options.destination_filter = [&seen](const std::string& address) {
            seen.push_back(address);
            return true;
        };
        try {
            (void)client.download("http://127.0.0.1:9/", options);
        } catch (const keen_pbr3::HttpError& error) {
            // Nothing is listening, so a connection failure is expected. What
            // must not appear is the policy refusal.
            const std::string message = error.what();
            CHECK(message.find("destination policy") == std::string::npos);
        }
        REQUIRE_FALSE(seen.empty());
        CHECK(seen.front() == "127.0.0.1");
    }

    SUBCASE("an IPv6 destination is rendered as an address, not as bytes") {
        std::vector<std::string> seen;
        keen_pbr3::HttpClient client;
        client.set_timeout(std::chrono::seconds(5));
        keen_pbr3::HttpRequestOptions options;
        options.destination_filter = [&seen](const std::string& address) {
            seen.push_back(address);
            return false;
        };
        try {
            (void)client.download("http://[::1]:9/", options);
        } catch (const keen_pbr3::HttpError&) {
        }
        if (!seen.empty()) {
            // Some builders run without an IPv6 loopback route; when the stack
            // is there, the filter must receive something it can parse.
            CHECK(seen.front() == "::1");
        }
    }

    SUBCASE("a throwing policy is refused without escaping libcurl's C stack") {
        keen_pbr3::HttpClient client;
        client.set_timeout(std::chrono::seconds(5));
        keen_pbr3::HttpRequestOptions options;
        options.destination_filter = [](const std::string&) -> bool {
            throw std::runtime_error("policy failure");
        };
        try {
            (void)client.download("http://127.0.0.1:9/", options);
            FAIL("Expected the destination filter to fail closed");
        } catch (const keen_pbr3::HttpError& error) {
            CHECK(std::string(error.what()).find("could not evaluate") !=
                  std::string::npos);
        }
    }
}

TEST_CASE("a filtered request never delegates destination policy to a proxy") {
    // CURLOPT_OPENSOCKETFUNCTION sees the proxy address when a proxy is in
    // use. If a filtered request inherited this environment, approving the
    // proxy would let it resolve and reach a forbidden destination itself.
    EnvironmentVariableGuard http_proxy(
        "http_proxy", "http://127.0.0.2:9");
    EnvironmentVariableGuard all_proxy(
        "ALL_PROXY", "http://127.0.0.2:9");
    EnvironmentVariableGuard no_proxy("no_proxy", "");
    EnvironmentVariableGuard upper_no_proxy("NO_PROXY", "");

    std::vector<std::string> seen;
    keen_pbr3::CurlRuntime curl_runtime;
    keen_pbr3::HttpClient client;
    client.set_timeout(std::chrono::seconds(5));
    keen_pbr3::HttpRequestOptions options;
    options.destination_filter = [&seen](const std::string& address) {
        seen.push_back(address);
        return address == "127.0.0.1";
    };
    try {
        (void)client.download("http://127.0.0.1:9/", options);
    } catch (const keen_pbr3::HttpError& error) {
        CHECK(std::string(error.what()).find("destination policy") ==
              std::string::npos);
    }
    REQUIRE_FALSE(seen.empty());
    CHECK(seen.front() == "127.0.0.1");
}

TEST_CASE("http client propagates and honors cooperative cancellation") {
    auto transport = std::make_shared<FakeTransport>();
    transport->response.status_code = 200;
    transport->response.body = "ok";
    keen_pbr3::HttpClient client(transport);
    auto cancellation = std::make_shared<std::atomic<bool>>(false);

    CHECK(client.download(
              "https://example.test/a",
              keen_pbr3::HttpRequestOptions{42, cancellation}) == "ok");
    CHECK(transport->request.cancellation == cancellation);
    CHECK(transport->calls == 1);

    cancellation->store(true, std::memory_order_relaxed);
    CHECK_THROWS_AS(
        client.download(
            "https://example.test/a",
            keen_pbr3::HttpRequestOptions{42, cancellation}),
        keen_pbr3::HttpRequestCancelled);
    CHECK(transport->calls == 1);
}

TEST_CASE("url tester uses discard transport probes and retry policy") {
    auto transport = std::make_shared<FakeTransport>();
    transport->response = {204, {}, {}, std::chrono::milliseconds(12)};
    keen_pbr3::URLTester tester(transport);
    keen_pbr3::RetryConfig retry;
    retry.attempts = 1;
    const auto result = tester.test("https://example.test/health", 77, 456, retry);
    CHECK(result.success);
    CHECK(result.latency_ms == 12);
    CHECK(transport->request.discard_body);
    CHECK(transport->request.timeout_ms == 456);
    CHECK(transport->request.fwmark == 77);
    CHECK(transport->request.max_redirects == 3);
    // Callers that do not name a device stay unpinned, as before.
    CHECK(transport->request.bind_interface.empty());
}

TEST_CASE("url tester pins the probe socket to the requested device") {
    auto transport = std::make_shared<FakeTransport>();
    transport->response = {204, {}, {}, std::chrono::milliseconds(9)};
    keen_pbr3::URLTester tester(transport);
    keen_pbr3::RetryConfig retry;
    retry.attempts = 1;

    const auto result =
        tester.test("https://example.test/health", 77, 456, retry, "nwg1");

    CHECK(result.success);
    // Without this the mark alone decides the route, and a table with no
    // usable default sends the probe out over the WAN instead.
    CHECK(transport->request.bind_interface == "nwg1");
    CHECK(transport->request.fwmark == 77);
}
