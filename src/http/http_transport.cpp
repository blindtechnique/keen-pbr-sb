#include "http_transport.hpp"

#include <cerrno>
#include <array>
#include <climits>
#include <cctype>
#include <cstring>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <memory>
#include <netinet/in.h>
#include <sys/socket.h>

namespace keen_pbr3 {
namespace {
struct EasyDeleter { void operator()(CURL* curl) const { if (curl) curl_easy_cleanup(curl); } };
struct SlistDeleter { void operator()(curl_slist* list) const { if (list) curl_slist_free_all(list); } };
using EasyHandle = std::unique_ptr<CURL, EasyDeleter>;
using HeaderList = std::unique_ptr<curl_slist, SlistDeleter>;

[[noreturn]] void fail(CURLcode code, const char* operation) {
    throw HttpTransportError(std::string(operation) + ": " + curl_easy_strerror(code));
}
template <typename T>
void setopt(CURL* curl, CURLoption option, T value) {
    const CURLcode rc = curl_easy_setopt(curl, option, value);
    if (rc != CURLE_OK) fail(rc, "curl_easy_setopt");
}

struct TransferContext {
    const HttpTransportRequest* request;
    HttpTransportResponse* response;
    int mark_errno{0};
    int bind_errno{0};
    // The address the destination filter refused, kept so the failure says
    // which one it was. Without it curl reports a plain connection failure and
    // a refusal by policy becomes indistinguishable from an unreachable host.
    std::array<char, INET6_ADDRSTRLEN> refused_address{};
    enum class CallbackFailure : std::uint8_t {
        none,
        response_body,
        response_header,
        destination_filter,
    } callback_failure{CallbackFailure::none};
};
bool cancellation_requested(const HttpTransportRequest& request) {
    return request.cancellation &&
           request.cancellation->load(std::memory_order_relaxed);
}
int progress_callback(void* opaque, curl_off_t download_total,
                      curl_off_t downloaded, curl_off_t,
                      curl_off_t) noexcept {
    const auto* context = static_cast<const TransferContext*>(opaque);
    if (context->request->progress) {
        // Curl reports a total of zero when the server did not say. Passed
        // through as zero rather than replaced with the bytes so far, which
        // would render as "100%" for the whole of a chunked download.
        const auto total = download_total > 0
                               ? static_cast<std::uint64_t>(download_total)
                               : 0U;
        const auto received =
            downloaded > 0 ? static_cast<std::uint64_t>(downloaded) : 0U;
        // Never allowed to abort the transfer, and never allowed to throw:
        // this runs on curl's thread across a C callback boundary, and
        // reporting progress is not a reason to fail a download.
        try {
            context->request->progress(received, total);
        } catch (...) {
        }
    }
    return cancellation_requested(*context->request) ? 1 : 0;
}
size_t write_callback(char* data, size_t size, size_t count,
                      void* opaque) noexcept {
    if (count && size > SIZE_MAX / count) return 0;
    auto* context = static_cast<TransferContext*>(opaque);
    const size_t total = size * count;
    if (context->request->discard_body) return total;
    if (total > context->request->max_response_size - context->response->body.size()) return 0;
    try {
        context->response->body.append(data, total);
        return total;
    } catch (...) {
        context->callback_failure =
            TransferContext::CallbackFailure::response_body;
        return 0;
    }
}
std::string trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}
size_t header_callback(char* data, size_t size, size_t count,
                       void* opaque) noexcept {
    if (count && size > SIZE_MAX / count) return 0;
    auto* context = static_cast<TransferContext*>(opaque);
    try {
        std::string line(data, size * count);
        if (line.rfind("HTTP/", 0) == 0) {
            context->response->headers.clear();
            return line.size();
        }
        const auto colon = line.find(':');
        if (colon != std::string::npos) {
            std::string name = line.substr(0, colon);
            for (char& c : name) {
                c = static_cast<char>(
                    std::tolower(static_cast<unsigned char>(c)));
            }
            context->response->headers[name] =
                trim(line.substr(colon + 1));
        }
        return line.size();
    } catch (...) {
        context->callback_failure =
            TransferContext::CallbackFailure::response_header;
        return 0;
    }
}
int sockopt_callback(void* opaque, curl_socket_t fd, curlsocktype) noexcept {
    auto* context = static_cast<TransferContext*>(opaque);
    const auto& request = *context->request;
    // Bind before the mark: a request that asked to be attributable must fail
    // rather than silently fall back to whatever routing the mark selects.
    if (!request.bind_interface.empty()) {
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, request.bind_interface.c_str(),
                       static_cast<socklen_t>(request.bind_interface.size())) != 0) {
            context->bind_errno = errno;
            return CURL_SOCKOPT_ERROR;
        }
    }
    if (request.fwmark == 0) return CURL_SOCKOPT_OK;
    const uint32_t mark = request.fwmark;
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) == 0) return CURL_SOCKOPT_OK;
    context->mark_errno = errno;
    return CURL_SOCKOPT_ERROR;
}
// Runs once per connection this transfer opens - the first one and every
// redirect hop - with the address curl has already resolved and is about to
// connect to. This is the only point where that address is knowable and the
// connection is still preventable.
curl_socket_t opensocket_callback(void* opaque, curlsocktype,
                                  struct curl_sockaddr* address) noexcept {
    auto* context = static_cast<TransferContext*>(opaque);
    const auto& request = *context->request;
    char text[INET6_ADDRSTRLEN] = {};
    const void* raw = nullptr;
    if (address->family == AF_INET) {
        raw = &reinterpret_cast<const sockaddr_in*>(&address->addr)->sin_addr;
    } else if (address->family == AF_INET6) {
        raw = &reinterpret_cast<const sockaddr_in6*>(&address->addr)->sin6_addr;
    }
    // An address family we cannot render is one we cannot judge, and an
    // unjudged address is refused: this callback exists to be the last word.
    if (raw == nullptr ||
        ::inet_ntop(address->family, raw, text, sizeof(text)) == nullptr) {
        constexpr char message[] = "unrepresentable address";
        std::memcpy(context->refused_address.data(), message, sizeof(message));
        return CURL_SOCKET_BAD;
    }
    bool permitted = false;
    try {
        permitted = request.destination_filter(text);
    } catch (...) {
        // A caller-controlled policy is invoked from libcurl's C stack. No
        // C++ exception may cross it; an unevaluable destination is refused.
        context->callback_failure =
            TransferContext::CallbackFailure::destination_filter;
        return CURL_SOCKET_BAD;
    }
    if (!permitted) {
        std::memcpy(context->refused_address.data(), text,
                    std::strlen(text) + 1U);
        return CURL_SOCKET_BAD;
    }
    return ::socket(address->family, address->socktype, address->protocol);
}
void restrict_protocols(CURL* curl) {
#if LIBCURL_VERSION_NUM >= 0x075500
    setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
    setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
#else
    setopt(curl, CURLOPT_PROTOCOLS, static_cast<long>(CURLPROTO_HTTP | CURLPROTO_HTTPS));
    setopt(curl, CURLOPT_REDIR_PROTOCOLS, static_cast<long>(CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif
}
} // namespace

HttpTransportResponse LibcurlHttpTransport::perform(const HttpTransportRequest& request) {
    if (cancellation_requested(request)) {
        throw HttpTransportCancelled("HTTP request cancelled");
    }
    EasyHandle curl(curl_easy_init());
    if (!curl) throw HttpTransportError("Failed to initialize curl handle");
    HttpTransportResponse response;
    TransferContext context{&request, &response};
    char error_buffer[CURL_ERROR_SIZE] = {};
    setopt(curl.get(), CURLOPT_URL, request.url.c_str());
    setopt(curl.get(), CURLOPT_NOSIGNAL, 1L);
    setopt(curl.get(), CURLOPT_TIMEOUT_MS, request.timeout_ms);
    setopt(curl.get(), CURLOPT_USERAGENT, request.user_agent.c_str());
    setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 1L);
    setopt(curl.get(), CURLOPT_MAXREDIRS, request.max_redirects);
    setopt(curl.get(), CURLOPT_WRITEFUNCTION, write_callback);
    setopt(curl.get(), CURLOPT_WRITEDATA, &context);
    setopt(curl.get(), CURLOPT_HEADERFUNCTION, header_callback);
    setopt(curl.get(), CURLOPT_HEADERDATA, &context);
    setopt(curl.get(), CURLOPT_SOCKOPTFUNCTION, sockopt_callback);
    setopt(curl.get(), CURLOPT_SOCKOPTDATA, &context);
    if (request.destination_filter) {
        // A proxy is the address CURLOPT_OPENSOCKETFUNCTION sees. Letting
        // libcurl inherit one from the environment would therefore approve
        // the proxy while leaving the proxy free to resolve and reach a
        // forbidden destination. Filtered fetches must connect directly.
        // This branch is deliberately absent for legacy unfiltered callers.
        setopt(curl.get(), CURLOPT_PROXY, "");
        setopt(curl.get(), CURLOPT_NOPROXY, "*");
        setopt(curl.get(), CURLOPT_OPENSOCKETFUNCTION, opensocket_callback);
        setopt(curl.get(), CURLOPT_OPENSOCKETDATA, &context);
    }
    setopt(curl.get(), CURLOPT_ERRORBUFFER, error_buffer);
    if (request.cancellation || request.progress) {
        setopt(curl.get(), CURLOPT_NOPROGRESS, 0L);
        setopt(curl.get(), CURLOPT_XFERINFOFUNCTION, progress_callback);
        setopt(curl.get(), CURLOPT_XFERINFODATA, &context);
    }
    if (!request.discard_body) setopt(curl.get(), CURLOPT_MAXFILESIZE_LARGE, static_cast<curl_off_t>(request.max_response_size));
    restrict_protocols(curl.get());
    HeaderList headers;
    for (const auto& header : request.headers) {
        curl_slist* appended = curl_slist_append(headers.get(), header.c_str());
        if (!appended) throw HttpTransportError("Failed to allocate HTTP request header");
        headers.release(); headers.reset(appended);
    }
    if (headers) setopt(curl.get(), CURLOPT_HTTPHEADER, headers.get());
    const auto started = std::chrono::steady_clock::now();
    const CURLcode result = curl_easy_perform(curl.get());
    response.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
    if (result != CURLE_OK) {
        if (result == CURLE_ABORTED_BY_CALLBACK &&
            cancellation_requested(request)) {
            throw HttpTransportCancelled("HTTP request cancelled");
        }
        if (context.refused_address.front() != '\0') {
            // Said before curl's own text, and said distinctly: a refusal by
            // policy is not an unreachable host, and an operator who reads it
            // as one will go looking for a network fault that is not there.
            throw HttpTransportError(
                std::string{
                    "HTTP request refused: the destination policy does not permit "} +
                context.refused_address.data());
        }
        if (context.callback_failure ==
            TransferContext::CallbackFailure::destination_filter) {
            throw HttpTransportError(
                "HTTP request refused: the destination policy could not "
                "evaluate an address");
        }
        if (context.callback_failure ==
            TransferContext::CallbackFailure::response_body) {
            throw HttpTransportError(
                "HTTP request failed while storing the response body");
        }
        if (context.callback_failure ==
            TransferContext::CallbackFailure::response_header) {
            throw HttpTransportError(
                "HTTP request failed while storing response headers");
        }
        std::string message = error_buffer[0] ? error_buffer : curl_easy_strerror(result);
        if (context.bind_errno) {
            message += "; SO_BINDTODEVICE(" + request.bind_interface +
                       ") failed: " + std::string(std::strerror(context.bind_errno));
            throw HttpTransportBindError("HTTP request failed: " + message);
        }
        if (context.mark_errno) message += "; SO_MARK failed: " + std::string(std::strerror(context.mark_errno));
        throw HttpTransportError("HTTP request failed: " + message);
    }
    const CURLcode info = curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &response.status_code);
    if (info != CURLE_OK) fail(info, "curl_easy_getinfo(CURLINFO_RESPONSE_CODE)");
    return response;
}

std::shared_ptr<HttpTransport> default_http_transport() {
    static const std::shared_ptr<HttpTransport> transport = std::make_shared<LibcurlHttpTransport>();
    return transport;
}
} // namespace keen_pbr3
