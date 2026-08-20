#include "ndms_native_import_transport.hpp"

#include "ndms_native_create_policy.hpp"

#include "../crypto/sha256.hpp"

#include <curl/curl.h>

#include <atomic>
#include <climits>
#include <cstdint>
#include <memory>

namespace keen_pbr3 {

namespace {

constexpr const char* kStockRciEndpoint = "http://127.0.0.1:79/rci/";
constexpr long kConnectTimeoutMilliseconds = 2000L;
constexpr long kTotalTimeoutMilliseconds = 15000L;
#ifdef KEEN_PBR3_TESTING
std::atomic<bool> test_fail_before_backend_once{false};
#endif
static_assert(
    std::chrono::duration_cast<std::chrono::milliseconds>(
        kNdmsNativeImportRequiredDispatchWindow).count() >=
        kTotalTimeoutMilliseconds + 2000L,
    "allocator receipt window must cover curl timeout and margin");

class ExactSuccessCursor final {
public:
    explicit ExactSuccessCursor(const std::string_view input)
        : input_(input) {}

    bool punctuation(const char value) {
        whitespace();
        if (position_ >= input_.size() || input_[position_] != value) {
            return false;
        }
        ++position_;
        return true;
    }

    bool quoted(const std::string_view literal) {
        whitespace();
        if (position_ >= input_.size() || input_[position_] != '"') {
            return false;
        }
        ++position_;
        if (literal.size() > input_.size() - position_ ||
            input_.substr(position_, literal.size()) != literal) {
            return false;
        }
        position_ += literal.size();
        if (position_ >= input_.size() || input_[position_] != '"') {
            return false;
        }
        ++position_;
        return true;
    }

    bool key_string(const std::string_view key,
                    const std::string_view value) {
        const std::size_t saved = position_;
        if (quoted(key) && punctuation(':') && quoted(value)) return true;
        position_ = saved;
        return false;
    }

    bool finished() {
        whitespace();
        return position_ == input_.size();
    }

private:
    void whitespace() {
        while (position_ < input_.size() &&
               (input_[position_] == ' ' || input_[position_] == '\t' ||
                input_[position_] == '\r' || input_[position_] == '\n')) {
            ++position_;
        }
    }

    std::string_view input_;
    std::size_t position_{0U};
};

bool exact_safe_success_body(const std::string_view body,
                             const std::string_view expected_target) {
    ExactSuccessCursor cursor(body);
    if (!cursor.punctuation('[') || !cursor.punctuation('{') ||
        !cursor.quoted("interface") || !cursor.punctuation(':') ||
        !cursor.punctuation('{') || !cursor.quoted("wireguard") ||
        !cursor.punctuation(':') || !cursor.punctuation('{') ||
        !cursor.quoted("import") || !cursor.punctuation(':') ||
        !cursor.punctuation('{')) {
        return false;
    }

    const bool created_first =
        cursor.key_string("created", expected_target);
    if (created_first) {
        if (!cursor.punctuation(',') ||
            !cursor.key_string("intersects", "")) {
            return false;
        }
    } else {
        if (!cursor.key_string("intersects", "") ||
            !cursor.punctuation(',') ||
            !cursor.key_string("created", expected_target)) {
            return false;
        }
    }

    return cursor.punctuation('}') && cursor.punctuation('}') &&
           cursor.punctuation('}') && cursor.punctuation('}') &&
           cursor.punctuation(']') && cursor.finished();
}

std::string_view trim_ascii_view(std::string_view value) noexcept {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1U);
}

unsigned char ascii_lower(const unsigned char character) noexcept {
    return character >= 'A' && character <= 'Z'
               ? static_cast<unsigned char>(character - 'A' + 'a')
               : character;
}

bool ascii_iequals(const std::string_view left,
                   const std::string_view right) noexcept {
    if (left.size() != right.size()) return false;
    for (std::size_t index = 0U; index < left.size(); ++index) {
        if (ascii_lower(static_cast<unsigned char>(left[index])) !=
            ascii_lower(static_cast<unsigned char>(right[index]))) {
            return false;
        }
    }
    return true;
}

bool ascii_iends_with(const std::string_view value,
                      const std::string_view suffix) noexcept {
    return value.size() >= suffix.size() &&
           ascii_iequals(value.substr(value.size() - suffix.size()), suffix);
}

bool json_content_type_header_value(std::string_view raw) noexcept {
    // Header values are classified in place and never copied. A generous
    // bound avoids spending unbounded time on an attacker-controlled local
    // response while accepting all normal MIME parameters.
    if (raw.size() > 1024U) return false;
    raw = trim_ascii_view(raw);
    const auto parameters = raw.find(';');
    if (parameters != std::string_view::npos) {
        raw = trim_ascii_view(raw.substr(0U, parameters));
    }
    return ascii_iequals(raw, "application/json") ||
           (raw.size() > std::string_view{"+json"}.size() &&
            ascii_iends_with(raw, "+json"));
}

NdmsNativeImportResponseManifestV3 uninspected_manifest(
    const NdmsNativeImportRawTransportResponse& response,
    const NdmsNativeTunnelImportKind request_kind) {
    NdmsNativeImportResponseManifestV3 manifest;
    manifest.request_kind = request_kind;
    const auto body = response.body.view();
    manifest.body_bytes = body.size();
    manifest.transport_ok =
        response.transport_ok && !response.callback_failed;
    manifest.http_status = response.status_code;
    manifest.content_type_is_json =
        response.content_type_seen &&
        response.content_type_is_json &&
        !response.content_type_ambiguous;
    if (body.size() > kNdmsNativeImportMaximumResponseBytes) {
        manifest.outcome = NdmsNativeImportResponseOutcome::body_too_large;
        return manifest;
    }
    Sha256 hasher;
    hasher.update(body.data(), body.size());
    manifest.body_sha256 = hasher.hex_digest();
    if (!manifest.transport_ok) {
        manifest.outcome = NdmsNativeImportResponseOutcome::transport_failed;
    } else if (response.status_code != 200) {
        manifest.outcome =
            NdmsNativeImportResponseOutcome::http_status_not_200;
    } else if (!manifest.content_type_is_json) {
        manifest.outcome =
            NdmsNativeImportResponseOutcome::content_type_not_json;
    } else if (body.empty()) {
        manifest.outcome = NdmsNativeImportResponseOutcome::body_empty;
    } else {
        // Production intentionally does not structurally decode an unknown
        // body: it may be a request echo containing a base64 private key.
        manifest.outcome = NdmsNativeImportResponseOutcome::shape_mismatch;
    }
    return manifest;
}

void secure_wipe(std::string& value) noexcept {
    volatile char* bytes = value.empty() ? nullptr : value.data();
    for (std::size_t index = 0U; index < value.size(); ++index) {
        bytes[index] = 0;
    }
    value.clear();
}

struct CurlDeleter {
    void operator()(CURL* handle) const noexcept {
        if (handle != nullptr) curl_easy_cleanup(handle);
    }
};

struct CurlSlistDeleter {
    void operator()(curl_slist* headers) const noexcept {
        if (headers != nullptr) curl_slist_free_all(headers);
    }
};

using CurlHandle = std::unique_ptr<CURL, CurlDeleter>;
using CurlHeaders = std::unique_ptr<curl_slist, CurlSlistDeleter>;

template <typename Value>
void set_curl_option(CURL* handle,
                     const CURLoption option,
                     Value value) {
    if (curl_easy_setopt(handle, option, value) != CURLE_OK) {
        throw NdmsNativeImportTransportError(
            "cannot configure fixed loopback RCI transport");
    }
}

bool starts_with_case_insensitive(std::string_view value,
                                  std::string_view prefix) noexcept {
    if (value.size() < prefix.size()) return false;
    for (std::size_t index = 0U; index < prefix.size(); ++index) {
        const auto left = static_cast<unsigned char>(value[index]);
        const auto right = static_cast<unsigned char>(prefix[index]);
        if (ascii_lower(left) != ascii_lower(right)) return false;
    }
    return true;
}

std::size_t receive_body(char* data,
                         const std::size_t size,
                         const std::size_t count,
                         void* opaque) noexcept {
    if (count != 0U && size > SIZE_MAX / count) return 0U;
    auto& response =
        *static_cast<NdmsNativeImportRawTransportResponse*>(opaque);
    try {
        auto& body = response.body;
        const std::size_t total = size * count;
        const std::size_t remaining =
            body.maximum_bytes() - body.size();
        if (total <= remaining) {
            return body.write_secret_body_chunk(
                       std::string_view(data, total))
                       ? total
                       : 0U;
        }

        // Keep exactly max+1 bytes at the caller-selected bound so the
        // structural inspector classifies body_too_large without hashing a
        // truncated body.
        if (remaining != 0U) {
            (void)body.write_secret_body_chunk(
                std::string_view(data, remaining));
        }
        return 0U;
    } catch (...) {
        response.callback_failed = true;
        return 0U;
    }
}

std::size_t receive_header(char* data,
                           const std::size_t size,
                           const std::size_t count,
                           void* opaque) noexcept {
    if (count != 0U && size > SIZE_MAX / count) return 0U;
    auto& response =
        *static_cast<NdmsNativeImportRawTransportResponse*>(opaque);
    try {
        const std::string_view line(data, size * count);
        if (line.rfind("HTTP/", 0U) == 0U) {
            response.content_type_seen = false;
            response.content_type_is_json = false;
            response.content_type_ambiguous = false;
        } else if (starts_with_case_insensitive(line, "Content-Type:")) {
            if (response.content_type_seen) {
                response.content_type_is_json = false;
                response.content_type_ambiguous = true;
            } else {
                response.content_type_seen = true;
                response.content_type_is_json =
                    json_content_type_header_value(line.substr(13U));
            }
        }
        return line.size();
    } catch (...) {
        response.callback_failed = true;
        return 0U;
    }
}

void restrict_to_plain_loopback_http(CURL* handle) {
#if LIBCURL_VERSION_NUM >= 0x075500
    set_curl_option(handle, CURLOPT_PROTOCOLS_STR, "http");
    set_curl_option(handle, CURLOPT_REDIR_PROTOCOLS_STR, "http");
#else
    set_curl_option(handle, CURLOPT_PROTOCOLS,
                    static_cast<long>(CURLPROTO_HTTP));
    set_curl_option(handle, CURLOPT_REDIR_PROTOCOLS,
                    static_cast<long>(CURLPROTO_HTTP));
#endif
}

} // namespace

NdmsNativeSecretBuffer::NdmsNativeSecretBuffer(
    const std::size_t maximum_bytes)
    : maximum_bytes_(maximum_bytes) {
    if (maximum_bytes_ == 0U) {
        throw NdmsNativeImportTransportError(
            "secret buffer maximum must be non-zero");
    }
    bytes_.reserve(maximum_bytes_);
}

NdmsNativeSecretBuffer::~NdmsNativeSecretBuffer() {
    wipe();
}

NdmsNativeSecretBuffer::NdmsNativeSecretBuffer(
    NdmsNativeSecretBuffer&& other)
    : bytes_(other.bytes_),
      maximum_bytes_(other.maximum_bytes_) {
    other.maximum_bytes_ = 0U;
    secure_wipe(other.bytes_);
}

NdmsNativeSecretBuffer& NdmsNativeSecretBuffer::operator=(
    NdmsNativeSecretBuffer&& other) {
    if (this != &other) {
        wipe();
        bytes_ = other.bytes_;
        maximum_bytes_ = other.maximum_bytes_;
        other.maximum_bytes_ = 0U;
        secure_wipe(other.bytes_);
    }
    return *this;
}

bool NdmsNativeSecretBuffer::write_secret_body_chunk(
    const std::string_view chunk) {
    if (maximum_bytes_ == 0U ||
        chunk.size() > maximum_bytes_ - bytes_.size()) {
        return false;
    }
    if (chunk.empty()) return true;
    bytes_.append(chunk.data(), chunk.size());
    return true;
}

std::string_view NdmsNativeSecretBuffer::view() const noexcept {
    return bytes_;
}

std::size_t NdmsNativeSecretBuffer::size() const noexcept {
    return bytes_.size();
}

std::size_t NdmsNativeSecretBuffer::maximum_bytes() const noexcept {
    return maximum_bytes_;
}

bool NdmsNativeSecretBuffer::empty() const noexcept {
    return bytes_.empty();
}

void NdmsNativeSecretBuffer::clear() noexcept {
    wipe();
}

void NdmsNativeSecretBuffer::wipe() noexcept {
    secure_wipe(bytes_);
}

NdmsNativeImportRawTransportResponse::
NdmsNativeImportRawTransportResponse()
    : body(kNdmsNativeImportMaximumResponseBytes + 1U) {}

NdmsNativeImportRawTransportResponse
NdmsNativeLibcurlLoopbackRciPostBackend::post_fixed_loopback_once(
    NdmsNativeImportDispatchCapability&&,
    NdmsNativeSecretBuffer&& request_body,
    NdmsNativeImportPreDispatchGuard& pre_dispatch_guard,
    NdmsNativeImportBackendTrace& trace) {
    CurlHandle handle(curl_easy_init());
    if (!handle) {
        throw NdmsNativeImportTransportError(
            "cannot initialize fixed loopback RCI transport");
    }

    NdmsNativeImportRawTransportResponse response;
    set_curl_option(handle.get(), CURLOPT_URL, kStockRciEndpoint);
    set_curl_option(handle.get(), CURLOPT_NOSIGNAL, 1L);
    set_curl_option(handle.get(), CURLOPT_CONNECTTIMEOUT_MS,
                    kConnectTimeoutMilliseconds);
    set_curl_option(handle.get(), CURLOPT_TIMEOUT_MS,
                    kTotalTimeoutMilliseconds);
    set_curl_option(handle.get(), CURLOPT_PROXY, "");
    set_curl_option(handle.get(), CURLOPT_NOPROXY, "*");
    set_curl_option(handle.get(), CURLOPT_FOLLOWLOCATION, 0L);
    set_curl_option(handle.get(), CURLOPT_MAXREDIRS, 0L);
    set_curl_option(handle.get(), CURLOPT_POST, 1L);
    set_curl_option(handle.get(), CURLOPT_POSTFIELDS,
                    request_body.view().data());
    set_curl_option(
        handle.get(), CURLOPT_POSTFIELDSIZE_LARGE,
        static_cast<curl_off_t>(request_body.size()));
    set_curl_option(handle.get(), CURLOPT_WRITEFUNCTION, receive_body);
    set_curl_option(handle.get(), CURLOPT_WRITEDATA, &response);
    set_curl_option(handle.get(), CURLOPT_HEADERFUNCTION, receive_header);
    set_curl_option(handle.get(), CURLOPT_HEADERDATA, &response);
    restrict_to_plain_loopback_http(handle.get());

    CurlHeaders headers;
    for (const char* header : {
             "Content-Type: application/json",
             "Accept: application/json",
             "Expect:",
             "Connection: close"}) {
        curl_slist* appended = curl_slist_append(headers.get(), header);
        if (appended == nullptr) {
            throw NdmsNativeImportTransportError(
                "cannot allocate fixed loopback RCI headers");
        }
        headers.release();
        headers.reset(appended);
    }
    set_curl_option(handle.get(), CURLOPT_HTTPHEADER, headers.get());

    // This is deliberately the final potentially long-lived admission point:
    // secret serialization and curl setup are complete, but perform has not
    // started. The guard also requires the complete 17-second lease budget.
    trace.pre_dispatch_guard_evaluated = true;
    if (!pre_dispatch_guard.authorize_dispatch()) {
        return response;
    }
    trace.pre_dispatch_guard_passed = true;

    // From this point a timeout or connection error is ambiguous. Recovery
    // must inspect the ownership marker and must never replay the import.
    trace.perform_started = true;
    response.request_may_have_been_dispatched = true;
    const CURLcode code = curl_easy_perform(handle.get());
    response.transport_ok = code == CURLE_OK && !response.callback_failed;

    long status_code = 0L;
    if (curl_easy_getinfo(handle.get(), CURLINFO_RESPONSE_CODE,
                          &status_code) == CURLE_OK &&
        status_code >= 0L && status_code <= INT_MAX) {
        response.status_code = static_cast<int>(status_code);
    }
    return response;
}

NdmsNativeImportDispatchCapability::
NdmsNativeImportDispatchCapability(ConstructionKey) noexcept
    : valid_(true) {}

NdmsNativeImportDispatchCapability::
NdmsNativeImportDispatchCapability(
    NdmsNativeImportDispatchCapability&& other) noexcept
    : valid_(other.valid_) {
    other.valid_ = false;
}

NdmsNativeImportDispatchCapability&
NdmsNativeImportDispatchCapability::operator=(
    NdmsNativeImportDispatchCapability&& other) noexcept {
    if (this == &other) {
        valid_ = false;
        return *this;
    }
    valid_ = other.valid_;
    other.valid_ = false;
    return *this;
}

bool NdmsNativeImportDispatchCapability::consume() noexcept {
    const bool was_valid = valid_;
    valid_ = false;
    return was_valid;
}

#ifdef KEEN_PBR3_TESTING
NdmsNativeImportDispatchCapability
NdmsNativeImportDispatchCapabilityTestIssuer::issue() noexcept {
    return NdmsNativeImportDispatchCapability{
        NdmsNativeImportDispatchCapability::ConstructionKey{}};
}

void NdmsNativeImportTransportTestControl::
fail_before_backend_once() noexcept {
    ::keen_pbr3::test_fail_before_backend_once.store(
        true, std::memory_order_release);
}

bool NdmsNativeImportTransportTestControl::
consume_fail_before_backend() noexcept {
    return ::keen_pbr3::test_fail_before_backend_once.exchange(
        false, std::memory_order_acq_rel);
}
#endif

NdmsNativeImportTransportResult post_ndms_native_import_once(
    NdmsNativeImportDispatchCapability&& capability,
    NdmsNativeWireguardImportRequest request,
    const std::string& expected_created_interface,
    NdmsNativeImportPreDispatchGuard& pre_dispatch_guard,
    NdmsNativeLoopbackRciPostBackend& backend) {
    if (!capability.consume()) {
        throw NdmsNativeImportTransportError(
            "native import dispatch capability is invalid");
    }
    if (!ndms_native_created_target_is_eligible(
            expected_created_interface)) {
        throw NdmsNativeImportTransportError(
            "expected native import target is not eligible");
    }
    const auto request_kind = request.kind();
    const std::size_t expected_bytes = request.content_length();
    NdmsNativeSecretBuffer request_body(expected_bytes);
    if (!request.write_stock_rci_body_once(request_body) ||
        request_body.size() != expected_bytes) {
        throw NdmsNativeImportTransportError(
            "native import request serialization failed");
    }
#ifdef KEEN_PBR3_TESTING
    if (NdmsNativeImportTransportTestControl::
            consume_fail_before_backend()) {
        throw NdmsNativeImportTransportError(
            "synthetic pre-backend transport failure");
    }
#endif

    NdmsNativeImportBackendTrace trace;
    bool backend_call_confirmed = false;
    try {
        // Both arguments are references, so no throwing object construction
        // can occur between this marker and virtual method entry.
        backend_call_confirmed = true;
        auto response = backend.post_fixed_loopback_once(
            std::move(capability), std::move(request_body),
            pre_dispatch_guard, trace);
        auto manifest = uninspected_manifest(response, request_kind);
        if (manifest.transport_ok && response.status_code == 200 &&
            manifest.content_type_is_json &&
            exact_safe_success_body(
                response.body.view(), expected_created_interface)) {
            // Only the exact two-field grammar contains no attacker- or
            // firmware-controlled opaque string. It is safe to pass to the
            // richer diagnostic parser without creating an un-wiped DOM copy
            // of a key.
            manifest = inspect_ndms_native_import_response_v3(
                NdmsNativeImportHttpResponseView{
                    true,
                    response.status_code,
                    "application/json",
                    response.body.view()},
                request_kind,
                expected_created_interface);
        }
        // A later stage is also proof that every earlier one was crossed.
        // Normalizing this way keeps the public trace internally consistent
        // even if a future backend forgets to set an earlier diagnostic bit.
        const bool guard_passed =
            trace.pre_dispatch_guard_passed || trace.perform_started;
        const bool guard_evaluated =
            trace.pre_dispatch_guard_evaluated || guard_passed;
        return NdmsNativeImportTransportResult{
            backend_call_confirmed,
            guard_evaluated,
            guard_passed,
            trace.perform_started,
            trace.perform_started ||
                response.request_may_have_been_dispatched,
            std::move(manifest)};
    } catch (...) {
        // The backend boundary has been entered, but setup can still fail
        // before the guard or perform. The trace is the only authority for
        // whether dispatch became ambiguous.
        NdmsNativeImportResponseManifestV3 manifest;
        manifest.request_kind = request_kind;
        manifest.transport_ok = false;
        manifest.outcome =
            NdmsNativeImportResponseOutcome::transport_failed;
        const bool guard_passed =
            trace.pre_dispatch_guard_passed || trace.perform_started;
        const bool guard_evaluated =
            trace.pre_dispatch_guard_evaluated || guard_passed;
        return NdmsNativeImportTransportResult{
            backend_call_confirmed,
            guard_evaluated,
            guard_passed,
            trace.perform_started,
            trace.perform_started,
            std::move(manifest)};
    }
}

} // namespace keen_pbr3
