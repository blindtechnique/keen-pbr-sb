#include "ndms_native_exact_mutation_transport.hpp"

#include "ndms_native_create_policy.hpp"

#include <curl/curl.h>

#include <climits>
#include <cstdint>
#include <memory>
#include <utility>

namespace keen_pbr3 {

namespace {

constexpr const char* kStockRciEndpoint =
    "http://127.0.0.1:79/rci/";
constexpr long kConnectTimeoutMilliseconds = 2000L;
constexpr long kTotalTimeoutMilliseconds = 15000L;
static_assert(
    std::chrono::duration_cast<std::chrono::milliseconds>(
        kNdmsNativeExactMutationRequiredDispatchWindow).count() >=
        kTotalTimeoutMilliseconds + 2000L,
    "exact mutation dispatch window must cover curl timeout and margin");
constexpr std::string_view kDeletePrefix{
    R"({"interface":{"name":")"};
constexpr std::string_view kDeleteSuffix{R"(","no":true}})"};
constexpr std::string_view kEnablePrefix{
    R"({"interface":{")"};
constexpr std::string_view kEnableSuffix{R"(":{"up":true}}})"};
constexpr std::string_view kSaveBody{
    R"({"system":{"configuration":{"save":{}}}})"};

void secure_wipe(std::string& value) noexcept {
    volatile char* bytes = value.empty() ? nullptr : value.data();
    for (std::size_t index = 0U; index < value.size(); ++index) {
        bytes[index] = 0;
    }
    value.clear();
}

class ExactAcknowledgementCursor final {
public:
    explicit ExactAcknowledgementCursor(const std::string_view input)
        : input_(input) {}

    bool punctuation(const char value) noexcept {
        whitespace();
        if (position_ >= input_.size() || input_[position_] != value) {
            return false;
        }
        ++position_;
        return true;
    }

    bool quoted(const std::string_view literal) noexcept {
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

    bool quoted_decimal() noexcept {
        whitespace();
        if (position_ >= input_.size() || input_[position_] != '"') {
            return false;
        }
        ++position_;
        const auto first = position_;
        while (position_ < input_.size() &&
               input_[position_] >= '0' && input_[position_] <= '9') {
            ++position_;
        }
        if (position_ == first || position_ - first > 20U ||
            position_ >= input_.size() || input_[position_] != '"') {
            return false;
        }
        ++position_;
        return true;
    }

    bool finished() noexcept {
        whitespace();
        return position_ == input_.size();
    }

private:
    void whitespace() noexcept {
        while (position_ < input_.size() &&
               (input_[position_] == ' ' || input_[position_] == '\t' ||
                input_[position_] == '\r' || input_[position_] == '\n')) {
            ++position_;
        }
    }

    std::string_view input_;
    std::size_t position_{0U};
};

bool exact_generic_acknowledgement_body(
    const std::string_view body) noexcept {
    // AWG Manager's canonical save fixture uses {}, and its generic RCI
    // fixture also uses {"status":"ok"}. Accept only those two bounded,
    // non-secret generic grammars here. Measured operation-specific
    // KeeneticOS responses are matched separately below.
    {
        ExactAcknowledgementCursor cursor(body);
        if (cursor.punctuation('{') && cursor.punctuation('}') &&
            cursor.finished()) {
            return true;
        }
    }
    ExactAcknowledgementCursor cursor(body);
    return cursor.punctuation('{') && cursor.quoted("status") &&
           cursor.punctuation(':') && cursor.quoted("ok") &&
           cursor.punctuation('}') && cursor.finished();
}

bool exact_status_message(
    ExactAcknowledgementCursor& cursor,
    const std::string_view ident,
    const std::string_view message) noexcept {
    return cursor.punctuation('{') && cursor.quoted("status") &&
           cursor.punctuation(':') && cursor.quoted("message") &&
           cursor.punctuation(',') && cursor.quoted("code") &&
           cursor.punctuation(':') && cursor.quoted_decimal() &&
           cursor.punctuation(',') && cursor.quoted("ident") &&
           cursor.punctuation(':') && cursor.quoted(ident) &&
           cursor.punctuation(',') && cursor.quoted("message") &&
           cursor.punctuation(':') && cursor.quoted(message) &&
           cursor.punctuation('}');
}

bool exact_firmware_acknowledgement_body(
    const std::string_view body,
    const NdmsNativeExactMutationKind kind,
    const std::string_view target) noexcept {
    if (exact_generic_acknowledgement_body(body)) return true;

    ExactAcknowledgementCursor cursor(body);
    if (kind == NdmsNativeExactMutationKind::save_configuration) {
        return cursor.punctuation('{') && cursor.quoted("system") &&
               cursor.punctuation(':') && cursor.punctuation('{') &&
               cursor.quoted("configuration") &&
               cursor.punctuation(':') && cursor.punctuation('{') &&
               cursor.quoted("save") && cursor.punctuation(':') &&
               cursor.punctuation('{') && cursor.quoted("status") &&
               cursor.punctuation(':') && cursor.punctuation('[') &&
               exact_status_message(
                   cursor, "Core::System::StartupConfig",
                   "saving (http/rci).") &&
               cursor.punctuation(']') && cursor.punctuation('}') &&
               cursor.punctuation('}') && cursor.punctuation('}') &&
               cursor.punctuation('}') && cursor.finished();
    }
    if (kind ==
            NdmsNativeExactMutationKind::enable_managed_interface &&
        !target.empty()) {
        const std::string message =
            "\\\"" + std::string(target) +
            "\\\": interface is up.";
        return cursor.punctuation('{') && cursor.quoted("interface") &&
               cursor.punctuation(':') && cursor.punctuation('{') &&
               cursor.quoted(target) && cursor.punctuation(':') &&
               cursor.punctuation('{') && cursor.quoted("up") &&
               cursor.punctuation(':') && cursor.punctuation('{') &&
               cursor.quoted("status") && cursor.punctuation(':') &&
               cursor.punctuation('[') &&
               exact_status_message(
                   cursor, "Network::Interface::Base", message) &&
               cursor.punctuation(']') && cursor.punctuation('}') &&
               cursor.punctuation('}') && cursor.punctuation('}') &&
               cursor.punctuation('}') && cursor.finished();
    }
    return false;
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

NdmsNativeExactMutationResponseManifest inspect_response(
    const NdmsNativeExactMutationRawResponse& response,
    const NdmsNativeExactMutationKind kind,
    const std::string_view target) noexcept {
    NdmsNativeExactMutationResponseManifest manifest;
    const auto body = response.body.view();
    manifest.body_bytes = body.size();
    manifest.transport_ok =
        response.transport_ok && !response.callback_failed;
    manifest.http_status = response.status_code;
    manifest.content_type_is_json =
        response.content_type_seen && response.content_type_is_json &&
        !response.content_type_ambiguous;

    if (body.size() > kNdmsNativeExactMutationMaximumResponseBytes) {
        manifest.outcome =
            NdmsNativeExactMutationResponseOutcome::body_too_large;
    } else if (!manifest.transport_ok) {
        manifest.outcome =
            NdmsNativeExactMutationResponseOutcome::transport_failed;
    } else if (response.status_code != 200) {
        manifest.outcome =
            NdmsNativeExactMutationResponseOutcome::http_status_not_200;
    } else if (!manifest.content_type_is_json) {
        manifest.outcome =
            NdmsNativeExactMutationResponseOutcome::content_type_not_json;
    } else if (body.empty()) {
        manifest.outcome =
            NdmsNativeExactMutationResponseOutcome::body_empty;
    } else if (!exact_firmware_acknowledgement_body(
                   body, kind, target)) {
        manifest.outcome =
            NdmsNativeExactMutationResponseOutcome::
                shape_not_acknowledged;
    } else {
        manifest.outcome =
            NdmsNativeExactMutationResponseOutcome::
                acknowledged_needs_observation;
    }
    return manifest;
}

struct CurlDeleter final {
    void operator()(CURL* handle) const noexcept {
        if (handle != nullptr) curl_easy_cleanup(handle);
    }
};

struct CurlSlistDeleter final {
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
        throw NdmsNativeExactMutationTransportError(
            "cannot configure fixed loopback RCI mutation transport");
    }
}

std::size_t receive_body(char* data,
                         const std::size_t size,
                         const std::size_t count,
                         void* opaque) noexcept {
    if (count != 0U && size > SIZE_MAX / count) return 0U;
    auto& response =
        *static_cast<NdmsNativeExactMutationRawResponse*>(opaque);
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
        *static_cast<NdmsNativeExactMutationRawResponse*>(opaque);
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

NdmsNativeExactMutationRequest::NdmsNativeExactMutationRequest(
    const NdmsNativeExactMutationKind kind,
    std::string target) noexcept
    : kind_(kind), target_(std::move(target)), available_(true) {}

NdmsNativeExactMutationRequest
NdmsNativeExactMutationRequest::delete_managed_interface(
    std::string target) {
    if (!ndms_native_created_target_is_eligible(target)) {
        secure_wipe(target);
        throw NdmsNativeExactMutationTransportError(
            "native exact delete target is not an eligible managed candidate");
    }
    return NdmsNativeExactMutationRequest{
        NdmsNativeExactMutationKind::delete_managed_interface,
        std::move(target)};
}

NdmsNativeExactMutationRequest
NdmsNativeExactMutationRequest::enable_managed_interface(
    std::string target) {
    if (!ndms_native_created_target_is_eligible(target)) {
        secure_wipe(target);
        throw NdmsNativeExactMutationTransportError(
            "native exact enable target is not an eligible managed candidate");
    }
    return NdmsNativeExactMutationRequest{
        NdmsNativeExactMutationKind::enable_managed_interface,
        std::move(target)};
}

NdmsNativeExactMutationRequest
NdmsNativeExactMutationRequest::save_configuration() {
    return NdmsNativeExactMutationRequest{
        NdmsNativeExactMutationKind::save_configuration, {}};
}

NdmsNativeExactMutationRequest::NdmsNativeExactMutationRequest(
    NdmsNativeExactMutationRequest&& other) noexcept
    : kind_(other.kind_),
      target_(std::move(other.target_)),
      available_(other.available_) {
    other.invalidate();
}

NdmsNativeExactMutationRequest&
NdmsNativeExactMutationRequest::operator=(
    NdmsNativeExactMutationRequest&& other) noexcept {
    if (this == &other) {
        invalidate();
        return *this;
    }
    invalidate();
    kind_ = other.kind_;
    target_ = std::move(other.target_);
    available_ = other.available_;
    other.invalidate();
    return *this;
}

NdmsNativeExactMutationRequest::~NdmsNativeExactMutationRequest() {
    invalidate();
}

NdmsNativeExactMutationKind
NdmsNativeExactMutationRequest::kind() const noexcept {
    return kind_;
}

std::string_view NdmsNativeExactMutationRequest::target() const noexcept {
    return target_;
}

std::size_t
NdmsNativeExactMutationRequest::content_length() const noexcept {
    if (!available_) return 0U;
    if (kind_ ==
        NdmsNativeExactMutationKind::delete_managed_interface) {
        return kDeletePrefix.size() + target_.size() +
               kDeleteSuffix.size();
    }
    if (kind_ ==
        NdmsNativeExactMutationKind::enable_managed_interface) {
        return kEnablePrefix.size() + target_.size() +
               kEnableSuffix.size();
    }
    return kSaveBody.size();
}

bool NdmsNativeExactMutationRequest::write_body_once(
    NdmsNativeSecretBuffer& sink) noexcept {
    if (!available_) return false;
    available_ = false;
    bool written = false;
    try {
        if (kind_ ==
            NdmsNativeExactMutationKind::delete_managed_interface) {
            written =
                sink.write_secret_body_chunk(kDeletePrefix) &&
                sink.write_secret_body_chunk(target_) &&
                sink.write_secret_body_chunk(kDeleteSuffix);
        } else if (kind_ ==
                   NdmsNativeExactMutationKind::
                       enable_managed_interface) {
            written =
                sink.write_secret_body_chunk(kEnablePrefix) &&
                sink.write_secret_body_chunk(target_) &&
                sink.write_secret_body_chunk(kEnableSuffix);
        } else {
            written = sink.write_secret_body_chunk(kSaveBody);
        }
    } catch (...) {
        written = false;
    }
    secure_wipe(target_);
    return written;
}

void NdmsNativeExactMutationRequest::invalidate() noexcept {
    available_ = false;
    secure_wipe(target_);
}

NdmsNativeExactMutationRawResponse::
NdmsNativeExactMutationRawResponse()
    : body(kNdmsNativeExactMutationMaximumResponseBytes + 1U) {}

NdmsNativeExactMutationDispatchAuthority::
NdmsNativeExactMutationDispatchAuthority(
    NdmsNativeExactMutationDispatchAuthority&& other) noexcept
    : valid_(other.valid_) {
    other.valid_ = false;
}

NdmsNativeExactMutationDispatchAuthority&
NdmsNativeExactMutationDispatchAuthority::operator=(
    NdmsNativeExactMutationDispatchAuthority&& other) noexcept {
    if (this == &other) {
        valid_ = false;
        return *this;
    }
    valid_ = other.valid_;
    other.valid_ = false;
    return *this;
}

bool NdmsNativeExactMutationDispatchAuthority::consume() noexcept {
    const bool was_valid = valid_;
    valid_ = false;
    return was_valid;
}

#ifdef KEEN_PBR3_TESTING
NdmsNativeExactMutationDispatchAuthority
NdmsNativeExactMutationDispatchAuthorityTestIssuer::issue() noexcept {
    return NdmsNativeExactMutationDispatchAuthority{
        NdmsNativeExactMutationDispatchAuthority::ConstructionKey{}};
}

bool NdmsNativeExactMutationDispatchAuthorityTestIssuer::consume_for_test(
    NdmsNativeExactMutationDispatchAuthority& authority) noexcept {
    return authority.consume();
}
#endif

NdmsNativeExactMutationRawResponse
NdmsNativeLibcurlExactMutationBackend::post_fixed_loopback_once(
    NdmsNativeExactMutationDispatchCapability&&,
    NdmsNativeSecretBuffer&& request_body,
    NdmsNativeExactMutationPreDispatchGuard& pre_dispatch_guard,
    NdmsNativeExactMutationBackendTrace& trace) {
    CurlHandle handle(curl_easy_init());
    if (!handle) {
        throw NdmsNativeExactMutationTransportError(
            "cannot initialize fixed loopback RCI mutation transport");
    }

    NdmsNativeExactMutationRawResponse response;
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
    set_curl_option(handle.get(), CURLOPT_FRESH_CONNECT, 1L);
    set_curl_option(handle.get(), CURLOPT_FORBID_REUSE, 1L);
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
            throw NdmsNativeExactMutationTransportError(
                "cannot allocate fixed loopback RCI mutation headers");
        }
        headers.release();
        headers.reset(appended);
    }
    set_curl_option(handle.get(), CURLOPT_HTTPHEADER, headers.get());

    // Final admission point: the exact body and every curl option are already
    // fixed, while no byte can have left the process yet.
    trace.pre_dispatch_guard_evaluated = true;
    if (!pre_dispatch_guard.authorize_dispatch()) return response;
    trace.pre_dispatch_guard_passed = true;

    // Any failure after this marker is ambiguous. Recovery must observe state
    // and must never replay this mutation merely because curl returned error.
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

NdmsNativeExactMutationDispatchCapability::
NdmsNativeExactMutationDispatchCapability(ConstructionKey) noexcept
    : valid_(true) {}

NdmsNativeExactMutationDispatchCapability::
NdmsNativeExactMutationDispatchCapability(
    NdmsNativeExactMutationDispatchCapability&& other) noexcept
    : valid_(other.valid_) {
    other.valid_ = false;
}

NdmsNativeExactMutationDispatchCapability&
NdmsNativeExactMutationDispatchCapability::operator=(
    NdmsNativeExactMutationDispatchCapability&& other) noexcept {
    if (this == &other) {
        valid_ = false;
        return *this;
    }
    valid_ = other.valid_;
    other.valid_ = false;
    return *this;
}

bool NdmsNativeExactMutationDispatchCapability::consume() noexcept {
    const bool was_valid = valid_;
    valid_ = false;
    return was_valid;
}

#ifdef KEEN_PBR3_TESTING
NdmsNativeExactMutationDispatchCapability
NdmsNativeExactMutationDispatchCapabilityTestIssuer::issue() noexcept {
    return NdmsNativeExactMutationDispatchCapability{
        NdmsNativeExactMutationDispatchCapability::ConstructionKey{}};
}
#endif

NdmsNativeExactMutationTransportResult
post_ndms_native_exact_mutation_once(
    NdmsNativeExactMutationDispatchCapability&& capability,
    NdmsNativeExactMutationRequest request,
    NdmsNativeExactMutationPreDispatchGuard& pre_dispatch_guard,
    NdmsNativeExactMutationBackend& backend) {
    if (!capability.consume()) {
        throw NdmsNativeExactMutationTransportError(
            "native exact mutation dispatch capability is invalid");
    }

    const auto kind = request.kind();
    const std::string target{request.target()};
    const std::size_t expected_bytes = request.content_length();
    if (expected_bytes == 0U) {
        throw NdmsNativeExactMutationTransportError(
            "native exact mutation request is unavailable");
    }
    NdmsNativeSecretBuffer request_body(expected_bytes);
    if (!request.write_body_once(request_body) ||
        request_body.size() != expected_bytes) {
        throw NdmsNativeExactMutationTransportError(
            "native exact mutation request serialization failed");
    }

    NdmsNativeExactMutationBackendTrace trace;
    bool backend_call_confirmed = false;
    try {
        backend_call_confirmed = true;
        auto response = backend.post_fixed_loopback_once(
            std::move(capability), std::move(request_body),
            pre_dispatch_guard, trace);
        auto manifest = inspect_response(response, kind, target);
        const bool guard_passed =
            trace.pre_dispatch_guard_passed || trace.perform_started;
        const bool guard_evaluated =
            trace.pre_dispatch_guard_evaluated || guard_passed;
        if (guard_evaluated && !guard_passed) {
            manifest.outcome =
                NdmsNativeExactMutationResponseOutcome::guard_rejected;
        }
        return NdmsNativeExactMutationTransportResult{
            kind,
            backend_call_confirmed,
            guard_evaluated,
            guard_passed,
            trace.perform_started,
            trace.perform_started ||
                response.request_may_have_been_dispatched,
            std::move(manifest)};
    } catch (...) {
        NdmsNativeExactMutationResponseManifest manifest;
        manifest.outcome =
            NdmsNativeExactMutationResponseOutcome::transport_failed;
        const bool guard_passed =
            trace.pre_dispatch_guard_passed || trace.perform_started;
        const bool guard_evaluated =
            trace.pre_dispatch_guard_evaluated || guard_passed;
        return NdmsNativeExactMutationTransportResult{
            kind,
            backend_call_confirmed,
            guard_evaluated,
            guard_passed,
            trace.perform_started,
            trace.perform_started,
            std::move(manifest)};
    }
}

} // namespace keen_pbr3
