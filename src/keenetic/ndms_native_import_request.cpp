#include "ndms_native_import_request.hpp"

#include "ndms_native_import_identity.hpp"
#include "ndms_native_panel_delete_snapshot.hpp"

#include <array>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <limits>
#include <string_view>
#include <sys/random.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

constexpr std::string_view kOperation =
    "interface.wireguard.import";
constexpr std::string_view kBodyPrefix =
    "[{\"interface\":{\"wireguard\":{\"import\":{\"import\":\"";
constexpr std::string_view kBodyFilenamePrefix =
    "\",\"name\":\"\",\"filename\":\"";
constexpr std::string_view kBodySuffix = "\"}}}}]";
constexpr std::size_t kMarkerRandomBytes = 16U;
constexpr std::size_t kBase64ScratchBytes = 4096U;
constexpr std::string_view kPanelDeleteSnapshotMagic =
    "keen-pbr-panel-delete-snapshot-v1\n";

static_assert(kBase64ScratchBytes % 4U == 0U);

[[noreturn]] void fail(
    const NdmsNativeWireguardImportRequestErrorCode code) {
    throw NdmsNativeWireguardImportRequestError(code);
}

void secure_wipe(char* data, const std::size_t size) noexcept {
    volatile char* bytes = data;
    for (std::size_t index = 0U; index < size; ++index) {
        bytes[index] = '\0';
    }
}

void secure_wipe(std::string& value) noexcept {
    if (!value.empty()) secure_wipe(&value[0], value.size());
    value.clear();
}

template <typename Byte, std::size_t Size>
void secure_wipe(std::array<Byte, Size>& value) noexcept {
    volatile Byte* bytes = value.data();
    for (std::size_t index = 0U; index < value.size(); ++index) {
        bytes[index] = static_cast<Byte>(0);
    }
}

class WipeStringGuard {
public:
    explicit WipeStringGuard(std::string& value) noexcept
        : value_(value) {}
    ~WipeStringGuard() { secure_wipe(value_); }

    WipeStringGuard(const WipeStringGuard&) = delete;
    WipeStringGuard& operator=(const WipeStringGuard&) = delete;

private:
    std::string& value_;
};

template <typename Byte, std::size_t Size>
class WipeArrayGuard {
public:
    explicit WipeArrayGuard(std::array<Byte, Size>& value) noexcept
        : value_(value) {}
    ~WipeArrayGuard() { secure_wipe(value_); }

    WipeArrayGuard(const WipeArrayGuard&) = delete;
    WipeArrayGuard& operator=(const WipeArrayGuard&) = delete;

private:
    std::array<Byte, Size>& value_;
};

void fill_from_urandom(unsigned char* output,
                       const std::size_t size) {
    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int descriptor = ::open("/dev/urandom", flags);
    if (descriptor < 0) {
        fail(NdmsNativeWireguardImportRequestErrorCode::
                 entropy_unavailable);
    }

    std::size_t offset = 0U;
    while (offset < size) {
        const auto count = ::read(
            descriptor, output + offset, size - offset);
        if (count > 0) {
            offset += static_cast<std::size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        (void)::close(descriptor);
        fail(NdmsNativeWireguardImportRequestErrorCode::
                 entropy_unavailable);
    }
    (void)::close(descriptor);
}

std::string generate_transaction_id() {
    std::array<unsigned char, kMarkerRandomBytes> random_bytes{};
    WipeArrayGuard<unsigned char, kMarkerRandomBytes> guard(random_bytes);

    std::size_t offset = 0U;
    bool use_urandom = false;
    while (offset < random_bytes.size()) {
        const auto count = ::getrandom(
            random_bytes.data() + offset,
            random_bytes.size() - offset,
            0);
        if (count > 0) {
            offset += static_cast<std::size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        use_urandom = true;
        break;
    }
    if (use_urandom) {
        fill_from_urandom(random_bytes.data(), random_bytes.size());
    }

    constexpr char hex[] = "0123456789abcdef";
    std::string transaction_id;
    transaction_id.reserve(random_bytes.size() * 2U);
    for (const auto byte : random_bytes) {
        transaction_id.push_back(hex[(byte >> 4U) & 0x0FU]);
        transaction_id.push_back(hex[byte & 0x0FU]);
    }
    return transaction_id;
}

std::size_t checked_add(const std::size_t left,
                        const std::size_t right) {
    if (right > std::numeric_limits<std::size_t>::max() - left) {
        throw std::length_error("native WireGuard canonical body too large");
    }
    return left + right;
}

std::size_t line_size(const std::string_view name,
                      const std::string_view value) {
    return checked_add(checked_add(name.size(), value.size()), 1U);
}

std::size_t joined_line_size(
    const std::string_view name,
    const std::vector<std::string>& values) {
    std::size_t size = checked_add(name.size(), 1U);
    for (std::size_t index = 0U; index < values.size(); ++index) {
        size = checked_add(size, values[index].size());
        if (index + 1U < values.size()) size = checked_add(size, 2U);
    }
    return size;
}

struct CanonicalNumberText {
    std::string listen_port;
    std::string mtu;
    std::vector<std::string> persistent_keepalive;
    std::string jc;
    std::string jmin;
    std::string jmax;
    std::string s1;
    std::string s2;
    std::string s3;
    std::string s4;
};

using AwgSignatureView = std::pair<
    std::string_view, const std::optional<std::string>*>;

std::array<AwgSignatureView, 5U> awg_signatures(
    const NdmsNativeTunnelImportAwgParameters& awg) noexcept {
    return {{
        {"I1 = ", &awg.i1}, {"I2 = ", &awg.i2},
        {"I3 = ", &awg.i3}, {"I4 = ", &awg.i4},
        {"I5 = ", &awg.i5},
    }};
}

CanonicalNumberText number_text(
    const NdmsNativeTunnelImport& imported) {
    CanonicalNumberText result;
    if (imported.listen_port) {
        result.listen_port = std::to_string(*imported.listen_port);
    }
    if (imported.mtu) result.mtu = std::to_string(*imported.mtu);
    if (imported.awg) {
        result.jc = std::to_string(imported.awg->jc);
        result.jmin = std::to_string(imported.awg->jmin);
        result.jmax = std::to_string(imported.awg->jmax);
        result.s1 = std::to_string(imported.awg->s1);
        result.s2 = std::to_string(imported.awg->s2);
        if (imported.awg->s3) {
            result.s3 = std::to_string(*imported.awg->s3);
            result.s4 = std::to_string(*imported.awg->s4);
        }
    }
    result.persistent_keepalive.reserve(imported.peers.size());
    for (const auto& peer : imported.peers) {
        result.persistent_keepalive.push_back(
            peer.persistent_keepalive
                ? std::to_string(*peer.persistent_keepalive)
                : std::string{});
    }
    return result;
}

std::size_t canonical_conf_size(
    const NdmsNativeTunnelImport& imported,
    const std::string_view marker,
    const CanonicalNumberText& numbers) {
    std::size_t size = line_size("# Name = ", marker);
    size = checked_add(size, std::string_view{"[Interface]\n"}.size());
    size = checked_add(size, line_size(
        "PrivateKey = ",
        imported.private_key.reveal_for_typed_rci()));
    size = checked_add(size, joined_line_size(
        "Address = ", imported.addresses));
    if (!imported.dns_servers.empty()) {
        size = checked_add(size, joined_line_size(
            "DNS = ", imported.dns_servers));
    }
    if (imported.listen_port) {
        size = checked_add(size, line_size(
            "ListenPort = ", numbers.listen_port));
    }
    if (imported.mtu) {
        size = checked_add(size, line_size("MTU = ", numbers.mtu));
    }
    if (imported.awg) {
        const auto& awg = *imported.awg;
        size = checked_add(size, line_size("Jc = ", numbers.jc));
        size = checked_add(size, line_size("Jmin = ", numbers.jmin));
        size = checked_add(size, line_size("Jmax = ", numbers.jmax));
        size = checked_add(size, line_size("S1 = ", numbers.s1));
        size = checked_add(size, line_size("S2 = ", numbers.s2));
        size = checked_add(size, line_size("H1 = ", awg.h1));
        size = checked_add(size, line_size("H2 = ", awg.h2));
        size = checked_add(size, line_size("H3 = ", awg.h3));
        size = checked_add(size, line_size("H4 = ", awg.h4));
        if (awg.s3) {
            size = checked_add(size, line_size("S3 = ", numbers.s3));
            size = checked_add(size, line_size("S4 = ", numbers.s4));
        }
        for (const auto& signature : awg_signatures(awg)) {
            if (*signature.second) {
                size = checked_add(size, line_size(
                    signature.first, signature.second->value()));
            }
        }
    }

    for (std::size_t index = 0U;
         index < imported.peers.size(); ++index) {
        const auto& peer = imported.peers[index];
        size = checked_add(size, std::string_view{"\n[Peer]\n"}.size());
        size = checked_add(size, line_size(
            "PublicKey = ", peer.public_key));
        if (peer.preshared_key) {
            size = checked_add(size, line_size(
                "PresharedKey = ",
                peer.preshared_key->reveal_for_typed_rci()));
        }
        size = checked_add(size, line_size("Endpoint = ", peer.endpoint));
        size = checked_add(size, joined_line_size(
            "AllowedIPs = ", peer.allowed_ips));
        if (peer.persistent_keepalive) {
            size = checked_add(size, line_size(
                "PersistentKeepalive = ",
                numbers.persistent_keepalive[index]));
        }
    }
    return size;
}

void append_line(std::string& output,
                 const std::string_view name,
                 const std::string_view value) {
    output.append(name.data(), name.size());
    output.append(value.data(), value.size());
    output.push_back('\n');
}

void append_joined_line(
    std::string& output,
    const std::string_view name,
    const std::vector<std::string>& values) {
    output.append(name.data(), name.size());
    for (std::size_t index = 0U; index < values.size(); ++index) {
        if (index != 0U) output.append(", ");
        output.append(values[index]);
    }
    output.push_back('\n');
}

std::string build_canonical_conf(
    const NdmsNativeTunnelImport& imported,
    const std::string_view marker) {
    const auto numbers = number_text(imported);
    const auto required = canonical_conf_size(imported, marker, numbers);
    std::string output;
    // Reserve before the first credential is copied. No old allocation can
    // therefore be released with a partial private key during construction.
    output.reserve(required);

    append_line(output, "# Name = ", marker);
    output.append("[Interface]\n");
    append_line(output, "PrivateKey = ",
                imported.private_key.reveal_for_typed_rci());
    append_joined_line(output, "Address = ", imported.addresses);
    if (!imported.dns_servers.empty()) {
        append_joined_line(output, "DNS = ", imported.dns_servers);
    }
    if (imported.listen_port) {
        append_line(output, "ListenPort = ", numbers.listen_port);
    }
    if (imported.mtu) append_line(output, "MTU = ", numbers.mtu);
    if (imported.awg) {
        const auto& awg = *imported.awg;
        append_line(output, "Jc = ", numbers.jc);
        append_line(output, "Jmin = ", numbers.jmin);
        append_line(output, "Jmax = ", numbers.jmax);
        append_line(output, "S1 = ", numbers.s1);
        append_line(output, "S2 = ", numbers.s2);
        append_line(output, "H1 = ", awg.h1);
        append_line(output, "H2 = ", awg.h2);
        append_line(output, "H3 = ", awg.h3);
        append_line(output, "H4 = ", awg.h4);
        if (awg.s3) {
            append_line(output, "S3 = ", numbers.s3);
            append_line(output, "S4 = ", numbers.s4);
        }
        for (const auto& signature : awg_signatures(awg)) {
            if (*signature.second) {
                append_line(
                    output, signature.first, signature.second->value());
            }
        }
    }

    for (std::size_t index = 0U;
         index < imported.peers.size(); ++index) {
        const auto& peer = imported.peers[index];
        output.append("\n[Peer]\n");
        append_line(output, "PublicKey = ", peer.public_key);
        if (peer.preshared_key) {
            append_line(
                output, "PresharedKey = ",
                peer.preshared_key->reveal_for_typed_rci());
        }
        append_line(output, "Endpoint = ", peer.endpoint);
        append_joined_line(output, "AllowedIPs = ", peer.allowed_ips);
        if (peer.persistent_keepalive) {
            append_line(output, "PersistentKeepalive = ",
                        numbers.persistent_keepalive[index]);
        }
    }

    if (output.size() != required) {
        secure_wipe(output);
        throw std::logic_error(
            "native WireGuard canonical body size mismatch");
    }
    return output;
}

std::size_t base64_encoded_size(const std::size_t raw_size) {
    return checked_add(raw_size, 2U) / 3U * 4U;
}

} // namespace

const char* ndms_native_wireguard_import_request_error_code_name(
    const NdmsNativeWireguardImportRequestErrorCode code) noexcept {
    switch (code) {
    case NdmsNativeWireguardImportRequestErrorCode::unsupported_source:
        return "unsupported_source";
    case NdmsNativeWireguardImportRequestErrorCode::entropy_unavailable:
        return "entropy_unavailable";
    case NdmsNativeWireguardImportRequestErrorCode::already_consumed:
        return "already_consumed";
    }
    return "unsupported_source";
}

NdmsNativeWireguardImportRequestError::
NdmsNativeWireguardImportRequestError(
    const NdmsNativeWireguardImportRequestErrorCode code)
    : std::runtime_error(
          std::string("native WireGuard import request rejected: ") +
          ndms_native_wireguard_import_request_error_code_name(code)),
      code_(code) {}

NdmsNativeWireguardImportRequestErrorCode
NdmsNativeWireguardImportRequestError::code() const noexcept {
    return code_;
}

NdmsNativeWireguardImportRequest::NdmsNativeWireguardImportRequest(
    std::string canonical_conf,
    const NdmsNativeTunnelImportKind kind,
    std::string transaction_id,
    std::string marker,
    std::string filename,
    std::string candidate_revision)
    : kind_(kind),
      transaction_id_(std::move(transaction_id)),
      marker_(std::move(marker)),
      filename_(std::move(filename)),
      candidate_revision_(std::move(candidate_revision)),
      consumed_(false) {
    canonical_conf_.swap(canonical_conf);
    secure_wipe(canonical_conf);
    try {
        const auto encoded = base64_encoded_size(canonical_conf_.size());
        content_length_ = checked_add(
            checked_add(
                checked_add(kBodyPrefix.size(), encoded),
                kBodyFilenamePrefix.size()),
            checked_add(filename_.size(), kBodySuffix.size()));
    } catch (...) {
        wipe_secret();
        throw;
    }
}

NdmsNativeWireguardImportRequest::~NdmsNativeWireguardImportRequest() {
    wipe_secret();
}

NdmsNativeWireguardImportRequest::NdmsNativeWireguardImportRequest(
    NdmsNativeWireguardImportRequest&& other) noexcept
    : kind_(other.kind_),
      transaction_id_(std::move(other.transaction_id_)),
      marker_(std::move(other.marker_)),
      filename_(std::move(other.filename_)),
      candidate_revision_(std::move(other.candidate_revision_)),
      content_length_(other.content_length_),
      consumed_(other.consumed_) {
    canonical_conf_.swap(other.canonical_conf_);
    other.wipe_secret();
    other.content_length_ = 0U;
    other.consumed_ = true;
}

NdmsNativeWireguardImportRequest&
NdmsNativeWireguardImportRequest::operator=(
    NdmsNativeWireguardImportRequest&& other) noexcept {
    if (this != &other) {
        wipe_secret();
        canonical_conf_.swap(other.canonical_conf_);
        kind_ = other.kind_;
        transaction_id_ = std::move(other.transaction_id_);
        marker_ = std::move(other.marker_);
        filename_ = std::move(other.filename_);
        candidate_revision_ = std::move(other.candidate_revision_);
        content_length_ = other.content_length_;
        consumed_ = other.consumed_;
        other.wipe_secret();
        other.content_length_ = 0U;
        other.consumed_ = true;
    }
    return *this;
}

std::string_view NdmsNativeWireguardImportRequest::operation()
    const noexcept {
    return kOperation;
}

bool valid_panel_delete_marker(const std::string_view marker) noexcept {
    return ndms_native_import_transaction_id_from_marker(marker)
        .has_value();
}

NdmsNativeTunnelImportKind NdmsNativeWireguardImportRequest::kind()
    const noexcept {
    return kind_;
}

std::string_view NdmsNativeWireguardImportRequest::marker()
    const noexcept {
    return marker_;
}

std::string_view NdmsNativeWireguardImportRequest::transaction_id()
    const noexcept {
    return transaction_id_;
}

std::string_view NdmsNativeWireguardImportRequest::filename()
    const noexcept {
    return filename_;
}

std::string_view NdmsNativeWireguardImportRequest::candidate_revision()
    const noexcept {
    return candidate_revision_;
}

std::size_t NdmsNativeWireguardImportRequest::content_length()
    const noexcept {
    return content_length_;
}

bool NdmsNativeWireguardImportRequest::has_pending_secret_body()
    const noexcept {
    return !consumed_ && !canonical_conf_.empty();
}

bool NdmsNativeWireguardImportRequest::write_stock_rci_body_once(
    NdmsNativeSecretBodySink& sink) {
    if (consumed_ || canonical_conf_.empty()) {
        fail(NdmsNativeWireguardImportRequestErrorCode::already_consumed);
    }
    consumed_ = true;
    try {
        const auto emit = [&](const std::string_view chunk) {
            return sink.write_secret_body_chunk(chunk);
        };
        if (!emit(kBodyPrefix)) {
            wipe_secret();
            return false;
        }

        constexpr std::string_view alphabet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::array<char, kBase64ScratchBytes> encoded{};
        WipeArrayGuard<char, kBase64ScratchBytes> encoded_guard(encoded);
        std::size_t used = 0U;
        const auto flush = [&]() {
            if (used == 0U) return true;
            const bool accepted =
                emit(std::string_view(encoded.data(), used));
            secure_wipe(encoded.data(), used);
            used = 0U;
            return accepted;
        };

        for (std::size_t offset = 0U;
             offset < canonical_conf_.size(); offset += 3U) {
            if (used + 4U > encoded.size() && !flush()) {
                wipe_secret();
                return false;
            }
            const auto first = static_cast<std::uint8_t>(
                canonical_conf_[offset]);
            const bool has_second = offset + 1U < canonical_conf_.size();
            const bool has_third = offset + 2U < canonical_conf_.size();
            const auto second = has_second
                ? static_cast<std::uint8_t>(canonical_conf_[offset + 1U])
                : 0U;
            const auto third = has_third
                ? static_cast<std::uint8_t>(canonical_conf_[offset + 2U])
                : 0U;
            const std::uint32_t block =
                (static_cast<std::uint32_t>(first) << 16U) |
                (static_cast<std::uint32_t>(second) << 8U) |
                static_cast<std::uint32_t>(third);
            encoded[used++] = alphabet[(block >> 18U) & 0x3FU];
            encoded[used++] = alphabet[(block >> 12U) & 0x3FU];
            encoded[used++] = has_second
                ? alphabet[(block >> 6U) & 0x3FU] : '=';
            encoded[used++] = has_third ? alphabet[block & 0x3FU] : '=';
        }
        if (!flush() || !emit(kBodyFilenamePrefix) ||
            !emit(filename_) || !emit(kBodySuffix)) {
            wipe_secret();
            return false;
        }
        wipe_secret();
        return true;
    } catch (...) {
        wipe_secret();
        throw;
    }
}

void NdmsNativeWireguardImportRequest::wipe_secret() noexcept {
    secure_wipe(canonical_conf_);
}

NdmsNativeWireguardImportRequest
make_ndms_native_wireguard_import_request(std::string&& raw_conf) {
    WipeStringGuard raw_guard(raw_conf);
    if (raw_conf.size() >
        kNdmsNativeWireguardImportRequestMaximumBytes) {
        throw NdmsNativeTunnelImportError(
            NdmsNativeTunnelImportErrorCode::input_too_large);
    }

    auto imported = parse_ndms_native_tunnel_import(raw_conf);
    if (imported.source !=
        NdmsNativeTunnelImportSource::wireguard_conf) {
        fail(NdmsNativeWireguardImportRequestErrorCode::
                 unsupported_source);
    }

    auto transaction_id = generate_transaction_id();
    auto marker = std::string{kNdmsNativeImportMarkerPrefix} +
                  transaction_id;
    auto filename = marker + ".conf";
    auto candidate_revision =
        build_ndms_native_tunnel_import_preview(imported).revision;
    auto canonical_conf = build_canonical_conf(imported, marker);
    WipeStringGuard canonical_guard(canonical_conf);
    return NdmsNativeWireguardImportRequest(
        std::move(canonical_conf),
        imported.kind,
        std::move(transaction_id),
        std::move(marker),
        std::move(filename),
        std::move(candidate_revision));
}

NdmsNativePanelDeleteSnapshot::NdmsNativePanelDeleteSnapshot(
    const NdmsNativeTunnelImportKind kind,
    std::string marker,
    std::string canonical_revision,
    const std::size_t preshared_key_count,
    const bool has_complete_awg_parameters,
    std::string sealed_payload) noexcept
    : kind_(kind),
      marker_(std::move(marker)),
      canonical_revision_(std::move(canonical_revision)),
      preshared_key_count_(preshared_key_count),
      has_complete_awg_parameters_(has_complete_awg_parameters) {
    sealed_payload_.swap(sealed_payload);
    secure_wipe(sealed_payload);
}

NdmsNativePanelDeleteSnapshot::NdmsNativePanelDeleteSnapshot(
    NdmsNativePanelDeleteSnapshot&& other) noexcept
    : kind_(other.kind_),
      marker_(std::move(other.marker_)),
      canonical_revision_(std::move(other.canonical_revision_)),
      preshared_key_count_(other.preshared_key_count_),
      has_complete_awg_parameters_(
          other.has_complete_awg_parameters_) {
    sealed_payload_.swap(other.sealed_payload_);
    other.wipe();
}

NdmsNativePanelDeleteSnapshot&
NdmsNativePanelDeleteSnapshot::operator=(
    NdmsNativePanelDeleteSnapshot&& other) noexcept {
    if (this == &other) {
        wipe();
        return *this;
    }
    wipe();
    kind_ = other.kind_;
    marker_ = std::move(other.marker_);
    canonical_revision_ = std::move(other.canonical_revision_);
    preshared_key_count_ = other.preshared_key_count_;
    has_complete_awg_parameters_ =
        other.has_complete_awg_parameters_;
    sealed_payload_.swap(other.sealed_payload_);
    other.wipe();
    return *this;
}

NdmsNativePanelDeleteSnapshot::~NdmsNativePanelDeleteSnapshot() {
    wipe();
}

NdmsNativeTunnelImportKind
NdmsNativePanelDeleteSnapshot::kind() const noexcept {
    return kind_;
}

std::string_view
NdmsNativePanelDeleteSnapshot::marker() const noexcept {
    return marker_;
}

std::string_view
NdmsNativePanelDeleteSnapshot::canonical_revision() const noexcept {
    return canonical_revision_;
}

std::size_t
NdmsNativePanelDeleteSnapshot::sealed_payload_bytes() const noexcept {
    return sealed_payload_.size();
}

std::size_t
NdmsNativePanelDeleteSnapshot::preshared_key_count() const noexcept {
    return preshared_key_count_;
}

bool NdmsNativePanelDeleteSnapshot::
has_complete_awg_parameters() const noexcept {
    return has_complete_awg_parameters_;
}

std::string_view
NdmsNativePanelDeleteSnapshot::sealed_payload_for_store() const noexcept {
    return sealed_payload_;
}

void NdmsNativePanelDeleteSnapshot::wipe() noexcept {
    secure_wipe(sealed_payload_);
    secure_wipe(marker_);
    secure_wipe(canonical_revision_);
    preshared_key_count_ = 0U;
    has_complete_awg_parameters_ = false;
}

NdmsNativePanelDeleteSnapshot make_ndms_native_panel_delete_snapshot(
    std::string&& raw_configuration,
    const std::string& ownership_marker) {
    WipeStringGuard raw_guard(raw_configuration);
    if (!valid_panel_delete_marker(ownership_marker)) {
        throw NdmsNativePanelDeleteSnapshotError(
            "panel delete snapshot ownership marker is invalid");
    }
    if (raw_configuration.size() >
        kNdmsNativeWireguardImportRequestMaximumBytes) {
        throw NdmsNativePanelDeleteSnapshotError(
            "panel delete snapshot configuration is too large");
    }

    auto imported =
        parse_ndms_native_tunnel_import(raw_configuration);
    if (imported.source !=
        NdmsNativeTunnelImportSource::wireguard_conf) {
        throw NdmsNativePanelDeleteSnapshotError(
            "panel delete snapshot must be a WG/AWG configuration");
    }
    const auto preview =
        build_ndms_native_tunnel_import_preview(imported);
    auto canonical =
        build_canonical_conf(imported, ownership_marker);
    WipeStringGuard canonical_guard(canonical);

    std::string payload;
    payload.reserve(
        kPanelDeleteSnapshotMagic.size() + canonical.size());
    payload.append(kPanelDeleteSnapshotMagic.data(),
                   kPanelDeleteSnapshotMagic.size());
    payload.append(canonical);
    WipeStringGuard payload_guard(payload);
    return NdmsNativePanelDeleteSnapshot{
        imported.kind,
        ownership_marker,
        preview.revision,
        preview.preshared_key_count,
        imported.kind ==
            NdmsNativeTunnelImportKind::amnezia_wireguard &&
            imported.awg.has_value(),
        std::move(payload)};
}

NdmsNativePanelDeleteSnapshot
NdmsNativePanelDeleteSnapshot::from_sealed_payload(
    std::string&& payload,
    const std::string& expected_marker) {
    WipeStringGuard payload_guard(payload);
    if (payload.size() <= kPanelDeleteSnapshotMagic.size() ||
        payload.size() >
            kPanelDeleteSnapshotMagic.size() +
                kNdmsNativeWireguardImportRequestMaximumBytes ||
        std::string_view(payload).substr(
            0U, kPanelDeleteSnapshotMagic.size()) !=
            kPanelDeleteSnapshotMagic) {
        throw NdmsNativePanelDeleteSnapshotError(
            "encrypted panel delete snapshot schema is invalid");
    }
    auto configuration = payload.substr(kPanelDeleteSnapshotMagic.size());
    WipeStringGuard configuration_guard(configuration);
    auto decoded = make_ndms_native_panel_delete_snapshot(
        std::move(configuration), expected_marker);
    if (decoded.sealed_payload_ != payload) {
        throw NdmsNativePanelDeleteSnapshotError(
            "encrypted panel delete snapshot is not canonical");
    }
    return decoded;
}

} // namespace keen_pbr3
