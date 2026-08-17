#include "dns_txt_client.hpp"

#include "../log/logger.hpp"

#include <algorithm>
#include <array>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <resolv.h>
#include <sys/socket.h>
#include <strings.h>
#include <sys/time.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#include "dns_server.hpp"
#include "legacy_resolver_lock.hpp"

namespace keen_pbr3 {

bool detail::dns_response_is_truncated(const unsigned char* packet, std::size_t size) {
    // DNS flags are the network-order bytes at offsets 2-3; TC is bit 9.
    return packet != nullptr && size >= NS_HFIXEDSZ && (packet[2] & 0x02U) != 0;
}

bool detail::dns_response_matches_query(const unsigned char* packet,
                                        std::size_t size,
                                        std::uint16_t transaction_id,
                                        const std::string& domain) {
    if (packet == nullptr || size < NS_HFIXEDSZ || size > static_cast<std::size_t>(INT_MAX)) {
        return false;
    }
    const std::uint16_t response_id =
        static_cast<std::uint16_t>((static_cast<std::uint16_t>(packet[0]) << 8U) | packet[1]);
    if (response_id != transaction_id || (packet[2] & 0x80U) == 0 ||
        (packet[2] & 0x78U) != 0 || (packet[3] & 0x0fU) != 0) {
        return false;
    }

    ns_msg handle {};
    if (ns_initparse(packet, static_cast<int>(size), &handle) < 0 ||
        ns_msg_count(handle, ns_s_qd) != 1) {
        return false;
    }
    ns_rr question {};
    if (ns_parserr(&handle, ns_s_qd, 0, &question) < 0 ||
        ns_rr_type(question) != ns_t_txt || ns_rr_class(question) != ns_c_in) {
        return false;
    }
    std::string expected = domain;
    if (!expected.empty() && expected.back() == '.') expected.pop_back();
    std::string actual = ns_rr_name(question);
    if (!actual.empty() && actual.back() == '.') actual.pop_back();
    return strcasecmp(actual.c_str(), expected.c_str()) == 0;
}

namespace {

constexpr const char* kDnsTxtAnswerNotFound = "DNS TXT answer not found";
constexpr std::size_t kMaxDnsTcpResponseSize = 16U * 1024U;

using DnsQueryDeadline = std::chrono::steady_clock::time_point;

bool configure_socket_deadline(int socket_fd,
                               DnsQueryDeadline deadline,
                               std::string* error_out) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
        if (error_out) *error_out = "DNS TXT query timed out";
        return false;
    }

    auto remaining =
        std::chrono::duration_cast<std::chrono::microseconds>(deadline - now);
    if (remaining.count() <= 0) {
        remaining = std::chrono::microseconds(1);
    }

    timeval socket_timeout {};
    socket_timeout.tv_sec = static_cast<time_t>(remaining.count() / 1000000);
    socket_timeout.tv_usec =
        static_cast<decltype(socket_timeout.tv_usec)>(remaining.count() % 1000000);
    if (setsockopt(socket_fd,
                   SOL_SOCKET,
                   SO_SNDTIMEO,
                   &socket_timeout,
                   sizeof(socket_timeout)) != 0 ||
        setsockopt(socket_fd,
                   SOL_SOCKET,
                   SO_RCVTIMEO,
                   &socket_timeout,
                   sizeof(socket_timeout)) != 0) {
        if (error_out) *error_out = "Failed to configure DNS socket timeout";
        return false;
    }
    return true;
}

bool send_all_before_deadline(int socket_fd,
                              const unsigned char* data,
                              std::size_t size,
                              DnsQueryDeadline deadline,
                              std::string* error_out) {
    std::size_t sent_total = 0;
    while (sent_total < size) {
        if (!configure_socket_deadline(socket_fd, deadline, error_out)) {
            return false;
        }
        const ssize_t sent =
            send(socket_fd, data + sent_total, size - sent_total, MSG_NOSIGNAL);
        if (sent > 0) {
            sent_total += static_cast<std::size_t>(sent);
            continue;
        }
        if (sent < 0 && errno == EINTR) {
            continue;
        }
        if (error_out) *error_out = "Failed to send DNS TXT query over TCP";
        return false;
    }
    return true;
}

bool receive_all_before_deadline(int socket_fd,
                                 unsigned char* data,
                                 std::size_t size,
                                 DnsQueryDeadline deadline,
                                 std::string* error_out) {
    std::size_t received_total = 0;
    while (received_total < size) {
        if (!configure_socket_deadline(socket_fd, deadline, error_out)) {
            return false;
        }
        const ssize_t received =
            recv(socket_fd, data + received_total, size - received_total, 0);
        if (received > 0) {
            received_total += static_cast<std::size_t>(received);
            continue;
        }
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (error_out) *error_out = received == 0
            ? "DNS TCP connection closed before the complete response"
            : "Failed to receive DNS TXT response over TCP";
        return false;
    }
    return true;
}

std::optional<std::vector<unsigned char>> query_dns_over_tcp(
    const sockaddr_in& resolver_addr,
    const unsigned char* query,
    std::size_t query_size,
    DnsQueryDeadline deadline,
    std::string* error_out) {
    if (query == nullptr || query_size == 0 || query_size > UINT16_MAX) {
        if (error_out) *error_out = "DNS TXT query is too large for TCP framing";
        return std::nullopt;
    }

    const int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        if (error_out) *error_out = "Failed to create DNS TCP socket";
        return std::nullopt;
    }
    const auto close_socket = [socket_fd]() { close(socket_fd); };

    if (!configure_socket_deadline(socket_fd, deadline, error_out)) {
        close_socket();
        return std::nullopt;
    }
    if (connect(socket_fd,
                reinterpret_cast<const sockaddr*>(&resolver_addr),
                sizeof(resolver_addr)) != 0) {
        if (error_out) *error_out = "Failed to connect DNS TCP socket";
        close_socket();
        return std::nullopt;
    }

    const auto query_size_u16 = static_cast<std::uint16_t>(query_size);
    const std::array<unsigned char, 2> query_prefix {
        static_cast<unsigned char>((query_size_u16 >> 8U) & 0xffU),
        static_cast<unsigned char>(query_size_u16 & 0xffU),
    };
    if (!send_all_before_deadline(
            socket_fd, query_prefix.data(), query_prefix.size(), deadline, error_out) ||
        !send_all_before_deadline(socket_fd, query, query_size, deadline, error_out)) {
        close_socket();
        return std::nullopt;
    }

    std::array<unsigned char, 2> response_prefix {};
    if (!receive_all_before_deadline(
            socket_fd, response_prefix.data(), response_prefix.size(), deadline, error_out)) {
        close_socket();
        return std::nullopt;
    }

    const std::size_t response_size =
        (static_cast<std::size_t>(response_prefix[0]) << 8U) |
        static_cast<std::size_t>(response_prefix[1]);
    if (response_size == 0) {
        if (error_out) *error_out = "DNS TCP response has an empty frame";
        close_socket();
        return std::nullopt;
    }
    if (response_size > kMaxDnsTcpResponseSize) {
        if (error_out) *error_out = "DNS TCP response exceeds the size limit";
        close_socket();
        return std::nullopt;
    }

    std::vector<unsigned char> response(response_size);
    if (!receive_all_before_deadline(
            socket_fd, response.data(), response.size(), deadline, error_out)) {
        close_socket();
        return std::nullopt;
    }

    close_socket();
    return response;
}

bool is_hex_char(char c) {
    return std::isxdigit(static_cast<unsigned char>(c)) != 0;
}

std::string trim_copy(const std::string& s) {
    size_t begin = 0;
    while (begin < s.size() && std::isspace(static_cast<unsigned char>(s[begin])) != 0) {
        ++begin;
    }
    size_t end = s.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(s[end - 1])) != 0) {
        --end;
    }
    return s.substr(begin, end - begin);
}

std::string strip_balanced_quotes(std::string value) {
    value = trim_copy(value);
    while (value.size() >= 2) {
        const char first = value.front();
        const char last = value.back();
        const bool wrapped_by_double = (first == '"' && last == '"');
        const bool wrapped_by_single = (first == '\'' && last == '\'');
        if (!wrapped_by_double && !wrapped_by_single) {
            break;
        }
        value = trim_copy(value.substr(1, value.size() - 2));
    }
    return value;
}

std::optional<std::string> parse_first_txt_answer(const unsigned char* response,
                                                  int response_len,
                                                  std::string* error_out) {
    ns_msg handle {};
    if (ns_initparse(response, response_len, &handle) < 0) {
        if (error_out) *error_out = "Failed to parse DNS response";
        return std::nullopt;
    }

    const int answer_count = ns_msg_count(handle, ns_s_an);
    std::optional<std::string> first_txt;
    std::optional<std::string> latest_ts_txt;
    std::optional<std::int64_t> latest_ts_value;
    std::vector<std::string> txt_records_log_lines;

    for (int i = 0; i < answer_count; ++i) {
        ns_rr rr {};
        if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) {
            continue;
        }
        if (ns_rr_type(rr) != ns_t_txt || ns_rr_class(rr) != ns_c_in) {
            continue;
        }

        const unsigned char* rdata = ns_rr_rdata(rr);
        const int rdlen = ns_rr_rdlen(rr);
        if (rdlen <= 0) {
            continue;
        }

        std::string txt;
        int offset = 0;
        while (offset < rdlen) {
            const unsigned char chunk_len = rdata[offset++];
            if (offset + chunk_len > rdlen) {
                if (error_out) *error_out = "DNS TXT chunk truncated";
                return std::nullopt;
            }
            txt.append(reinterpret_cast<const char*>(rdata + offset), chunk_len);
            offset += chunk_len;
        }

        if (!first_txt.has_value()) {
            first_txt = txt;
        }

        const ResolverConfigHashTxtValue parsed = parse_resolver_config_hash_txt(txt);
        txt_records_log_lines.push_back(
            std::string("#") + std::to_string(i) + " txt=\"" + txt +
            "\" ts=" + (parsed.ts.has_value() ? std::to_string(*parsed.ts) : "none") +
            " hash=" + parsed.hash);
        if (parsed.ts.has_value() &&
            (!latest_ts_value.has_value() || *parsed.ts > *latest_ts_value)) {
            latest_ts_value = parsed.ts;
            latest_ts_txt = txt;
        }
    }

    if (!txt_records_log_lines.empty()) {
        std::string records_joined;
        for (size_t i = 0; i < txt_records_log_lines.size(); ++i) {
            if (i > 0) {
                records_joined += " ; ";
            }
            records_joined += txt_records_log_lines[i];
        }
        Logger::instance().verbose("Resolver TXT answers: {}", records_joined);
    } else {
        Logger::instance().verbose("Resolver TXT answers: <none>");
    }

    if (latest_ts_txt.has_value()) {
        const ResolverConfigHashTxtValue parsed = parse_resolver_config_hash_txt(*latest_ts_txt);
        Logger::instance().verbose("Resolver TXT selected by latest ts: txt=\"{}\" ts={} hash={}",
                                   *latest_ts_txt,
                                   parsed.ts.has_value() ? std::to_string(*parsed.ts) : "none",
                                   parsed.hash);
        return latest_ts_txt;
    }
    if (first_txt.has_value()) {
        const ResolverConfigHashTxtValue parsed = parse_resolver_config_hash_txt(*first_txt);
        Logger::instance().verbose("Resolver TXT selected by first answer: txt=\"{}\" ts={} hash={}",
                                   *first_txt,
                                   parsed.ts.has_value() ? std::to_string(*parsed.ts) : "none",
                                   parsed.hash);
        return first_txt;
    }

    if (error_out) *error_out = kDnsTxtAnswerNotFound;
    return std::nullopt;
}

} // namespace

std::optional<std::string> query_dns_txt_record(const std::string& dns_server_address,
                                                const std::string& domain,
                                                std::chrono::milliseconds timeout,
                                                std::string* error_out) {
    const auto started_at = std::chrono::steady_clock::now();
    const auto timeout_ms = std::chrono::milliseconds(std::max<int64_t>(1, timeout.count()));
    const auto deadline = started_at + timeout_ms;
    Logger::instance().trace("dns_txt_query_start",
                             "resolver={} domain={} timeout_ms={}",
                             dns_server_address,
                             domain,
                             timeout.count());
    if (domain.empty()) {
        if (error_out) *error_out = "DNS TXT query domain is empty";
        Logger::instance().trace("dns_txt_query_error",
                                 "resolver={} domain={} duration_ms={} error=empty_domain",
                                 dns_server_address,
                                 domain,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started_at).count());
        return std::nullopt;
    }

    ParsedDnsAddress parsed_server = parse_dns_address_str(dns_server_address);

    if (parsed_server.ip.find(':') != std::string::npos) {
        if (error_out) *error_out = "IPv6 resolver addresses are not supported by this resolver backend";
        Logger::instance().trace("dns_txt_query_error",
                                 "resolver={} domain={} duration_ms={} error=ipv6_unsupported",
                                 dns_server_address,
                                 domain,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started_at).count());
        return std::nullopt;
    }

    sockaddr_in resolver_addr {};
    resolver_addr.sin_family = AF_INET;
    resolver_addr.sin_port = htons(parsed_server.port);
    if (inet_pton(AF_INET, parsed_server.ip.c_str(), &resolver_addr.sin_addr) != 1) {
        if (error_out) *error_out = "Invalid IPv4 DNS resolver address";
        Logger::instance().trace("dns_txt_query_error",
                                 "resolver={} domain={} duration_ms={} error=invalid_ipv4",
                                 dns_server_address,
                                 domain,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started_at).count());
        return std::nullopt;
    }

    std::array<unsigned char, NS_PACKETSZ * 2> query {};
    int query_len = -1;
    {
        // res_mkquery() builds the packet using the global _res; serialize it.
        std::lock_guard<std::mutex> resolver_lock(legacy_resolver_mutex());
        query_len = res_mkquery(ns_o_query,
                                domain.c_str(),
                                ns_c_in,
                                ns_t_txt,
                                nullptr,
                                0,
                                nullptr,
                                query.data(),
                                static_cast<int>(query.size()));
    }
    if (query_len < 0) {
        if (error_out) *error_out = "Failed to build DNS TXT query";
        Logger::instance().trace("dns_txt_query_error",
                                 "resolver={} domain={} duration_ms={} error=build_query_failed",
                                 dns_server_address,
                                 domain,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started_at).count());
        return std::nullopt;
    }

    const int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        if (error_out) *error_out = "Failed to create DNS socket";
        Logger::instance().trace("dns_txt_query_error",
                                 "resolver={} domain={} duration_ms={} error=socket_failed",
                                 dns_server_address,
                                 domain,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started_at).count());
        return std::nullopt;
    }
    const auto close_socket = [socket_fd]() { close(socket_fd); };

    if (connect(socket_fd,
                reinterpret_cast<const sockaddr*>(&resolver_addr),
                sizeof(resolver_addr)) != 0) {
        if (error_out) *error_out = "Failed to connect DNS socket";
        close_socket();
        return std::nullopt;
    }

    if (!configure_socket_deadline(socket_fd, deadline, error_out)) {
        Logger::instance().trace("dns_txt_query_error",
                                 "resolver={} domain={} duration_ms={} error=setsockopt_failed",
                                 dns_server_address,
                                 domain,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started_at).count());
        close_socket();
        return std::nullopt;
    }

    std::array<unsigned char, NS_PACKETSZ * 8> response {};
    const ssize_t sent = send(socket_fd, query.data(), static_cast<size_t>(query_len), 0);
    if (sent != static_cast<ssize_t>(query_len)) {
        if (error_out) *error_out = "Failed to send DNS TXT query";
        Logger::instance().trace("dns_txt_query_error",
                                 "resolver={} domain={} duration_ms={} error=send_failed",
                                 dns_server_address,
                                 domain,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started_at).count());
        close_socket();
        return std::nullopt;
    }

    const ssize_t response_len = recv(socket_fd, response.data(), response.size(), 0);
    if (response_len <= 0) {
        if (error_out) *error_out = "DNS TXT query failed";
        Logger::instance().trace("dns_txt_query_error",
                                 "resolver={} domain={} duration_ms={} error=recv_failed",
                                 dns_server_address,
                                 domain,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started_at).count());
        close_socket();
        return std::nullopt;
    }

    const std::uint16_t query_id = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(query[0]) << 8U) | query[1]);
    if (!detail::dns_response_matches_query(response.data(),
                                            static_cast<std::size_t>(response_len),
                                            query_id,
                                            domain)) {
        if (error_out) *error_out = "DNS TXT response did not match query";
        close_socket();
        return std::nullopt;
    }

    const bool udp_response_truncated =
        detail::dns_response_is_truncated(response.data(),
                                          static_cast<std::size_t>(response_len));
    close_socket();

    const unsigned char* final_response = response.data();
    std::size_t final_response_size = static_cast<std::size_t>(response_len);
    std::vector<unsigned char> tcp_response;
    bool used_tcp = false;

    if (udp_response_truncated) {
        Logger::instance().trace("dns_txt_tcp_fallback_start",
                                 "resolver={} domain={} udp_bytes={}",
                                 dns_server_address,
                                 domain,
                                 response_len);
        auto fallback = query_dns_over_tcp(resolver_addr,
                                           query.data(),
                                           static_cast<std::size_t>(query_len),
                                           deadline,
                                           error_out);
        if (!fallback.has_value()) {
            Logger::instance().trace(
                "dns_txt_query_error",
                "resolver={} domain={} duration_ms={} error=tcp_fallback_failed",
                dns_server_address,
                domain,
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - started_at).count());
            return std::nullopt;
        }
        tcp_response = std::move(*fallback);
        final_response = tcp_response.data();
        final_response_size = tcp_response.size();
        used_tcp = true;

        if (detail::dns_response_is_truncated(final_response, final_response_size)) {
            if (error_out) *error_out = "DNS TXT response remained truncated over TCP";
            return std::nullopt;
        }
        if (!detail::dns_response_matches_query(
                final_response, final_response_size, query_id, domain)) {
            if (error_out) *error_out = "DNS TCP response did not match query";
            return std::nullopt;
        }
    }

    auto result = parse_first_txt_answer(
        final_response, static_cast<int>(final_response_size), error_out);
    Logger::instance().trace(result.has_value() ? "dns_txt_query_end" : "dns_txt_query_error",
                             "resolver={} domain={} duration_ms={} bytes={} transport={} success={}",
                             dns_server_address,
                             domain,
                             std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - started_at).count(),
                             final_response_size,
                             used_tcp ? "tcp" : "udp",
                             result.has_value() ? "true" : "false");
    return result;
}

std::string normalize_dns_txt_md5(const std::string& txt_payload) {
    std::string normalized = trim_copy(txt_payload);

    while (normalized.size() >= 2) {
        const char first = normalized.front();
        const char last = normalized.back();
        const bool wrapped_by_double = (first == '"' && last == '"');
        const bool wrapped_by_single = (first == '\'' && last == '\'');
        if (!wrapped_by_double && !wrapped_by_single) {
            break;
        }
        normalized = trim_copy(normalized.substr(1, normalized.size() - 2));
    }

    std::string compact;
    compact.reserve(normalized.size());
    for (char c : normalized) {
        if (c == '"' || c == '\'' || std::isspace(static_cast<unsigned char>(c)) != 0) {
            continue;
        }
        compact.push_back(c);
    }

    const std::string md5_prefix = "md5=";
    if (compact.size() > md5_prefix.size()) {
        std::string lower_prefix = compact.substr(0, md5_prefix.size());
        std::transform(lower_prefix.begin(), lower_prefix.end(), lower_prefix.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lower_prefix == md5_prefix) {
            compact = compact.substr(md5_prefix.size());
        }
    }

    std::string hex_only;
    hex_only.reserve(compact.size());
    for (char c : compact) {
        if (is_hex_char(c)) {
            hex_only.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
    }
    if (hex_only.size() == 32) {
        return hex_only;
    }

    return compact;
}

ResolverConfigHashTxtValue parse_resolver_config_hash_txt(const std::string& txt_payload) {
    ResolverConfigHashTxtValue value;
    const std::string normalized = strip_balanced_quotes(txt_payload);

    const size_t delimiter = normalized.find('|');
    if (delimiter == std::string::npos) {
        value.hash = normalize_dns_txt_md5(normalized);
        return value;
    }

    const std::string ts_part = trim_copy(normalized.substr(0, delimiter));
    const std::string hash_part = trim_copy(normalized.substr(delimiter + 1));
    value.hash = normalize_dns_txt_md5(hash_part);

    if (!ts_part.empty() &&
        std::all_of(ts_part.begin(), ts_part.end(), [](unsigned char c) {
            return std::isdigit(c) != 0;
        })) {
        try {
            value.ts = std::stoll(ts_part);
        } catch (...) {
            value.ts = std::nullopt;
        }
    }

    return value;
}

ResolverStateTxtValue parse_resolver_state_txt(const std::string& txt_payload) {
    ResolverStateTxtValue value;
    const std::string normalized = strip_balanced_quotes(txt_payload);

    const size_t timestamp_delimiter = normalized.find('|');
    if (timestamp_delimiter == std::string::npos) {
        return value;
    }
    const size_t mode_delimiter =
        normalized.find('|', timestamp_delimiter + 1);

    const std::string ts_part =
        trim_copy(normalized.substr(0, timestamp_delimiter));
    const std::string mode_part = trim_copy(normalized.substr(
        timestamp_delimiter + 1,
        mode_delimiter == std::string::npos
            ? std::string::npos
            : mode_delimiter - timestamp_delimiter - 1));

    if (!ts_part.empty() &&
        std::all_of(ts_part.begin(), ts_part.end(), [](unsigned char c) {
            return std::isdigit(c) != 0;
        })) {
        try {
            value.ts = std::stoll(ts_part);
        } catch (...) {
            value.ts = std::nullopt;
        }
    }

    if (mode_part == "active") {
        value.mode = ResolverRuntimeMode::ACTIVE;
    } else if (mode_part == "fallback") {
        value.mode = ResolverRuntimeMode::FALLBACK;
    }

    if (mode_delimiter != std::string::npos) {
        value.reason = trim_copy(normalized.substr(mode_delimiter + 1));
    }

    return value;
}

bool is_valid_resolver_config_hash_txt_value(const ResolverConfigHashTxtValue& value) {
    if (value.hash.size() != 32) {
        return false;
    }
    return std::all_of(value.hash.begin(), value.hash.end(), [](unsigned char c) {
        return std::isxdigit(c) != 0;
    });
}

namespace {

// A dropped datagram and a dnsmasq that is mid-reload both look like this, and
// neither means the configuration is stale. An answer that parses but carries
// the wrong payload does mean something, so it is not retried.
bool is_transient_probe_status(ResolverConfigHashProbeStatus status) {
    return status == ResolverConfigHashProbeStatus::QUERY_FAILED ||
           status == ResolverConfigHashProbeStatus::NO_USABLE_TXT;
}

ResolverConfigHashProbeResult query_resolver_config_hash_txt_once(
    const std::string& dns_server_address,
    const std::string& domain,
    std::chrono::milliseconds timeout) {
    ResolverConfigHashProbeResult result;
    try {
        auto txt = query_dns_txt_record(dns_server_address, domain, timeout, &result.error);
        if (!txt.has_value()) {
            result.status = (result.error == kDnsTxtAnswerNotFound)
                ? ResolverConfigHashProbeStatus::NO_USABLE_TXT
                : ResolverConfigHashProbeStatus::QUERY_FAILED;
            return result;
        }

        result.raw_txt = *txt;
        result.parsed_value = parse_resolver_config_hash_txt(*txt);
        result.status = is_valid_resolver_config_hash_txt_value(result.parsed_value)
            ? ResolverConfigHashProbeStatus::SUCCESS
            : ResolverConfigHashProbeStatus::INVALID_TXT;
        if (result.status == ResolverConfigHashProbeStatus::INVALID_TXT) {
            result.error = "Resolver TXT payload is missing a valid md5 hash";
        }
        return result;
    } catch (const std::exception& e) {
        result.status = ResolverConfigHashProbeStatus::QUERY_FAILED;
        result.error = e.what();
        return result;
    }
}

} // namespace

ResolverConfigHashProbeResult query_resolver_config_hash_txt(
    const std::string& dns_server_address,
    const std::string& domain,
    std::chrono::milliseconds timeout,
    int attempts,
    std::chrono::milliseconds retry_delay) {
    ResolverConfigHashProbeResult result;
    std::optional<ResolverConfigHashProbeResult> last_negative_response;

    for (int attempt = 1; attempt <= std::max(1, attempts); ++attempt) {
        result = query_resolver_config_hash_txt_once(dns_server_address, domain, timeout);
        if (!is_transient_probe_status(result.status)) {
            return result;
        }
        // A syntactically valid DNS response without a usable TXT record is
        // stronger evidence than a later dropped datagram. Keep retrying in
        // case dnsmasq is mid-reload, but do not replace the valid negative
        // response with QUERY_FAILED merely because a retry timed out.
        if (result.status == ResolverConfigHashProbeStatus::NO_USABLE_TXT) {
            last_negative_response = result;
        }
        if (attempt < attempts) {
            Logger::instance().trace("resolver_hash_probe_retry",
                                     "resolver={} domain={} attempt={} status=transient",
                                     dns_server_address,
                                     domain,
                                     attempt);
            std::this_thread::sleep_for(retry_delay);
        }
    }

    return last_negative_response.value_or(result);
}

} // namespace keen_pbr3
