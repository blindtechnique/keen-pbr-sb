#include "conntrack_manager.hpp"

#include "../util/safe_exec.hpp"

#include <algorithm>
#include <array>
#include <arpa/inet.h>
#include <charconv>
#include <chrono>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>
#include <tuple>
#include <utility>

namespace keen_pbr3 {

namespace {

bool is_empty_delete_result(const ConntrackManager::CommandResult& result) {
    // conntrack exits with status 1 when the selector matches no flows.
    // Cleanup is intentionally idempotent, so an already-empty family is
    // success rather than a best-effort cleanup failure.
    return result.exit_code == 1 &&
           result.output.find("0 flow entries have been deleted") !=
               std::string::npos;
}

std::string trim_ascii_whitespace(std::string_view value) {
    constexpr std::string_view whitespace{" \t\r\n"};
    const auto first = value.find_first_not_of(whitespace);
    if (first == std::string_view::npos) {
        return {};
    }
    const auto last = value.find_last_not_of(whitespace);
    return std::string{value.substr(first, last - first + 1U)};
}

enum class TargetAddressFamily {
    Ipv4,
    Ipv6,
};

struct NormalizedTargetCidr {
    TargetAddressFamily family{TargetAddressFamily::Ipv4};
    std::string value;
    std::array<unsigned char, 16> network{};
    unsigned int prefix{0};
};

std::optional<NormalizedTargetCidr> normalize_targeted_cidr(
    std::string_view raw) {
    const std::string cidr = trim_ascii_whitespace(raw);
    if (cidr.empty()) {
        return std::nullopt;
    }

    const auto slash = cidr.find('/');
    if (slash != std::string::npos &&
        cidr.find('/', slash + 1U) != std::string::npos) {
        return std::nullopt;
    }
    const std::string ip =
        slash == std::string::npos ? cidr : cidr.substr(0, slash);
    const bool ipv6 = ip.find(':') != std::string::npos;
    const int address_family = ipv6 ? AF_INET6 : AF_INET;
    const int max_prefix = ipv6 ? 128 : 32;
    int prefix = max_prefix;
    if (slash != std::string::npos) {
        const std::string_view prefix_text{
            cidr.data() + slash + 1U,
            cidr.size() - slash - 1U};
        if (prefix_text.empty()) {
            return std::nullopt;
        }
        const auto [end, error] = std::from_chars(
            prefix_text.data(),
            prefix_text.data() + prefix_text.size(),
            prefix);
        if (error != std::errc{} ||
            end != prefix_text.data() + prefix_text.size()) {
            return std::nullopt;
        }
    }
    // /0 would select every flow in the address family and is deliberately
    // outside the contract of this targeted cleanup API.
    if (prefix <= 0 || prefix > max_prefix) {
        return std::nullopt;
    }

    if (!ipv6) {
        in_addr address{};
        if (::inet_pton(address_family, ip.c_str(), &address) != 1) {
            return std::nullopt;
        }
        const std::uint32_t mask =
            prefix == 32
                ? std::numeric_limits<std::uint32_t>::max()
                : std::numeric_limits<std::uint32_t>::max()
                      << (32 - prefix);
        address.s_addr = ::htonl(::ntohl(address.s_addr) & mask);

        char normalized[INET_ADDRSTRLEN]{};
        if (::inet_ntop(
                address_family,
                &address,
                normalized,
                sizeof(normalized)) == nullptr) {
            return std::nullopt;
        }
        NormalizedTargetCidr result;
        result.family = TargetAddressFamily::Ipv4;
        result.value =
            std::string{normalized} + "/" + std::to_string(prefix);
        std::copy_n(
            reinterpret_cast<const unsigned char*>(&address),
            sizeof(address),
            result.network.begin());
        result.prefix = static_cast<unsigned int>(prefix);
        return result;
    }

    in6_addr address{};
    if (::inet_pton(address_family, ip.c_str(), &address) != 1) {
        return std::nullopt;
    }
    const std::size_t complete_bytes =
        static_cast<std::size_t>(prefix / 8);
    const unsigned int remaining_bits =
        static_cast<unsigned int>(prefix % 8);
    std::size_t first_zero_byte = complete_bytes;
    if (remaining_bits != 0U) {
        const auto mask = static_cast<unsigned char>(
            0xFFU << (8U - remaining_bits));
        address.s6_addr[complete_bytes] &= mask;
        first_zero_byte = complete_bytes + 1U;
    }
    std::fill(
        address.s6_addr + first_zero_byte,
        address.s6_addr + sizeof(address.s6_addr),
        0U);

    char normalized[INET6_ADDRSTRLEN]{};
    if (::inet_ntop(
            address_family,
            &address,
            normalized,
            sizeof(normalized)) == nullptr) {
        return std::nullopt;
    }
    NormalizedTargetCidr result;
    result.family = TargetAddressFamily::Ipv6;
    result.value =
        std::string{normalized} + "/" + std::to_string(prefix);
    std::copy_n(address.s6_addr, sizeof(address.s6_addr), result.network.begin());
    result.prefix = static_cast<unsigned int>(prefix);
    return result;
}

std::optional<std::string> normalize_targeted_ipv4_cidr(
    std::string_view raw) {
    const auto normalized = normalize_targeted_cidr(raw);
    if (!normalized.has_value() ||
        normalized->family != TargetAddressFamily::Ipv4) {
        return std::nullopt;
    }
    return normalized->value;
}

struct NormalizedHostAddress {
    TargetAddressFamily family{TargetAddressFamily::Ipv4};
    std::string value;
    std::array<unsigned char, 16> bytes{};
};

std::optional<NormalizedHostAddress> normalize_host_address(
    std::string_view raw) {
    std::string value = trim_ascii_whitespace(raw);
    const auto slash = value.find('/');
    if (slash != std::string::npos) {
        value.resize(slash);
    }
    if (value.empty()) {
        return std::nullopt;
    }

    const bool ipv6 = value.find(':') != std::string::npos;
    const int family = ipv6 ? AF_INET6 : AF_INET;
    std::array<unsigned char, 16> bytes{};
    if (::inet_pton(family, value.c_str(), bytes.data()) != 1) {
        return std::nullopt;
    }
    char normalized[INET6_ADDRSTRLEN]{};
    if (::inet_ntop(family, bytes.data(), normalized, sizeof(normalized)) ==
        nullptr) {
        return std::nullopt;
    }
    return NormalizedHostAddress{
        ipv6 ? TargetAddressFamily::Ipv6 : TargetAddressFamily::Ipv4,
        normalized,
        bytes};
}

bool cidr_contains(const NormalizedTargetCidr& cidr,
                   const NormalizedHostAddress& host) noexcept {
    if (cidr.family != host.family) {
        return false;
    }
    const std::size_t byte_count =
        cidr.family == TargetAddressFamily::Ipv6 ? 16U : 4U;
    const std::size_t complete_bytes = cidr.prefix / 8U;
    const unsigned int remaining_bits = cidr.prefix % 8U;
    if (!std::equal(cidr.network.begin(),
                    cidr.network.begin() +
                        static_cast<std::ptrdiff_t>(complete_bytes),
                    host.bytes.begin())) {
        return false;
    }
    if (remaining_bits == 0U || complete_bytes >= byte_count) {
        return true;
    }
    const auto mask = static_cast<unsigned char>(
        0xFFU << (8U - remaining_bits));
    return (cidr.network[complete_bytes] & mask) ==
           (host.bytes[complete_bytes] & mask);
}

std::optional<std::uint32_t> parse_explicit_conntrack_mark(
    std::string_view value) {
    if (value.empty()) {
        return std::nullopt;
    }
    std::uint32_t mark = 0;
    const int base = value.size() > 2U && value[0] == '0' &&
            (value[1] == 'x' || value[1] == 'X')
        ? 16
        : 10;
    if (base == 16) {
        value.remove_prefix(2U);
        if (value.empty()) {
            return std::nullopt;
        }
    }
    const auto [end, error] = std::from_chars(
        value.data(), value.data() + value.size(), mark, base);
    if (error != std::errc{} || end != value.data() + value.size()) {
        return std::nullopt;
    }
    return mark;
}

struct ParsedConntrackOriginalPair {
    NormalizedHostAddress source;
    NormalizedHostAddress destination;
    std::uint32_t mark{0};
};

struct NormalizedForwardedDestinationSelector {
    NormalizedTargetCidr cidr;
    bool allow_unmarked{false};
    bool allow_owned_mark{false};
};

std::optional<ParsedConntrackOriginalPair> parse_conntrack_original_pair(
    std::string_view line) {
    std::istringstream stream(std::string{line});
    std::string token;
    std::string family_token;
    if (!(stream >> family_token) ||
        (family_token != "ipv4" && family_token != "ipv6")) {
        return std::nullopt;
    }
    std::optional<NormalizedHostAddress> source;
    std::optional<NormalizedHostAddress> destination;
    std::optional<std::uint32_t> mark;
    while (stream >> token) {
        if (token.rfind("src=", 0) == 0U && !destination.has_value()) {
            if (source.has_value()) {
                return std::nullopt;
            }
            const auto raw_source = std::string_view{token}.substr(4U);
            if (raw_source.find('/') != std::string_view::npos) {
                return std::nullopt;
            }
            source = normalize_host_address(
                raw_source);
            if (!source.has_value()) {
                return std::nullopt;
            }
            continue;
        }
        if (token.rfind("dst=", 0) == 0U && !destination.has_value()) {
            if (!source.has_value()) {
                return std::nullopt;
            }
            const auto raw_destination =
                std::string_view{token}.substr(4U);
            if (raw_destination.find('/') != std::string_view::npos) {
                return std::nullopt;
            }
            destination = normalize_host_address(
                raw_destination);
            if (!destination.has_value()) {
                return std::nullopt;
            }
            continue;
        }
        if (token.rfind("mark=", 0) == 0U) {
            if (mark.has_value()) {
                return std::nullopt;
            }
            mark = parse_explicit_conntrack_mark(
                std::string_view{token}.substr(5U));
            if (!mark.has_value()) {
                return std::nullopt;
            }
        }
    }
    if (!source.has_value() || !destination.has_value() ||
        !mark.has_value() || source->family != destination->family) {
        return std::nullopt;
    }
    const bool parsed_ipv6 =
        source->family == TargetAddressFamily::Ipv6;
    if ((family_token == "ipv6") != parsed_ipv6) {
        return std::nullopt;
    }
    return ParsedConntrackOriginalPair{
        *source, *destination, *mark};
}

template <typename Integer>
std::optional<Integer> parse_unsigned_decimal(std::string_view value) {
    if (value.empty()) {
        return std::nullopt;
    }
    Integer parsed{};
    const auto [end, error] = std::from_chars(
        value.data(), value.data() + value.size(), parsed, 10);
    if (error != std::errc{} || end != value.data() + value.size()) {
        return std::nullopt;
    }
    return parsed;
}

std::optional<ConntrackTcpState> parse_conntrack_tcp_state(
    std::string_view value) {
    static constexpr std::array<std::pair<std::string_view, ConntrackTcpState>,
                                13>
        states{{
            {"NONE", ConntrackTcpState::None},
            {"SYN_SENT", ConntrackTcpState::SynSent},
            {"SYN_RECV", ConntrackTcpState::SynRecv},
            {"ESTABLISHED", ConntrackTcpState::Established},
            {"FIN_WAIT", ConntrackTcpState::FinWait},
            {"CLOSE_WAIT", ConntrackTcpState::CloseWait},
            {"LAST_ACK", ConntrackTcpState::LastAck},
            {"TIME_WAIT", ConntrackTcpState::TimeWait},
            {"CLOSE", ConntrackTcpState::Close},
            {"LISTEN", ConntrackTcpState::Listen},
            {"SYN_SENT2", ConntrackTcpState::SynSent2},
            {"RETRANS", ConntrackTcpState::Retrans},
            {"UNACK", ConntrackTcpState::Unack},
        }};
    const auto state = std::find_if(
        states.begin(), states.end(),
        [value](const auto& candidate) { return candidate.first == value; });
    if (state == states.end()) {
        return std::nullopt;
    }
    return state->second;
}

struct ParsedConntrackTupleCounters {
    NormalizedHostAddress source;
    NormalizedHostAddress destination;
    std::uint16_t source_port{0};
    std::uint16_t destination_port{0};
    ConntrackFlowCounters counters;
};

struct ParsedExactConntrackFlow {
    ConntrackFlowFamily family{ConntrackFlowFamily::Ipv4};
    ConntrackFlowProtocol protocol{ConntrackFlowProtocol::Tcp};
    ParsedConntrackTupleCounters original;
    ParsedConntrackTupleCounters reply;
    std::uint32_t mark{0};
    std::optional<ConntrackTcpState> tcp_state;
    bool assured{false};
    bool seen_reply{false};
    bool fastnat{false};
};

std::optional<ParsedExactConntrackFlow> parse_exact_conntrack_flow(
    std::string_view line) {
    std::istringstream stream(std::string{line});
    std::string family_token;
    std::string family_number_token;
    std::string protocol_token;
    std::string protocol_number_token;
    std::string timeout_token;
    if (!(stream >> family_token >> family_number_token >> protocol_token >>
          protocol_number_token >> timeout_token)) {
        return std::nullopt;
    }

    ConntrackFlowFamily family;
    unsigned int expected_family_number = 0U;
    if (family_token == "ipv4") {
        family = ConntrackFlowFamily::Ipv4;
        expected_family_number = static_cast<unsigned int>(AF_INET);
    } else if (family_token == "ipv6") {
        family = ConntrackFlowFamily::Ipv6;
        expected_family_number = static_cast<unsigned int>(AF_INET6);
    } else {
        return std::nullopt;
    }
    const auto family_number =
        parse_unsigned_decimal<unsigned int>(family_number_token);
    const auto protocol_number =
        parse_unsigned_decimal<unsigned int>(protocol_number_token);
    const auto timeout = parse_unsigned_decimal<std::uint64_t>(timeout_token);
    if (!family_number.has_value() ||
        *family_number != expected_family_number ||
        !protocol_number.has_value() || !timeout.has_value()) {
        return std::nullopt;
    }

    ConntrackFlowProtocol protocol;
    std::optional<ConntrackTcpState> tcp_state;
    if (protocol_token == "tcp" && *protocol_number == 6U) {
        protocol = ConntrackFlowProtocol::Tcp;
        std::string state_token;
        if (!(stream >> state_token)) {
            return std::nullopt;
        }
        tcp_state = parse_conntrack_tcp_state(state_token);
        if (!tcp_state.has_value()) {
            return std::nullopt;
        }
    } else if (protocol_token == "udp" && *protocol_number == 17U) {
        protocol = ConntrackFlowProtocol::Udp;
    } else {
        return std::nullopt;
    }

    struct TupleBuilder {
        std::optional<NormalizedHostAddress> source;
        std::optional<NormalizedHostAddress> destination;
        std::optional<std::uint16_t> source_port;
        std::optional<std::uint16_t> destination_port;
        std::optional<std::uint64_t> packets;
        std::optional<std::uint64_t> bytes;
    };
    TupleBuilder original;
    TupleBuilder reply;
    constexpr std::array<std::string_view, 6> tuple_fields{
        "src", "dst", "sport", "dport", "packets", "bytes"};
    std::size_t tuple_field_index = 0U;
    std::optional<std::uint32_t> mark;
    bool assured = false;
    bool unreplied = false;
    bool explicit_seen_reply = false;
    bool fastnat = false;
    std::string token;
    while (stream >> token) {
        if (token == "[ASSURED]") {
            assured = true;
            continue;
        }
        if (token == "[UNREPLIED]") {
            unreplied = true;
            continue;
        }
        if (token == "[SEEN_REPLY]") {
            explicit_seen_reply = true;
            continue;
        }
        if (token == "[FASTNAT]") {
            fastnat = true;
            continue;
        }

        const auto equals = token.find('=');
        if (equals == std::string::npos) {
            continue;
        }
        const std::string_view key{token.data(), equals};
        const std::string_view value{
            token.data() + equals + 1U,
            token.size() - equals - 1U};
        if (key == "mark") {
            if (tuple_field_index != tuple_fields.size() * 2U ||
                mark.has_value()) {
                return std::nullopt;
            }
            mark = parse_explicit_conntrack_mark(value);
            if (!mark.has_value()) {
                return std::nullopt;
            }
            continue;
        }

        const auto recognized = std::find(
            tuple_fields.begin(), tuple_fields.end(), key);
        if (recognized == tuple_fields.end()) {
            continue;
        }
        if (tuple_field_index >= tuple_fields.size() * 2U ||
            key != tuple_fields[tuple_field_index % tuple_fields.size()]) {
            return std::nullopt;
        }
        TupleBuilder& tuple = tuple_field_index < tuple_fields.size()
            ? original
            : reply;
        switch (tuple_field_index % tuple_fields.size()) {
        case 0U:
            if (value.find('/') != std::string_view::npos) {
                return std::nullopt;
            }
            tuple.source = normalize_host_address(value);
            if (!tuple.source.has_value()) {
                return std::nullopt;
            }
            break;
        case 1U:
            if (value.find('/') != std::string_view::npos) {
                return std::nullopt;
            }
            tuple.destination = normalize_host_address(value);
            if (!tuple.destination.has_value()) {
                return std::nullopt;
            }
            break;
        case 2U:
            tuple.source_port =
                parse_unsigned_decimal<std::uint16_t>(value);
            if (!tuple.source_port.has_value()) {
                return std::nullopt;
            }
            break;
        case 3U:
            tuple.destination_port =
                parse_unsigned_decimal<std::uint16_t>(value);
            if (!tuple.destination_port.has_value()) {
                return std::nullopt;
            }
            break;
        case 4U:
            tuple.packets = parse_unsigned_decimal<std::uint64_t>(value);
            if (!tuple.packets.has_value()) {
                return std::nullopt;
            }
            break;
        case 5U:
            tuple.bytes = parse_unsigned_decimal<std::uint64_t>(value);
            if (!tuple.bytes.has_value()) {
                return std::nullopt;
            }
            break;
        default:
            return std::nullopt;
        }
        ++tuple_field_index;
    }

    if (tuple_field_index != tuple_fields.size() * 2U ||
        !mark.has_value() || assured && unreplied ||
        explicit_seen_reply && unreplied) {
        return std::nullopt;
    }
    const auto expected_address_family =
        family == ConntrackFlowFamily::Ipv6
        ? TargetAddressFamily::Ipv6
        : TargetAddressFamily::Ipv4;
    if (original.source->family != expected_address_family ||
        original.destination->family != expected_address_family ||
        reply.source->family != expected_address_family ||
        reply.destination->family != expected_address_family) {
        return std::nullopt;
    }

    return ParsedExactConntrackFlow{
        family,
        protocol,
        ParsedConntrackTupleCounters{
            *original.source,
            *original.destination,
            *original.source_port,
            *original.destination_port,
            ConntrackFlowCounters{*original.packets, *original.bytes}},
        ParsedConntrackTupleCounters{
            *reply.source,
            *reply.destination,
            *reply.source_port,
            *reply.destination_port,
            ConntrackFlowCounters{*reply.packets, *reply.bytes}},
        *mark,
        tcp_state,
        assured,
        !unreplied || explicit_seen_reply,
        fastnat};
}

std::optional<NormalizedHostAddress> normalize_local_scope_address(
    std::string_view raw) {
    const std::string value = trim_ascii_whitespace(raw);
    if (value.empty()) {
        return std::nullopt;
    }
    const auto slash = value.find('/');
    if (slash != std::string::npos) {
        if (value.find('/', slash + 1U) != std::string::npos) {
            return std::nullopt;
        }
        const std::string_view host{value.data(), slash};
        const bool ipv6 = host.find(':') != std::string_view::npos;
        const auto prefix = parse_unsigned_decimal<unsigned int>(
            std::string_view{
                value.data() + slash + 1U,
                value.size() - slash - 1U});
        if (host.empty() || !prefix.has_value() || *prefix == 0U ||
            *prefix > (ipv6 ? 128U : 32U)) {
            return std::nullopt;
        }
    }
    return normalize_host_address(value);
}

bool mark_is_observer_eligible(std::uint32_t mark,
                               std::uint32_t owned_mask) noexcept {
    if (mark == 0U) {
        return true;
    }
    return (mark & owned_mask) != 0U && (mark & ~owned_mask) == 0U;
}

} // namespace

ConntrackManager::ConntrackManager(CommandRunner runner,
                                   SnapshotReader snapshot_reader)
    : runner_(std::move(runner)),
      snapshot_reader_(std::move(snapshot_reader)) {
    if (!runner_) {
        runner_ = [](const std::vector<std::string>& args) {
            constexpr size_t kMaxDiagnosticBytes = 1024;
            // Conntrack retirement is best effort and can run on the serialized
            // runtime control path after SNAT recovery. Never let a wedged
            // utility stall firewall reconciliation for the global 30-second
            // command timeout.
            const SafeExecTimeouts cleanup_timeouts{
                std::chrono::seconds{1},
                std::chrono::milliseconds{100}};
            const auto result = safe_exec_capture(
                args,
                /*suppress_stderr=*/false,
                kMaxDiagnosticBytes,
                /*capture_stderr=*/true,
                /*drain_after_limit=*/true,
                SafeExecFailureLog::DiagnosticOnly,
                cleanup_timeouts);
            return CommandResult{result.exit_code, result.stdout_output};
        };
    }
    if (!snapshot_reader_) {
        snapshot_reader_ = [](std::size_t max_bytes)
            -> std::optional<Snapshot> {
            std::ifstream input("/proc/net/nf_conntrack");
            if (!input) {
                return std::nullopt;
            }

            Snapshot snapshot;
            snapshot.content.reserve(
                std::min<std::size_t>(max_bytes, 64U * 1024U));
            std::string line;
            while (std::getline(input, line)) {
                const std::size_t required = line.size() + 1U;
                if (required > max_bytes -
                        std::min(max_bytes, snapshot.content.size())) {
                    snapshot.truncated = true;
                    break;
                }
                snapshot.content.append(line);
                snapshot.content.push_back('\n');
            }
            if (input.bad()) {
                return std::nullopt;
            }
            return snapshot;
        };
    }
}

bool ConntrackManager::reconcile(ConntrackPolicy desired) {
    if (active_ == desired) {
        return false;
    }
    active_ = desired;
    return true;
}

ConntrackPolicy ConntrackManager::inspect() const {
    return active_;
}

uint32_t ConntrackManager::restore_original_mark(uint32_t nfmark,
                                                 uint32_t ctmark,
                                                 uint32_t owned_mask) {
    return (nfmark & ~owned_mask) | (ctmark & owned_mask);
}

uint32_t ConntrackManager::save_selected_mark(uint32_t ctmark,
                                              uint32_t nfmark,
                                              uint32_t owned_mask) {
    return (ctmark & ~owned_mask) | (nfmark & owned_mask);
}

ConntrackCleanupResult ConntrackManager::delete_mark(
    uint32_t mark,
    uint32_t owned_mask) const {
    const auto summary = delete_marks_ordered(
        std::vector<uint32_t>{mark}, owned_mask);
    if (summary.command_unavailable) {
        return ConntrackCleanupResult::CommandUnavailable;
    }
    return summary.failed == 0U && !summary.budget_exhausted
        ? ConntrackCleanupResult::Succeeded
        : ConntrackCleanupResult::Failed;
}

ConntrackCleanupSummary ConntrackManager::delete_marks(
    const std::set<uint32_t>& marks,
    uint32_t owned_mask,
    ConntrackCleanupOptions options) const {
    return delete_marks_ordered(
        std::vector<uint32_t>{marks.begin(), marks.end()},
        owned_mask,
        options);
}

ConntrackCleanupSummary ConntrackManager::delete_marks_ordered(
    const std::vector<uint32_t>& marks,
    uint32_t owned_mask,
    ConntrackCleanupOptions options) const {
    ConntrackCleanupSummary summary;
    std::vector<uint32_t> ordered_marks;
    std::set<uint32_t> seen;
    ordered_marks.reserve(marks.size());
    for (const uint32_t mark : marks) {
        if (seen.insert(mark).second) {
            ordered_marks.push_back(mark);
        }
    }

    const auto deadline =
        std::chrono::steady_clock::now() +
        std::max(options.budget, std::chrono::milliseconds{0});
    const auto deadline_reached = [&deadline]() {
        return std::chrono::steady_clock::now() >= deadline;
    };
    std::vector<uint32_t> failed_marks;
    std::vector<uint32_t> unattempted_marks;
    const auto retain_unattempted =
        [&ordered_marks, &unattempted_marks](std::size_t first) {
            unattempted_marks.insert(
                unattempted_marks.end(),
                ordered_marks.begin() +
                    static_cast<std::ptrdiff_t>(first),
                ordered_marks.end());
        };

    for (std::size_t index = 0; index < ordered_marks.size(); ++index) {
        if (index >= options.max_marks) {
            summary.skipped += ordered_marks.size() - index;
            retain_unattempted(index);
            break;
        }
        const uint32_t mark = ordered_marks[index];
        // Never turn an invalid/custom fwmark configuration into a broad
        // `--mark 0/<mask>` delete. That selector matches ordinary unmarked
        // connections and would evict unrelated router traffic.
        if (owned_mask == 0 || (mark & owned_mask) == 0) {
            ++summary.failed;
            failed_marks.push_back(mark);
            continue;
        }
        if (deadline_reached()) {
            summary.budget_exhausted = true;
            summary.skipped += ordered_marks.size() - index;
            retain_unattempted(index);
            break;
        }

        const std::string selector =
            std::to_string(mark & owned_mask) + "/" +
            std::to_string(owned_mask);
        const auto delete_family = [this, &selector](const char* family) {
            const auto result =
                runner_({"conntrack", "-D", "-f", family, "--mark", selector});
            if (result.exit_code == 127) {
                return ConntrackCleanupResult::CommandUnavailable;
            }
            return result.exit_code == 0 || is_empty_delete_result(result)
                       ? ConntrackCleanupResult::Succeeded
                       : ConntrackCleanupResult::Failed;
        };

        const auto ipv4 = delete_family("ipv4");
        if (ipv4 == ConntrackCleanupResult::CommandUnavailable) {
            summary.command_unavailable = true;
            summary.skipped += ordered_marks.size() - index;
            retain_unattempted(index);
            break;
        }

        bool mark_failed = ipv4 == ConntrackCleanupResult::Failed;
        if (options.ipv6_enabled) {
            if (deadline_reached()) {
                summary.budget_exhausted = true;
                mark_failed = true;
                summary.skipped += ordered_marks.size() - index - 1U;
                retain_unattempted(index + 1U);
            } else {
                // A family-specific failure must not prevent cleanup of the
                // other enabled family.
                const auto ipv6 = delete_family("ipv6");
                if (ipv6 == ConntrackCleanupResult::CommandUnavailable) {
                    summary.command_unavailable = true;
                    summary.skipped += ordered_marks.size() - index - 1U;
                    failed_marks.push_back(mark);
                    retain_unattempted(index + 1U);
                    break;
                }
                mark_failed =
                    mark_failed ||
                    ipv6 == ConntrackCleanupResult::Failed;
            }
        }
        if (mark_failed) {
            ++summary.failed;
            failed_marks.push_back(mark);
        }
        if (summary.budget_exhausted) {
            break;
        }
    }
    summary.remaining_marks.reserve(
        unattempted_marks.size() + failed_marks.size());
    summary.remaining_marks.insert(
        summary.remaining_marks.end(),
        unattempted_marks.begin(),
        unattempted_marks.end());
    summary.remaining_marks.insert(
        summary.remaining_marks.end(),
        failed_marks.begin(),
        failed_marks.end());
    return summary;
}

ConntrackSourceCleanupSummary ConntrackManager::delete_ipv4_source_cidrs(
    const std::vector<std::string>& source_cidrs,
    ConntrackSourceCleanupOptions options) const {
    struct SourceSelector {
        std::string value;
        bool valid{false};
    };

    std::vector<SourceSelector> selectors;
    std::set<std::string> seen;
    selectors.reserve(source_cidrs.size());
    for (const auto& raw : source_cidrs) {
        const auto normalized = normalize_targeted_ipv4_cidr(raw);
        const std::string value =
            normalized.has_value() ? *normalized : trim_ascii_whitespace(raw);
        if (seen.insert(value).second) {
            selectors.push_back(SourceSelector{
                value,
                normalized.has_value()});
        }
    }

    ConntrackSourceCleanupSummary summary;
    const auto deadline =
        std::chrono::steady_clock::now() +
        std::max(options.budget, std::chrono::milliseconds{0});
    const auto deadline_reached = [&deadline]() {
        return std::chrono::steady_clock::now() >= deadline;
    };
    std::vector<std::string> failed_selectors;
    std::vector<std::string> unattempted_selectors;
    const auto retain_unattempted =
        [&selectors, &unattempted_selectors](std::size_t first) {
            for (std::size_t index = first; index < selectors.size(); ++index) {
                unattempted_selectors.push_back(selectors[index].value);
            }
        };

    for (std::size_t index = 0; index < selectors.size(); ++index) {
        if (index >= options.max_source_cidrs) {
            summary.skipped += selectors.size() - index;
            retain_unattempted(index);
            break;
        }

        const auto& selector = selectors[index];
        if (!selector.valid) {
            ++summary.failed;
            failed_selectors.push_back(selector.value);
            continue;
        }
        if (deadline_reached()) {
            summary.budget_exhausted = true;
            summary.skipped += selectors.size() - index;
            retain_unattempted(index);
            break;
        }

        const auto result = runner_({
            "conntrack", "-D", "-f", "ipv4", "-s", selector.value});
        if (result.exit_code == 127) {
            summary.command_unavailable = true;
            summary.skipped += selectors.size() - index;
            retain_unattempted(index);
            break;
        }
        if (result.exit_code != 0 && !is_empty_delete_result(result)) {
            ++summary.failed;
            failed_selectors.push_back(selector.value);
        }
    }

    summary.remaining_source_cidrs.reserve(
        unattempted_selectors.size() + failed_selectors.size());
    summary.remaining_source_cidrs.insert(
        summary.remaining_source_cidrs.end(),
        unattempted_selectors.begin(),
        unattempted_selectors.end());
    summary.remaining_source_cidrs.insert(
        summary.remaining_source_cidrs.end(),
        failed_selectors.begin(),
        failed_selectors.end());
    return summary;
}

ConntrackForwardedFlowCleanupSummary
ConntrackManager::delete_forwarded_destination_flows(
    const std::vector<std::string>& normal_destination_cidrs,
    const std::vector<std::string>& aggressive_destination_cidrs,
    const std::vector<std::string>& local_interface_addresses,
    uint32_t owned_mask,
    ConntrackForwardedFlowCleanupOptions options) const {
    ConntrackForwardedFlowCleanupSummary summary;
    if (owned_mask == 0U) {
        summary.invalid_owned_mask = true;
        return summary;
    }

    std::vector<NormalizedForwardedDestinationSelector> selectors;
    std::map<std::string, std::size_t> selector_indices;
    selectors.reserve(std::min(
        normal_destination_cidrs.size() +
            aggressive_destination_cidrs.size(),
        options.max_destination_input_cidrs));
    const auto append_selectors =
        [&](const std::vector<std::string>& inputs,
            bool allow_unmarked,
            bool allow_owned_mark) {
            // Each policy class gets the same bounded read allowance. This
            // lets an overlapping normal/aggressive selector merge both
            // permissions without consuming the unique-selector budget
            // twice, while still bounding hostile or malformed input.
            const std::size_t input_limit = std::min(
                inputs.size(), options.max_destination_input_cidrs);
            if (input_limit < inputs.size()) {
                summary.destination_input_truncated = true;
                summary.skipped += inputs.size() - input_limit;
            }
            for (std::size_t input_index = 0;
                 input_index < input_limit;
                 ++input_index) {
                const auto normalized =
                    normalize_targeted_cidr(inputs[input_index]);
                if (normalized.has_value() &&
                    normalized->family == TargetAddressFamily::Ipv6 &&
                    !options.ipv6_enabled) {
                    // IPv6 is intentionally outside the active runtime in
                    // this mode; omitting its selectors mirrors mark cleanup's
                    // family handling and creates no impossible retry work.
                    continue;
                }
                if (!normalized.has_value()) {
                    ++summary.failed;
                    continue;
                }

                const std::string key =
                    (normalized->family == TargetAddressFamily::Ipv6
                         ? "6:"
                         : "4:") +
                    normalized->value;
                const auto position = selector_indices.find(key);
                if (position == selector_indices.end()) {
                    if (selectors.size() >=
                        options.max_destination_input_cidrs) {
                        summary.destination_input_truncated = true;
                        ++summary.skipped;
                        continue;
                    }
                    selector_indices.emplace(key, selectors.size());
                    selectors.push_back(
                        NormalizedForwardedDestinationSelector{
                            *normalized,
                            allow_unmarked,
                            allow_owned_mark});
                } else {
                    auto& selector = selectors[position->second];
                    selector.allow_unmarked =
                        selector.allow_unmarked || allow_unmarked;
                    selector.allow_owned_mark =
                        selector.allow_owned_mark || allow_owned_mark;
                }
            }
        };
    append_selectors(
        normal_destination_cidrs,
        /*allow_unmarked=*/true,
        /*allow_owned_mark=*/false);
    append_selectors(
        aggressive_destination_cidrs,
        /*allow_unmarked=*/true,
        /*allow_owned_mark=*/true);
    if (selectors.empty()) {
        return summary;
    }

    // The local-address inventory is the authority which separates forwarded
    // client traffic from router-originated probes, DNS, downloads and control
    // traffic. If it cannot be established completely, do nothing.
    if (local_interface_addresses.empty()) {
        summary.local_address_scope_missing = true;
        return summary;
    }
    std::set<std::string> local_addresses;
    for (const auto& raw : local_interface_addresses) {
        const auto normalized = normalize_host_address(raw);
        if (!normalized.has_value()) {
            summary.local_address_scope_missing = true;
            return summary;
        }
        local_addresses.insert(
            (normalized->family == TargetAddressFamily::Ipv6 ? "6:" : "4:") +
            normalized->value);
    }
    if (local_addresses.empty()) {
        summary.local_address_scope_missing = true;
        return summary;
    }

    const auto deadline =
        std::chrono::steady_clock::now() +
        std::max(options.budget, std::chrono::milliseconds{0});
    const auto deadline_reached = [&deadline]() {
        return std::chrono::steady_clock::now() >= deadline;
    };
    const auto snapshot = snapshot_reader_(options.max_snapshot_bytes);
    if (!snapshot.has_value()) {
        summary.snapshot_unavailable = true;
        return summary;
    }
    summary.snapshot_truncated = snapshot->truncated;

    std::vector<ConntrackForwardedFlowPair> flows;
    flows.reserve(std::min<std::size_t>(options.max_flows, 64U));
    std::set<std::string> seen_flows;
    std::istringstream snapshot_lines(snapshot->content);
    std::string line;
    std::size_t line_count = 0U;
    while (std::getline(snapshot_lines, line)) {
        if (line_count++ >= options.max_snapshot_lines) {
            summary.snapshot_truncated = true;
            break;
        }
        if (deadline_reached()) {
            summary.budget_exhausted = true;
            break;
        }
        const auto parsed = parse_conntrack_original_pair(line);
        if (!parsed.has_value()) {
            continue;
        }
        const bool ipv6 =
            parsed->source.family == TargetAddressFamily::Ipv6;
        if (ipv6 && !options.ipv6_enabled) {
            continue;
        }
        const std::string source_key =
            (ipv6 ? "6:" : "4:") + parsed->source.value;
        const std::string destination_key =
            (ipv6 ? "6:" : "4:") + parsed->destination.value;
        if (local_addresses.count(source_key) != 0U ||
            local_addresses.count(destination_key) != 0U) {
            continue;
        }
        const bool destination_matches = std::any_of(
            selectors.begin(), selectors.end(),
            [&parsed, owned_mask](
                const NormalizedForwardedDestinationSelector& selector) {
                if (!cidr_contains(selector.cidr, parsed->destination)) {
                    return false;
                }
                if (parsed->mark == 0U) {
                    return selector.allow_unmarked;
                }
                return selector.allow_owned_mark &&
                       (parsed->mark & owned_mask) != 0U;
            });
        if (!destination_matches) {
            continue;
        }
        const std::string flow_key = source_key + ">" +
            parsed->destination.value + "#" +
            std::to_string(parsed->mark);
        if (!seen_flows.insert(flow_key).second) {
            continue;
        }
        ++summary.matched;
        if (flows.size() >= options.max_flows) {
            ++summary.skipped;
            continue;
        }
        flows.push_back(ConntrackForwardedFlowPair{
            parsed->source.value,
            parsed->destination.value,
            ipv6,
            parsed->mark});
    }

    const auto retain_from =
        [&flows, &summary](std::size_t first) {
            summary.remaining_flows.insert(
                summary.remaining_flows.end(),
                flows.begin() + static_cast<std::ptrdiff_t>(first),
                flows.end());
        };
    for (std::size_t index = 0; index < flows.size(); ++index) {
        if (deadline_reached()) {
            summary.budget_exhausted = true;
            summary.skipped += flows.size() - index;
            retain_from(index);
            break;
        }
        const auto& flow = flows[index];
        const std::string mark_selector =
            std::to_string(flow.mark) + "/4294967295";
        const auto result = runner_({
            "conntrack", "-D", "-f", flow.ipv6 ? "ipv6" : "ipv4",
            "-s", flow.source, "-d", flow.destination,
            "--mark", mark_selector});
        ++summary.attempted;
        if (result.exit_code == 127) {
            summary.command_unavailable = true;
            summary.skipped += flows.size() - index;
            retain_from(index);
            break;
        }
        if (result.exit_code != 0 && !is_empty_delete_result(result)) {
            ++summary.failed;
            summary.remaining_flows.push_back(flow);
        }
    }
    return summary;
}

ConntrackFlowObservation
ConntrackManager::observe_forwarded_destination_flows(
    const std::vector<std::string>& destination_cidrs,
    const std::vector<std::string>& local_interface_addresses,
    uint32_t owned_mask,
    ConntrackFlowObservationOptions options,
    const std::vector<std::string>& media_guard_source_addresses,
    const std::vector<std::string>& media_seed_destination_cidrs,
    const std::set<uint32_t>& media_seed_owned_marks) const {
    ConntrackFlowObservation observation;
    if (owned_mask == 0U) {
        observation.invalid_owned_mask = true;
        return observation;
    }
    for (const auto mark : media_seed_owned_marks) {
        if (mark == 0U || (mark & ~owned_mask) != 0U) {
            observation.invalid_owned_mask = true;
            return observation;
        }
    }

    std::vector<NormalizedTargetCidr> selectors;
    selectors.reserve(std::min(
        destination_cidrs.size(), options.max_destination_input_cidrs));
    std::set<std::string> seen_selectors;
    const std::size_t selector_input_limit = std::min(
        destination_cidrs.size(), options.max_destination_input_cidrs);
    if (selector_input_limit < destination_cidrs.size()) {
        observation.destination_input_truncated = true;
        observation.skipped_destination_selectors +=
            destination_cidrs.size() - selector_input_limit;
    }
    for (std::size_t index = 0U; index < selector_input_limit; ++index) {
        const auto normalized = normalize_targeted_cidr(
            destination_cidrs[index]);
        if (!normalized.has_value()) {
            ++observation.invalid_destination_selectors;
            continue;
        }
        if (normalized->family == TargetAddressFamily::Ipv6 &&
            !options.ipv6_enabled) {
            ++observation.skipped_destination_selectors;
            continue;
        }
        const std::string key =
            (normalized->family == TargetAddressFamily::Ipv6 ? "6:" : "4:") +
            normalized->value;
        if (seen_selectors.insert(key).second) {
            selectors.push_back(*normalized);
        }
    }
    if (selectors.empty()) {
        return observation;
    }

    std::vector<NormalizedTargetCidr> media_seed_selectors;
    media_seed_selectors.reserve(std::min(
        media_seed_destination_cidrs.size(),
        options.max_destination_input_cidrs));
    std::set<std::string> seen_media_seed_selectors;
    const std::size_t media_seed_input_limit = std::min(
        media_seed_destination_cidrs.size(),
        options.max_destination_input_cidrs);
    if (media_seed_input_limit < media_seed_destination_cidrs.size()) {
        observation.media_seed_destination_input_truncated = true;
    }
    for (std::size_t index = 0U; index < media_seed_input_limit; ++index) {
        const auto normalized = normalize_targeted_cidr(
            media_seed_destination_cidrs[index]);
        if (!normalized.has_value()) {
            ++observation.invalid_media_seed_destination_selectors;
            continue;
        }
        if (normalized->family == TargetAddressFamily::Ipv6 &&
            !options.ipv6_enabled) {
            continue;
        }
        const std::string key =
            (normalized->family == TargetAddressFamily::Ipv6 ? "6:" : "4:") +
            normalized->value;
        if (seen_media_seed_selectors.insert(key).second) {
            media_seed_selectors.push_back(*normalized);
        }
    }
    if (observation.invalid_media_seed_destination_selectors != 0U ||
        observation.media_seed_destination_input_truncated) {
        return observation;
    }

    std::set<std::string> media_guard_sources;
    for (const auto& raw : media_guard_source_addresses) {
        const std::string trimmed = trim_ascii_whitespace(raw);
        // Media protection is host-scoped. Accepting a CIDR here would turn a
        // read-only call guard into an unexpectedly broad authority.
        if (trimmed.empty() || trimmed.find('/') != std::string::npos) {
            ++observation.invalid_media_guard_sources;
            continue;
        }
        const auto normalized = normalize_host_address(trimmed);
        if (!normalized.has_value() ||
            (normalized->family == TargetAddressFamily::Ipv6 &&
             !options.ipv6_enabled)) {
            ++observation.invalid_media_guard_sources;
            continue;
        }
        media_guard_sources.insert(
            (normalized->family == TargetAddressFamily::Ipv6 ? "6:" : "4:") +
            normalized->value);
    }
    if (observation.invalid_media_guard_sources != 0U) {
        return observation;
    }

    // Forwarded traffic can only be distinguished safely from traffic
    // originated by the router when the live local-address inventory is
    // complete. One malformed entry invalidates the authority as a whole.
    if (local_interface_addresses.empty()) {
        observation.local_address_scope_missing = true;
        return observation;
    }
    std::set<std::string> local_addresses;
    for (const auto& raw : local_interface_addresses) {
        const auto normalized = normalize_local_scope_address(raw);
        if (!normalized.has_value()) {
            observation.local_address_scope_missing = true;
            return observation;
        }
        local_addresses.insert(
            (normalized->family == TargetAddressFamily::Ipv6 ? "6:" : "4:") +
            normalized->value);
    }
    if (local_addresses.empty()) {
        observation.local_address_scope_missing = true;
        return observation;
    }

    const auto snapshot = snapshot_reader_(options.max_snapshot_bytes);
    if (!snapshot.has_value()) {
        observation.snapshot_unavailable = true;
        return observation;
    }
    observation.snapshot_truncated = snapshot->truncated;

    const std::size_t readable_bytes = std::min(
        snapshot->content.size(), options.max_snapshot_bytes);
    if (readable_bytes < snapshot->content.size()) {
        observation.snapshot_truncated = true;
    }
    std::string_view content{snapshot->content.data(), readable_bytes};
    std::size_t parse_bytes = content.size();
    // A custom reader may return more than requested. Never parse a partial
    // record at the byte boundary; the default reader already returns only
    // complete lines.
    if (readable_bytes < snapshot->content.size() && parse_bytes != 0U &&
        content.back() != '\n') {
        const auto last_newline = content.find_last_of('\n');
        parse_bytes = last_newline == std::string_view::npos
            ? 0U
            : last_newline + 1U;
    }
    content = content.substr(0U, parse_bytes);

    observation.flows.reserve(
        std::min<std::size_t>(options.max_flows, 64U));
    using FlowIdentity = std::tuple<
        ConntrackFlowFamily,
        ConntrackFlowProtocol,
        std::string,
        std::string,
        std::uint16_t,
        std::uint16_t,
        std::uint32_t>;
    std::set<FlowIdentity> seen_flows;
    std::set<FlowIdentity> seen_media_flows;
    std::set<FlowIdentity> seen_media_seed_flows;
    // One conntrack entry may intentionally appear in more than one semantic
    // view (for example, a selected WhatsApp seed is also part of the
    // source-wide UDP guard). Charge the bounded observation budget once per
    // exact identity, not once per output vector containing that identity.
    std::set<FlowIdentity> budgeted_flows;
    const auto claim_flow_budget = [&](const FlowIdentity& identity) {
        if (budgeted_flows.find(identity) != budgeted_flows.end()) {
            return true;
        }
        if (budgeted_flows.size() >= options.max_flows) {
            return false;
        }
        budgeted_flows.insert(identity);
        return true;
    };
    std::size_t cursor = 0U;
    std::size_t line_count = 0U;
    while (cursor < content.size()) {
        if (line_count >= options.max_snapshot_lines) {
            observation.line_limit_reached = true;
            observation.snapshot_truncated = true;
            break;
        }
        const auto newline = content.find('\n', cursor);
        const std::size_t line_end = newline == std::string_view::npos
            ? content.size()
            : newline;
        const std::string_view line = content.substr(
            cursor, line_end - cursor);
        cursor = newline == std::string_view::npos
            ? content.size()
            : newline + 1U;
        ++line_count;

        const auto parsed = parse_exact_conntrack_flow(line);
        if (!parsed.has_value()) {
            continue;
        }
        if (parsed->family == ConntrackFlowFamily::Ipv6 &&
            !options.ipv6_enabled) {
            continue;
        }
        const bool ordinary_mark_eligible =
            mark_is_observer_eligible(parsed->mark, owned_mask);
        const bool media_mark_eligible = ordinary_mark_eligible ||
            options.allow_foreign_mark_bits_for_media;
        if (!media_mark_eligible) {
            continue;
        }

        const bool ipv6 = parsed->family == ConntrackFlowFamily::Ipv6;
        const std::string source_key =
            (ipv6 ? "6:" : "4:") + parsed->original.source.value;
        const std::string destination_key =
            (ipv6 ? "6:" : "4:") + parsed->original.destination.value;
        if (local_addresses.count(source_key) != 0U ||
            local_addresses.count(destination_key) != 0U) {
            continue;
        }
        FlowIdentity identity{
            parsed->family,
            parsed->protocol,
            parsed->original.source.value,
            parsed->original.destination.value,
            parsed->original.source_port,
            parsed->original.destination_port,
            parsed->mark};
        if (parsed->protocol == ConntrackFlowProtocol::Udp &&
            media_guard_sources.count(source_key) != 0U &&
            seen_media_flows.insert(identity).second) {
            if (!claim_flow_budget(identity)) {
                observation.flow_limit_reached = true;
                break;
            }
            observation.source_wide_udp_flows.push_back(
                ConntrackExactForwardedFlow{
                    parsed->family,
                    parsed->protocol,
                    parsed->original.source.value,
                    parsed->original.destination.value,
                    parsed->original.source_port,
                    parsed->original.destination_port,
                    parsed->mark,
                    parsed->original.counters,
                    parsed->reply.counters,
                    parsed->tcp_state,
                    parsed->assured,
                    parsed->seen_reply,
                    parsed->fastnat});
        }
        const bool destination_matches = std::any_of(
            selectors.begin(), selectors.end(),
            [&parsed](const NormalizedTargetCidr& selector) {
                return cidr_contains(selector, parsed->original.destination);
            });
        if (!destination_matches) {
            continue;
        }

        ConntrackExactForwardedFlow observed_flow{
            parsed->family,
            parsed->protocol,
            parsed->original.source.value,
            parsed->original.destination.value,
            parsed->original.source_port,
            parsed->original.destination_port,
            parsed->mark,
            parsed->original.counters,
            parsed->reply.counters,
            parsed->tcp_state,
            parsed->assured,
            parsed->seen_reply,
            parsed->fastnat};
        const bool media_seed_matches = std::any_of(
            media_seed_selectors.begin(), media_seed_selectors.end(),
            [&parsed](const NormalizedTargetCidr& selector) {
                return cidr_contains(selector, parsed->original.destination);
            });
        if (ordinary_mark_eligible &&
            seen_flows.insert(identity).second) {
            if (!claim_flow_budget(identity)) {
                observation.flow_limit_reached = true;
                break;
            }
            observation.flows.push_back(observed_flow);
        }
        if (media_seed_matches &&
            seen_media_seed_flows.insert(identity).second) {
            if (!claim_flow_budget(identity)) {
                observation.flow_limit_reached = true;
                break;
            }
            observation.media_seed_flows.push_back(
                std::move(observed_flow));
        }
    }

    // Discover source-scoped call candidates from the same immutable snapshot
    // instead of reading /proc a second time. The first pass establishes only
    // trusted companion destinations and owned marks; this second bounded pass
    // can therefore recover UDP peers regardless of line order without making
    // an idle WhatsApp session double the kernel-read rate.
    std::set<std::string> derived_media_guard_sources;
    if (!media_seed_owned_marks.empty() &&
        !observation.snapshot_truncated &&
        !observation.line_limit_reached &&
        !observation.flow_limit_reached) {
        for (const auto& flow : observation.media_seed_flows) {
            const bool transport_ready =
                flow.protocol == ConntrackFlowProtocol::Udp
                ? !flow.tcp_state.has_value()
                : flow.protocol == ConntrackFlowProtocol::Tcp &&
                      flow.tcp_state == ConntrackTcpState::Established;
            if (!transport_ready || flow.destination_port != 443U ||
                !flow.assured || !flow.seen_reply ||
                flow.original.packets == 0U ||
                flow.reply.packets == 0U ||
                media_seed_owned_marks.count(flow.mark & owned_mask) == 0U) {
                continue;
            }
            const bool ipv6 = flow.family == ConntrackFlowFamily::Ipv6;
            const std::string source_key =
                (ipv6 ? "6:" : "4:") + flow.source;
            if (media_guard_sources.count(source_key) == 0U) {
                derived_media_guard_sources.insert(source_key);
            }
        }
    }

    if (!derived_media_guard_sources.empty()) {
        cursor = 0U;
        line_count = 0U;
        while (cursor < content.size()) {
            if (line_count >= options.max_snapshot_lines) {
                observation.line_limit_reached = true;
                observation.snapshot_truncated = true;
                break;
            }
            const auto newline = content.find('\n', cursor);
            const std::size_t line_end = newline == std::string_view::npos
                ? content.size()
                : newline;
            const std::string_view line = content.substr(
                cursor, line_end - cursor);
            cursor = newline == std::string_view::npos
                ? content.size()
                : newline + 1U;
            ++line_count;

            const auto parsed = parse_exact_conntrack_flow(line);
            if (!parsed.has_value() ||
                parsed->protocol != ConntrackFlowProtocol::Udp ||
                (parsed->family == ConntrackFlowFamily::Ipv6 &&
                 !options.ipv6_enabled)) {
                continue;
            }
            const bool ordinary_mark_eligible =
                mark_is_observer_eligible(parsed->mark, owned_mask);
            if (!ordinary_mark_eligible &&
                !options.allow_foreign_mark_bits_for_media) {
                continue;
            }
            const bool ipv6 =
                parsed->family == ConntrackFlowFamily::Ipv6;
            const std::string source_key =
                (ipv6 ? "6:" : "4:") + parsed->original.source.value;
            const std::string destination_key =
                (ipv6 ? "6:" : "4:") +
                parsed->original.destination.value;
            if (derived_media_guard_sources.count(source_key) == 0U ||
                local_addresses.count(source_key) != 0U ||
                local_addresses.count(destination_key) != 0U) {
                continue;
            }
            const FlowIdentity identity{
                parsed->family,
                parsed->protocol,
                parsed->original.source.value,
                parsed->original.destination.value,
                parsed->original.source_port,
                parsed->original.destination_port,
                parsed->mark};
            if (!seen_media_flows.insert(identity).second) {
                continue;
            }
            if (!claim_flow_budget(identity)) {
                observation.flow_limit_reached = true;
                break;
            }
            observation.source_wide_udp_flows.push_back(
                ConntrackExactForwardedFlow{
                    parsed->family,
                    parsed->protocol,
                    parsed->original.source.value,
                    parsed->original.destination.value,
                    parsed->original.source_port,
                    parsed->original.destination_port,
                    parsed->mark,
                    parsed->original.counters,
                    parsed->reply.counters,
                    parsed->tcp_state,
                    parsed->assured,
                    parsed->seen_reply,
                    parsed->fastnat});
        }
    }

    return observation;
}

ConntrackCleanupResult ConntrackManager::delete_exact_forwarded_flow(
    const ConntrackExactForwardedFlow& flow,
    uint32_t owned_mask,
    std::optional<std::uint32_t> expected_owned_mark) const {
    if (owned_mask == 0U) {
        return ConntrackCleanupResult::Failed;
    }
    if (expected_owned_mark.has_value()) {
        if (*expected_owned_mark == 0U ||
            (*expected_owned_mark & ~owned_mask) != 0U) {
            return ConntrackCleanupResult::Failed;
        }
        const auto live_owned_mark = flow.mark & owned_mask;
        if (live_owned_mark != 0U &&
            live_owned_mark != *expected_owned_mark) {
            return ConntrackCleanupResult::Failed;
        }
    } else if (!mark_is_observer_eligible(flow.mark, owned_mask)) {
        return ConntrackCleanupResult::Failed;
    }

    const std::string raw_source = trim_ascii_whitespace(flow.source);
    const std::string raw_destination = trim_ascii_whitespace(flow.destination);
    if (raw_source.empty() || raw_destination.empty() ||
        raw_source.find('/') != std::string::npos ||
        raw_destination.find('/') != std::string::npos) {
        return ConntrackCleanupResult::Failed;
    }
    const auto source = normalize_host_address(raw_source);
    const auto destination = normalize_host_address(raw_destination);
    if (!source.has_value() || !destination.has_value() ||
        source->family != destination->family) {
        return ConntrackCleanupResult::Failed;
    }
    TargetAddressFamily expected_family;
    std::string family;
    switch (flow.family) {
    case ConntrackFlowFamily::Ipv4:
        expected_family = TargetAddressFamily::Ipv4;
        family = "ipv4";
        break;
    case ConntrackFlowFamily::Ipv6:
        expected_family = TargetAddressFamily::Ipv6;
        family = "ipv6";
        break;
    default:
        return ConntrackCleanupResult::Failed;
    }
    if (source->family != expected_family) {
        return ConntrackCleanupResult::Failed;
    }

    std::string protocol;
    switch (flow.protocol) {
    case ConntrackFlowProtocol::Tcp:
        if (!flow.tcp_state.has_value()) {
            return ConntrackCleanupResult::Failed;
        }
        protocol = "tcp";
        break;
    case ConntrackFlowProtocol::Udp:
        if (flow.tcp_state.has_value()) {
            return ConntrackCleanupResult::Failed;
        }
        protocol = "udp";
        break;
    default:
        return ConntrackCleanupResult::Failed;
    }

    const std::string mark_selector =
        std::to_string(flow.mark) + "/4294967295";
    const auto result = runner_({
        "conntrack", "-D",
        "-f", family,
        "-p", protocol,
        "-s", source->value,
        "--sport", std::to_string(flow.source_port),
        "-d", destination->value,
        "--dport", std::to_string(flow.destination_port),
        "--mark", mark_selector});
    if (result.exit_code == 127) {
        return ConntrackCleanupResult::CommandUnavailable;
    }
    return result.exit_code == 0 || is_empty_delete_result(result)
        ? ConntrackCleanupResult::Succeeded
        : ConntrackCleanupResult::Failed;
}

ConntrackForwardedFlowCleanupSummary
ConntrackManager::delete_unmarked_forwarded_destination_flows(
    const std::vector<std::string>& destination_cidrs,
    const std::vector<std::string>& local_interface_addresses,
    uint32_t owned_mask,
    ConntrackForwardedFlowCleanupOptions options) const {
    return delete_forwarded_destination_flows(
        destination_cidrs,
        {},
        local_interface_addresses,
        owned_mask,
        options);
}

} // namespace keen_pbr3
