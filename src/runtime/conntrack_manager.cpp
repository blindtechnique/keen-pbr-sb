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
        /*allow_unmarked=*/false,
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
