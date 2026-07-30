#include "conntrack_manager.hpp"

#include "../util/safe_exec.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <charconv>
#include <chrono>
#include <optional>
#include <set>
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

std::optional<std::string> normalize_targeted_ipv4_cidr(
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
    int prefix = 32;
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
    // /0 would select every IPv4 flow and is deliberately outside the
    // contract of this targeted cleanup API.
    if (prefix <= 0 || prefix > 32) {
        return std::nullopt;
    }

    in_addr address{};
    if (::inet_pton(AF_INET, ip.c_str(), &address) != 1) {
        return std::nullopt;
    }
    const std::uint32_t mask =
        prefix == 32
            ? std::numeric_limits<std::uint32_t>::max()
            : std::numeric_limits<std::uint32_t>::max() << (32 - prefix);
    address.s_addr = ::htonl(::ntohl(address.s_addr) & mask);

    char normalized[INET_ADDRSTRLEN]{};
    if (::inet_ntop(AF_INET, &address, normalized, sizeof(normalized)) ==
        nullptr) {
        return std::nullopt;
    }
    return std::string{normalized} + "/" + std::to_string(prefix);
}

} // namespace

ConntrackManager::ConntrackManager(CommandRunner runner)
    : runner_(std::move(runner)) {
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

} // namespace keen_pbr3
