#include "conntrack_manager.hpp"

#include "../util/safe_exec.hpp"

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

} // namespace

ConntrackManager::ConntrackManager(CommandRunner runner)
    : runner_(std::move(runner)) {
    if (!runner_) {
        runner_ = [](const std::vector<std::string>& args) {
            constexpr size_t kMaxDiagnosticBytes = 1024;
            const auto result = safe_exec_capture(
                args,
                /*suppress_stderr=*/false,
                kMaxDiagnosticBytes,
                /*capture_stderr=*/true,
                /*drain_after_limit=*/true);
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
    // Never turn an invalid/custom fwmark configuration into a broad
    // `--mark 0/<mask>` delete. That selector matches ordinary unmarked
    // connections and would evict unrelated router traffic.
    if (owned_mask == 0 || (mark & owned_mask) == 0) {
        return ConntrackCleanupResult::Failed;
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
        return ipv4;
    }
    // A family-specific failure must not prevent cleanup of the other family.
    const auto ipv6 = delete_family("ipv6");
    if (ipv6 == ConntrackCleanupResult::CommandUnavailable) {
        return ipv6;
    }
    return ipv4 == ConntrackCleanupResult::Succeeded &&
                   ipv6 == ConntrackCleanupResult::Succeeded
               ? ConntrackCleanupResult::Succeeded
               : ConntrackCleanupResult::Failed;
}

ConntrackCleanupSummary ConntrackManager::delete_marks(
    const std::set<uint32_t>& marks,
    uint32_t owned_mask) const {
    ConntrackCleanupSummary summary;
    for (const uint32_t mark : marks) {
        const auto result = delete_mark(mark, owned_mask);
        if (result == ConntrackCleanupResult::CommandUnavailable) {
            summary.command_unavailable = true;
            break;
        }
        if (result == ConntrackCleanupResult::Failed) {
            ++summary.failed;
        }
    }
    return summary;
}

} // namespace keen_pbr3
