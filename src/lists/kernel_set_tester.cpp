#include "kernel_set_tester.hpp"

#include "../util/safe_exec.hpp"

namespace keen_pbr3 {

namespace {

int run_membership_command(
    FirewallBackend backend,
    const std::string& set_name,
    const std::string& ip,
    const SafeExecTimeouts& timeouts) {
    if (backend == FirewallBackend::nftables) {
        return safe_exec_with_timeouts(
            {"nft", "get", "element", "inet", "KeenPbrTable",
             set_name, "{", ip, "}"},
            /*suppress_output=*/true,
            timeouts);
    }
    return safe_exec_with_timeouts(
        {"ipset", "test", set_name, ip},
        /*suppress_output=*/true,
        timeouts);
}

std::optional<bool> membership_from_exit_code(int exit_code) {
    if (exit_code == 127 || exit_code < 0) {
        return std::nullopt;
    }
    return exit_code == 0;
}

} // namespace

KernelSetTester::KernelSetTester(FirewallBackend backend)
    : backend_(backend) {}

std::optional<bool> KernelSetTester::contains(const std::string& set_name,
                                              const std::string& ip) const {
    return membership_from_exit_code(run_membership_command(
        backend_, set_name, ip, safe_exec_timeouts()));
}

KernelSetTestResult KernelSetTester::contains_until(
    const std::string& set_name,
    const std::string& ip,
    std::chrono::steady_clock::time_point deadline) const {
    const auto remaining =
        std::chrono::ceil<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
    if (remaining.count() <= 0) {
        return KernelSetTestResult{std::nullopt, true};
    }

    const SafeExecTimeouts timeouts{
        remaining,
        std::chrono::milliseconds{100},
    };
    const int exit_code = run_membership_command(
        backend_, set_name, ip, timeouts);
    const bool timed_out =
        exit_code < 0 &&
        std::chrono::steady_clock::now() >= deadline;
    const std::optional<bool> membership = timed_out
        ? std::optional<bool>{}
        : membership_from_exit_code(exit_code);
    return KernelSetTestResult{
        membership,
        timed_out,
    };
}

} // namespace keen_pbr3
