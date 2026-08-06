#pragma once

#include "safe_exec.hpp"

#include <algorithm>
#include <cstddef>
#include <functional>
#include <string>
#include <unistd.h>
#include <vector>

namespace keen_pbr3 {

// Every ndmc invocation from the daemon goes through this header, and the
// shipped shell scripts follow the same contract with an `LD_LIBRARY_PATH= `
// prefix.
//
// KeeneticOS ships the CLI as a system binary linked against the firmware's own
// libraries. Entware installs its own glibc in /opt/lib, so an inherited
// LD_LIBRARY_PATH pointing there makes the loader hand ndmc the wrong libc and
// it dies before running a single command:
//
//     ndm: ndmc: system failed [0xcffd0062].
//     Cli::Main: failed to initialize.
//
// Reproduced on KeeneticOS 5.01.C.1.0-0 (aarch64): with LD_LIBRARY_PATH=/opt/lib
// `ndmc -c "show ip dhcp bindings"` exits 1 and prints that banner instead of
// the bindings; with the variable cleared it exits 0 and returns them. The
// scrub is child-only - the daemon's own environ is never mutated.

// The value is deliberately empty rather than absent: an empty LD_LIBRARY_PATH
// means "no extra directories" to the loader, and that is the exact form
// verified against the firmware.
inline const ChildEnvironmentOverrides& ndmc_child_environment() {
    static const ChildEnvironmentOverrides overrides{
        {"LD_LIBRARY_PATH", std::string{}}};
    return overrides;
}

// KeeneticOS installs the CLI as /bin/ndmc. The list stays short on purpose:
// an unexpected location is a firmware change worth seeing rather than papering
// over, and execve() needs an absolute path anyway.
inline const std::vector<std::string>& ndmc_path_candidates() {
    static const std::vector<std::string> candidates{"/bin/ndmc"};
    return candidates;
}

// Returns the first executable candidate, or an empty string when the CLI is
// absent. Injectable so tests never depend on the host filesystem.
using NdmcPathResolver = std::function<std::string()>;

inline std::string resolve_ndmc_path() {
    for (const auto& candidate : ndmc_path_candidates()) {
        if (::access(candidate.c_str(), X_OK) == 0) {
            return candidate;
        }
    }
    return std::string{};
}

using NdmcCaptureExecutor = std::function<ExecCaptureResult(
    const std::vector<std::string>& args,
    const ChildEnvironmentOverrides& child_environment)>;

inline ExecCaptureResult ndmc_default_executor(
    const std::vector<std::string>& args,
    const ChildEnvironmentOverrides& child_environment,
    std::size_t max_bytes) {
    // ndmc reports initialization failure on stdout, not stderr, so stderr is
    // merged into the same bounded capture: a non-zero exit must not be able to
    // lose its diagnostic either way.
    return safe_exec_capture(args,
                             /*suppress_stderr=*/false,
                             max_bytes,
                             /*capture_stderr=*/true,
                             /*drain_after_limit=*/false,
                             SafeExecFailureLog::Enabled,
                             std::nullopt,
                             child_environment);
}

struct NdmcResult {
    // A CLI that is absent is a different condition from a CLI that ran and
    // failed. Callers must not conflate them: the first is an unsupported
    // platform, the second is a request that deserves a diagnostic.
    bool executable_found{false};
    std::string executable;
    ExecCaptureResult capture;

    bool succeeded() const {
        return executable_found && capture.exit_code == 0 &&
               !capture.truncated && !capture.timed_out;
    }
};

// Collapse a captured banner into one bounded log line. ndmc pads its output
// with terminal control sequences, and a multi-line diagnostic in the journal
// is harder to correlate than a single truncated one.
inline std::string ndmc_diagnostic_excerpt(const std::string& output,
                                           std::size_t max_chars = 200U) {
    std::string excerpt;
    excerpt.reserve(std::min(output.size(), max_chars));
    for (const char character : output) {
        if (excerpt.size() >= max_chars) {
            excerpt += "...";
            break;
        }
        if (character == '\n' || character == '\r' || character == '\t') {
            if (!excerpt.empty() && excerpt.back() != ' ') {
                excerpt.push_back(' ');
            }
            continue;
        }
        if (static_cast<unsigned char>(character) < 0x20) {
            continue;
        }
        excerpt.push_back(character);
    }
    while (!excerpt.empty() && excerpt.back() == ' ') {
        excerpt.pop_back();
    }
    return excerpt;
}

// Run `ndmc -c <command>` with a scrubbed child LD_LIBRARY_PATH and capture the
// output. Failures are reported once here so no call site has to remember to do
// it; the previous behaviour discarded the banner and left an empty result
// indistinguishable from "the router has no bindings".
inline NdmcResult ndmc_capture(
    const std::string& command,
    std::size_t max_bytes,
    const NdmcPathResolver& resolver = NdmcPathResolver{},
    const NdmcCaptureExecutor& executor = NdmcCaptureExecutor{}) {
    NdmcResult result;
    result.executable = resolver ? resolver() : resolve_ndmc_path();
    if (result.executable.empty()) {
        Logger::instance().verbose(
            "ndmc_unavailable command={} reason=no_executable_candidate",
            command);
        return result;
    }
    result.executable_found = true;

    const std::vector<std::string> args{result.executable, "-c", command};
    result.capture =
        executor ? executor(args, ndmc_child_environment())
                 : ndmc_default_executor(
                       args, ndmc_child_environment(), max_bytes);

    if (result.capture.exit_code != 0 || result.capture.timed_out) {
        Logger::instance().verbose(
            "ndmc_failed command={} exit_code={} timed_out={} truncated={} output={}",
            command,
            result.capture.exit_code,
            result.capture.timed_out ? "true" : "false",
            result.capture.truncated ? "true" : "false",
            ndmc_diagnostic_excerpt(result.capture.stdout_output));
    }
    return result;
}

}  // namespace keen_pbr3
