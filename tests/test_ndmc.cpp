#include "../src/api/dhcp_bindings.hpp"
#include "../src/util/ndmc.hpp"
#include "../src/util/safe_exec.hpp"

#include <doctest/doctest.h>

#include <cstdlib>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

namespace {

// Restores whatever the process had before the test poisoned it. The whole
// point of the invariant is that the daemon's own environment is untouched, so
// a test that leaked its override would hide the very regression it guards.
struct EnvironmentVariableGuard {
    std::string name;
    std::optional<std::string> original;

    explicit EnvironmentVariableGuard(std::string variable)
        : name(std::move(variable)) {
        const char* value = std::getenv(name.c_str());
        if (value != nullptr) {
            original = std::string(value);
        }
    }

    void set(const std::string& value) {
        ::setenv(name.c_str(), value.c_str(), 1);
    }

    ~EnvironmentVariableGuard() {
        if (original.has_value()) {
            ::setenv(name.c_str(), original->c_str(), 1);
        } else {
            ::unsetenv(name.c_str());
        }
    }
};

// The exact shape KeeneticOS 5.01.C.1.0-0 (aarch64) emits, with the device
// values replaced by documentation-range placeholders. Three details are load
// bearing and were all observed on the live firmware:
//   * the output opens with an ESC[K terminal control sequence;
//   * the record header is "lease:" followed by a trailing space;
//   * every field is indented, and records are separated by a blank line.
const char* const kObservedBindingsOutput =
    "\x1b[K\n"
    "            lease: \n"
    "                   ip: 192.0.2.10\n"
    "                  mac: 00:11:22:33:44:55\n"
    "                  via: br0\n"
    "             hostname: laptop-dhcp\n"
    "                 name: Laptop in the study\n"
    "              expires: 3600\n"
    "\n"
    "            lease: \n"
    "                   ip: 192.0.2.11\n"
    "                  mac: 00:11:22:33:44:66\n"
    "                  via: br0\n"
    "             hostname: printer\n"
    "              expires: 3600\n";

}  // namespace

TEST_CASE("safe_exec_capture scrubs LD_LIBRARY_PATH for the child only") {
    EnvironmentVariableGuard guard("LD_LIBRARY_PATH");
    guard.set("/opt/lib");

    const std::vector<std::string> print_variable{
        "/bin/sh", "-c", "printf %s \"${LD_LIBRARY_PATH-UNSET}\""};

    // Control: without an override the child inherits the poisoned value. If
    // this ever stops holding, the assertion below would pass for the wrong
    // reason and the scrub would no longer be under test.
    const auto inherited = safe_exec_capture(print_variable);
    CHECK(inherited.exit_code == 0);
    CHECK(inherited.stdout_output == "/opt/lib");

    const auto scrubbed = safe_exec_capture(print_variable,
                                            /*suppress_stderr=*/false,
                                            /*max_bytes=*/0,
                                            /*capture_stderr=*/false,
                                            /*drain_after_limit=*/false,
                                            SafeExecFailureLog::Enabled,
                                            std::nullopt,
                                            ndmc_child_environment());
    CHECK(scrubbed.exit_code == 0);
    CHECK(scrubbed.stdout_output.empty());

    const char* after = std::getenv("LD_LIBRARY_PATH");
    REQUIRE(after != nullptr);
    CHECK(std::string(after) == "/opt/lib");
}

TEST_CASE("safe_exec_capture refuses a relative executable with overrides") {
    // execve() performs no PATH lookup, so a relative argv[0] combined with an
    // override would silently exec nothing. It must be refused before fork().
    const auto result = safe_exec_capture({"sh", "-c", "exit 0"},
                                          /*suppress_stderr=*/true,
                                          /*max_bytes=*/0,
                                          /*capture_stderr=*/false,
                                          /*drain_after_limit=*/false,
                                          SafeExecFailureLog::Enabled,
                                          std::nullopt,
                                          {{"KEEN_PBR_MUST_NOT_RUN", "1"}});
    CHECK(result.exit_code == -1);
    CHECK(result.stdout_output.empty());
}

TEST_CASE("safe_exec_capture rejects malformed environment overrides") {
    const auto named_with_equals =
        safe_exec_capture({"/bin/sh", "-c", "exit 0"},
                          true, 0, false, false,
                          SafeExecFailureLog::Enabled, std::nullopt,
                          {{"BAD=NAME", "value"}});
    CHECK(named_with_equals.exit_code == -1);

    const auto empty_name =
        safe_exec_capture({"/bin/sh", "-c", "exit 0"},
                          true, 0, false, false,
                          SafeExecFailureLog::Enabled, std::nullopt,
                          {{"", "value"}});
    CHECK(empty_name.exit_code == -1);
}

TEST_CASE("ndmc candidates are absolute so execve can use them") {
    REQUIRE(!ndmc_path_candidates().empty());
    for (const auto& candidate : ndmc_path_candidates()) {
        CHECK(!candidate.empty());
        CHECK(candidate.front() == '/');
    }
}

TEST_CASE("ndmc scrub is exactly an empty LD_LIBRARY_PATH") {
    REQUIRE(ndmc_child_environment().size() == 1U);
    CHECK(ndmc_child_environment().front().first == "LD_LIBRARY_PATH");
    CHECK(ndmc_child_environment().front().second.empty());
}

TEST_CASE("ndmc_capture reports a missing CLI instead of running anything") {
    bool executor_ran = false;
    const auto result = ndmc_capture(
        "show ip dhcp bindings",
        1024U,
        []() { return std::string{}; },
        [&executor_ran](const std::vector<std::string>&,
                        const ChildEnvironmentOverrides&) {
            executor_ran = true;
            return ExecCaptureResult{};
        });

    CHECK(!result.executable_found);
    CHECK(!result.succeeded());
    CHECK(!executor_ran);
}

TEST_CASE("ndmc_capture passes the resolved path and the scrub to the child") {
    std::vector<std::string> observed_args;
    ChildEnvironmentOverrides observed_environment;

    const auto result = ndmc_capture(
        "show ip dhcp bindings",
        1024U,
        []() { return std::string{"/opt/test/ndmc"}; },
        [&observed_args, &observed_environment](
            const std::vector<std::string>& args,
            const ChildEnvironmentOverrides& environment) {
            observed_args = args;
            observed_environment = environment;
            ExecCaptureResult capture;
            capture.exit_code = 0;
            capture.stdout_output = "ok";
            return capture;
        });

    REQUIRE(observed_args.size() == 3U);
    CHECK(observed_args[0] == "/opt/test/ndmc");
    CHECK(observed_args[1] == "-c");
    CHECK(observed_args[2] == "show ip dhcp bindings");
    REQUIRE(observed_environment.size() == 1U);
    CHECK(observed_environment.front().first == "LD_LIBRARY_PATH");
    CHECK(observed_environment.front().second.empty());
    CHECK(result.executable == "/opt/test/ndmc");
    CHECK(result.succeeded());
}

TEST_CASE("ndmc_capture keeps the diagnostic of a failed invocation") {
    // Verbatim from the live firmware with LD_LIBRARY_PATH=/opt/lib: ndmc
    // reports on stdout, exits 1, and prints no bindings at all.
    const std::string banner =
        "\x1b[K[C] Aug  6 21:32:06 ndm: ndmc: system failed [0xcffd0062].\n"
        "\x1b[K[C] Aug  6 21:32:06 ndm: Cli::Main: failed to initialize.\n";

    const auto result = ndmc_capture(
        "show ip dhcp bindings",
        1024U,
        []() { return std::string{"/bin/ndmc"}; },
        [&banner](const std::vector<std::string>&,
                  const ChildEnvironmentOverrides&) {
            ExecCaptureResult capture;
            capture.exit_code = 1;
            capture.stdout_output = banner;
            return capture;
        });

    CHECK(result.executable_found);
    CHECK(!result.succeeded());
    CHECK(result.capture.stdout_output == banner);
}

TEST_CASE("ndmc_capture treats truncation and timeout as failure") {
    const auto truncated = ndmc_capture(
        "show ip dhcp bindings", 1024U,
        []() { return std::string{"/bin/ndmc"}; },
        [](const std::vector<std::string>&, const ChildEnvironmentOverrides&) {
            ExecCaptureResult capture;
            capture.exit_code = 0;
            capture.truncated = true;
            return capture;
        });
    CHECK(!truncated.succeeded());

    const auto timed_out = ndmc_capture(
        "show ip dhcp bindings", 1024U,
        []() { return std::string{"/bin/ndmc"}; },
        [](const std::vector<std::string>&, const ChildEnvironmentOverrides&) {
            ExecCaptureResult capture;
            capture.exit_code = 0;
            capture.timed_out = true;
            return capture;
        });
    CHECK(!timed_out.succeeded());
}

TEST_CASE("ndmc diagnostic excerpt collapses the banner into one line") {
    const std::string banner =
        "\x1b[K[C] ndm: ndmc: system failed [0xcffd0062].\n"
        "\x1b[K[C] ndm: Cli::Main: failed to initialize.\n";

    const auto excerpt = ndmc_diagnostic_excerpt(banner);
    CHECK(excerpt.find('\n') == std::string::npos);
    CHECK(excerpt.find('\x1b') == std::string::npos);
    CHECK(excerpt.find("system failed [0xcffd0062].") != std::string::npos);
    CHECK(excerpt.find("failed to initialize.") != std::string::npos);

    const std::string long_output(500U, 'x');
    const auto bounded = ndmc_diagnostic_excerpt(long_output, 32U);
    CHECK(bounded.size() == 35U);  // 32 kept characters plus the "..." marker
}

TEST_CASE("dhcp bindings parser accepts the shape the firmware emits") {
    std::map<std::string, std::string> names;
    merge_dhcp_bindings(kObservedBindingsOutput, names);

    REQUIRE(names.size() == 2U);
    // NDMS `name` is what the user typed in the router UI and wins over the
    // client-supplied DHCP hostname.
    CHECK(names.at("192.0.2.10") == "Laptop in the study");
    // Without a `name` the DHCP hostname is the only thing left to show.
    CHECK(names.at("192.0.2.11") == "printer");
}

TEST_CASE("dhcp bindings override lease-file names for the same address") {
    std::map<std::string, std::string> names{
        {"192.0.2.10", "from-dnsmasq-lease"},
        {"192.0.2.99", "untouched"}};
    merge_dhcp_bindings(kObservedBindingsOutput, names);

    CHECK(names.at("192.0.2.10") == "Laptop in the study");
    CHECK(names.at("192.0.2.99") == "untouched");
}

TEST_CASE("dhcp bindings parser ignores records it cannot attribute") {
    std::map<std::string, std::string> names;

    // No address: nothing to key the name on.
    merge_dhcp_bindings("            lease: \n                 name: orphan\n",
                        names);
    CHECK(names.empty());

    // No name and no hostname: an address alone is not a display name.
    merge_dhcp_bindings("            lease: \n                   ip: 192.0.2.5\n",
                        names);
    CHECK(names.empty());

    // Garbage never throws and never invents an entry.
    merge_dhcp_bindings("", names);
    merge_dhcp_bindings("\x1b[K\nnot a record at all\n", names);
    CHECK(names.empty());
}

TEST_CASE("dhcp bindings parser accepts the alternate address key") {
    std::map<std::string, std::string> names;
    merge_dhcp_bindings(
        "            binding: \n"
        "              address: 192.0.2.20\n"
        "                 name: Static entry\n",
        names);

    REQUIRE(names.size() == 1U);
    CHECK(names.at("192.0.2.20") == "Static entry");
}

}  // namespace keen_pbr3
