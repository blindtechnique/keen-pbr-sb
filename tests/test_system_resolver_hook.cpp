#include "../src/daemon/system_resolver_hook.hpp"

#include <doctest/doctest.h>

namespace keen_pbr3 {

TEST_CASE("build_system_resolver_reload_args: empty when resolver config absent") {
    Config cfg;
    CHECK(build_system_resolver_reload_args(cfg).empty());
}

TEST_CASE("build_system_resolver_reload_args: returns hook and reload as separate args") {
    Config cfg;
    cfg.dns = DnsConfig{};
    cfg.dns->system_resolver = api::SystemResolver{};

    const auto args = build_system_resolver_reload_args(cfg);
    REQUIRE(args.size() == 2);
    CHECK(args[0] == system_resolver_hook_path());
    CHECK(args[1] == "reload");
}

TEST_CASE("resolver hook carries an opaque exact attempt id as a separate argument") {
    Config cfg;
    cfg.dns = DnsConfig{};
    cfg.dns->system_resolver = api::SystemResolver{};
    const std::string attempt_id = "0123456789abcdef0123456789abcdef";

    const auto args = build_system_resolver_reload_args(cfg, attempt_id);

    REQUIRE(args.size() == 3);
    CHECK(args[0] == system_resolver_hook_path());
    CHECK(args[1] == "reload");
    CHECK(args[2] == attempt_id);
}

TEST_CASE("resolver attempt ids are strict lowercase 128-bit hex values") {
    CHECK(is_valid_resolver_attempt_id(
        "0123456789abcdef0123456789abcdef"));
    CHECK_FALSE(is_valid_resolver_attempt_id(""));
    CHECK_FALSE(is_valid_resolver_attempt_id(
        "0123456789ABCDEF0123456789ABCDEF"));
    CHECK_FALSE(is_valid_resolver_attempt_id(
        "0123456789abcdef0123456789abcdeg"));
    CHECK_FALSE(is_valid_resolver_attempt_id(
        "0123456789abcdef0123456789abcde"));
}

TEST_CASE("runtime stop followed by start reactivates the resolver helper") {
    Config cfg;
    cfg.dns = DnsConfig{};
    cfg.dns->system_resolver = api::SystemResolver{};

    const auto stop_args =
        build_system_resolver_hook_args(cfg, "deactivate");
    const auto start_args =
        build_system_resolver_hook_args(
            cfg, runtime_start_resolver_action());

    REQUIRE(stop_args.size() == 2);
    REQUIRE(start_args.size() == 2);
    CHECK(stop_args[1] == "deactivate");
    CHECK(start_args[1] == "activate");
}

TEST_CASE("runtime restart retries only a transient resolver activation race") {
    CHECK(runtime_restart_should_retry(
        "System resolver activation hook failed"));
    CHECK(runtime_restart_should_retry(
        "Routing runtime restart failed: System resolver activation hook failed"));
    CHECK_FALSE(runtime_restart_should_retry(
        "Failed to install routing policy"));
    CHECK_FALSE(runtime_restart_should_retry(
        "System resolver deactivate hook failed"));
}

TEST_CASE("execute_system_resolver_reload_hook: succeeds for zero exit code") {
    Config cfg;
    cfg.dns = DnsConfig{};
    cfg.dns->system_resolver = api::SystemResolver{};

    std::vector<std::string> observed_args;
    std::string command;
    int exit_code = -1;

    const bool ok = execute_system_resolver_reload_hook(
        cfg,
        [&observed_args](const std::vector<std::string>& args) {
            observed_args = args;
            return 0;
        },
        command,
        exit_code);

    CHECK(ok);
    CHECK(command == std::string(system_resolver_hook_path()) + " reload");
    REQUIRE(observed_args.size() == 2);
    CHECK(observed_args[0] == system_resolver_hook_path());
    CHECK(observed_args[1] == "reload");
    CHECK(exit_code == 0);
}

TEST_CASE("execute_system_resolver_reload_hook: fails but remains non-throwing") {
    Config cfg;
    cfg.dns = DnsConfig{};
    cfg.dns->system_resolver = api::SystemResolver{};

    std::string command;
    int exit_code = -1;

    const bool ok = execute_system_resolver_reload_hook(
        cfg,
        [](const std::vector<std::string>&) {
            return 17;
        },
        command,
        exit_code);

    CHECK_FALSE(ok);
    CHECK(command == std::string(system_resolver_hook_path()) + " reload");
    CHECK(exit_code == 17);
}

} // namespace keen_pbr3
