#include "system_resolver_hook.hpp"

#include "../util/safe_exec.hpp"

#include <array>
#include <fstream>
#include <stdexcept>

namespace keen_pbr3 {

const char* system_resolver_hook_path() noexcept {
#ifdef KEEN_PBR_SYSTEM_RESOLVER_HOOK
    return KEEN_PBR_SYSTEM_RESOLVER_HOOK;
#else
    return "/usr/lib/keen-pbr/dnsmasq.sh";
#endif
}

std::string_view runtime_start_resolver_action() noexcept {
    // stop_routing_runtime() deliberately switches the helper to inactive
    // fallback mode. An in-process start must restore that state before
    // waiting for dnsmasq to consume the new generation stream.
    return "activate";
}

bool runtime_restart_should_retry(std::string_view error) noexcept {
    // Route/firewall failures are deterministic and must be surfaced
    // immediately. The only bounded restart retry is for the known Keenetic
    // dnsmasq activation race after a clean rollback.
    return error.find("System resolver activation hook failed") !=
           std::string_view::npos;
}

std::vector<std::string> build_system_resolver_hook_args(const Config& config,
                                                         std::string_view action,
                                                         std::string_view attempt_id) {
    if (!config.dns.has_value() || !config.dns->system_resolver.has_value()) {
        return {};
    }

    if (action.empty()) {
        return {};
    }

    std::vector<std::string> args{
        system_resolver_hook_path(), std::string(action)};
    if (!attempt_id.empty()) {
        if (!is_valid_resolver_attempt_id(attempt_id)) {
            throw std::invalid_argument("invalid resolver attempt id");
        }
        args.emplace_back(attempt_id);
    }
    return args;
}

std::vector<std::string> build_system_resolver_reload_args(
    const Config& config,
    std::string_view attempt_id) {
    return build_system_resolver_hook_args(config, "reload", attempt_id);
}

bool is_valid_resolver_attempt_id(std::string_view attempt_id) noexcept {
    if (attempt_id.size() != 32) {
        return false;
    }
    for (const char ch : attempt_id) {
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
            return false;
        }
    }
    return true;
}

std::string generate_resolver_attempt_id() {
    std::array<unsigned char, 16> random_bytes{};
    std::ifstream random("/dev/urandom", std::ios::binary);
    if (!random.read(reinterpret_cast<char*>(random_bytes.data()),
                     static_cast<std::streamsize>(random_bytes.size()))) {
        throw std::runtime_error(
            "failed to read resolver attempt id from /dev/urandom");
    }

    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.resize(random_bytes.size() * 2);
    for (std::size_t index = 0; index < random_bytes.size(); ++index) {
        result[index * 2] = hex[random_bytes[index] >> 4U];
        result[index * 2 + 1] = hex[random_bytes[index] & 0x0fU];
    }
    return result;
}

bool execute_system_resolver_reload_hook(
    const Config& config,
    const HookCommandExecutor& executor,
    std::string& command,
    int& exit_code) {
    const auto args = build_system_resolver_reload_args(config);
    if (args.empty()) {
        command.clear();
        exit_code = 0;
        return true;
    }

    // Build command string for logging
    command.clear();
    for (size_t i = 0; i < args.size(); ++i) {
        if (i > 0) command += ' ';
        command += args[i];
    }

    exit_code = executor(args);
    return exit_code == 0;
}

int default_hook_command_executor(const std::vector<std::string>& args) {
    return safe_exec(args);
}

} // namespace keen_pbr3
