#include "ipv6_support.hpp"

#include "../log/logger.hpp"
#include "firewall_backend_utils.hpp"
#include "safe_exec.hpp"

#include <sys/socket.h>
#include <unistd.h>

namespace keen_pbr3 {

#ifdef KEEN_PBR3_TESTING
namespace {
thread_local std::optional<bool> ipv6_support_override_for_tests;
}

namespace testing {

ScopedIpv6SupportOverride::ScopedIpv6SupportOverride(bool supported) noexcept
    : previous_(ipv6_support_override_for_tests) {
    ipv6_support_override_for_tests = supported;
}

ScopedIpv6SupportOverride::~ScopedIpv6SupportOverride() noexcept {
    ipv6_support_override_for_tests = previous_;
}

} // namespace testing
#endif

bool system_ipv6_supported() {
    const int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
        return false;
    }
    close(fd);
    return true;
}

bool nft_ipv6_supported() {
    static constexpr const char* kProbeRuleset =
        "table inet keen_pbr_ipv6_probe {\n"
        "  chain prerouting {\n"
        "    type filter hook prerouting priority -150; policy accept;\n"
        "    ip6 saddr ::1 accept\n"
        "  }\n"
        "}\n";
    return safe_exec_pipe_stdin(
               {"nft", "-c", "-f", "-"},
               kProbeRuleset,
               nullptr,
               SafeExecFailureLog::Suppressed) == 0;
}

bool iptables_ipv6_supported() {
    static constexpr const char* kProbeRuleset = "*mangle\nCOMMIT\n";
    return safe_exec({"ip6tables", "-t", "mangle", "-S"},
                     /*suppress_output=*/true) == 0
        && safe_exec_pipe_stdin(
               {"ip6tables-restore", "--test"},
               kProbeRuleset,
               nullptr,
               SafeExecFailureLog::Suppressed) == 0;
}

bool firewall_ipv6_supported(const Config& config) {
    try {
        const FirewallBackend backend =
            resolve_firewall_backend(firewall_backend_preference(config));
        if (backend == FirewallBackend::iptables) {
            return iptables_ipv6_supported();
        }
        if (backend == FirewallBackend::nftables) {
            return nft_ipv6_supported();
        }
    } catch (const std::exception&) {
        return true;
    }

    return true;
}

Ipv6SupportDecision resolve_ipv6_support(const Config& config) {
    if (config.daemon.has_value()
        && config.daemon->ipv6_enabled.has_value()
        && !*config.daemon->ipv6_enabled) {
        return {false, Ipv6SupportDecision::Reason::DisabledByConfig};
    }

#ifdef KEEN_PBR3_TESTING
    if (ipv6_support_override_for_tests.has_value()) {
        return *ipv6_support_override_for_tests
            ? Ipv6SupportDecision{true, Ipv6SupportDecision::Reason::Enabled}
            : Ipv6SupportDecision{false, Ipv6SupportDecision::Reason::UnsupportedBySystem};
    }
#endif

    if (!system_ipv6_supported() || !firewall_ipv6_supported(config)) {
        return {false, Ipv6SupportDecision::Reason::UnsupportedBySystem};
    }

    return {true, Ipv6SupportDecision::Reason::Enabled};
}

void log_ipv6_support_decision_once(const Ipv6SupportDecision& decision) {
    static bool logged_user_disabled = false;
    static bool logged_system_unsupported = false;

    if (decision.reason == Ipv6SupportDecision::Reason::DisabledByConfig) {
        if (!logged_user_disabled) {
            // Не предупреждение: человек сам выключил IPv6 в настройках, и
            // сообщать ему об исполнении его же решения как о проблеме -
            // значит поднимать тревогу на пустом месте. В колокольчике
            // собираются предупреждения и ошибки, и эта строка засоряла его
            // при каждом запуске.
            Logger::instance().verbose("IPv6 disabled in the configuration; running IPv4-only");
            logged_user_disabled = true;
        }
        return;
    }

    if (decision.reason == Ipv6SupportDecision::Reason::UnsupportedBySystem) {
        if (!logged_system_unsupported) {
            Logger::instance().error(
                "IPv6 is not supported by this system; continuing in IPv4-only mode");
            logged_system_unsupported = true;
        }
    }
}

} // namespace keen_pbr3
