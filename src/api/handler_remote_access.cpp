#ifdef WITH_API

#include "handler_remote_access.hpp"

#include "../log/logger.hpp"
#include "../util/safe_exec.hpp"

#include <fstream>
#include <limits>
#include <mutex>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>

namespace keen_pbr3 {

namespace {

constexpr const char* kSettingsPath = "/opt/etc/keen-pbr/remote-access.json";
constexpr const char* kAuthPath = "/opt/etc/keen-pbr/auth.json";
constexpr const char* kChain = "KeenPbrRemote";
// The panel itself always listens here; a different external port is published
// with a REDIRECT rather than by moving the listener.
constexpr int kInternalPort = 12121;
constexpr int kDefaultPort = 12121;

std::mutex& settings_mutex() {
    static std::mutex mutex;
    return mutex;
}

std::string read_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return {};
    std::ostringstream out;
    out << file.rdbuf();
    return out.str();
}

nlohmann::json load_settings() {
    nlohmann::json settings;
    settings["enabled"] = false;
    settings["port"] = kDefaultPort;

    try {
        const auto raw = read_file(kSettingsPath);
        if (raw.empty()) return settings;
        const auto stored = nlohmann::json::parse(raw);
        if (stored.contains("enabled") && stored["enabled"].is_boolean()) {
            settings["enabled"] = stored["enabled"].get<bool>();
        }
        if (stored.contains("port") && stored["port"].is_number_integer()) {
            settings["port"] = stored["port"].get<int>();
        }
    } catch (const std::exception&) {
        // A damaged file must not leave the panel exposed: fall back to closed.
    }
    return settings;
}

bool save_settings(const nlohmann::json& settings) {
    std::ofstream file(kSettingsPath, std::ios::out | std::ios::trunc);
    if (!file.is_open()) return false;
    file << settings.dump(2) << "\n";
    return file.good();
}

// Login must be on before anything is published. Reading auth.json directly
// keeps this independent of whichever provider is configured.
bool login_required() {
    try {
        const auto raw = read_file(kAuthPath);
        if (raw.empty()) return false;
        const auto parsed = nlohmann::json::parse(raw);
        return parsed.value("enabled", false);
    } catch (const std::exception&) {
        return false;
    }
}

// True when the kernel actually has an interface by this name.
//
// iptables accepts "-i" for names that do not exist, on the assumption the
// interface will appear later. That turned a wrong name into a rule which is
// present, looks right in -S output, and never matches anything.
bool kernel_interface_exists(const std::string& name) {
    std::ifstream dev("/proc/net/dev");
    if (!dev.is_open()) {
        return true; // Cannot check; do not block on our own inability to tell.
    }
    std::string line;
    while (std::getline(dev, line)) {
        const auto colon = line.find(':');
        if (colon == std::string::npos) {
            continue;
        }
        const auto begin = line.find_first_not_of(" \t");
        if (begin == std::string::npos || begin >= colon) {
            continue;
        }
        if (line.substr(begin, colon - begin) == name) {
            return true;
        }
    }
    return false;
}

// The device carrying the default route in the main table.
//
// Asking the firmware was the mistake: RCI answers in its own vocabulary -
// "ISP", "GigabitEthernet1" - and those are roles and configuration ids, not
// kernel device names. The routing table is where the two worlds already
// agree, and keen-pbr keeps tunnel defaults in tables of their own, so the
// main table's default is the uplink by construction.
std::string wan_interface() {
    std::ifstream routes("/proc/net/route");
    if (!routes.is_open()) {
        return {};
    }

    std::string line;
    std::getline(routes, line); // header

    std::string best_iface;
    long best_metric = std::numeric_limits<long>::max();

    while (std::getline(routes, line)) {
        std::istringstream fields(line);
        std::string iface, destination, gateway, flags, refcnt, use, metric;
        if (!(fields >> iface >> destination >> gateway >> flags >> refcnt >> use >> metric)) {
            continue;
        }
        if (destination != "00000000" || iface == "lo") {
            continue;
        }
        long metric_value = 0;
        try {
            metric_value = std::stol(metric);
        } catch (const std::exception&) {
            metric_value = 0;
        }
        if (metric_value < best_metric) {
            best_metric = metric_value;
            best_iface = iface;
        }
    }

    return best_iface;
}

void drop_rules() {
    safe_exec({"iptables", "-D", "INPUT", "-j", kChain}, true);
    safe_exec({"iptables", "-F", kChain}, true);
    safe_exec({"iptables", "-X", kChain}, true);
    safe_exec({"iptables", "-t", "nat", "-D", "PREROUTING", "-j", kChain}, true);
    safe_exec({"iptables", "-t", "nat", "-F", kChain}, true);
    safe_exec({"iptables", "-t", "nat", "-X", kChain}, true);
}

} // namespace

bool listen_address_is_reachable(const std::string& listen_address) {
    if (listen_address.empty()) {
        // Nothing to check against; assume the caller knows better than we do.
        return true;
    }
    const auto colon = listen_address.rfind(':');
    const auto host = colon == std::string::npos ? listen_address
                                                 : listen_address.substr(0, colon);
    return host != "127.0.0.1" && host != "localhost" && host != "::1";
}

void apply_remote_access_rules(const std::string& listen_address) {
    std::lock_guard<std::mutex> lock(settings_mutex());
    const auto settings = load_settings();

    drop_rules();

    if (!settings.value("enabled", false)) {
        return;
    }
    if (!login_required()) {
        Logger::instance().warn(
            "Remote access is enabled in settings but login is off; keeping the panel closed");
        return;
    }
    // Opening the firewall in front of a loopback-only listener produces a
    // port that accepts nothing, which from outside is indistinguishable from
    // a blocked one - so say it plainly instead of pretending it worked.
    if (!listen_address_is_reachable(listen_address)) {
        Logger::instance().error(
            "Remote access cannot work: the panel is bound to {}, which only accepts "
            "connections from the router itself. Set api.listen to 0.0.0.0:<port> and restart.",
            listen_address);
        return;
    }

    const auto wan = wan_interface();
    if (wan.empty()) {
        Logger::instance().error(
            "Remote access: no default route to hang the rule on, keeping the panel closed");
        return;
    }
    // Checked because the previous version installed a rule on the firmware's
    // name for the uplink ("ISP"), which iptables accepted and never matched.
    if (!kernel_interface_exists(wan)) {
        Logger::instance().error(
            "Remote access: '{}' is not a kernel interface, so the rule would never match; "
            "keeping the panel closed",
            wan);
        return;
    }

    const int port = settings.value("port", kDefaultPort);
    const auto port_text = std::to_string(port);

    safe_exec({"iptables", "-N", kChain}, true);
    safe_exec({"iptables", "-I", "INPUT", "1", "-j", kChain}, true);
    safe_exec({"iptables", "-A", kChain, "-i", wan, "-p", "tcp", "--dport",
               std::to_string(kInternalPort), "-j", "ACCEPT"}, true);

    if (port != kInternalPort) {
        safe_exec({"iptables", "-t", "nat", "-N", kChain}, true);
        safe_exec({"iptables", "-t", "nat", "-I", "PREROUTING", "1", "-j", kChain}, true);
        safe_exec({"iptables", "-t", "nat", "-A", kChain, "-i", wan, "-p", "tcp",
                   "--dport", port_text, "-j", "REDIRECT", "--to-ports",
                   std::to_string(kInternalPort)}, true);
        safe_exec({"iptables", "-A", kChain, "-i", wan, "-p", "tcp", "--dport",
                   port_text, "-j", "ACCEPT"}, true);
    }

    Logger::instance().warn(
        "Remote access is OPEN: the web interface is reachable from the internet on {}:{}",
        wan, port);
}

void register_remote_access_handler(ApiServer& server, ApiContext& ctx) {
    server.get("/api/system/remote-access", [&ctx]() -> std::string {
        const auto config = ctx.get_visible_config();
        const auto listen = config.api.has_value()
                                ? config.api->listen.value_or(std::string{})
                                : std::string{};

        std::lock_guard<std::mutex> lock(settings_mutex());
        auto settings = load_settings();
        settings["login_required"] = login_required();
        settings["internal_port"] = kInternalPort;
        settings["listen"] = listen;
        settings["listen_reachable"] = listen_address_is_reachable(listen);
        return settings.dump();
    });

    server.post("/api/system/remote-access", [&ctx](const std::string& body) -> std::string {
        nlohmann::json response;
        try {
            const auto request = nlohmann::json::parse(body);
            const bool enabled = request.value("enabled", false);
            const int port = request.value("port", kDefaultPort);

            if (port < 1 || port > 65535) {
                response["error"] = "port must be between 1 and 65535";
                return response.dump();
            }
            // Refusing here rather than warning later: the whole point of the
            // check is that the panel never reaches the internet unprotected.
            if (enabled && !login_required()) {
                response["error"] = "login_disabled";
                return response.dump();
            }

            const auto config = ctx.get_visible_config();
            const auto listen = config.api.has_value()
                                    ? config.api->listen.value_or(std::string{})
                                    : std::string{};
            if (enabled && !listen_address_is_reachable(listen)) {
                response["error"] = "listen_loopback";
                response["listen"] = listen;
                return response.dump();
            }

            nlohmann::json settings;
            settings["enabled"] = enabled;
            settings["port"] = port;
            if (!save_settings(settings)) {
                response["error"] = "cannot write remote-access.json";
                return response.dump();
            }

            apply_remote_access_rules(listen);
            response["ok"] = true;
            response["settings"] = settings;
        } catch (const std::exception& e) {
            response["error"] = e.what();
        }
        return response.dump();
    });
}

} // namespace keen_pbr3

#endif // WITH_API
