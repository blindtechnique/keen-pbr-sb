#ifdef WITH_API

#include "handler_remote_access.hpp"

#include "../http/http_client.hpp"
#include "../log/logger.hpp"
#include "../util/safe_exec.hpp"

#include <fstream>
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

// The interface the firmware itself routes through, so the hole is opened on
// the real uplink rather than on a name that differs per router.
std::string wan_interface() {
    try {
        HttpClient client;
        client.set_timeout(std::chrono::seconds(2));
        client.set_max_response_size(64U * 1024U);
        const auto status = nlohmann::json::parse(
            client.download("http://127.0.0.1:79/rci/show/internet/status"));
        const auto gateway = status.find("gateway");
        if (gateway == status.end() || !gateway->is_object()) return {};
        const auto id = gateway->value("interface", std::string{});
        if (id.empty()) return {};

        const auto interface = nlohmann::json::parse(
            client.download("http://127.0.0.1:79/rci/show/interface/" + id));
        return interface.value("interface-name", interface.value("id", std::string{}));
    } catch (const std::exception&) {
        return {};
    }
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

void apply_remote_access_rules() {
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

    const auto wan = wan_interface();
    if (wan.empty()) {
        Logger::instance().warn(
            "Remote access: could not determine the WAN interface, keeping the panel closed");
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

void register_remote_access_handler(ApiServer& server, ApiContext& /*ctx*/) {
    server.get("/api/system/remote-access", []() -> std::string {
        std::lock_guard<std::mutex> lock(settings_mutex());
        auto settings = load_settings();
        settings["login_required"] = login_required();
        settings["internal_port"] = kInternalPort;
        return settings.dump();
    });

    server.post("/api/system/remote-access", [](const std::string& body) -> std::string {
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

            nlohmann::json settings;
            settings["enabled"] = enabled;
            settings["port"] = port;
            if (!save_settings(settings)) {
                response["error"] = "cannot write remote-access.json";
                return response.dump();
            }

            apply_remote_access_rules();
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
