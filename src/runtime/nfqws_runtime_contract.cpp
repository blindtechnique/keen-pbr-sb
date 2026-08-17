#include "nfqws_runtime_contract.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <system_error>
#include <vector>

namespace keen_pbr3 {
namespace {

namespace fs = std::filesystem;

struct BoundedRead {
    bool ok{false};
    bool too_large{false};
    std::string data;
};

BoundedRead read_bounded(const fs::path& path, std::size_t limit) {
    BoundedRead result;
    std::ifstream input(path, std::ios::binary);
    if (!input) return result;

    char buffer[4096];
    while (input) {
        input.read(buffer, static_cast<std::streamsize>(sizeof(buffer)));
        const auto count = input.gcount();
        if (count <= 0) continue;
        const auto size = static_cast<std::size_t>(count);
        if (size > limit - std::min(limit, result.data.size())) {
            result.too_large = true;
            result.data.clear();
            return result;
        }
        result.data.append(buffer, size);
    }
    if (!input.eof()) return result;
    result.ok = true;
    return result;
}

std::vector<std::string> split_nul_argv(const std::string& data) {
    std::vector<std::string> result;
    std::size_t begin = 0;
    while (begin < data.size()) {
        const auto end = data.find('\0', begin);
        const auto finish = end == std::string::npos ? data.size() : end;
        if (finish > begin) result.push_back(data.substr(begin, finish - begin));
        if (end == std::string::npos) break;
        begin = end + 1U;
    }
    return result;
}

bool numeric_name(const std::string& name) {
    return !name.empty() &&
           std::all_of(name.begin(), name.end(), [](unsigned char ch) {
               return std::isdigit(ch) != 0;
           });
}

std::string trim_line(std::string value) {
    while (!value.empty() &&
           (value.back() == '\n' || value.back() == '\r' ||
            value.back() == '\0')) {
        value.pop_back();
    }
    return value;
}

std::optional<std::string> linux_process_starttime(const std::string& stat) {
    // /proc/<pid>/stat field 2 is parenthesized and may contain spaces or ')'.
    // Find the final ") " delimiter, then field 3 starts the ordinary
    // space-delimited tail. starttime is field 22, i.e. tail token 20.
    const auto close = stat.rfind(") ");
    if (close == std::string::npos) return std::nullopt;
    std::istringstream fields(stat.substr(close + 2U));
    std::string value;
    for (std::size_t field = 3U; field <= 22U; ++field) {
        if (!(fields >> value)) return std::nullopt;
    }
    if (value.empty() ||
        !std::all_of(value.begin(), value.end(), [](unsigned char ch) {
            return std::isdigit(ch) != 0;
        })) {
        return std::nullopt;
    }
    return value;
}

std::optional<std::string> read_process_identity(const fs::path& process) {
    const auto stat = read_bounded(process / "stat", 4096U);
    if (!stat.ok) return std::nullopt;
    return linux_process_starttime(stat.data);
}

NfqwsPpeRuntimeContractObservation unavailable(
    std::string diagnostic,
    NfqwsPpePortContract contract = {}) {
    NfqwsPpeRuntimeContractObservation result;
    result.diagnostic = std::move(diagnostic);
    result.contract = std::move(contract);
    return result;
}

bool queue_is_bound(const std::string& table, int expected_queue) {
    std::istringstream lines(table);
    std::string line;
    while (std::getline(lines, line)) {
        std::istringstream fields(line);
        int queue = -1;
        if (fields >> queue && queue == expected_queue) return true;
    }
    return false;
}

} // namespace

NfqwsPpeRuntimeContractObservation observe_nfqws_ppe_runtime_contract(
    const NfqwsRuntimeContractPaths& paths,
    const NfqwsPathResolver& resolve_path) {
    const auto config_read = read_bounded(paths.active_config,
                                          paths.max_config_bytes);
    if (!config_read.ok) {
        return unavailable(config_read.too_large
                               ? "active nfqws configuration exceeds the read bound"
                               : "active nfqws configuration is unavailable");
    }

    auto expected = extract_nfqws_ppe_port_contract(config_read.data,
                                                     resolve_path);
    if (!expected.available) {
        return unavailable("active nfqws configuration has no PPE contract: " +
                               expected.reason,
                           std::move(expected));
    }

    std::error_code error;
    fs::directory_iterator iterator(paths.proc_root, error);
    if (error) {
        return unavailable("nfqws process table is unavailable", expected);
    }

    struct StableProcess {
        fs::path path;
        std::string starttime;
    };
    std::vector<StableProcess> processes;
    std::size_t inspected = 0;
    const fs::directory_iterator end;
    for (; iterator != end; iterator.increment(error)) {
        if (error) {
            return unavailable("nfqws process table inspection failed", expected);
        }
        const auto name = iterator->path().filename().string();
        if (!numeric_name(name)) continue;
        if (++inspected > paths.max_proc_entries) {
            return unavailable("nfqws process table exceeds the inspection bound",
                               expected);
        }
        const auto identity = read_process_identity(iterator->path());
#ifdef KEEN_PBR3_TESTING
        if (identity.has_value() && paths.after_identity_read)
            paths.after_identity_read(iterator->path().string());
#endif
        const auto comm = read_bounded(iterator->path() / "comm", 64U);
        if (!comm.ok) continue; // a process may exit between directory reads
        const auto process_name = trim_line(comm.data);
        if (process_name != "nfqws2" && process_name != "nfqws") continue;
        if (!identity.has_value()) {
            return unavailable(
                "nfqws process identity is unavailable", expected);
        }
        const auto identity_after = read_process_identity(iterator->path());
        if (!identity_after.has_value() || *identity_after != *identity) {
            return unavailable(
                "nfqws process identity changed during observation", expected);
        }
        processes.push_back({iterator->path(), *identity});
    }
    if (error) {
        return unavailable("nfqws process table inspection failed", expected);
    }

    if (processes.size() != 1U) {
        auto result = unavailable(
            processes.empty() ? "nfqws process is not running"
                              : "multiple nfqws processes make runtime ownership ambiguous",
            expected);
        result.process_count = processes.size();
        return result;
    }

    const auto cmdline = read_bounded(processes.front().path / "cmdline",
                                      paths.max_cmdline_bytes);
    if (!cmdline.ok || cmdline.data.empty()) {
        auto result = unavailable(
            cmdline.too_large ? "nfqws cmdline exceeds the read bound"
                              : "nfqws cmdline is unavailable",
            expected);
        result.process_count = 1U;
        return result;
    }
    const auto argv = split_nul_argv(cmdline.data);
    if (argv.empty()) {
        auto result = unavailable("nfqws cmdline is empty", expected);
        result.process_count = 1U;
        return result;
    }
    const auto identity_after_cmdline =
        read_process_identity(processes.front().path);
    if (!identity_after_cmdline.has_value() ||
        *identity_after_cmdline != processes.front().starttime) {
        auto result = unavailable(
            "nfqws process identity changed while reading cmdline", expected);
        result.process_count = 1U;
        return result;
    }
    const auto executable = fs::path(argv.front()).filename().string();
    if (executable != "nfqws2" && executable != "nfqws") {
        auto result = unavailable(
            "nfqws process executable name does not match its comm entry",
            expected);
        result.process_count = 1U;
        return result;
    }

    const auto live = extract_nfqws_ppe_port_contract_from_argv(argv);
    if (!live.available) {
        auto result = unavailable("live nfqws cmdline has no PPE contract: " +
                                      live.reason,
                                  expected);
        result.process_count = 1U;
        return result;
    }

    if (live.queue_number != expected.queue_number ||
        live.tcp_ranges != expected.tcp_ranges ||
        live.quic_udp_443 != expected.quic_udp_443) {
        auto result = unavailable(
            "config_runtime_mismatch: live nfqws queue or traffic selectors differ from nfqws2.conf",
            expected);
        result.process_count = 1U;
        return result;
    }

    const auto queue_table = read_bounded(paths.nfqueue_table,
                                          paths.max_queue_bytes);
    if (!queue_table.ok) {
        auto result = unavailable(
            queue_table.too_large ? "NFQUEUE table exceeds the read bound"
                                  : "NFQUEUE table is unavailable",
            expected);
        result.process_count = 1U;
        result.config_runtime_match = true;
        return result;
    }
    const bool bound = queue_is_bound(queue_table.data, expected.queue_number);
    if (!bound) {
        auto result = unavailable("configured NFQUEUE is not bound", expected);
        result.process_count = 1U;
        result.config_runtime_match = true;
        return result;
    }

    const auto final_identity = read_process_identity(processes.front().path);
    if (!final_identity.has_value() ||
        *final_identity != processes.front().starttime) {
        auto result = unavailable(
            "nfqws process identity changed before observation completed",
            expected);
        result.process_count = 1U;
        result.queue_bound = true;
        result.config_runtime_match = true;
        return result;
    }

    NfqwsPpeRuntimeContractObservation result;
    result.available = true;
    result.process_count = 1U;
    result.queue_bound = true;
    result.config_runtime_match = true;
    result.contract = std::move(expected);
    return result;
}

} // namespace keen_pbr3
