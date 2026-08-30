#include "nfqws_scan_source.hpp"

#include "../config/list_parser.hpp"
#include "../nfqws/list_match.hpp"

#include <fstream>
#include <map>
#include <sstream>
#include <utility>

namespace keen_pbr3 {

std::string nfqws_flag_value(const std::string& config, const std::string& flag) {
    const auto needle = flag + "=";
    std::size_t from = 0;
    while (true) {
        const auto at = config.find(needle, from);
        if (at == std::string::npos) return {};
        // Only accept it where a flag can start, so `--hostlist-auto-debug=`
        // is never matched inside `--hostlist-auto=`.
        const bool at_flag_start = at == 0 || config[at - 1] == ' ' ||
                                   config[at - 1] == '"' || config[at - 1] == '\n';
        if (at_flag_start) {
            auto value_at = at + needle.size();
            // Shell assignments carry their value in quotes - ISP_INTERFACE
            // is written `ISP_INTERFACE="eth3"` - while nfqws2 flags usually
            // do not. Reading until the first quote would return nothing for
            // the first shape and the whole rest of the line for neither.
            const bool quoted =
                value_at < config.size() && config[value_at] == '"';
            if (quoted) ++value_at;
            const auto end = config.find_first_of(quoted ? "\"\n" : " \"\n",
                                                  value_at);
            return config.substr(value_at, end == std::string::npos
                                               ? std::string::npos
                                               : end - value_at);
        }
        from = at + needle.size();
    }
}

std::string read_whole_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return {};
    std::ostringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

namespace {

std::vector<std::string> read_nfqws_list(const std::string& path,
                                         const FileReader& read_file) {
    if (path.empty()) return {};
    return nfqws::parse_hostlist(read_file(path));
}

}  // namespace

NfqwsScanSourceResult read_nfqws_scan_source(const std::string& config_path,
                                             const FileReader& read_file) {
    NfqwsScanSourceResult result;

    const auto config = read_file(config_path);
    if (config.empty()) {
        result.error = NfqwsScanSourceError::config_unreadable;
        return result;
    }

    NfqwsScanSource source;
    source.log_path = nfqws_flag_value(config, "--hostlist-auto-debug");
    if (source.log_path.empty()) {
        result.error = NfqwsScanSourceError::no_debug_log;
        return result;
    }

    // Without the provider's own device the direct leg would measure whatever
    // routing happened to pick, and the whole comparison would prove nothing.
    source.isp_interface = nfqws_flag_value(config, "ISP_INTERFACE");
    if (source.isp_interface.empty()) {
        result.error = NfqwsScanSourceError::no_isp_interface;
        return result;
    }

    source.handled = read_nfqws_list(nfqws_flag_value(config, "--hostlist"),
                                     read_file);
    source.excluded =
        read_nfqws_list(nfqws_flag_value(config, "--hostlist-exclude"),
                        read_file);

    result.source = std::move(source);
    return result;
}

CoverageIndex build_scan_coverage(const Config& config,
                                  const NfqwsScanSource& source) {
    CoverageIndex index;

    const auto& lists =
        config.lists.value_or(std::map<std::string, ListConfig>{});
    for (const auto& [name, list] : lists) {
        CoverageIndex::RoutingList entry;
        entry.name = name;
        if (list.domains.has_value()) {
            for (const auto& domain : *list.domains) {
                auto normalized = ListParser::normalize_domain(domain);
                if (normalized.has_value()) {
                    entry.domains.push_back(std::move(*normalized));
                }
            }
        }
        if (list.ip_cidrs.has_value()) {
            entry.addresses = *list.ip_cidrs;
        }
        // A list with neither is one that lives in a cache file; this says so
        // rather than pretending the list is empty.
        index.routing_lists.push_back(std::move(entry));
    }

    index.nfqws_handled = source.handled;
    index.nfqws_excluded = source.excluded;
    return index;
}

}  // namespace keen_pbr3
