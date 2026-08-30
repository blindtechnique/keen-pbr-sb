#pragma once

// What nfqws2 has been failing on, and where to read it from.
//
// A scan pass needs four things out of nfqws2's own configuration: the file it
// writes its auto-hostlist decisions to, the device that faces the provider (so
// the direct leg really is direct), and the two hostlists that say what nfqws2
// already considers its own. Both the `scan-tunnel-candidates` command and the
// daemon's periodic pass need exactly that, so it lives here rather than in
// either of them.
//
// Reading is injectable. The parsing is the part that has been wrong before -
// `--hostlist-auto-debug=` hiding inside `--hostlist-auto=`, a shell assignment
// quoting its value while an nfqws2 flag does not - and that part deserves
// tests that never touch a filesystem.

#include "host_coverage.hpp"

#include "../config/config.hpp"

#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Where nfqws2 keeps its configuration on the router.
constexpr const char* kNfqwsConfigPath = "/opt/etc/nfqws2/nfqws2.conf";

// Pulls one `--flag=value` out of nfqws2.conf as it is written there.
//
// Deliberately a plain scan rather than a shell evaluation: a caller only needs
// to find files to read, and running the operator's configuration as a script
// to learn a path would be a poor trade.
std::string nfqws_flag_value(const std::string& config, const std::string& flag);

// Everything a pass needs from nfqws2's configuration.
struct NfqwsScanSource {
    // --hostlist-auto-debug: where nfqws2 records what it decided and why.
    std::string log_path;
    // ISP_INTERFACE: the provider's own device.
    std::string isp_interface;
    // --hostlist: what nfqws2 was told to handle.
    std::vector<std::string> handled;
    // --hostlist-exclude: what nfqws2 was told to leave alone.
    std::vector<std::string> excluded;
};

// Why a source could not be assembled. Each caller says it in its own voice -
// the command prints advice, the daemon logs and stands down - so this reports
// the shape of the problem rather than a message.
enum class NfqwsScanSourceError {
    ok,
    // nfqws2.conf could not be read at all.
    config_unreadable,
    // nfqws2 is not writing its auto-hostlist decisions anywhere.
    no_debug_log,
    // Nothing says which device faces the provider.
    no_isp_interface,
};

// Reads a file whole, or returns empty when it cannot be read. The two are not
// distinguished on purpose: for every file here an empty one is as useless as
// a missing one.
using FileReader = std::function<std::string(const std::string&)>;

struct NfqwsScanSourceResult {
    std::optional<NfqwsScanSource> source;
    NfqwsScanSourceError error{NfqwsScanSourceError::ok};
};

// Assembles the source by reading `config_path` and then the files it names.
NfqwsScanSourceResult read_nfqws_scan_source(const std::string& config_path,
                                             const FileReader& read_file);

// The default reader: the filesystem.
std::string read_whole_file(const std::string& path);

// What is already covered, from the routing configuration plus what nfqws2
// owns. `nfqws_handled` is deliberately not coverage: a host nfqws2 was asked
// to handle and kept failing on is exactly the subject of a scan.
CoverageIndex build_scan_coverage(const Config& config,
                                  const NfqwsScanSource& source);

}  // namespace keen_pbr3
