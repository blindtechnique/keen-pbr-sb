#pragma once

// One pass of the automation, from nfqws2's log to a list file.
//
// Every side effect is injected: reading files, writing one, probing a host,
// asking the registry, and telling the caller that the list changed. What is
// left is the order of the steps and the decision to stop at each one, which
// is the part worth testing.

#include "nfqws_scan_source.hpp"
#include "tunnel_candidate_scan.hpp"
#include "tunnel_probe_automation.hpp"

#include "../config/config.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

class TunnelProbeTask {
public:
    struct Io {
        FileReader read_file;
        // False when the file could not be written. The pass then reports what
        // it would have added rather than claiming it did.
        std::function<bool(const std::string& path,
                           const std::string& contents)> write_file;
        // Runs one prepared request. The task builds it, because which device
        // each leg is pinned to is the subtle part: the direct leg must go out
        // the provider's own interface, which is named in nfqws2's
        // configuration and so is not knowable to the caller.
        std::function<DifferentialProbeReport(const DifferentialProbeRequest&)>
            run_probe;
        // Optional. Without it the registry gate cannot be satisfied, so a
        // pass that requires confirmation will hold everything back rather
        // than act on an unanswered question.
        TunnelCandidateScan::RegistryFn registry_lookup;
        // Called once after a write that changed the file, so the caller can
        // make the new hosts take effect.
        std::function<void(const TunnelProbeSetup&)> on_list_changed;
    };

    struct PassOutcome {
        // The pass reached the point of probing. False for every early exit
        // below, each of which names its own reason.
        bool ran{false};
        TunnelProbeRefusal refusal{TunnelProbeRefusal::none};
        NfqwsScanSourceError source_error{NfqwsScanSourceError::ok};
        // nfqws2's debug log exists but has nothing in it yet.
        bool log_empty{false};
        bool write_failed{false};
        std::size_t probed{0};
        std::size_t remaining{0};
        std::vector<std::string> appended;
        std::vector<std::string> unconfirmed;
        std::vector<std::string> already_present;
    };

    explicit TunnelProbeTask(Io io);

    // Runs one pass against the current configuration. Safe to call when the
    // automation is off: it reports the refusal and does nothing else.
    PassOutcome run(const Config& config);

    // A sentence for a log line, whatever the outcome was.
    static std::string describe(const PassOutcome& outcome);

private:
    Io io_;
    // Kept across passes so the queue remembers what it has already answered,
    // and rebuilt when the configuration names a different tunnel or list.
    std::unique_ptr<TunnelCandidateScan> scan_;
    std::string scan_key_;
};

}  // namespace keen_pbr3
