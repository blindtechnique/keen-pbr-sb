#pragma once

// One pass of the automation, from nfqws2's log to a list file.
//
// Every side effect is injected: reading files, writing one, probing a host,
// asking the registry, and telling the caller that the list changed. What is
// left is the order of the steps and the decision to stop at each one, which
// is the part worth testing.

#include "log_follower.hpp"
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
    // How much of nfqws2's log one pass turns into strings. The file was
    // 1.75 MB after a few days on the owner's router and the router had 134 MiB
    // free; a reader that has been away must not swallow the whole backlog at
    // once. What is left over is read by the next pass.
    static constexpr std::size_t kLogReadBudget = 512U * 1024U;

    struct Io {
        FileReader read_file;
        // Size and first bytes of the log, for deciding whether this is the
        // same file still growing or a new one after rotation. False when the
        // file cannot be inspected at all.
        std::function<bool(const std::string& path,
                           std::uint64_t& size,
                           std::string& fingerprint)> stat_log;
        // At most `budget` bytes starting at `offset`.
        std::function<std::string(const std::string& path,
                                  std::uint64_t offset,
                                  std::size_t budget)> read_log_from;
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
        // Creates the list file when it is not there. Called on every pass
        // that gets as far as a resolved setup, because a list whose `file`
        // does not exist makes list streaming throw, and that throw surfaces
        // inside the firewall apply - a missing file does not disable one
        // list, it stops routing from being applied. The automation owns this
        // file, so it is the one that must make sure it exists.
        std::function<void(const std::string& path)> ensure_file;
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
        // How many new log lines this pass read. Zero is ordinary once the
        // reader has caught up: the queue it built earlier is still there.
        std::size_t new_log_lines{0};
        // The log was re-read from the beginning because it had been rotated,
        // truncated or replaced.
        bool log_restarted{false};
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
    // Where the last pass stopped reading nfqws2's log.
    //
    // This is what makes the queue advance. Feeding the whole file again every
    // pass puts every host back into the queue - including the ones just
    // answered, since the lines that named them are still in the file - so the
    // same handful stays at the head and nothing behind it is ever reached.
    // Measured on the router: eight probed, "120 left for the next pass", pass
    // after pass, the same eight.
    LogPosition log_position_;
};

}  // namespace keen_pbr3
