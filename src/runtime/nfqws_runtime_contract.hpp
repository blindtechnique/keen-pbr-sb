#pragma once

#include "../util/nfqws_validator.hpp"

#include <cstddef>
#include <functional>
#include <string>

namespace keen_pbr3 {

// Fixed production paths with narrow overrides for deterministic unit tests.
// All reads are bounded; this observer never starts/stops nfqws and never
// rewrites its configuration.
struct NfqwsRuntimeContractPaths {
    std::string active_config{"/opt/etc/nfqws2/nfqws2.conf"};
    std::string proc_root{"/proc"};
    std::string nfqueue_table{"/proc/net/netfilter/nfnetlink_queue"};
    std::size_t max_config_bytes{256U * 1024U};
    std::size_t max_cmdline_bytes{256U * 1024U};
    std::size_t max_proc_entries{65536U};
    std::size_t max_queue_bytes{1024U * 1024U};
#ifdef KEEN_PBR3_TESTING
    // Test-only observation hook. Production omits it entirely. It runs after
    // the first PID identity read and before comm/cmdline, allowing a fixture
    // to model PID reuse without exposing any runtime mutation surface.
    std::function<void(const std::string& pid_path)> after_identity_read;
#endif
};

// `available` means all four facts were established in one observation:
// validated active file, exactly one nfqws process, a live cmdline whose queue
// and canonical PPE selectors equal that file, and the same queue bound in the
// kernel.  Anything less is a cleanup/no-apply signal to the firewall owner.
struct NfqwsPpeRuntimeContractObservation {
    bool available{false};
    std::string diagnostic;
    std::size_t process_count{0};
    bool queue_bound{false};
    bool config_runtime_match{false};
    NfqwsPpePortContract contract;
};

NfqwsPpeRuntimeContractObservation observe_nfqws_ppe_runtime_contract(
    const NfqwsRuntimeContractPaths& paths = {},
    const NfqwsPathResolver& resolve_path = {});

} // namespace keen_pbr3
