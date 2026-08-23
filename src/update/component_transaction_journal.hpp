#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace keen_pbr3 {

// A durable record that a component mutation is in flight.
//
// Item 6 asks for byte-exact rollback "on any error or reboot". A reboot is
// the case nothing in this path handles today: `opkg upgrade nfqws2-keenetic`
// runs from an HTTP request, and if the router loses power halfway there is no
// trace that anything was in progress. The next boot brings up whatever
// happens to be on disk, and nobody is looking.
//
// This is the trace. It is written before the first mutation and removed after
// the transaction finishes, so its presence at any later moment means exactly
// one thing: a component mutation started and did not report an end.
//
// Deliberately not a recovery mechanism. Recovery needs captured bytes that do
// not exist yet, and a journal that promised repair it cannot perform would be
// worse than none. What it does is make the interruption knowable, and stop
// the next upgrade from running on top of an unknown state.
enum class ComponentTransactionPhase {
    // Written, nothing mutated yet. An interruption here changed nothing.
    started,
    // The package manager is running. An interruption here can leave the
    // component in any state at all.
    mutating,
    // The mutation returned and the checks are running. The files are settled;
    // what is unknown is whether they work.
    verifying,
};

struct ComponentTransactionRecord {
    std::string component;
    std::string operation;
    ComponentTransactionPhase phase{ComponentTransactionPhase::started};
    // Wall clock, because this outlives the process that wrote it and a
    // monotonic reading means nothing after a reboot.
    std::int64_t started_at{0};
    // Enough of the pre-mutation world to say what was lost, once something
    // can act on it.
    std::string binary_sha256;
    std::string config_sha256;
    bool runtime_was_running{false};
    // What the package manager was asked to do, in package-version terms,
    // and whether the version being replaced is held byte-exact in the
    // component store. A record carrying these lets recovery after a reboot
    // decide between reinstalling the exact previous package and a file-only
    // restore, instead of guessing from whatever opkg now reports. Absent
    // in records written before they existed; empty then, never invented.
    std::string previous_version;
    std::string target_version;
    bool exact_previous_ipk{false};
    // Who is doing this, so a record left behind can be told from one that is
    // being written right now. Filled by the writer; a record without them is
    // readable but can only ever be classified as abandoned.
    //
    // The start time is carried with the pid because pids are reused, and a
    // reboot makes reuse near-certain: without it, any live process that
    // happens to land on the recorded number would make an interrupted
    // operation look like a running one.
    std::int64_t owner_pid{0};
    std::string owner_start;
    // A synchronous HTTP operation runs inside the long-lived API daemon. Its
    // PID surviving does not prove the request handler survived. Such writers
    // set this false, making a leftover record abandoned immediately instead
    // of falsely "in flight" until the daemon restarts.
    bool owner_is_operation_process{true};
};

enum class ComponentTransactionState {
    // No record. Nothing was in flight.
    none,
    // A well-formed record whose owning process is alive. Something is
    // happening right now. Another operation must still wait, but nothing is
    // wrong, and telling an operator their upgrade "did not finish" while it
    // is running is how a warning stops being read.
    in_flight,
    // A well-formed record whose owner is gone. A mutation started and never
    // reported an end - the case a reboot in the middle produces.
    abandoned,
    // A record exists and cannot be read. Reported as its own state and never
    // as `none`: a journal we cannot parse is the one case where assuming
    // "nothing happened" is most likely to be wrong, because a torn write is
    // itself evidence of an interruption.
    unreadable,
};

struct ComponentTransactionStatus {
    ComponentTransactionState state{ComponentTransactionState::none};
    std::optional<ComponentTransactionRecord> record;
};

// Durable: the record is visible after the call returns or not at all.
// Throws on failure - a transaction that could not announce itself must not
// proceed silently.
void write_component_transaction(const std::filesystem::path& path,
                                 const ComponentTransactionRecord& record);

ComponentTransactionStatus read_component_transaction(
    const std::filesystem::path& path);

// Durable removal, including the directory entry. Returns false when the
// record survived, which the caller must treat as the transaction still being
// on record rather than as a cosmetic failure.
bool clear_component_transaction(const std::filesystem::path& path);

const char* component_transaction_phase_name(
    ComponentTransactionPhase phase) noexcept;

const char* component_transaction_state_name(
    ComponentTransactionState state) noexcept;

} // namespace keen_pbr3
