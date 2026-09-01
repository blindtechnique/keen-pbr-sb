#pragma once

#include "../config/config.hpp"
#include "../util/traced_mutex.hpp"

#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

namespace keen_pbr3 {

struct ActiveConfigSnapshot {
    Config config;
    OutboundMarkMap outbound_marks;
};

using ActiveConfigSnapshotHandle =
    std::shared_ptr<const ActiveConfigSnapshot>;

struct VisibleConfigSnapshot {
    Config config;
    bool is_draft{false};
    std::string revision;
};

struct StagedConfigSnapshot {
    Config config;
    std::string serialized;
    std::string base_revision;
    std::string active_revision;
};

// Everything that can allocate for an active-config publication is prepared
// before ConfigStore takes its publication lock. The base handle is an exact
// generation identity, rather than a digest that could be recomputed from a
// different in-memory snapshot.
struct PreparedActiveConfigCommit {
    ActiveConfigSnapshotHandle base;
    ActiveConfigSnapshotHandle candidate;
    std::string staged_serialized;
};

enum class PreparedActiveConfigCommitResult {
    committed,
    base_mismatch,
    staged_mismatch,
};

// A runtime reload is not an API draft save. It publishes a pre-built active
// snapshot only while the exact pinned active base is still current, and it
// must neither require nor modify a concurrently visible panel draft.
struct PreparedActiveRuntimeReloadCommit {
    ActiveConfigSnapshotHandle base;
    ActiveConfigSnapshotHandle candidate;
};

enum class PreparedActiveRuntimeReloadCommitResult {
    committed,
    base_mismatch,
};

class ConfigStore {
public:
    explicit ConfigStore(Config active_config = {});

    ActiveConfigSnapshotHandle pin_active_snapshot() const;
    ActiveConfigSnapshot active_snapshot() const;
    Config active_config() const;
    OutboundMarkMap outbound_marks() const;
    Config visible_config() const;
    VisibleConfigSnapshot visible_snapshot() const;

    // Runs one narrow projection while both active config and the optional
    // panel draft are protected by the same shared lock. The callback must
    // return owned data and must not retain either reference. This avoids a
    // torn two-read delete decision without copying unrelated multi-megabyte
    // lists, URLs or other configuration into the native mutation boundary.
    template <typename Projection>
    auto project_active_and_staged(Projection&& projection) const
        -> decltype(std::forward<Projection>(projection)(
            std::declval<const Config&>(),
            std::declval<const std::optional<Config>&>())) {
        KPBR_SHARED_LOCK(lock, mutex_);
        return std::forward<Projection>(projection)(
            active_snapshot_->config, staged_config_);
    }
    bool config_is_draft() const;

    // Builds one immutable config/mark generation before any publication
    // lock is taken. The same handle can then be shared by runtime
    // preparation and either prepared CAS path without rebuilding or copying
    // the candidate into a second generation object.
    static ActiveConfigSnapshotHandle prepare_active_snapshot(
        Config config,
        OutboundMarkMap outbound_marks);
    void replace_active(Config active_config, OutboundMarkMap outbound_marks);
    static PreparedActiveConfigCommit prepare_active_commit(
        ActiveConfigSnapshotHandle base,
        ActiveConfigSnapshotHandle candidate,
        std::string staged_serialized);
    static PreparedActiveConfigCommit prepare_active_commit(
        ActiveConfigSnapshotHandle base,
        Config candidate_config,
        OutboundMarkMap candidate_outbound_marks,
        std::string staged_serialized);
    static PreparedActiveRuntimeReloadCommit
    prepare_active_runtime_reload_commit(
        ActiveConfigSnapshotHandle base,
        ActiveConfigSnapshotHandle candidate);
    static PreparedActiveRuntimeReloadCommit
    prepare_active_runtime_reload_commit(
        ActiveConfigSnapshotHandle base,
        Config candidate_config,
        OutboundMarkMap candidate_outbound_marks);

    // The caller prepares both shared handles and the exact staged bytes
    // before entering this seam. A throwing publisher is rejected during
    // overload resolution: once the CAS succeeds there is no fallible step
    // between publication and the ConfigStore generation switch.
    template <
        typename Publication,
        std::enable_if_t<
            std::is_nothrow_invocable_v<Publication&>,
            int> = 0>
    PreparedActiveConfigCommitResult commit_prepared_active(
        const PreparedActiveConfigCommit& prepared,
        Publication&& publication) {
        if (!prepared.base || !prepared.candidate) {
            return PreparedActiveConfigCommitResult::base_mismatch;
        }

        KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);
        if (active_snapshot_ != prepared.base) {
            return PreparedActiveConfigCommitResult::base_mismatch;
        }
        if (!staged_config_.has_value() ||
            !staged_config_json_.has_value() ||
            *staged_config_json_ != prepared.staged_serialized) {
            return PreparedActiveConfigCommitResult::staged_mismatch;
        }

        publication();
        // shared_ptr assignment and optional reset do not allocate. The
        // prepared base retains the old generation until after this lock is
        // released, so replacing active_snapshot_ cannot destroy it here.
        active_snapshot_ = prepared.candidate;
        staged_config_.reset();
        staged_config_json_.reset();
        staged_base_revision_.reset();
        return PreparedActiveConfigCommitResult::committed;
    }

    // Runtime reload publication has a separate exact-base CAS so it cannot
    // accidentally inherit the staged-save contract above. The no-throw
    // callback runs under the same unique lock as the active handle switch;
    // on any failed precondition it is not invoked and no state changes.
    // Existing staged data is deliberately left byte-for-byte intact.
    template <
        typename Publication,
        std::enable_if_t<
            std::is_nothrow_invocable_v<Publication&>,
            int> = 0>
    PreparedActiveRuntimeReloadCommitResult
    commit_prepared_active_runtime_reload(
        const PreparedActiveRuntimeReloadCommit& prepared,
        Publication&& publication) {
        if (!prepared.base || !prepared.candidate) {
            return PreparedActiveRuntimeReloadCommitResult::base_mismatch;
        }

        KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);
        if (active_snapshot_ != prepared.base) {
            return PreparedActiveRuntimeReloadCommitResult::base_mismatch;
        }

        publication();
        // Both handles were allocated before entering the lock. Assignment is
        // noexcept and the pinned base keeps the old generation alive until
        // the caller retires its transaction.
        active_snapshot_ = prepared.candidate;
        return PreparedActiveRuntimeReloadCommitResult::committed;
    }

    void stage_config(Config staged_config, std::string staged_config_json);
    bool stage_config_if_visible_revision(
        const std::string& expected_visible_revision,
        Config staged_config,
        std::string staged_config_json);
    std::optional<std::pair<Config, std::string>> staged_snapshot() const;
    std::optional<StagedConfigSnapshot> staged_cas_snapshot() const;
    void clear_staged();
    void clear_staged_if_matches(const std::string& staged_config_json);

private:
    mutable TracedSharedMutex mutex_;
    ActiveConfigSnapshotHandle active_snapshot_ GUARDED_BY(mutex_);
    std::optional<Config> staged_config_ GUARDED_BY(mutex_);
    std::optional<std::string> staged_config_json_ GUARDED_BY(mutex_);
    std::optional<std::string> staged_base_revision_ GUARDED_BY(mutex_);
};

} // namespace keen_pbr3
