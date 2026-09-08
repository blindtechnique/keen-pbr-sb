#pragma once

#include "package_footprint.hpp"
#include "component_opkg_metadata.hpp"

#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

// The bytes a component rollback would need, taken before anything replaces
// them.
//
// The roadmap asks for an "exact old+target IPK". The exact old IPK cannot be
// obtained on this device: opkg keeps no package cache, and the feed may no
// longer publish the version that is installed. What is obtainable here is a
// bounded repair point for installed bytes. It is not an exact opkg rollback:
// maintainer-script effects still require a pinned old IPK and a separate
// recovery transaction. Opt-in v3 captures remember exact absent target paths;
// v4 additionally records finite package info files and the shared status snapshot.
//
// This is the same lesson the keen-pbr rescue store taught earlier in this
// work, arriving for a different component: a previous version that was never
// captured cannot be manufactured afterwards. So it is captured first.
//
// Files are stored under sequential names and the manifest maps a name to its
// original path. Nothing derives a storage path from a source path, so no
// input can direct a write outside the store.
struct ComponentCaptureResult {
    bool complete{false};
    std::size_t captured{0};
    // Listed by the footprint and not on disk. No stored blob is needed.
    // Opt-in v3 retains these entries in its manifest; default v2 skips them.
    std::size_t skipped_absent{0};
    // Present and not captured. This is what makes a capture incomplete, and
    // it is named rather than counted so an operator can see what is missing.
    std::vector<std::string> failed;
    bool metadata_recorded{false};
};

// Publishes a complete generation atomically. A failed or interrupted capture
// never replaces the previously selected usable generation.
ComponentCaptureResult capture_component_files(
    const PackageFootprint& footprint,
    const std::filesystem::path& store,
    bool record_absent = false,
    std::optional<ComponentOpkgMetadataPaths> metadata = std::nullopt);

// Re-observes the bounded union before opkg runs, including target-only paths
// which may already contain operator-owned bytes. Only verified target package
// paths belong here; failure preserves the previously selected generation.
ComponentCaptureResult capture_component_upgrade_files(
    const PackageFootprint& previous,
    const std::vector<std::string>& target_paths,
    const std::filesystem::path& store,
    std::optional<ComponentOpkgMetadataPaths> metadata = std::nullopt);

enum class ComponentCaptureState {
    // Payload files match their digests. Optional v4 metadata is checked
    // separately during recovery so damaged metadata cannot block old bytes.
    usable,
    // No capture at all.
    absent,
    // A capture exists without a valid readiness marker: it was interrupted,
    // or its manifest does not match what was declared ready.
    incomplete,
    // Ready, but a stored file is missing or its bytes have drifted. Kept
    // apart from `incomplete` because one means the capture never finished and
    // the other means it finished and then rotted, and only the second says
    // something is damaging this store.
    corrupted,
};

ComponentCaptureState verify_component_capture(
    const std::filesystem::path& store);

const char* component_capture_state_name(
    ComponentCaptureState state) noexcept;

struct ComponentCaptureReinstallPreparation {
    bool complete{false};
    bool metadata_recorded{false};
    bool status_repaired{false};
    std::string error;
    // Structural recovery cannot prove status-only changes lost in a crash.
    bool shared_database_reconstructed{false};
};

// Failed-upgrade/boot rollback only, before spawning the exact old IPK.
// A v4 capture can repair a torn, uniquely identified component status stanza
// without changing any info/payload files or unrelated current paragraphs.
// Healthy databases and legacy captures are left untouched. A missing/torn
// shared database can be reconstructed when the saved database and live foreign
// info agree; healthy current foreign paragraphs win. Lost/conflicting foreign
// info leaves captured-payload/runtime recovery available.
// The native opkg lock is released before this function returns.
ComponentCaptureReinstallPreparation prepare_component_capture_reinstall(
    const std::filesystem::path& store,
    const std::string& expected_version = {});

struct ComponentRestoreResult {
    bool complete{false};
    // Installed bytes and their basic ownership/mode can be verified here,
    // but the old IPK, maintainer-script side effects and unrecorded paths are
    // outside this snapshot. v4 recovers only this package's status paragraph.
    bool exact_package_state{false};
    std::size_t restored{0};
    std::vector<std::string> failed;
    // Why nothing was attempted, when nothing was. Empty on an attempt.
    std::string refused;
    // Actual exact-leaf removals; already absent entries succeed without
    // incrementing this count. No directory trees are ever removed.
    std::size_t removed{0};
    bool metadata_recorded{false};
    bool metadata_restored{false};
    // True even if optional metadata recovery failed. The caller can restart
    // known old runtime bytes without claiming a complete package rollback.
    bool payload_restored{false};
    std::vector<std::string> metadata_failed;
};

// Puts the captured bytes back at their recorded paths, with their recorded
// modes.
//
// Refuses unless the capture verifies first. A restore that discovers halfway
// through that its source is damaged leaves the component in a state that is
// neither the old one nor the new one, which is worse than both.
//
// Manual restore never deletes added files. Only failed-upgrade/boot recovery
// may opt into restoring recorded v3 absences after restoring all present
// entries. It unlinks exact regular/symlink leaves, never follows parent links
// and never removes directories. The same recovery opt-in enables v4 metadata
// after payload recovery; manual restore never changes the opkg database/info.
// Metadata failure is reported independently and does not undo payload repair.
ComponentRestoreResult restore_component_files(
    const std::filesystem::path& store,
    bool restore_absent = false,
    const std::string& expected_version = {});

} // namespace keen_pbr3
