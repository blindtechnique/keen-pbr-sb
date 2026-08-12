#pragma once

#include "package_footprint.hpp"

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace keen_pbr3 {

// The bytes a component rollback would need, taken before anything replaces
// them.
//
// The roadmap asks for an "exact old+target IPK". The exact old IPK cannot be
// obtained on this device: opkg keeps no package cache, and the feed may no
// longer publish the version that is installed. What is obtainable is the only
// thing a rollback actually restores - the installed bytes, which are on the
// disk right now and stop being so the moment opkg runs.
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
    // Listed by the footprint and not on disk. Expected, not a fault: the
    // package deliberately deletes files it declared.
    std::size_t skipped_absent{0};
    // Present and not captured. This is what makes a capture incomplete, and
    // it is named rather than counted so an operator can see what is missing.
    std::vector<std::string> failed;
};

// Replaces any previous capture in `store`. The readiness marker is written
// last, so an interrupted capture is detectably unusable rather than silently
// short.
ComponentCaptureResult capture_component_files(
    const PackageFootprint& footprint,
    const std::filesystem::path& store);

enum class ComponentCaptureState {
    // Every recorded file is present and matches its digest.
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

struct ComponentRestoreResult {
    bool complete{false};
    std::size_t restored{0};
    std::vector<std::string> failed;
    // Why nothing was attempted, when nothing was. Empty on an attempt.
    std::string refused;
};

// Puts the captured bytes back at their recorded paths, with their recorded
// modes.
//
// Refuses unless the capture verifies first. A restore that discovers halfway
// through that its source is damaged leaves the component in a state that is
// neither the old one nor the new one, which is worse than both.
//
// Restores only what was captured. Files the new package added are reported by
// the caller's own footprint diff and deliberately not deleted here: a list of
// paths to unlink, assembled by us rather than by the package manager, is not
// something to run against a live system on the strength of our own bookkeeping.
// So this returns the component to its captured bytes, not the machine to its
// exact former state, and the difference is named rather than glossed.
ComponentRestoreResult restore_component_files(
    const std::filesystem::path& store);

} // namespace keen_pbr3
