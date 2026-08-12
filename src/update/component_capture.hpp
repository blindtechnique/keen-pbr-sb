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

} // namespace keen_pbr3
