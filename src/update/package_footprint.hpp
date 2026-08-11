#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace keen_pbr3 {

// What a package actually occupies on disk, as opposed to what opkg's records
// claim.
//
// Measured on a live router, for nfqws2-keenetic, before this was written:
//
//   * opkg lists 24 files. Eight of them do not exist - the package is built
//     `Architecture: all`, ships a binary for every architecture, and its
//     postinst deletes the staging directory once it has picked one.
//   * The binary that actually runs, /opt/usr/bin/nfqws2, is NOT in opkg's
//     list at all. The postinst creates it with `cp`, so opkg has never heard
//     of the one file whose loss stops the service.
//
// Both directions matter for the component transaction. A rollback driven by
// opkg's records would restore files that are meant to be gone and would not
// restore the binary, because nothing told it the binary exists. And a
// verifier that treated a listed-but-absent file as damage would report a
// perfectly healthy router as broken.
//
// So this records what is there, without inferring intent from an absence.
struct PackageFileState {
    std::string path;
    bool present{false};
    // Present but not hashable - a permission error, a race with a package
    // manager mid-write. Kept apart from absence because "I could not look"
    // is not "it is not there", and only one of them is evidence.
    bool unreadable{false};
    std::string sha256;
    std::uint32_t mode{0};
};

struct PackageFootprint {
    // Sorted by path, so two observations of the same package are directly
    // comparable and a diff is a linear walk.
    std::vector<PackageFileState> files;
    std::size_t present_count{0};
    std::size_t absent_count{0};
    std::size_t unreadable_count{0};
};

// The tracked binary's fate across an upgrade.
enum class PackageBinaryOutcome {
    // The bytes changed. Something really was installed.
    replaced,
    // Byte-identical. Normal when the router already had the current version;
    // reported rather than hidden, because "upgrade succeeded" and "nothing
    // changed" are different answers to the operator's question.
    unchanged,
    // It was there before and is gone now. The upgrade left the service with
    // nothing to run - the one outcome that must never be reported as success.
    missing_after,
    // It was not there before either. Nothing to compare; not a regression.
    absent_throughout,
    // Present on both sides but at least one side could not be read, so no
    // claim about change can be made honestly.
    indeterminate,
};

// Reads opkg's own file list. Returns an empty vector when the record is
// missing, which the caller must not confuse with "the package owns no files".
std::vector<std::string> read_opkg_file_list(
    const std::filesystem::path& list_file);

// Observes the given paths. Duplicates are collapsed; order of the input does
// not matter.
PackageFootprint observe_package_footprint(
    const std::vector<std::string>& paths);

struct PackageFootprintDiff {
    std::vector<std::string> changed;
    std::vector<std::string> added;
    std::vector<std::string> removed;
    // Paths whose state could not be established on one side or the other.
    // Never folded into `changed`: an unreadable file is not a changed file,
    // and counting it as one would make every permission error look like an
    // upgrade doing work.
    std::vector<std::string> indeterminate;
};

PackageFootprintDiff diff_package_footprint(const PackageFootprint& before,
                                            const PackageFootprint& after);

PackageBinaryOutcome judge_package_binary(const PackageFootprint& before,
                                          const PackageFootprint& after,
                                          const std::string& binary_path);

const char* package_binary_outcome_name(PackageBinaryOutcome outcome) noexcept;

} // namespace keen_pbr3
