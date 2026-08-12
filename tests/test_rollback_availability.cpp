#include <doctest/doctest.h>

#include "../src/update/rescue_integrity.hpp"
#include "../src/update/rollback_availability.hpp"

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <system_error>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace {

namespace fs = std::filesystem;
using keen_pbr3::PackageRollbackObservations;
using keen_pbr3::PackageRollbackState;
using keen_pbr3::RescueStoreLayout;
using keen_pbr3::classify_package_rollback;
using keen_pbr3::observe_package_rollback;
using keen_pbr3::package_rollback_is_available;
using keen_pbr3::package_rollback_state_message;
using keen_pbr3::package_rollback_state_name;
using keen_pbr3::rescue_integrity::kManagedFiles;
using keen_pbr3::rescue_integrity::sha256_file;

class TempDirectory {
public:
    TempDirectory() {
        std::string pattern =
            (fs::temp_directory_path() / "keen-pbr-rollback-XXXXXX").string();
        std::vector<char> writable(pattern.begin(), pattern.end());
        writable.push_back('\0');
        const char* created = ::mkdtemp(writable.data());
        if (created == nullptr)
            throw std::system_error(errno, std::generic_category(), "mkdtemp");
        path = created;
    }

    ~TempDirectory() {
        std::error_code error;
        fs::remove_all(path, error);
    }

    fs::path path;
};

void write_file(const fs::path& path,
                const std::string& content,
                mode_t mode = 0600) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    REQUIRE(output);
    output << content;
    output.close();
    REQUIRE(output);
    REQUIRE(::chmod(path.c_str(), mode) == 0);
}

void write_package(const fs::path& path, const std::string& content) {
    write_file(path, content);
    const auto digest = sha256_file(path);
    REQUIRE(digest.has_value());
    write_file(fs::path(path.string() + ".sha256"), *digest + "\n");
}

void build_snapshot(const fs::path& path) {
    std::error_code error;
    fs::remove_all(path, error);
    REQUIRE_FALSE(error);
    fs::create_directories(path);
    write_file(path / "config.json", "{}\n", 0600);
    const auto config_hash = sha256_file(path / "config.json");
    REQUIRE(config_hash.has_value());

    std::string manifest = "keen-pbr-snapshot-v2\n";
    for (const auto name : kManagedFiles) {
        if (name == "config.json") {
            manifest += "present config.json 600 " + *config_hash + "\n";
        } else {
            manifest += "absent " + std::string(name) + " - -\n";
        }
    }
    write_file(path / ".snapshot-manifest", manifest);
    const auto manifest_hash = sha256_file(path / ".snapshot-manifest");
    REQUIRE(manifest_hash.has_value());
    write_file(path / ".snapshot-ready", *manifest_hash + "\n");
}

// The store as the shipped helper lays it out, under a directory the test owns.
RescueStoreLayout layout_for(const fs::path& root) {
    RescueStoreLayout layout;
    layout.helper = root / "rescue-update.sh";
    layout.previous_package = root / "previous.ipk";
    layout.previous_config = root / "previous-config";
    layout.pending_marker = root / "pending";
    layout.unknown_marker = root / "UNKNOWN";
    return layout;
}

void install_helper(const RescueStoreLayout& layout) {
    write_file(layout.helper, "#!/bin/sh\nexit 0\n", 0755);
}

// Everything a rollback needs, and nothing that would block it.
void build_complete_store(const RescueStoreLayout& layout) {
    install_helper(layout);
    write_package(layout.previous_package, "previous-package\n");
    build_snapshot(layout.previous_config);
}

const std::vector<PackageRollbackState>& every_state() {
    static const std::vector<PackageRollbackState> states = {
        PackageRollbackState::available,
        PackageRollbackState::recovery_pending,
        PackageRollbackState::recovery_unknown,
        PackageRollbackState::helper_missing,
        PackageRollbackState::never_captured,
        PackageRollbackState::package_unverified,
        PackageRollbackState::snapshot_unverified,
    };
    return states;
}

} // namespace

TEST_CASE("only the available state reports a rollback as possible") {
    for (const auto state : every_state()) {
        CHECK(package_rollback_is_available(state) ==
              (state == PackageRollbackState::available));
    }
}

TEST_CASE("every state carries a distinct name and a reason") {
    std::set<std::string> names;
    std::set<std::string> messages;
    for (const auto state : every_state()) {
        const std::string name = package_rollback_state_name(state);
        const std::string message = package_rollback_state_message(state);
        CHECK_FALSE(name.empty());
        // A state whose reason is empty is a state that tells an operator
        // nothing they did not already know from the bare boolean.
        CHECK_FALSE(message.empty());
        CHECK(names.insert(name).second);
        CHECK(messages.insert(message).second);
    }
}

TEST_CASE("a store that cannot describe itself is reported before its contents") {
    PackageRollbackObservations observations;
    observations.helper_usable = true;
    observations.previous_package_present = true;
    observations.previous_package_verified = true;
    observations.previous_config_present = true;
    observations.previous_config_verified = true;
    REQUIRE(classify_package_rollback(observations) ==
            PackageRollbackState::available);

    // A complete-looking store is not a rollback target while a transition is
    // unfinished: what it describes is the move, not a resting state.
    observations.recovery_pending = true;
    CHECK(classify_package_rollback(observations) ==
          PackageRollbackState::recovery_pending);

    // UNKNOWN outranks pending. Pending says what is happening; UNKNOWN says
    // the store's own account of itself cannot be trusted, and that has to
    // reach the operator rather than be hidden behind the milder value.
    observations.recovery_unknown = true;
    CHECK(classify_package_rollback(observations) ==
          PackageRollbackState::recovery_unknown);
}

TEST_CASE("recovery outranks an empty store, not only a complete one") {
    // The precedence above is invisible when everything else is in order:
    // checking the markers last still reaches them and returns the same value.
    // It only becomes observable when the store is degenerate as well - which
    // is the state a real router is actually in, since a package installed
    // with opkg captures nothing.
    //
    // The distinction matters to the operator: "recovery pending" is something
    // to finish, "never captured" is something to accept. Reporting the second
    // while the first is true sends them to the wrong action.
    PackageRollbackObservations observations;
    observations.helper_usable = true;
    REQUIRE(classify_package_rollback(observations) ==
            PackageRollbackState::never_captured);

    observations.recovery_pending = true;
    CHECK(classify_package_rollback(observations) ==
          PackageRollbackState::recovery_pending);

    observations.recovery_pending = false;
    observations.recovery_unknown = true;
    CHECK(classify_package_rollback(observations) ==
          PackageRollbackState::recovery_unknown);

    // And with nothing at all to drive a rollback, the unfinished transition
    // still outranks the missing helper.
    observations.helper_usable = false;
    CHECK(classify_package_rollback(observations) ==
          PackageRollbackState::recovery_unknown);
    observations.recovery_unknown = false;
    observations.recovery_pending = true;
    CHECK(classify_package_rollback(observations) ==
          PackageRollbackState::recovery_pending);
}

TEST_CASE("a missing helper is reported before the store contents") {
    PackageRollbackObservations observations;
    observations.previous_package_present = true;
    observations.previous_package_verified = true;
    observations.previous_config_present = true;
    observations.previous_config_verified = true;
    // The contents are perfect and still unusable: nothing can drive them.
    CHECK(classify_package_rollback(observations) ==
          PackageRollbackState::helper_missing);

    // Also with nothing captured, where the two answers differ: a store that
    // was never written is not the reason a rollback cannot run when the tool
    // that would run it is absent.
    observations = PackageRollbackObservations{};
    CHECK(classify_package_rollback(observations) ==
          PackageRollbackState::helper_missing);
}

TEST_CASE("absence and damage are separated") {
    PackageRollbackObservations observations;
    observations.helper_usable = true;
    CHECK(classify_package_rollback(observations) ==
          PackageRollbackState::never_captured);

    // Half a pair is not an absence. Something wrote this store and it is now
    // wrong, which calls for a different response than "run one update".
    observations.previous_config_present = true;
    CHECK(classify_package_rollback(observations) ==
          PackageRollbackState::package_unverified);

    observations.previous_package_present = true;
    CHECK(classify_package_rollback(observations) ==
          PackageRollbackState::package_unverified);

    observations.previous_package_verified = true;
    CHECK(classify_package_rollback(observations) ==
          PackageRollbackState::snapshot_unverified);

    observations.previous_config_verified = true;
    CHECK(classify_package_rollback(observations) ==
          PackageRollbackState::available);
}

TEST_CASE("a complete store on disk is observed as available") {
    TempDirectory directory;
    const auto layout = layout_for(directory.path);
    build_complete_store(layout);
    CHECK(classify_package_rollback(observe_package_rollback(layout)) ==
          PackageRollbackState::available);
}

TEST_CASE("the store left by an opkg install reports never_captured") {
    // Measured on the live router before this was written: the rescue
    // directory held its three scripts and no packages at all, because only
    // keen-pbr's own update path writes them. The status endpoint said
    // "rollback unavailable" and nothing said why.
    //
    // This is the case the slice exists for, so it is asserted against a store
    // built to look exactly like the measured one.
    TempDirectory directory;
    const auto layout = layout_for(directory.path);
    install_helper(layout);
    write_file(directory.path / "portable-stat.sh", "#!/bin/sh\n", 0755);
    write_file(directory.path / "update-lock.sh", "#!/bin/sh\n", 0755);

    const auto observations = observe_package_rollback(layout);
    CHECK_FALSE(observations.previous_package_present);
    CHECK_FALSE(observations.previous_config_present);
    CHECK(observations.helper_usable);
    CHECK(classify_package_rollback(observations) ==
          PackageRollbackState::never_captured);
}

TEST_CASE("a tampered previous package is damage, not absence") {
    TempDirectory directory;
    const auto layout = layout_for(directory.path);
    build_complete_store(layout);
    REQUIRE(classify_package_rollback(observe_package_rollback(layout)) ==
            PackageRollbackState::available);

    // Rewrite the archive without touching its sidecar.
    write_file(layout.previous_package, "tampered\n");
    const auto observations = observe_package_rollback(layout);
    CHECK(observations.previous_package_present);
    CHECK_FALSE(observations.previous_package_verified);
    CHECK(classify_package_rollback(observations) ==
          PackageRollbackState::package_unverified);
}

TEST_CASE("a broken configuration snapshot is not reported as a missing one") {
    TempDirectory directory;
    const auto layout = layout_for(directory.path);
    build_complete_store(layout);
    REQUIRE(classify_package_rollback(observe_package_rollback(layout)) ==
            PackageRollbackState::available);

    std::error_code error;
    fs::remove(layout.previous_config / ".snapshot-ready", error);
    REQUIRE_FALSE(error);
    const auto observations = observe_package_rollback(layout);
    CHECK(observations.previous_config_present);
    CHECK_FALSE(observations.previous_config_verified);
    CHECK(classify_package_rollback(observations) ==
          PackageRollbackState::snapshot_unverified);
}

TEST_CASE("recovery markers on disk suppress an otherwise complete store") {
    TempDirectory directory;
    const auto layout = layout_for(directory.path);
    build_complete_store(layout);

    write_file(layout.pending_marker, "rollback-previous\n");
    CHECK(classify_package_rollback(observe_package_rollback(layout)) ==
          PackageRollbackState::recovery_pending);

    write_file(layout.unknown_marker, "interrupted\n");
    CHECK(classify_package_rollback(observe_package_rollback(layout)) ==
          PackageRollbackState::recovery_unknown);
}

TEST_CASE("a helper that is not executable is not a usable helper") {
    TempDirectory directory;
    const auto layout = layout_for(directory.path);
    build_complete_store(layout);
    // No execute bit at all, so this holds under root too: root's X_OK check
    // still requires at least one of them to be set.
    REQUIRE(::chmod(layout.helper.c_str(), 0644) == 0);

    const auto observations = observe_package_rollback(layout);
    CHECK_FALSE(observations.helper_usable);
    CHECK(classify_package_rollback(observations) ==
          PackageRollbackState::helper_missing);
}
