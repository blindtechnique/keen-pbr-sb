#include <doctest/doctest.h>

#include "../src/update/sing_box_install_observation.hpp"

#include <string>

namespace keen_pbr3 {

namespace {

// What `opkg print-architecture` actually prints on a Keenetic with Entware:
// several architectures with priorities, plus the firmware's own `_kn` ones
// that are not Entware targets.
constexpr const char* kRealOpkgOutput =
    "arch all 1\n"
    "arch aarch64-3.10 10\n"
    "arch aarch64-3.10_kn 20\n";

SingBoxInstallProbes silent_probes() {
    SingBoxInstallProbes probes;
    probes.read_opkg_architectures = []() { return std::string{}; };
    probes.read_binary_version = [](const std::string&) {
        return std::string{};
    };
    probes.path_exists = [](const std::string&) { return false; };
    probes.directory_writable = [](const std::string&) { return false; };
    return probes;
}

} // namespace

TEST_CASE("the Entware architecture is chosen the way the installer chooses") {
    // Several lines, and picking a different one picks a different asset. The
    // firmware's `_kn` architecture has the HIGHEST priority here, which is
    // exactly why it has to be excluded rather than out-ranked.
    CHECK(select_entware_architecture(kRealOpkgOutput) == "aarch64-3.10");
    CHECK(select_entware_architecture("arch all 1\n") .empty());
    CHECK(select_entware_architecture("").empty());

    // Highest priority wins among real candidates.
    CHECK(select_entware_architecture(
              "arch mips-3.4 5\narch mipsel-3.4 15\n") == "mipsel-3.4");
    // Ties keep the last line, matching the installer's awk.
    CHECK(select_entware_architecture(
              "arch a-1 10\narch b-1 10\n") == "b-1");

    // Malformed lines are skipped, not guessed at.
    CHECK(select_entware_architecture(
              "arch aarch64-3.10\narch armv7-3.2 7\n") == "armv7-3.2");
    CHECK(select_entware_architecture("arch armv7-3.2 x\n").empty());
    CHECK(select_entware_architecture(
              "arch armv7-3.2 7 extra\n").empty());
}

TEST_CASE("a version is read only from output shaped like a version") {
    CHECK(parse_sing_box_version("sing-box version 1.13.14\n") == "1.13.14");
    CHECK(parse_sing_box_version(
              "sing-box version 1.13.14\r\n\r\nEnvironment: go1.22\n") ==
          "1.13.14");

    for (const char* unusable :
         {"", "\n", "sing-box\n", "sing-box version\n",
          // A development build is not the pinned release, and letting it
          // read as one would report an unpinned binary as pinned.
          "sing-box version 1.13.14-dirty\n",
          "sing-box version v1.13.14\n",
          // Something else entirely answered.
          "bash: sing-box: not found\n",
          "sing-box version ...\n"}) {
        CHECK(parse_sing_box_version(unusable).empty());
    }
}

TEST_CASE("a router that answers nothing is unknown, never assumed empty") {
    // Every probe fails. The observation must carry that through as absence
    // of knowledge, and the policy must refuse - which is the whole point of
    // measuring separately from deciding.
    const auto observation = observe_sing_box_install(
        silent_probes(), "/opt/bin/sing-box",
        "/opt/etc/keen-pbr/sing-box-managed.path");

    CHECK_FALSE(observation.entware_present);
    CHECK(observation.entware_architecture.empty());
    CHECK_FALSE(observation.binary_present);
    // No probe was supplied for the transport count, so nobody took it.
    CHECK_FALSE(observation.running_transports.has_value());

    const auto policy = evaluate_sing_box_install(observation, "1.13.14");
    CHECK_FALSE(policy.available);
}

TEST_CASE("a working router is measured into a usable observation") {
    SingBoxInstallProbes probes = silent_probes();
    probes.read_opkg_architectures = []() {
        return std::string(kRealOpkgOutput);
    };
    probes.path_exists = [](const std::string& path) {
        return path == "/opt/bin/sing-box";
    };
    probes.read_binary_version = [](const std::string&) {
        return std::string("sing-box version 1.12.0\n");
    };
    probes.directory_writable = [](const std::string& directory) {
        return directory == "/opt/bin";
    };
    probes.count_running_transports = []() { return std::size_t{0U}; };

    const auto observation = observe_sing_box_install(
        probes, "/opt/bin/sing-box",
        "/opt/etc/keen-pbr/sing-box-managed.path");

    CHECK(observation.entware_present);
    CHECK(observation.entware_architecture == "aarch64-3.10");
    CHECK(observation.binary_present);
    // The marker does not exist, so this binary is the operator's.
    CHECK_FALSE(observation.managed_marker_present);
    CHECK(observation.installed_version == "1.12.0");
    CHECK(observation.target_directory_writable);
    REQUIRE(observation.running_transports.has_value());
    CHECK(*observation.running_transports == 0U);

    const auto policy = evaluate_sing_box_install(observation, "1.13.14");
    CHECK_FALSE(policy.available);
}

TEST_CASE("the version is not read from a binary that is not there") {
    // Running `<path> version` on a missing path is a pointless exec, and its
    // failure output must not be mistaken for a version.
    bool asked = false;
    SingBoxInstallProbes probes = silent_probes();
    probes.read_opkg_architectures = []() {
        return std::string(kRealOpkgOutput);
    };
    probes.read_binary_version = [&asked](const std::string&) {
        asked = true;
        return std::string("sing-box version 9.9.9\n");
    };
    probes.count_running_transports = []() { return std::size_t{0U}; };

    const auto observation = observe_sing_box_install(
        probes, "/opt/bin/sing-box", "/opt/etc/keen-pbr/marker");
    CHECK_FALSE(asked);
    CHECK(observation.installed_version.empty());
}

TEST_CASE("the writable target is the binary's directory, not the binary") {
    std::string asked;
    SingBoxInstallProbes probes = silent_probes();
    probes.directory_writable = [&asked](const std::string& directory) {
        asked = directory;
        return true;
    };
    (void)observe_sing_box_install(probes, "/opt/bin/sing-box",
                                   "/opt/etc/keen-pbr/marker");
    CHECK(asked == "/opt/bin");
}

} // namespace keen_pbr3
