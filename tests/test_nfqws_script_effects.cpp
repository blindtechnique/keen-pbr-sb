#include <doctest/doctest.h>

#include "../src/update/component_capture.hpp"
#include "../src/update/nfqws_script_effects.hpp"

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {
namespace {

namespace fs = std::filesystem;

struct TempDirectory {
    fs::path path;
    TempDirectory() {
        std::string pattern =
            (fs::temp_directory_path() / "nfqws-effects-XXXXXX").string();
        const auto created = ::mkdtemp(&pattern[0]);
        if (!created)
            throw std::system_error(errno, std::generic_category(), "mkdtemp");
        path = created;
    }
    ~TempDirectory() {
        std::error_code error;
        fs::remove_all(path, error);
    }
};

void write_file(const fs::path& path, const std::string& body,
                mode_t mode = 0644) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    REQUIRE(output);
    output << body;
    output.close();
    REQUIRE(output);
    REQUIRE(::chmod(path.c_str(), mode) == 0);
}

std::string read_file(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    REQUIRE(input);
    return {std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
}

mode_t file_mode(const fs::path& path) {
    struct stat status {};
    REQUIRE(::stat(path.c_str(), &status) == 0);
    return status.st_mode & 0777;
}

std::string package_record(const std::string& package,
                           const std::string& version) {
    return "Package: " + package + "\nVersion: " + version +
           "\nStatus: install user installed\n";
}

struct ScriptEffectsFixture {
    TempDirectory directory;
    fs::path opt = directory.path / "opt";
    fs::path store = directory.path / "capture";
    fs::path config = opt / "etc/nfqws2/nfqws2.conf";
    fs::path config_old = opt / "etc/nfqws2/nfqws2.conf-old";
    fs::path user_list = opt / "etc/nfqws2/lists/user.list";
    fs::path list_old = opt / "etc/nfqws2/lists/user.list-old";
    fs::path marker = opt / "tmp/nfqws2_install_type";
    fs::path binary = opt / "usr/bin/nfqws2";
    fs::path init = opt / "etc/init.d/S51nfqws2";
    ComponentOpkgMetadataPaths metadata{
        "nfqws2-keenetic", opt / "lib/opkg/status",
        opt / "lib/opkg/info", opt / "tmp/opkg.lock"};

    ScriptEffectsFixture() {
        write_file(config, "CONFIG_VERSION=1\n# operator config\n", 0600);
        write_file(user_list, "old-user.example\n", 0640);
        write_file(binary, "old-binary\n", 0755);
        write_file(init, "old-init\n", 0755);
        fs::create_directories(opt / "tmp");
        write_file(info("control"), "Package: nfqws2-keenetic\nVersion: 1\n");
        // Model an installed .list that does not describe script destinations.
        write_file(info("list"), binary.string() + "\n" + init.string() +
                                    "\n" + user_list.string() + "\n");
        write_file(metadata.status_file, target("1") + "\n" +
                   package_record("foreign", "1") + "\n");
    }

    fs::path info(const std::string& suffix) const {
        return metadata.info_directory / (metadata.package + "." + suffix);
    }
    std::string target(const std::string& version) const {
        return package_record(metadata.package, version);
    }
    std::vector<std::string> tracked_paths() const {
        std::vector<std::string> paths{
            binary.string(), init.string(), user_list.string()};
        for (const auto& absolute : nfqws_known_script_effect_paths()) {
            REQUIRE(absolute.compare(0U, 5U, "/opt/") == 0);
            paths.push_back((opt / absolute.substr(5U)).string());
        }
        return paths;
    }
    ComponentCaptureResult capture() const {
        // Only the on-disk generation survives this method. No retained
        // footprint is available to the later fresh recovery call.
        return capture_component_upgrade_files(
            observe_package_footprint(tracked_paths()),
            {binary.string(), init.string(), user_list.string()}, store, metadata);
    }
    void check_v4() const {
        auto generation = read_file(store / "current");
        REQUIRE_FALSE(generation.empty());
        REQUIRE(generation.back() == '\n');
        generation.pop_back();
        CHECK(read_file(store / "generations" / generation / "manifest")
                  .find("keen-pbr-component-capture-v4\n") == 0U);
    }
};

} // namespace

TEST_CASE("nfqws known script effects are four exact bounded Entware leaves") {
    const std::vector<std::string> expected{
        "/opt/etc/nfqws2/lists/user.list-old",
        "/opt/etc/nfqws2/nfqws2.conf",
        "/opt/etc/nfqws2/nfqws2.conf-old",
        "/opt/tmp/nfqws2_install_type",
    };
    CHECK(nfqws_known_script_effect_paths() == expected);
    for (const auto& path : nfqws_known_script_effect_paths()) {
        CHECK(path.size() <= kComponentMaxPathLength);
        CHECK(fs::path(path).lexically_normal().string() == path);
        CHECK_FALSE(fs::path(path).filename().empty());
    }
}

TEST_CASE("nfqws v4 reload restores overwritten migration siblings after reinstall") {
    ScriptEffectsFixture fixture;
    write_file(fixture.config_old, "operator's older config backup\n", 0640);
    write_file(fixture.list_old, "operator's older list backup\n", 0600);
    const auto original_list = read_file(fixture.info("list"));
    REQUIRE(fixture.capture().complete);
    fixture.check_v4();

    // preinst's config migration overwrites an already existing -old leaf.
    write_file(fixture.marker, "upgrade\n");
    fs::rename(fixture.config, fixture.config_old);
    write_file(fixture.config, "new package config\n");
    // The explicitly named list-migration destination must be safe too,
    // although its migration branch is dormant in the audited version.
    fs::rename(fixture.user_list, fixture.list_old);
    write_file(fixture.user_list, "new-user.example\n");
    write_file(fixture.binary, "failed-new-binary\n", 0755);
    REQUIRE(fs::remove(fixture.info("list")));
    const auto foreign = package_record("foreign", "newer") +
                         "X-Keep: byte-for-byte\n\n" +
                         package_record("new-foreign", "7") + "\n";
    write_file(fixture.metadata.status_file, fixture.target("2") + "\n" + foreign);

    // A failed upgrade's exact-old reinstall can repeat these script writes.
    write_file(fixture.config_old, "reinstall migration overwrite\n");
    write_file(fixture.config, "old package default, not operator config\n");
    write_file(fixture.marker, "install\n");
    const auto result = restore_component_files(fixture.store, true, "1");
    CHECK(result.complete);
    CHECK(result.payload_restored);
    CHECK(result.metadata_recorded);
    CHECK(result.metadata_restored);
    CHECK_FALSE(result.exact_package_state);
    CHECK(result.removed == 1U);
    CHECK(read_file(fixture.config) == "CONFIG_VERSION=1\n# operator config\n");
    CHECK(file_mode(fixture.config) == 0600);
    CHECK(read_file(fixture.config_old) == "operator's older config backup\n");
    CHECK(file_mode(fixture.config_old) == 0640);
    CHECK(read_file(fixture.list_old) == "operator's older list backup\n");
    CHECK(file_mode(fixture.list_old) == 0600);
    CHECK(read_file(fixture.user_list) == "old-user.example\n");
    CHECK(read_file(fixture.binary) == "old-binary\n");
    CHECK_FALSE(fs::exists(fixture.marker));
    CHECK(read_file(fixture.info("list")) == original_list);
    CHECK(read_file(fixture.metadata.status_file) == fixture.target("1") + "\n" + foreign);

    const auto repeated = restore_component_files(fixture.store, true, "1");
    CHECK(repeated.complete);
    CHECK(repeated.removed == 0U);
}

TEST_CASE("nfqws v4 records absence without granting manual or recursive cleanup") {
    ScriptEffectsFixture fixture;
    REQUIRE(fixture.capture().complete);
    write_file(fixture.config_old, "created migration backup\n");
    write_file(fixture.list_old, "created list backup\n");
    const auto unrelated = fixture.opt / "tmp/operator-note";
    write_file(unrelated, "unrelated marker sibling\n");
    const auto link_target = fixture.directory.path / "outside-marker-target";
    write_file(link_target, "must not follow marker link\n");
    fs::create_symlink(link_target, fixture.marker);
    const auto staging = fixture.opt / "tmp/nfqws2_binary";
    fs::create_directories(staging);

    const auto manual = restore_component_files(fixture.store);
    CHECK(manual.complete);
    CHECK(manual.removed == 0U);
    CHECK_FALSE(manual.metadata_restored);
    CHECK(fs::exists(fixture.config_old));
    CHECK(fs::exists(fixture.list_old));
    CHECK(fs::is_symlink(fs::symlink_status(fixture.marker)));

    const auto recovery = restore_component_files(fixture.store, true, "1");
    CHECK(recovery.complete);
    CHECK(recovery.removed == 3U);
    CHECK_FALSE(fs::exists(fixture.config_old));
    CHECK_FALSE(fs::exists(fixture.list_old));
    CHECK_FALSE(fs::is_symlink(fs::symlink_status(fixture.marker)));
    CHECK(read_file(link_target) == "must not follow marker link\n");
    CHECK(read_file(unrelated) == "unrelated marker sibling\n");
    CHECK(fs::is_directory(staging));
}

TEST_CASE("nfqws v4 restores a preexisting install marker consumed by postinst") {
    ScriptEffectsFixture fixture;
    write_file(fixture.marker, "preexisting operator bytes\n", 0600);
    REQUIRE(fixture.capture().complete);
    write_file(fixture.marker, "install\n");
    REQUIRE(fs::remove(fixture.marker));

    const auto result = restore_component_files(fixture.store, true, "1");
    CHECK(result.complete);
    CHECK(result.removed == 0U);
    CHECK(read_file(fixture.marker) == "preexisting operator bytes\n");
    CHECK(file_mode(fixture.marker) == 0600);
}

TEST_CASE("nfqws v4 refuses a directory at an absent script leaf") {
    ScriptEffectsFixture fixture;
    REQUIRE(fixture.capture().complete);
    const auto nested = fixture.marker / "operator-data";
    write_file(nested, "never recursively remove\n");
    write_file(fixture.config, "failed config\n");

    const auto result = restore_component_files(fixture.store, true, "1");
    CHECK_FALSE(result.complete);
    CHECK_FALSE(result.payload_restored);
    CHECK_FALSE(result.metadata_restored);
    CHECK(result.removed == 0U);
    CHECK(result.failed == std::vector<std::string>{fixture.marker.string()});
    CHECK(read_file(nested) == "never recursively remove\n");
    CHECK(read_file(fixture.config) == "CONFIG_VERSION=1\n# operator config\n");
}

} // namespace keen_pbr3
