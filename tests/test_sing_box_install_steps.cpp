#include <doctest/doctest.h>

#include "../src/update/sing_box_install_steps.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

namespace keen_pbr3 {

namespace {

namespace fs = std::filesystem;

class StepsTempDir {
public:
    StepsTempDir() {
        char pattern[] = "/tmp/keen-pbr-sing-box-steps-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        REQUIRE(created != nullptr);
        path = created;
    }
    ~StepsTempDir() {
        std::error_code error;
        fs::remove_all(path, error);
    }
    fs::path path;
};

SingBoxInstallPaths paths_in(const StepsTempDir& directory) {
    SingBoxInstallPaths paths;
    paths.binary_path = (directory.path / "bin" / "sing-box").string();
    paths.managed_marker_path =
        (directory.path / "etc" / "sing-box-managed.path").string();
    fs::create_directories(directory.path / "bin");
    return paths;
}

std::string read_file(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    return {(std::istreambuf_iterator<char>(input)),
            std::istreambuf_iterator<char>()};
}

} // namespace

TEST_CASE("the install replaces the target and leaves it executable") {
    StepsTempDir directory;
    const auto paths = paths_in(directory);
    const auto steps = production_sing_box_install_steps(paths);

    // An existing binary, so this exercises replacement rather than creation.
    { std::ofstream(paths.binary_path) << "old"; }
    const auto staged = directory.path / "staged-sing-box";
    { std::ofstream(staged) << "new-binary-bytes"; }

    const auto result = steps.install_atomically(staged.string());
    REQUIRE(result.committed);
    CHECK(result.durable);
    CHECK(read_file(paths.binary_path) == "new-binary-bytes");

    struct stat metadata {};
    REQUIRE(::stat(paths.binary_path.c_str(), &metadata) == 0);
    CHECK((metadata.st_mode & 0777) == 0755);

    // The temporary the install writes before renaming must not survive it.
    CHECK_FALSE(fs::exists(paths.binary_path + ".new"));
}

TEST_CASE("a staged file that is not there leaves the target alone") {
    // The failure that matters: the router keeps working. Everything before
    // the rename is reversible by deleting a file nobody runs, and this is the
    // path that must never get as far as the rename.
    StepsTempDir directory;
    const auto paths = paths_in(directory);
    const auto steps = production_sing_box_install_steps(paths);
    { std::ofstream(paths.binary_path) << "old"; }

    const auto result = steps.install_atomically(
        (directory.path / "absent").string());
    CHECK_FALSE(result.committed);
    CHECK_FALSE(result.durable);
    CHECK(read_file(paths.binary_path) == "old");
    CHECK_FALSE(fs::exists(paths.binary_path + ".new"));
}

TEST_CASE("an empty staged file is refused before the rename") {
    // A truncated copy is not a sing-box, and installing it would replace a
    // working binary with nothing.
    StepsTempDir directory;
    const auto paths = paths_in(directory);
    const auto steps = production_sing_box_install_steps(paths);
    { std::ofstream(paths.binary_path) << "old"; }
    const auto empty = directory.path / "empty";
    { std::ofstream(empty); }

    const auto result = steps.install_atomically(empty.string());
    CHECK_FALSE(result.committed);
    CHECK_FALSE(result.durable);
    CHECK(read_file(paths.binary_path) == "old");
}

TEST_CASE("the marker records the binary the install actually replaced") {
    // The next capability read compares this against the configured binary. A
    // marker naming a different path would make the daemon disown the file it
    // installed.
    StepsTempDir directory;
    const auto paths = paths_in(directory);
    const auto steps = production_sing_box_install_steps(paths);

    REQUIRE(steps.write_managed_marker());
    CHECK(read_file(paths.managed_marker_path) ==
          paths.binary_path + "\n");
    CHECK_FALSE(fs::exists(paths.managed_marker_path + ".new"));
}

TEST_CASE("staging happens beside the target, not in a temp filesystem") {
    // rename() is atomic only within a filesystem. Staging under /tmp or
    // /opt/tmp would make the final step a cross-device copy wearing a
    // rename's name, and it would stop being atomic exactly when it mattered.
    StepsTempDir directory;
    const auto paths = paths_in(directory);
    const auto steps = production_sing_box_install_steps(paths);

    // Not a real archive, so staging fails - but it must fail having created
    // its working directory beside the target.
    (void)steps.stage_archive("not-a-tar-gz");
    const auto beside =
        fs::path(paths.binary_path).parent_path() /
        ".keen-pbr-sing-box-staging";
    CHECK(fs::exists(beside));

    discard_sing_box_staging(paths);
    CHECK_FALSE(fs::exists(beside));
}

TEST_CASE("an archive with no sing-box inside stages nothing") {
    StepsTempDir directory;
    const auto paths = paths_in(directory);
    const auto steps = production_sing_box_install_steps(paths);

    // A real gzip stream that unpacks to something that is not a sing-box.
    const auto payload = directory.path / "payload";
    fs::create_directories(payload / "sing-box-1.13.14-linux-arm64");
    { std::ofstream(payload / "sing-box-1.13.14-linux-arm64" / "LICENSE")
          << "text"; }
    const auto archive = directory.path / "archive.tar.gz";
    const auto command = "tar -czf " + archive.string() + " -C " +
                         payload.string() + " .";
    REQUIRE(std::system(command.c_str()) == 0);

    CHECK(steps.stage_archive(read_file(archive)).empty());
    discard_sing_box_staging(paths);
}

TEST_CASE("a real archive yields an executable staged binary") {
    StepsTempDir directory;
    const auto paths = paths_in(directory);
    const auto steps = production_sing_box_install_steps(paths);

    const auto payload = directory.path / "payload";
    const auto inner = payload / "sing-box-1.13.14-linux-arm64";
    fs::create_directories(inner);
    { std::ofstream(inner / "sing-box") << "#!/bin/sh\necho hi\n"; }
    const auto archive = directory.path / "archive.tar.gz";
    const auto command = "tar -czf " + archive.string() + " -C " +
                         payload.string() + " .";
    REQUIRE(std::system(command.c_str()) == 0);

    const auto staged = steps.stage_archive(read_file(archive));
    REQUIRE_FALSE(staged.empty());
    CHECK(fs::path(staged).filename() == "sing-box");
    // Found inside the staging directory and nowhere else.
    CHECK(staged.rfind(
              (fs::path(paths.binary_path).parent_path() /
               ".keen-pbr-sing-box-staging")
                  .string(),
              0U) == 0U);

    struct stat metadata {};
    REQUIRE(::stat(staged.c_str(), &metadata) == 0);
    CHECK((metadata.st_mode & 0111) != 0);

    discard_sing_box_staging(paths);
}

TEST_CASE("the staged binary is asked its version under a byte bound") {
    // This reads a program that arrived over the internet. It matched the
    // digest the release publishes, which is why it got this far - but the
    // staged-version check exists precisely because a verified archive can
    // still hold the wrong build, so "verified" cannot mean "safe to read
    // without a limit".
    //
    // Falsifiable on purpose: the version line is valid, so the only thing
    // that can reject this output is the bound. Dropping it - which is what
    // passing max_bytes into the wrong parameter did - makes this return
    // 1.13.14 after reading every byte the program cared to write.
    StepsTempDir directory;
    const auto paths = paths_in(directory);
    const auto steps = production_sing_box_install_steps(paths);

    const auto flooding = directory.path / "flooding-sing-box";
    {
        std::ofstream script(flooding);
        script << "#!/bin/sh\n"
               << "echo 'sing-box version 1.13.14'\n"
               << "i=0\n"
               << "while [ $i -lt 4096 ]; do\n"
               << "  echo 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n"
               << "  i=$((i+1))\n"
               << "done\n";
    }
    REQUIRE(::chmod(flooding.c_str(), 0755) == 0);

    CHECK(steps.read_staged_version(flooding.string()).empty());
}

TEST_CASE("a staged binary that answers briefly is read") {
    // The other side of the bound: it must not be so tight that the real
    // answer cannot fit through it.
    StepsTempDir directory;
    const auto paths = paths_in(directory);
    const auto steps = production_sing_box_install_steps(paths);

    const auto brief = directory.path / "brief-sing-box";
    {
        std::ofstream script(brief);
        script << "#!/bin/sh\necho 'sing-box version 1.13.14'\n";
    }
    REQUIRE(::chmod(brief.c_str(), 0755) == 0);

    CHECK(steps.read_staged_version(brief.string()) == "1.13.14");
}

TEST_CASE("the install keeps the binary it replaced") {
    // Without a byte-exact copy, "undo this install" means "download the old
    // release and hope", which is not an undo. The capability reports the
    // presence of this file, so keeping it is what earns the promise.
    StepsTempDir directory;
    const auto paths = paths_in(directory);
    const auto steps = production_sing_box_install_steps(paths);

    { std::ofstream(paths.binary_path) << "the-old-binary"; }
    const auto staged = directory.path / "staged-sing-box";
    { std::ofstream(staged) << "the-new-binary"; }

    const auto result = steps.install_atomically(staged.string());
    REQUIRE(result.committed);
    CHECK(result.durable);
    CHECK(read_file(paths.binary_path) == "the-new-binary");
    CHECK(read_file(paths.binary_path + ".previous") == "the-old-binary");
}

TEST_CASE("a first install has nothing to keep and still installs") {
    // Preserving a previous binary is best effort: there being none is a
    // reason to have no rollback, not a reason to refuse the install.
    StepsTempDir directory;
    const auto paths = paths_in(directory);
    const auto steps = production_sing_box_install_steps(paths);

    const auto staged = directory.path / "staged-sing-box";
    { std::ofstream(staged) << "the-first-binary"; }

    const auto result = steps.install_atomically(staged.string());
    REQUIRE(result.committed);
    CHECK(result.durable);
    CHECK(read_file(paths.binary_path) == "the-first-binary");
    CHECK_FALSE(fs::exists(paths.binary_path + ".previous"));
}

TEST_CASE("a failed directory sync reports committed but not durable") {
    StepsTempDir directory;
    const auto paths = paths_in(directory);
    std::string synced_directory;
    const auto steps = production_sing_box_install_steps(
        paths, {}, {}, [&synced_directory](const std::string& candidate) {
            synced_directory = candidate;
            return false;
        });
    { std::ofstream(paths.binary_path) << "old"; }
    const auto staged = directory.path / "staged-sing-box";
    { std::ofstream(staged) << "new"; }

    const auto result = steps.install_atomically(staged.string());
    CHECK(result.committed);
    CHECK_FALSE(result.durable);
    CHECK(read_file(paths.binary_path) == "new");
    CHECK(synced_directory ==
          fs::path(paths.binary_path).parent_path().string());
}

} // namespace keen_pbr3
