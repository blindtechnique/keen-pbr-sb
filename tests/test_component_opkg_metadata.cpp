#include <doctest/doctest.h>

#include "../src/update/component_opkg_metadata.hpp"
#include "../src/update/package_footprint.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace keen_pbr3 {
namespace {
namespace fs = std::filesystem;
constexpr const char* kPackage = "nfqws2-keenetic";

std::string paragraph(const std::string& package, const std::string& version) {
    return "Package: " + package + "\nVersion: " + version +
           "\nStatus: install user installed\n";
}

struct MetadataFixture {
    fs::path root;
    ComponentOpkgMetadataPaths paths;
    MetadataFixture() {
        std::string pattern = (fs::temp_directory_path() / "opkg-metadata-XXXXXX").string();
        REQUIRE(::mkdtemp(&pattern[0]) != nullptr);
        root = pattern;
        fs::create_directories(root / "opkg" / "info");
        paths = {kPackage, root / "opkg" / "status", root / "opkg" / "info",
                 root / "opkg.lock"};
    }
    ~MetadataFixture() {
        std::error_code error;
        fs::remove_all(root, error);
    }
};

void write_file(const fs::path& path, const std::string& body, mode_t mode = 0644) {
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
    return {(std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>()};
}
void installed_info(const MetadataFixture& fixture, const std::string& package,
                    const std::string& version) {
    write_file(fixture.paths.info_directory / (package + ".control"),
               "Package: " + package + "\nVersion: " + version + "\nDescription: installed\n");
    write_file(fixture.paths.info_directory / (package + ".list"), "/opt/share/" + package + "\n");
}

ComponentOpkgStatusFileAttributes saved_attributes() {
    return {0640U, static_cast<std::uint32_t>(::geteuid()),
            static_cast<std::uint32_t>(::getegid())};
}
} // namespace

TEST_CASE("opkg metadata inventory is finite and scoped to exact component info names") {
    MetadataFixture fixture;
    CHECK(valid_component_opkg_metadata_paths(fixture.paths));
    const auto files = component_opkg_metadata_files(fixture.paths);
    REQUIRE(files.size() == 9U);
    CHECK(files.front() == fixture.paths.status_file.string());
    for (std::size_t index = 1; index < files.size(); ++index) {
        CHECK(fs::path(files[index]).parent_path() == fixture.paths.info_directory);
        CHECK(fs::path(files[index]).filename().string().rfind("nfqws2-keenetic.", 0) == 0U);
    }
    CHECK(std::find(files.begin(), files.end(),
                    (fixture.root / "opkg" / "status-old").string()) == files.end());
    SUBCASE("package traversal") { fixture.paths.package = "../other"; }
    SUBCASE("package suffix ambiguity") { fixture.paths.package = "."; }
    SUBCASE("relative status") { fixture.paths.status_file = "opkg/status"; }
    SUBCASE("noncanonical status") { fixture.paths.status_file = fixture.root / "opkg" / ".." / "status"; }
    SUBCASE("different info root") { fixture.paths.info_directory = fixture.root / "other" / "info"; }
    SUBCASE("global status backup") { fixture.paths.status_file = fixture.root / "opkg" / "status-old"; }
    SUBCASE("broad info root") { fixture.paths.info_directory = "/"; }
    SUBCASE("wrong native lock leaf") { fixture.paths.lock_file = fixture.root / "lock"; }
    CHECK_FALSE(valid_component_opkg_metadata_paths(fixture.paths));
    CHECK(component_opkg_metadata_files(fixture.paths).empty());
}

TEST_CASE("opkg status merge preserves every unrelated raw paragraph byte") {
    const auto old_target = paragraph(kPackage, "1.2.4") +
        "Conffiles:\n /opt/etc/nfqws2/nfqws2.conf abc\n"
        "Description: old configuration\n Package: continuation-not-a-package\n"
        "X-Future: keep exactly\n";
    const auto before = paragraph("libc", "newer-than-snapshot") + "\n\n";
    const auto after = paragraph("nfqws2-keenetic-extra", "7") + "\n";
    const auto saved = paragraph("libc", "ancient") + "\n" + old_target + "\n";
    const auto current = before + paragraph(kPackage, "1.2.5") + "\n" + after;
    const auto merged = merge_component_opkg_status(saved, current, kPackage);
    REQUIRE(merged.complete);
    CHECK(merged.body == before + old_target + "\n" + after);
    CHECK(merged.error.empty());
    const auto again = merge_component_opkg_status(saved, merged.body, kPackage);
    CHECK(again.complete);
    CHECK(again.body == merged.body);
}

TEST_CASE("opkg status merge appends a missing component without restoring stale foreign records") {
    const auto current = paragraph("libc", "fresh") + "\n";
    const auto saved = paragraph("libc", "old") + "\n" + paragraph(kPackage, "1.2.4");
    const auto merged = merge_component_opkg_status(saved, current, kPackage);
    REQUIRE(merged.complete);
    CHECK(merged.body == current + paragraph(kPackage, "1.2.4"));
}

TEST_CASE("opkg status merge handles CRLF continuations and a saved final paragraph without newline") {
    const std::string foreign = "Package: libc\r\nVersion: 9\r\nX-Unknown: z\r\n\r\n";
    const std::string old_target = "Package: nfqws2-keenetic\r\nVersion: 1.2.4\r\n"
                                   "Status: install ok installed\r\nDescription: old\r\n second line";
    const auto current = foreign + paragraph(kPackage, "1.2.5") + "\n" + paragraph("other", "3");
    const auto merged = merge_component_opkg_status(old_target, current, kPackage);
    REQUIRE(merged.complete);
    CHECK(merged.body == foreign + old_target + "\n\n" + paragraph("other", "3"));
    CHECK(merge_component_opkg_status(old_target, merged.body, kPackage).complete);
}

TEST_CASE("opkg status merge refuses ambiguous or unusable evidence without producing a body") {
    auto saved = paragraph(kPackage, "1.2.4");
    auto current = paragraph(kPackage, "1.2.5");
    SUBCASE("duplicate saved target") { saved += "\n" + saved; }
    SUBCASE("duplicate current target") { current += "\n" + current; }
    SUBCASE("missing saved target") { saved = paragraph("other", "1"); }
    SUBCASE("saved version absent") { saved = "Package: nfqws2-keenetic\nStatus: install ok installed\n"; }
    SUBCASE("saved package not installed") { saved = "Package: nfqws2-keenetic\nVersion: 1\nStatus: install ok unpacked\n"; }
    SUBCASE("duplicate saved version") { saved += "Version: 99\n"; }
    SUBCASE("duplicate saved status") { saved += "Status: install ok installed\n"; }
    SUBCASE("malformed current paragraph") { current += "\nstranded bytes\n"; }
    SUBCASE("unidentifiable current paragraph") { current += "\nVersion: 3\n"; }
    SUBCASE("missing paragraph separator") { current += paragraph("foreign", "3"); }
    SUBCASE("current database empty") { current.clear(); }
    SUBCASE("current database whitespace only") { current = "\r\n \t\n"; }
    SUBCASE("NUL current database") { current.push_back('\0'); }
    SUBCASE("oversized current database") { current.resize(kComponentMaxFileBytes + 1U, 'x'); }
    const auto result = merge_component_opkg_status(saved, current, kPackage);
    CHECK_FALSE(result.complete);
    CHECK(result.body.empty());
    CHECK_FALSE(result.error.empty());
}

TEST_CASE("opkg status merge repairs an identifiable interrupted target paragraph") {
    const auto current = paragraph("libc", "9") + "\nPackage: nfqws2-keenetic\nVersion: ";
    const auto result = merge_component_opkg_status(paragraph(kPackage, "1.2.4"), current, kPackage);
    REQUIRE(result.complete);
    CHECK(result.body == paragraph("libc", "9") + "\n" + paragraph(kPackage, "1.2.4"));
}

TEST_CASE("opkg status recovery requires the journal version when supplied") {
    MetadataFixture fixture;
    const auto saved = paragraph(kPackage, "1.2.4");
    const auto current = paragraph(kPackage, "1.2.5");
    CHECK(merge_component_opkg_status(saved, current, kPackage, "1.2.4").complete);
    const auto mismatched = merge_component_opkg_status(saved, current, kPackage, "1.2.3");
    CHECK_FALSE(mismatched.complete);
    CHECK(mismatched.body.empty());
    write_file(fixture.paths.status_file, current);
    ComponentOpkgMetadataLock lock(fixture.paths.lock_file);
    REQUIRE(lock.locked());
    CHECK_FALSE(restore_component_opkg_status(fixture.paths, saved, "1.2.3").complete);
    CHECK(read_file(fixture.paths.status_file) == current);
}

TEST_CASE("opkg status IO reads current data late and preserves current database metadata") {
    MetadataFixture fixture;
    const auto saved = paragraph(kPackage, "1.2.4") + "\n" + paragraph("foreign", "old");
    const auto current = paragraph(kPackage, "1.2.5") + "\n" + paragraph("foreign", "new");
    write_file(fixture.paths.status_file, current, 0640);
    struct stat before {};
    REQUIRE(::stat(fixture.paths.status_file.c_str(), &before) == 0);
    ComponentOpkgMetadataLock lock(fixture.paths.lock_file);
    REQUIRE(lock.locked());
    const auto restored = restore_component_opkg_status(fixture.paths, saved);
    REQUIRE(restored.complete);
    CHECK(read_file(fixture.paths.status_file) == paragraph(kPackage, "1.2.4") + "\n" + paragraph("foreign", "new"));
    struct stat after {};
    REQUIRE(::stat(fixture.paths.status_file.c_str(), &after) == 0);
    CHECK((after.st_mode & 07777) == 0640);
    CHECK(after.st_uid == before.st_uid);
    CHECK(after.st_gid == before.st_gid);
}

TEST_CASE("opkg status IO refuses missing unsafe or malformed current database without copyback") {
    MetadataFixture fixture;
    const auto saved = paragraph(kPackage, "1.2.4") + "\n" + paragraph("foreign", "old");
    SUBCASE("missing") {}
    SUBCASE("malformed") { write_file(fixture.paths.status_file, "broken\n"); }
    SUBCASE("empty") { write_file(fixture.paths.status_file, ""); }
    SUBCASE("directory") { fs::create_directory(fixture.paths.status_file); }
    SUBCASE("symlink") {
        write_file(fixture.root / "foreign", "keep\n");
        fs::create_symlink(fixture.root / "foreign", fixture.paths.status_file);
    }
    ComponentOpkgMetadataLock lock(fixture.paths.lock_file);
    REQUIRE(lock.locked());
    const auto result = restore_component_opkg_status(fixture.paths, saved);
    CHECK_FALSE(result.complete);
    CHECK_FALSE(result.error.empty());
    if (fs::exists(fixture.root / "foreign")) CHECK(read_file(fixture.root / "foreign") == "keep\n");
}

TEST_CASE("native opkg metadata lock interoperates with a competing process and is never unlinked") {
    MetadataFixture fixture;
    {
        ComponentOpkgMetadataLock lock(fixture.paths.lock_file);
        REQUIRE(lock.locked());
        const auto child = ::fork();
        REQUIRE(child >= 0);
        if (child == 0) {
            const int native = ::open(fixture.paths.lock_file.c_str(), O_WRONLY);
            if (native < 0) ::_exit(2);
            const bool acquired = ::lockf(native, F_TLOCK, 0) == 0;
            ::close(native);
            ::_exit(acquired ? 1 : 0);
        }
        int status = 0;
        REQUIRE(::waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status));
        CHECK(WEXITSTATUS(status) == 0);
    }
    CHECK(fs::is_regular_file(fixture.paths.lock_file));
    ComponentOpkgMetadataLock next(fixture.paths.lock_file);
    CHECK(next.locked());
}

TEST_CASE("native opkg metadata lock detects its old inode being unlinked and replaced") {
    MetadataFixture fixture;
    {
        ComponentOpkgMetadataLock lock(fixture.paths.lock_file);
        REQUIRE(lock.locked());
        REQUIRE(fs::remove(fixture.paths.lock_file));
        CHECK_FALSE(lock.locked());
        write_file(fixture.paths.lock_file, "replacement");
        CHECK_FALSE(lock.locked());
    }
    CHECK(read_file(fixture.paths.lock_file) == "replacement");
}

TEST_CASE("metadata helpers do not follow lock or status parent symlinks") {
    MetadataFixture fixture;
    fs::create_directory(fixture.root / "real");
    fs::create_symlink(fixture.root / "real", fixture.root / "linked");
    ComponentOpkgMetadataLock lock(fixture.root / "linked" / "opkg.lock");
    CHECK_FALSE(lock.locked());
    CHECK_FALSE(fs::exists(fixture.root / "real" / "opkg.lock"));
    fs::create_directory(fixture.root / "real" / "info");
    write_file(fixture.root / "real" / "status", paragraph(kPackage, "1.2.5"));
    fixture.paths.status_file = fixture.root / "linked" / "status";
    fixture.paths.info_directory = fixture.root / "linked" / "info";
    const auto result = restore_component_opkg_status(fixture.paths, paragraph(kPackage, "1.2.4"));
    CHECK_FALSE(result.complete);
    CHECK(read_file(fixture.root / "real" / "status") == paragraph(kPackage, "1.2.5"));
}

TEST_CASE("opkg reinstall preparation keeps healthy current data even without usable saved metadata") {
    MetadataFixture fixture;
    auto current = paragraph("foreign", "new") + "\n" + paragraph(kPackage, "2");
    SUBCASE("target absent") { current = paragraph("foreign", "new"); }
    SUBCASE("unpacked target") {
        current = "Package: nfqws2-keenetic\nVersion: 2\nStatus: install ok unpacked\n";
    }
    SUBCASE("half-installed target") {
        current = "Package: nfqws2-keenetic\nVersion: 2\nStatus: install ok half-installed\n";
    }
    write_file(fixture.paths.status_file, current, 0600);
    struct stat before {};
    REQUIRE(::stat(fixture.paths.status_file.c_str(), &before) == 0);
    ComponentOpkgMetadataLock lock(fixture.paths.lock_file);
    REQUIRE(lock.locked());
    for (const auto& saved : {std::string{}, std::string("corrupt\n"), paragraph(kPackage, "wrong")}) {
        const auto result = prepare_component_opkg_status_for_reinstall(fixture.paths, saved, "1");
        CHECK(result.complete);
        CHECK_FALSE(result.changed);
        CHECK(result.error.empty());
        CHECK(read_file(fixture.paths.status_file) == current);
        struct stat after {};
        REQUIRE(::stat(fixture.paths.status_file.c_str(), &after) == 0);
        CHECK(after.st_ino == before.st_ino);
        CHECK(after.st_mode == before.st_mode);
    }
}

TEST_CASE("opkg reinstall preparation repairs only the clearly identified damaged target") {
    MetadataFixture fixture;
    const std::string before = "\r\nPackage: foreign\r\nVersion: latest\r\nStatus: install user installed\r\n"
                               "Description: keep raw\r\n Package: not-an-identity\r\n\r\n\r\n";
    const auto after = paragraph("new-foreign-package", "9") + "\n";
    const auto old_target = paragraph(kPackage, "1") + "Conffiles:\n /opt/config old-hash\nX-Unknown: old\n";
    const auto current = before + paragraph(kPackage, "2") + "Torn field without colon\n\n" + after;
    write_file(fixture.paths.status_file, current, 0640);
    write_file(fixture.paths.status_file.parent_path() / "status-old", "not our backup\n");
    struct stat original {};
    REQUIRE(::stat(fixture.paths.status_file.c_str(), &original) == 0);
    ComponentOpkgMetadataLock lock(fixture.paths.lock_file);
    REQUIRE(lock.locked());
    const auto result = prepare_component_opkg_status_for_reinstall(fixture.paths,
        paragraph("foreign", "stale") + "\n" + old_target, "1");
    REQUIRE(result.complete);
    CHECK(result.changed);
    CHECK(result.error.empty());
    CHECK(read_file(fixture.paths.status_file) == before + old_target + "\n" + after);
    CHECK(read_file(fixture.paths.status_file.parent_path() / "status-old") == "not our backup\n");
    struct stat restored {};
    REQUIRE(::stat(fixture.paths.status_file.c_str(), &restored) == 0);
    CHECK(restored.st_mode == original.st_mode);
    CHECK(restored.st_uid == original.st_uid);
    CHECK(restored.st_gid == original.st_gid);
    const auto repeated = prepare_component_opkg_status_for_reinstall(fixture.paths, {}, "1");
    CHECK(repeated.complete);
    CHECK_FALSE(repeated.changed);
}

TEST_CASE("opkg reinstall preparation repairs incomplete or duplicate target version and status fields") {
    MetadataFixture fixture;
    const std::string prefix = "Package: nfqws2-keenetic\n";
    const std::vector<std::string> damaged{
        prefix + "Version: ", prefix + "Status: install ok installed\n",
        prefix + "Version: 2\n", prefix + "Version: 2\nVersion: 3\nStatus: install ok installed\n",
        prefix + "Version: 2\nStatus: install ok installed\nStatus: install ok unpacked\n",
        prefix + "Version: two words\nStatus: install ok installed\n",
        prefix + "Version: 2\nStatus: install ok\n",
        prefix + "Version: 2\nStatus: install ok installed extra\n"};
    ComponentOpkgMetadataLock lock(fixture.paths.lock_file);
    REQUIRE(lock.locked());
    const auto foreign = paragraph("foreign", "new") + "\n";
    for (const auto& target : damaged) {
        CAPTURE(target);
        write_file(fixture.paths.status_file, foreign + target);
        const auto result = prepare_component_opkg_status_for_reinstall(fixture.paths, paragraph(kPackage, "1"), "1");
        REQUIRE(result.complete);
        CHECK(result.changed);
        CHECK(read_file(fixture.paths.status_file) == foreign + paragraph(kPackage, "1"));
    }
}

TEST_CASE("opkg reinstall preparation refuses damage that could belong to unrelated packages") {
    MetadataFixture fixture;
    auto current = paragraph(kPackage, "2") + "Broken field\n";
    SUBCASE("foreign malformed field") { current += "\n" + paragraph("foreign", "new") + "Broken foreign\n"; }
    SUBCASE("unidentifiable paragraph") { current += "\nVersion: 7\n"; }
    SUBCASE("duplicate target paragraph") { current += "\n" + paragraph(kPackage, "2"); }
    SUBCASE("foreign record without separator") { current += paragraph("foreign", "new"); }
    SUBCASE("damaged second package identity") { current += "Package foreign\n"; }
    SUBCASE("target identity is not intact first field") {
        current = "Version: 2\nPackage: nfqws2-keenetic\nBroken field\n";
    }
    write_file(fixture.paths.status_file, current);
    ComponentOpkgMetadataLock lock(fixture.paths.lock_file);
    REQUIRE(lock.locked());
    const auto result = prepare_component_opkg_status_for_reinstall(fixture.paths, paragraph(kPackage, "1"), "1");
    CHECK_FALSE(result.complete);
    CHECK_FALSE(result.changed);
    CHECK_FALSE(result.error.empty());
    CHECK(read_file(fixture.paths.status_file) == current);
}

TEST_CASE("opkg reinstall preparation requires exact installed saved evidence only for repair") {
    MetadataFixture fixture;
    const auto current = paragraph(kPackage, "2") + "Broken field\n";
    auto saved = paragraph(kPackage, "1");
    SUBCASE("saved missing") { saved.clear(); }
    SUBCASE("saved corrupt") { saved = "Broken field\n"; }
    SUBCASE("wrong captured version") { saved = paragraph(kPackage, "3"); }
    SUBCASE("saved missing version") { saved = "Package: nfqws2-keenetic\nStatus: install ok installed\n"; }
    SUBCASE("saved duplicate target") { saved += "\n" + saved; }
    SUBCASE("saved target unpacked") { saved = "Package: nfqws2-keenetic\nVersion: 1\nStatus: install ok unpacked\n"; }
    write_file(fixture.paths.status_file, current);
    ComponentOpkgMetadataLock lock(fixture.paths.lock_file);
    REQUIRE(lock.locked());
    const auto result = prepare_component_opkg_status_for_reinstall(fixture.paths, saved, "1");
    CHECK_FALSE(result.complete);
    CHECK_FALSE(result.changed);
    CHECK_FALSE(result.error.empty());
    CHECK(read_file(fixture.paths.status_file) == current);
}

TEST_CASE("opkg reinstall preparation does not fabricate missing empty or unsafe shared databases") {
    MetadataFixture fixture;
    SUBCASE("missing") {}
    SUBCASE("empty") { write_file(fixture.paths.status_file, ""); }
    SUBCASE("whitespace") { write_file(fixture.paths.status_file, "\r\n \t\n"); }
    SUBCASE("binary") { write_file(fixture.paths.status_file, paragraph(kPackage, "2") + '\0'); }
    SUBCASE("directory") { fs::create_directory(fixture.paths.status_file); }
    SUBCASE("FIFO") { REQUIRE(::mkfifo(fixture.paths.status_file.c_str(), 0600) == 0); }
    SUBCASE("symlink") {
        write_file(fixture.root / "foreign", "do not overwrite\n");
        fs::create_symlink(fixture.root / "foreign", fixture.paths.status_file);
    }
    const auto backup = fixture.paths.status_file.parent_path() / "status-old";
    write_file(backup, paragraph("foreign", "not-a-recovery-source"));
    ComponentOpkgMetadataLock lock(fixture.paths.lock_file);
    REQUIRE(lock.locked());
    const auto result = prepare_component_opkg_status_for_reinstall(fixture.paths,
        paragraph(kPackage, "1") + "\n" + paragraph("foreign", "stale"), "1");
    CHECK_FALSE(result.complete);
    CHECK_FALSE(result.changed);
    CHECK_FALSE(result.error.empty());
    CHECK(read_file(backup) == paragraph("foreign", "not-a-recovery-source"));
    if (fs::exists(fixture.root / "foreign")) CHECK(read_file(fixture.root / "foreign") == "do not overwrite\n");
}

TEST_CASE("shared opkg recovery reconstructs missing empty torn and boundary-truncated databases") {
    MetadataFixture fixture;
    const auto saved = paragraph(kPackage, "1") + "\n" + paragraph("alpha", "4") +
        "\n" + paragraph("beta", "7");
    installed_info(fixture, "alpha", "4");
    installed_info(fixture, "beta", "7");
    bool missing = false;
    std::string current;
    SUBCASE("missing") { missing = true; }
    SUBCASE("empty") {}
    SUBCASE("whitespace only") { current = "\r\n \t\n"; }
    SUBCASE("torn identified foreign paragraph") {
        current = paragraph(kPackage, "2") + "\nPackage: alpha\nVersion: ";
    }
    SUBCASE("clean prefix ending between paragraphs") {
        current = paragraph(kPackage, "2") + "\n" + paragraph("alpha", "4") + "\n";
    }
    SUBCASE("damaged target and missing foreign suffix") {
        current = paragraph(kPackage, "2") + "Torn field\n";
    }
    if (!missing) write_file(fixture.paths.status_file, current, 0600);
    const auto backup = fixture.paths.status_file.parent_path() / "status-old";
    write_file(backup, "native backup is not consumed or modified\n");
    ComponentOpkgMetadataLock lock(fixture.paths.lock_file);
    REQUIRE(lock.locked());
    const auto result = prepare_component_opkg_status_for_reinstall(
        fixture.paths, saved, "1", saved_attributes());
    REQUIRE(result.complete);
    CHECK(result.changed);
    CHECK(result.shared_database_reconstructed);
    CHECK(result.error.empty());
    const auto restored = read_file(fixture.paths.status_file);
    CHECK(restored.find(paragraph(kPackage, "1")) != std::string::npos);
    CHECK(restored.find(paragraph("alpha", "4")) != std::string::npos);
    CHECK(restored.find(paragraph("beta", "7")) != std::string::npos);
    CHECK(merge_component_opkg_status(saved, restored, kPackage, "1").complete);
    CHECK(read_file(backup) == "native backup is not consumed or modified\n");
    struct stat state {};
    REQUIRE(::stat(fixture.paths.status_file.c_str(), &state) == 0);
    CHECK((state.st_mode & 07777) == (missing ? 0640 : 0600));
    CHECK(state.st_uid == ::geteuid());
    CHECK(state.st_gid == ::getegid());
    const auto again = prepare_component_opkg_status_for_reinstall(fixture.paths, {}, "1");
    CHECK(again.complete);
    CHECK_FALSE(again.changed);
    CHECK_FALSE(again.shared_database_reconstructed);
    CHECK(read_file(fixture.paths.status_file) == restored);
}

TEST_CASE("shared opkg recovery preserves newer foreign flags multiline bytes and removal records") {
    MetadataFixture fixture;
    const auto saved = paragraph(kPackage, "1") + "\n" + paragraph("alpha", "4") +
        "\n" + paragraph("beta", "7");
    installed_info(fixture, "beta", "7");
    auto status = std::string("install hold,user installed");
    SUBCASE("held newer version") { installed_info(fixture, "alpha", "9"); }
    SUBCASE("removed config files without live info") { status = "deinstall ok config-files"; }
    SUBCASE("not installed without live info") { status = "purge ok not-installed"; }
    SUBCASE("post install failure") { status = "install user post-inst-failed"; }
    const auto survivor = "Package: alpha\r\nVersion: 9\r\nStatus: " + status +
        "\r\nDescription: raw\r\n Package: continuation\r\nConffiles:\r\n /opt/config hash\r\n"
        "X-Unknown: unchanged\r\n\r\n";
    write_file(fixture.paths.status_file, survivor + paragraph(kPackage, "2"), 0600);
    ComponentOpkgMetadataLock lock(fixture.paths.lock_file);
    REQUIRE(lock.locked());
    const auto result = prepare_component_opkg_status_for_reinstall(fixture.paths, saved, "1");
    REQUIRE(result.complete);
    CHECK(result.shared_database_reconstructed);
    const auto restored = read_file(fixture.paths.status_file);
    CHECK(restored.rfind(survivor, 0) == 0U);
    CHECK(restored.find(paragraph("alpha", "4")) == std::string::npos);
    CHECK(restored.find(paragraph("beta", "7")) != std::string::npos);
}

TEST_CASE("shared opkg recovery never publishes ambiguous foreign versions or incomplete info") {
    MetadataFixture fixture;
    const auto saved = paragraph(kPackage, "1") + "\n" + paragraph("alpha", "4");
    installed_info(fixture, "alpha", "4");
    std::string current;
    SUBCASE("newer live control version") { installed_info(fixture, "alpha", "5"); }
    SUBCASE("new foreign package lost its status") { installed_info(fixture, "new-package", "1"); }
    SUBCASE("missing both info files could mean removal or loss") {
        REQUIRE(fs::remove(fixture.paths.info_directory / "alpha.control"));
        REQUIRE(fs::remove(fixture.paths.info_directory / "alpha.list"));
    }
    SUBCASE("missing control") { REQUIRE(fs::remove(fixture.paths.info_directory / "alpha.control")); }
    SUBCASE("missing list") { REQUIRE(fs::remove(fixture.paths.info_directory / "alpha.list")); }
    SUBCASE("symlink control") {
        REQUIRE(fs::remove(fixture.paths.info_directory / "alpha.control"));
        write_file(fixture.root / "outside-control", "Package: alpha\nVersion: 4\n");
        fs::create_symlink(fixture.root / "outside-control", fixture.paths.info_directory / "alpha.control");
    }
    SUBCASE("symlink list") {
        REQUIRE(fs::remove(fixture.paths.info_directory / "alpha.list"));
        write_file(fixture.root / "outside-list", "/opt/keep\n");
        fs::create_symlink(fixture.root / "outside-list", fixture.paths.info_directory / "alpha.list");
    }
    SUBCASE("list is FIFO") {
        REQUIRE(fs::remove(fixture.paths.info_directory / "alpha.list"));
        REQUIRE(::mkfifo((fixture.paths.info_directory / "alpha.list").c_str(), 0600) == 0);
    }
    SUBCASE("current damaged foreign shows newer version") {
        current = paragraph("alpha", "5") + "Torn field\n";
    }
    SUBCASE("mixed damaged target and lost foreign has newer control") {
        current = paragraph(kPackage, "2") + "Torn field\n";
        installed_info(fixture, "alpha", "5");
    }
    SUBCASE("duplicate current foreign versions conflict") {
        current = paragraph("alpha", "4") + "Version: 5\n";
    }
    SUBCASE("duplicate identical current foreign versions are ambiguous") {
        current = paragraph("alpha", "4") + "Version: 4\n";
    }
    SUBCASE("current foreign version continuation") {
        current = "Package: alpha\nVersion: 4\n 0\nStatus: install user installed\n";
    }
    SUBCASE("duplicate current foreign status") {
        current = paragraph("alpha", "4") + "Status: install user unpacked\n";
    }
    SUBCASE("control scalar continuation") {
        write_file(fixture.paths.info_directory / "alpha.control", "Package: alpha\nVersion: 4\n 5\n");
    }
    SUBCASE("control package does not match filename") {
        write_file(fixture.paths.info_directory / "alpha.control", "Package: another\nVersion: 4\n");
    }
    write_file(fixture.paths.status_file, current, 0600);
    struct stat before {};
    REQUIRE(::stat(fixture.paths.status_file.c_str(), &before) == 0);
    ComponentOpkgMetadataLock lock(fixture.paths.lock_file);
    REQUIRE(lock.locked());
    const auto result = prepare_component_opkg_status_for_reinstall(
        fixture.paths, saved, "1", saved_attributes());
    CHECK_FALSE(result.complete);
    CHECK_FALSE(result.changed);
    CHECK_FALSE(result.shared_database_reconstructed);
    CHECK_FALSE(result.error.empty());
    CHECK(read_file(fixture.paths.status_file) == current);
    struct stat after {};
    REQUIRE(::stat(fixture.paths.status_file.c_str(), &after) == 0);
    CHECK(after.st_ino == before.st_ino);
    CHECK(after.st_mode == before.st_mode);
}

TEST_CASE("shared opkg recovery requires exact installed captured records and verified missing file attributes") {
    MetadataFixture fixture;
    installed_info(fixture, "alpha", "4");
    auto saved = paragraph(kPackage, "1") + "\n" + paragraph("alpha", "4");
    auto attrs = std::optional<ComponentOpkgStatusFileAttributes>(saved_attributes());
    SUBCASE("missing verified attributes") { attrs.reset(); }
    SUBCASE("invalid saved mode") { attrs->mode = 0100000U; }
    SUBCASE("wrong target version") { saved = paragraph(kPackage, "2") + "\n" + paragraph("alpha", "4"); }
    SUBCASE("captured target missing") { saved = paragraph("alpha", "4"); }
    SUBCASE("duplicate captured foreign") { saved += "\n" + paragraph("alpha", "4"); }
    SUBCASE("captured foreign has no status") {
        saved = paragraph(kPackage, "1") + "\nPackage: alpha\nVersion: 4\n";
    }
    SUBCASE("captured foreign status is truncated") {
        saved = paragraph(kPackage, "1") + "\nPackage: alpha\nVersion: 4\nStatus: install user instal\n";
    }
    SUBCASE("captured foreign is not installed") {
        saved = paragraph(kPackage, "1") + "\nPackage: alpha\nVersion: 4\nStatus: install user unpacked\n";
    }
    SUBCASE("captured foreign scalar continuation") { saved += " unpacked\n"; }
    ComponentOpkgMetadataLock lock(fixture.paths.lock_file);
    REQUIRE(lock.locked());
    const auto result = prepare_component_opkg_status_for_reinstall(fixture.paths, saved, "1", attrs);
    CHECK_FALSE(result.complete);
    CHECK_FALSE(result.changed);
    CHECK_FALSE(result.shared_database_reconstructed);
    CHECK_FALSE(fs::exists(fixture.paths.status_file));
}

TEST_CASE("shared opkg recovery does not guess unidentified or duplicate current paragraph boundaries") {
    MetadataFixture fixture;
    const auto saved = paragraph(kPackage, "1") + "\n" + paragraph("alpha", "4");
    installed_info(fixture, "alpha", "4");
    std::string current;
    SUBCASE("unidentified fragment") { current = "Version: 4\nTorn field\n"; }
    SUBCASE("duplicate foreign") { current = paragraph("alpha", "4") + "\n" + paragraph("alpha", "4"); }
    SUBCASE("package boundary without blank separator") { current = paragraph("alpha", "4") + paragraph(kPackage, "2"); }
    SUBCASE("damaged second package field") { current = paragraph("alpha", "4") + "Package other\n"; }
    SUBCASE("unidentified damaged package prefix") { current = "Packag"; }
    write_file(fixture.paths.status_file, current);
    ComponentOpkgMetadataLock lock(fixture.paths.lock_file);
    REQUIRE(lock.locked());
    const auto result = prepare_component_opkg_status_for_reinstall(fixture.paths, saved, "1");
    CHECK_FALSE(result.complete);
    CHECK_FALSE(result.changed);
    CHECK(read_file(fixture.paths.status_file) == current);
}

TEST_CASE("shared opkg recovery recognizes torn foreign scalar metadata as damage not healthy state") {
    MetadataFixture fixture;
    const auto saved = paragraph(kPackage, "1") + "\n" + paragraph("alpha", "4");
    installed_info(fixture, "alpha", "4");
    auto damaged = std::string("Package: alpha\nVersion: 4\nStatus: install user instal\n");
    SUBCASE("truncated state token") {}
    SUBCASE("truncated flag token") { damaged = "Package: alpha\nVersion: 4\nStatus: install us installed\n"; }
    SUBCASE("scalar continuation") { damaged = paragraph("alpha", "4") + " unpacked\n"; }
    SUBCASE("missing status") { damaged = "Package: alpha\nVersion: 4\n"; }
    write_file(fixture.paths.status_file, paragraph(kPackage, "2") + "\n" + damaged);
    ComponentOpkgMetadataLock lock(fixture.paths.lock_file);
    REQUIRE(lock.locked());
    const auto result = prepare_component_opkg_status_for_reinstall(fixture.paths, saved, "1");
    REQUIRE(result.complete);
    CHECK(result.shared_database_reconstructed);
    CHECK(read_file(fixture.paths.status_file).find(paragraph("alpha", "4")) != std::string::npos);
}

TEST_CASE("shared opkg recovery permits control field ordering and empty meta-package lists") {
    MetadataFixture fixture;
    write_file(fixture.paths.info_directory / "alpha.control",
               "Version: 4\nDescription: meta package\n continuation\nPackage: alpha\n");
    write_file(fixture.paths.info_directory / "alpha.list", "");
    write_file(fixture.paths.status_file, "");
    ComponentOpkgMetadataLock lock(fixture.paths.lock_file);
    REQUIRE(lock.locked());
    const auto result = prepare_component_opkg_status_for_reinstall(fixture.paths,
        paragraph(kPackage, "1") + "\n" + paragraph("alpha", "4"), "1");
    CHECK(result.complete);
    CHECK(result.shared_database_reconstructed);
}

TEST_CASE("shared opkg recovery permits a captured component-only database without foreign info") {
    MetadataFixture fixture;
    SUBCASE("missing status") {}
    SUBCASE("empty status") { write_file(fixture.paths.status_file, "", 0600); }
    ComponentOpkgMetadataLock lock(fixture.paths.lock_file);
    REQUIRE(lock.locked());
    const auto saved = paragraph(kPackage, "1");
    const auto result = prepare_component_opkg_status_for_reinstall(
        fixture.paths, saved, "1", saved_attributes());
    REQUIRE(result.complete);
    CHECK(result.shared_database_reconstructed);
    CHECK(read_file(fixture.paths.status_file) == saved);
}

TEST_CASE("shared opkg recovery keeps healthy complete databases unchanged despite optional invalid saved evidence") {
    MetadataFixture fixture;
    installed_info(fixture, "alpha", "9");
    const auto current = paragraph(kPackage, "2") + "\n" + paragraph("alpha", "9");
    write_file(fixture.paths.status_file, current, 0600);
    ComponentOpkgMetadataLock lock(fixture.paths.lock_file);
    REQUIRE(lock.locked());
    const auto result = prepare_component_opkg_status_for_reinstall(fixture.paths, "bad saved data", "1");
    CHECK(result.complete);
    CHECK_FALSE(result.changed);
    CHECK_FALSE(result.shared_database_reconstructed);
    CHECK(read_file(fixture.paths.status_file) == current);
}

} // namespace keen_pbr3
