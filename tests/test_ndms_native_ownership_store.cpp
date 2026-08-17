#include <doctest/doctest.h>

#include "../src/keenetic/ndms_native_ownership_store.hpp"

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

#include <unistd.h>

namespace keen_pbr3 {

namespace {

namespace fs = std::filesystem;

class TempDirectory {
public:
    TempDirectory() {
        std::string pattern =
            (fs::temp_directory_path() / "keen-pbr-own-XXXXXX").string();
        std::vector<char> writable(pattern.begin(), pattern.end());
        writable.push_back('\0');
        const char* created = ::mkdtemp(writable.data());
        REQUIRE(created != nullptr);
        path = created;
    }

    ~TempDirectory() {
        std::error_code error;
        fs::remove_all(path, error);
    }

    fs::path path;
};

NdmsNativeOwnershipRecord record_fixture() {
    NdmsNativeOwnershipRecord record;
    record.interface_name = "Wireguard5";
    record.transaction_id = std::string(32U, 'a');
    record.marker = "kpbr-ni-v1-" + record.transaction_id;
    record.target_full_revision = std::string(64U, 'b');
    return record;
}

} // namespace

TEST_CASE("a published claim reads back exactly, with a stable revision") {
    TempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    const auto record = record_fixture();
    const auto revision = store.publish(record);
    CHECK(revision == ndms_native_ownership_revision(record));

    const auto read = store.read("Wireguard5");
    REQUIRE(read.state == NdmsNativeOwnershipReadState::valid);
    REQUIRE(read.record.has_value());
    CHECK(*read.record == record);
    REQUIRE(read.revision.has_value());
    CHECK(*read.revision == revision);

    // Any field change moves the revision - the WAL carries the digest, and a
    // digest that survived a field change would let a swapped claim pass the
    // ownership_record_matches comparison.
    auto other = record;
    other.target_full_revision = std::string(64U, 'c');
    CHECK(ndms_native_ownership_revision(other) != revision);
}

TEST_CASE("a protected slot cannot even be claimed") {
    TempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    for (const char* name : {"Wireguard0", "Wireguard99", "Wireguard126",
                             "Wireguard05", "wireguard5", "Wireguard127"}) {
        auto record = record_fixture();
        record.interface_name = name;
        CHECK_THROWS(store.publish(record));
        // And a claim planted by hand is refused at read, before any caller
        // can act on it.
        CHECK(store.read(name).state ==
              NdmsNativeOwnershipReadState::unreadable);
    }
}

TEST_CASE("a torn claim is unreadable, never absent") {
    TempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    store.publish(record_fixture());

    std::ofstream torn(directory.path / "ownership" / "Wireguard5",
                       std::ios::binary | std::ios::trunc);
    torn << "keen-pbr-native-ownership-v1\nWireguard5\n";
    torn.close();

    // "No claim" is exactly the reading that must not come from a torn one:
    // it would tell recovery the interface belongs to the operator.
    CHECK(store.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::unreadable);
}

TEST_CASE("a claim naming a different interface than its filename is refused") {
    TempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    auto record = record_fixture();
    record.interface_name = "Wireguard6";
    store.publish(record);

    std::error_code error;
    fs::rename(directory.path / "ownership" / "Wireguard6",
               directory.path / "ownership" / "Wireguard5", error);
    REQUIRE_FALSE(error);
    // A renamed claim asserts ownership of an interface it never named.
    CHECK(store.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::unreadable);
}

TEST_CASE("remove_exact removes only the claim it was shown") {
    TempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    const auto record = record_fixture();
    store.publish(record);

    auto different = record;
    different.target_full_revision = std::string(64U, 'c');
    CHECK_FALSE(store.remove_exact(different));
    CHECK(store.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::valid);

    CHECK(store.remove_exact(record));
    CHECK(store.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::absent);
    // Removing an absent claim is not a success: the caller asked to remove
    // something that is not what the store holds.
    CHECK_FALSE(store.remove_exact(record));
}

TEST_CASE("the published revision satisfies the recovery observation") {
    TempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    const auto claim = record_fixture();
    const auto revision = store.publish(claim);

    // The wiring the classifier's ownership_published phase depends on: the
    // WAL carries this revision, the store returns it on read, and the
    // observation builder compares the two.
    NdmsNativeImportWalRecord record;
    record.ownership_revision = revision;
    const auto read = store.read("Wireguard5");
    REQUIRE(read.revision.has_value());
    CHECK(*read.revision == *record.ownership_revision);
}

} // namespace keen_pbr3
