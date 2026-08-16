#include <doctest/doctest.h>

#include "../src/keenetic/ndms_native_ownership_reconcile.hpp"

#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

#include <unistd.h>

namespace keen_pbr3 {

namespace {

namespace fs = std::filesystem;

class ReconcileTempDirectory {
public:
    ReconcileTempDirectory() {
        std::string pattern =
            (fs::temp_directory_path() / "keen-pbr-reconcile-XXXXXX")
                .string();
        std::vector<char> writable(pattern.begin(), pattern.end());
        writable.push_back('\0');
        const char* created = ::mkdtemp(writable.data());
        REQUIRE(created != nullptr);
        path = created;
    }
    ~ReconcileTempDirectory() {
        std::error_code error;
        fs::remove_all(path, error);
    }
    fs::path path;
};

NdmsNativeOwnershipRecord claim_for(const std::string& name) {
    NdmsNativeOwnershipRecord claim;
    claim.interface_name = name;
    claim.transaction_id = std::string(32U, 'a');
    claim.marker = "kpbr-ni-v1-" + std::string(32U, 'a');
    claim.kind = NdmsNativeTunnelImportKind::wireguard;
    claim.target_full_revision =
        "ndms-rci-full-v1-" + std::string(64U, 'd');
    return claim;
}

// Present interfaces answer with a document; absent ones with a null json,
// which is how the firmware's zero-byte body arrives.
struct FakeRouter {
    std::map<std::string, bool> present;
    bool reads_fail{false};

    NdmsNativeInterfaceDeleteDependencies dependencies() {
        NdmsNativeInterfaceDeleteDependencies deps;
        deps.read_document =
            [this](const std::string& path) -> std::optional<nlohmann::json> {
            if (reads_fail) return std::nullopt;
            for (const auto& [name, is_present] : present) {
                if (path.size() >= name.size() &&
                    path.compare(path.size() - name.size(), name.size(),
                                 name) == 0) {
                    if (!is_present) return nlohmann::json();
                    return nlohmann::json{{"description", "tunnel"},
                                          {"type", "Wireguard"}};
                }
            }
            return nlohmann::json();
        };
        deps.run_command = [](const std::string&) { return false; };
        return deps;
    }
};

} // namespace

TEST_CASE("a claim whose interface is gone is retired") {
    // The removal crash window: the delete landed, the process died before the
    // claim was retired, and nothing but this would ever notice.
    ReconcileTempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    store.publish(claim_for("Wireguard5"));
    FakeRouter router;
    router.present["Wireguard5"] = false;

    const auto result = reconcile_ndms_native_ownership_claims(
        store, false, router.dependencies());
    CHECK(result.store_readable);
    CHECK(result.claims_examined == 1U);
    CHECK(result.retired == std::vector<std::string>{"Wireguard5"});
    CHECK(result.unresolved.empty());
    CHECK(store.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::absent);
}

TEST_CASE("a claim whose interface is still there is left alone") {
    ReconcileTempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    store.publish(claim_for("Wireguard5"));
    FakeRouter router;
    router.present["Wireguard5"] = true;

    const auto result = reconcile_ndms_native_ownership_claims(
        store, false, router.dependencies());
    CHECK(result.retired.empty());
    CHECK(result.unresolved.empty());
    CHECK(store.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::valid);
}

TEST_CASE("an in-flight transaction stops reconciliation entirely") {
    // The dispatcher retracts its own claim. A second remover racing it would
    // turn that retirement into a failure for no reason.
    ReconcileTempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    store.publish(claim_for("Wireguard5"));
    FakeRouter router;
    router.present["Wireguard5"] = false;

    const auto result = reconcile_ndms_native_ownership_claims(
        store, true, router.dependencies());
    CHECK(result.skipped_transaction_in_flight);
    CHECK(result.store_readable);
    CHECK(result.claims_examined == 0U);
    CHECK(store.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::valid);
}

TEST_CASE("a read that failed is never treated as absence") {
    ReconcileTempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    store.publish(claim_for("Wireguard5"));
    FakeRouter router;
    router.reads_fail = true;

    const auto result = reconcile_ndms_native_ownership_claims(
        store, false, router.dependencies());
    CHECK(result.retired.empty());
    CHECK(result.unresolved == std::vector<std::string>{"Wireguard5"});
    CHECK(store.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::valid);
}

TEST_CASE("a torn claim is reported, not silently retired") {
    ReconcileTempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    store.publish(claim_for("Wireguard5"));
    {
        std::ofstream torn(directory.path / "ownership" / "Wireguard5",
                           std::ios::binary | std::ios::trunc);
        torn << "half a claim";
    }
    FakeRouter router;
    router.present["Wireguard5"] = false;

    const auto result = reconcile_ndms_native_ownership_claims(
        store, false, router.dependencies());
    CHECK(result.claims_examined == 1U);
    CHECK(result.retired.empty());
    CHECK(result.unresolved == std::vector<std::string>{"Wireguard5"});
}

TEST_CASE("a store that was never written is readable and empty") {
    ReconcileTempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "never-written");
    FakeRouter router;

    const auto result = reconcile_ndms_native_ownership_claims(
        store, false, router.dependencies());
    // Not an error: a fresh install has no claims, and reporting that as an
    // unreadable store would raise an alarm on every first boot.
    CHECK(result.store_readable);
    CHECK(result.claims_examined == 0U);
}

TEST_CASE("foreign residue in the claim directory is never acted on") {
    ReconcileTempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    store.publish(claim_for("Wireguard5"));
    const auto root = directory.path / "ownership";
    for (const char* name : {"Wireguard0", "Wireguard99", "notes.txt"}) {
        std::ofstream stray(root / name, std::ios::binary | std::ios::trunc);
        stray << "not a claim";
    }
    FakeRouter router;
    router.present["Wireguard5"] = false;

    const auto result = reconcile_ndms_native_ownership_claims(
        store, false, router.dependencies());
    // Only the one claimable name was examined; the protected and non-slot
    // names are foreign residue this store must never offer to a caller.
    CHECK(result.claims_examined == 1U);
    CHECK(result.retired == std::vector<std::string>{"Wireguard5"});
    for (const char* name : {"Wireguard0", "Wireguard99", "notes.txt"}) {
        CHECK(fs::exists(root / name));
    }
}

TEST_CASE("several claims are each judged on their own interface") {
    ReconcileTempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    store.publish(claim_for("Wireguard5"));
    store.publish(claim_for("Wireguard6"));
    store.publish(claim_for("Wireguard7"));
    FakeRouter router;
    router.present["Wireguard5"] = false;
    router.present["Wireguard6"] = true;
    router.present["Wireguard7"] = false;

    const auto result = reconcile_ndms_native_ownership_claims(
        store, false, router.dependencies());
    CHECK(result.claims_examined == 3U);
    CHECK(result.retired ==
          (std::vector<std::string>{"Wireguard5", "Wireguard7"}));
    CHECK(store.read("Wireguard6").state ==
          NdmsNativeOwnershipReadState::valid);
}

TEST_CASE("missing dependencies report an unreadable store, not a clean one") {
    ReconcileTempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    NdmsNativeInterfaceDeleteDependencies empty;

    const auto result =
        reconcile_ndms_native_ownership_claims(store, false, empty);
    CHECK_FALSE(result.store_readable);
}

} // namespace keen_pbr3
