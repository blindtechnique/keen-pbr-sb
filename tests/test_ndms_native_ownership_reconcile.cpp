#include <doctest/doctest.h>

#include "../src/keenetic/ndms_native_ownership_reconcile.hpp"
#include "../src/keenetic/ndms_native_interface_read_production.hpp"

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

TEST_CASE("production ownership reads can connect only to exact IPv4 loopback") {
    CHECK(ndms_native_interface_read_loopback_destination_permitted(
        "127.0.0.1"));
    CHECK_FALSE(ndms_native_interface_read_loopback_destination_permitted(
        "127.0.0.2"));
    CHECK_FALSE(ndms_native_interface_read_loopback_destination_permitted(
        "::1"));
    CHECK_FALSE(ndms_native_interface_read_loopback_destination_permitted(
        "192.168.1.1"));
    CHECK_FALSE(ndms_native_interface_read_loopback_destination_permitted(
        "203.0.113.1"));
}

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
    claim.snapshot_revision =
        "ndms-native-import-v1-" + std::string(64U, 'c');
    claim.target_full_revision =
        "ndms-rci-full-v1-" + std::string(64U, 'd');
    return claim;
}

NdmsNativeOwnershipRecord tombstone_for(
    NdmsNativeOwnershipRecord claim) {
    claim.lifecycle = NdmsNativeOwnershipLifecycle::
        deleted_save_acknowledged_unverified;
    NdmsNativeOwnershipLifecycleEvidence evidence;
    evidence.transaction_id = std::string(32U, 'b');
    evidence.observation_binding = {std::string(32U, 'c'), 2U, 1U};
    evidence.runtime_catalog_revision =
        "ndms-native-catalog-v1-" + std::string(64U, 'd');
    evidence.runtime_sequence = 2U;
    evidence.running_config_catalog_revision =
        "ndms-native-catalog-v1-" + std::string(64U, 'e');
    evidence.running_config_sequence = 3U;
    claim.lifecycle_evidence = std::move(evidence);
    return claim;
}

NdmsNativeOwnershipRecord save_acknowledged_active_for(
    NdmsNativeOwnershipRecord claim) {
    claim.lifecycle = NdmsNativeOwnershipLifecycle::
        active_save_acknowledged_unverified;
    NdmsNativeOwnershipLifecycleEvidence evidence;
    evidence.transaction_id = std::string(32U, 'b');
    evidence.observation_binding = {std::string(32U, 'c'), 2U, 1U};
    evidence.runtime_catalog_revision =
        "ndms-native-catalog-v1-" + std::string(64U, 'd');
    evidence.runtime_sequence = 2U;
    evidence.running_config_catalog_revision =
        "ndms-native-catalog-v1-" + std::string(64U, 'e');
    evidence.running_config_sequence = 3U;
    claim.lifecycle_evidence = std::move(evidence);
    return claim;
}

// Present interfaces answer with a document; absent ones with a null json,
// which is how the firmware's zero-byte body arrives.
struct FakeRouter {
    std::map<std::string, bool> present;
    bool reads_fail{false};
    std::size_t reads{0U};
    std::optional<nlohmann::json> forced_document;

    NdmsNativeInterfaceReadDependencies dependencies() {
        NdmsNativeInterfaceReadDependencies deps;
        deps.read_document =
            [this](const std::string& path) -> std::optional<nlohmann::json> {
            ++reads;
            if (reads_fail) return std::nullopt;
            if (forced_document.has_value()) return forced_document;
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
        return deps;
    }
};

} // namespace

TEST_CASE("startup absence retains every active ownership lifecycle") {
    for (const bool save_was_acknowledged : {false, true}) {
        CAPTURE(save_was_acknowledged);
        ReconcileTempDirectory directory;
        NdmsNativeOwnershipStore store(directory.path / "ownership");
        const auto running = claim_for("Wireguard5");
        store.publish(running);
        if (save_was_acknowledged) {
            const auto save_acknowledged =
                save_acknowledged_active_for(running);
            REQUIRE(store.replace_exact(
                        running, save_acknowledged).has_value());
        }
        FakeRouter router;
        router.present["Wireguard5"] = false;

        const auto result = reconcile_ndms_native_ownership_claims(
            store, false, router.dependencies());
        CHECK(result.store_readable);
        CHECK(result.claims_examined == 1U);
        CHECK(result.retired.empty());
        CHECK(result.unresolved ==
              std::vector<std::string>{"Wireguard5"});
        const auto retained = store.read("Wireguard5");
        REQUIRE(retained.record.has_value());
        CHECK(ndms_native_ownership_is_active(*retained.record));
        CHECK(retained.record->lifecycle ==
              (save_was_acknowledged
                   ? NdmsNativeOwnershipLifecycle::
                         active_save_acknowledged_unverified
                   : NdmsNativeOwnershipLifecycle::
                         active_running_only));
    }
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

TEST_CASE("every non-clean delete WAL state suppresses all retirement") {
    CHECK(ndms_native_ownership_reconciliation_permitted(
        false, NdmsNativeDeleteWalReadiness::clean));
    CHECK_FALSE(ndms_native_ownership_reconciliation_permitted(
        false, NdmsNativeDeleteWalReadiness::unfinished));
    CHECK_FALSE(ndms_native_ownership_reconciliation_permitted(
        false, NdmsNativeDeleteWalReadiness::unsafe));

    for (const auto readiness : {
             NdmsNativeDeleteWalReadiness::unfinished,
             NdmsNativeDeleteWalReadiness::unsafe}) {
        CAPTURE(ndms_native_delete_wal_readiness_name(readiness));
        ReconcileTempDirectory directory;
        NdmsNativeOwnershipStore store(directory.path / "ownership");
        store.publish(claim_for("Wireguard5"));
        FakeRouter router;
        router.present["Wireguard5"] = false;

        const auto result = reconcile_ndms_native_ownership_claims(
            store, false, router.dependencies(), readiness);
        CHECK(result.store_readable);
        CHECK(result.skipped_delete_wal_not_clean);
        CHECK_FALSE(result.skipped_transaction_in_flight);
        CHECK(result.claims_examined == 0U);
        CHECK(router.reads == 0U);
        CHECK(store.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::valid);
    }
}

TEST_CASE("delete tombstones are retained without router reads") {
    ReconcileTempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    const auto active = claim_for("Wireguard5");
    store.publish(active);
    const auto tombstone = tombstone_for(active);
    REQUIRE(store.replace_exact(active, tombstone).has_value());
    FakeRouter router;
    router.present["Wireguard5"] = false;

    const auto result = reconcile_ndms_native_ownership_claims(
        store, false, router.dependencies());
    CHECK(result.store_readable);
    CHECK(result.claims_examined == 1U);
    CHECK(result.retained_tombstones ==
          std::vector<std::string>{"Wireguard5"});
    CHECK(result.retired.empty());
    CHECK(result.unresolved.empty());
    CHECK(router.reads == 0U);
    const auto read = store.read("Wireguard5");
    REQUIRE(read.record.has_value());
    CHECK(ndms_native_ownership_is_delete_tombstone(*read.record));
}

TEST_CASE("noncanonical RCI documents never prove interface absence") {
    for (const auto& malformed :
         {nlohmann::json::object(), nlohmann::json::array(),
          nlohmann::json("absent"), nlohmann::json(false),
          nlohmann::json(0)}) {
        CAPTURE(malformed.dump());
        ReconcileTempDirectory directory;
        NdmsNativeOwnershipStore store(directory.path / "ownership");
        store.publish(claim_for("Wireguard5"));
        FakeRouter router;
        router.forced_document = malformed;

        const auto result = reconcile_ndms_native_ownership_claims(
            store, false, router.dependencies());
        CHECK(result.retired.empty());
        CHECK(result.unresolved ==
              std::vector<std::string>{"Wireguard5"});
        CHECK(store.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::valid);
    }
}

TEST_CASE("one null document plus one malformed document is not absence") {
    ReconcileTempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    store.publish(claim_for("Wireguard5"));
    std::size_t reads = 0U;
    NdmsNativeInterfaceReadDependencies dependencies;
    dependencies.read_document =
        [&reads](const std::string&) -> std::optional<nlohmann::json> {
        ++reads;
        return reads == 1U ? nlohmann::json()
                           : nlohmann::json::array();
    };

    const auto result = reconcile_ndms_native_ownership_claims(
        store, false, dependencies);
    CHECK(reads == 2U);
    CHECK(result.retired.empty());
    CHECK(result.unresolved ==
          std::vector<std::string>{"Wireguard5"});
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
    // An ownership directory is a closed namespace. Unknown residue makes the
    // inventory unreadable, so reconciliation cannot retire even an otherwise
    // valid claim from an incomplete view of the directory.
    CHECK_FALSE(result.store_readable);
    CHECK(result.claims_examined == 0U);
    CHECK(result.retired.empty());
    CHECK(store.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::unreadable);
    CHECK(fs::exists(root / "Wireguard5"));
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
    CHECK(result.retired.empty());
    CHECK(result.unresolved ==
          (std::vector<std::string>{"Wireguard5", "Wireguard7"}));
    for (const char* name : {"Wireguard5", "Wireguard6", "Wireguard7"}) {
        CHECK(store.read(name).state ==
              NdmsNativeOwnershipReadState::valid);
    }
}

TEST_CASE("missing dependencies report an unreadable store, not a clean one") {
    ReconcileTempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    NdmsNativeInterfaceReadDependencies empty;

    const auto result =
        reconcile_ndms_native_ownership_claims(store, false, empty);
    CHECK_FALSE(result.store_readable);
}

} // namespace keen_pbr3
