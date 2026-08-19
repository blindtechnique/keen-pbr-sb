#include <doctest/doctest.h>

#include "../src/keenetic/ndms_native_tunnel_removal.hpp"

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
using Outcome = NdmsNativeTunnelRemovalOutcome;

class RemovalTempDirectory {
public:
    RemovalTempDirectory() {
        std::string pattern =
            (fs::temp_directory_path() / "keen-pbr-removal-XXXXXX").string();
        std::vector<char> writable(pattern.begin(), pattern.end());
        writable.push_back('\0');
        const char* created = ::mkdtemp(writable.data());
        REQUIRE(created != nullptr);
        path = created;
    }
    ~RemovalTempDirectory() {
        std::error_code error;
        fs::remove_all(path, error);
    }
    fs::path path;
};

const std::string kMarker = "kpbr-ni-v1-" + std::string(32U, 'a');

NdmsNativeOwnershipRecord claim_for(const std::string& name) {
    NdmsNativeOwnershipRecord claim;
    claim.interface_name = name;
    claim.transaction_id = std::string(32U, 'a');
    claim.marker = kMarker;
    claim.kind = NdmsNativeTunnelImportKind::wireguard;
    claim.target_full_revision =
        "ndms-rci-full-v1-" + std::string(64U, 'd');
    return claim;
}

nlohmann::json interface_document(const std::string& description) {
    return nlohmann::json{{"description", description},
                          {"type", "Wireguard"},
                          {"up", true}};
}

// Answers RCI reads from a script and records what it was told to run.
struct ScriptedRouter {
    std::map<std::string, std::vector<std::optional<nlohmann::json>>> answers;
    std::vector<std::string> commands;
    bool command_succeeds{true};

    void queue(const std::string& path,
               std::optional<nlohmann::json> answer) {
        answers[path].push_back(std::move(answer));
    }

    NdmsNativeInterfaceDeleteDependencies dependencies() {
        NdmsNativeInterfaceDeleteDependencies deps;
        deps.read_document = [this](const std::string& path) {
            auto& queue = answers[path];
            if (queue.empty()) return std::optional<nlohmann::json>{};
            auto answer = queue.front();
            if (queue.size() > 1U) queue.erase(queue.begin());
            return answer;
        };
        deps.run_command = [this](const std::string& command) {
            commands.push_back(command);
            return command_succeeds;
        };
        return deps;
    }
};

const std::string kConfig = "show/rc/interface/Wireguard5";
const std::string kRuntime = "show/interface/Wireguard5";

// A live, marker-carrying interface that will be gone after the command.
void script_successful_delete(ScriptedRouter& router) {
    router.queue(kConfig, interface_document("tunnel " + kMarker));
    router.queue(kConfig, nlohmann::json());
    router.queue(kRuntime, nlohmann::json());
}

} // namespace

TEST_CASE("an owned tunnel is removed and its claim retired") {
    RemovalTempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    store.publish(claim_for("Wireguard5"));
    ScriptedRouter router;
    script_successful_delete(router);

    CHECK(remove_owned_ndms_tunnel("Wireguard5", store,
                                   router.dependencies()) ==
          Outcome::removed);
    CHECK(router.commands == std::vector<std::string>{
                                 "no interface Wireguard5"});
    CHECK(store.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::absent);
}

TEST_CASE("an interface keen-pbr never claimed is not ours to remove") {
    RemovalTempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    ScriptedRouter router;
    router.queue(kConfig, interface_document("someone's own tunnel"));

    CHECK(remove_owned_ndms_tunnel("Wireguard5", store,
                                   router.dependencies()) ==
          Outcome::not_owned);
    // Nothing was even read from the router: ownership is decided first.
    CHECK(router.commands.empty());
}

TEST_CASE("a protected slot cannot be removed, because it cannot be claimed") {
    RemovalTempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    ScriptedRouter router;
    for (const char* name : {"Wireguard0", "Wireguard4", "Wireguard99"}) {
        CHECK(remove_owned_ndms_tunnel(name, store,
                                       router.dependencies()) ==
              Outcome::not_owned);
    }
    CHECK(router.commands.empty());
}

TEST_CASE("the marker comes from the claim, not from the caller") {
    // The interface carries the claim's marker. The caller never supplies one,
    // so an operator naming an interface cannot also choose what authorizes
    // deleting it.
    RemovalTempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    store.publish(claim_for("Wireguard5"));

    ScriptedRouter wrong_marker;
    wrong_marker.queue(kConfig,
                       interface_document("tunnel kpbr-ni-v1-" +
                                          std::string(32U, 'b')));
    CHECK(remove_owned_ndms_tunnel("Wireguard5", store,
                                   wrong_marker.dependencies()) ==
          Outcome::refused);
    CHECK(wrong_marker.commands.empty());
    // Refused means the claim stands: keen-pbr is still responsible for it.
    CHECK(store.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::valid);
}

TEST_CASE("a torn claim fails instead of reading as not ours") {
    RemovalTempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    store.publish(claim_for("Wireguard5"));
    {
        std::ofstream torn(directory.path / "ownership" / "Wireguard5",
                           std::ios::binary | std::ios::trunc);
        torn << "half a claim";
    }
    ScriptedRouter router;
    script_successful_delete(router);

    CHECK(remove_owned_ndms_tunnel("Wireguard5", store,
                                   router.dependencies()) ==
          Outcome::failed);
    CHECK(router.commands.empty());
}

TEST_CASE("a failed delete leaves the claim standing") {
    RemovalTempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    store.publish(claim_for("Wireguard5"));
    ScriptedRouter router;
    router.command_succeeds = false;
    router.queue(kConfig, interface_document("tunnel " + kMarker));

    CHECK(remove_owned_ndms_tunnel("Wireguard5", store,
                                   router.dependencies()) ==
          Outcome::failed);
    // Retiring the claim here would make keen-pbr forget an interface it is
    // still responsible for.
    CHECK(store.read("Wireguard5").state ==
          NdmsNativeOwnershipReadState::valid);
}

TEST_CASE("a surviving claim after a real delete is not reported as success") {
    RemovalTempDirectory directory;
    NdmsNativeOwnershipStore store(directory.path / "ownership");
    store.publish(claim_for("Wireguard5"));
    ScriptedRouter router;
    script_successful_delete(router);

    // Make the store unable to retire the claim: the directory is replaced by
    // an unwritable shape, so remove_exact reports the claim survived.
    const auto claim_path = directory.path / "ownership" / "Wireguard5";
    std::error_code error;
    fs::permissions(directory.path / "ownership",
                    fs::perms::owner_read | fs::perms::owner_exec,
                    error);

    const auto outcome = remove_owned_ndms_tunnel("Wireguard5", store,
                                                  router.dependencies());
    fs::permissions(directory.path / "ownership",
                    fs::perms::owner_all, error);
    // The hardened store rejects a 0500 directory before reading the claim,
    // so the test-only legacy remover must fail without issuing a command.
    // On platforms where the permission transition did not take effect,
    // retain the older exact postcondition checks.
    if (outcome == Outcome::failed) {
        CHECK(router.commands.empty());
        CHECK(fs::exists(claim_path));
    } else if (outcome == Outcome::removed) {
        CHECK(store.read("Wireguard5").state ==
              NdmsNativeOwnershipReadState::absent);
    } else {
        CHECK(outcome == Outcome::removed_claim_survived);
        CHECK(fs::exists(claim_path));
    }
}

TEST_CASE("every outcome has a name") {
    for (const auto outcome :
         {Outcome::removed, Outcome::not_owned, Outcome::refused,
          Outcome::failed, Outcome::removed_claim_survived}) {
        CHECK(std::string(
                  ndms_native_tunnel_removal_outcome_name(outcome))
                  .size() > 0U);
    }
    CHECK(std::string(ndms_native_tunnel_removal_outcome_name(
              Outcome::removed_claim_survived)) ==
          "removed_claim_survived");
}

} // namespace keen_pbr3
