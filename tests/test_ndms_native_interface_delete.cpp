#include <doctest/doctest.h>

#include "../src/keenetic/ndms_native_interface_delete.hpp"

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

namespace {

using Outcome = NdmsNativeImportRecoveryDeleteOutcome;

const std::string kMarker = "kpbr-ni-v1-" + std::string(32U, 'a');

nlohmann::json interface_document(const std::string& description) {
    return nlohmann::json{{"description", description},
                          {"type", "Wireguard"},
                          {"up", true}};
}

// A router that answers from a script: each RCI path maps to a sequence of
// answers, consumed one per read, so a test can say "present, then absent"
// and pin the exact number of reads the operation makes.
class ScriptedRouter {
public:
    void queue(const std::string& path,
               std::optional<nlohmann::json> answer) {
        answers_[path].push_back(std::move(answer));
    }

    NdmsNativeInterfaceDeleteDependencies dependencies() {
        NdmsNativeInterfaceDeleteDependencies dependencies;
        dependencies.read_document =
            [this](const std::string& path) {
                ++reads;
                auto& queue = answers_[path];
                if (queue.empty()) {
                    // An unscripted read is a test bug, not a router state.
                    unscripted_reads.push_back(path);
                    return std::optional<nlohmann::json>{};
                }
                auto answer = queue.front();
                if (queue.size() > 1U) queue.erase(queue.begin());
                return answer;
            };
        dependencies.run_command = [this](const std::string& command) {
            commands.push_back(command);
            return command_succeeds;
        };
        return dependencies;
    }

    std::map<std::string, std::vector<std::optional<nlohmann::json>>>
        answers_;
    std::vector<std::string> commands;
    std::vector<std::string> unscripted_reads;
    std::size_t reads{0U};
    bool command_succeeds{true};
};

const std::string kConfig = "show/rc/interface/Wireguard5";
const std::string kRuntime = "show/interface/Wireguard5";

} // namespace

TEST_CASE("an owned interface is deleted and its absence proven") {
    ScriptedRouter router;
    router.queue(kConfig, interface_document("tunnel " + kMarker));
    router.queue(kConfig, nlohmann::json());  // gone after the command
    router.queue(kRuntime, nlohmann::json());

    const auto outcome = delete_exact_owned_ndms_interface(
        "Wireguard5", kMarker, router.dependencies());
    CHECK(outcome == Outcome::deleted_confirmed);
    REQUIRE(router.commands.size() == 1U);
    CHECK(router.commands.front() == "no interface Wireguard5");
    CHECK(router.unscripted_reads.empty());
}

TEST_CASE("an interface that stopped being ours is never removed") {
    // The observation that authorized the plan is not evidence about this
    // instant: between it and here the interface may have been renamed,
    // replaced or re-described, and the fresh read is what decides.
    ScriptedRouter router;
    router.queue(kConfig, interface_document("somebody else's tunnel"));

    CHECK(delete_exact_owned_ndms_interface("Wireguard5", kMarker,
                                            router.dependencies()) ==
          Outcome::refused);
    CHECK(router.commands.empty());
}

TEST_CASE("a protected slot is refused even when it carries our marker") {
    ScriptedRouter router;
    router.queue("show/rc/interface/Wireguard0",
                 interface_document("tunnel " + kMarker));
    for (const char* name : {"Wireguard0", "Wireguard4", "Wireguard99",
                             "Wireguard126", "wireguard5", "Wireguard05"}) {
        CHECK(delete_exact_owned_ndms_interface(name, kMarker,
                                                router.dependencies()) ==
              Outcome::refused);
    }
    CHECK(router.commands.empty());
}

TEST_CASE("an unreadable world never authorizes a delete") {
    ScriptedRouter router;
    router.queue(kConfig, std::nullopt);  // the read itself failed

    CHECK(delete_exact_owned_ndms_interface("Wireguard5", kMarker,
                                            router.dependencies()) ==
          Outcome::failed);
    CHECK(router.commands.empty());
}

TEST_CASE("a command that failed is never reported as a deletion") {
    ScriptedRouter router;
    router.command_succeeds = false;
    router.queue(kConfig, interface_document("tunnel " + kMarker));

    CHECK(delete_exact_owned_ndms_interface("Wireguard5", kMarker,
                                            router.dependencies()) ==
          Outcome::failed);
    REQUIRE(router.commands.size() == 1U);
}

TEST_CASE("a survivor after a successful command is a failure, not a win") {
    // ndmc reporting success is not absence. deleted_confirmed advances the
    // WAL into a phase that asserts the interface is gone, so it may not rest
    // on an exit code.
    ScriptedRouter router;
    router.queue(kConfig, interface_document("tunnel " + kMarker));
    router.queue(kConfig, interface_document("tunnel " + kMarker));
    router.queue(kRuntime, nlohmann::json());

    CHECK(delete_exact_owned_ndms_interface("Wireguard5", kMarker,
                                            router.dependencies()) ==
          Outcome::failed);
}

TEST_CASE("a config that is gone while the runtime survives is a failure") {
    // Half-deleted is not deleted. The runtime interface still exists, so
    // absence is not proven and the WAL must not advance.
    ScriptedRouter router;
    router.queue(kConfig, interface_document("tunnel " + kMarker));
    router.queue(kConfig, nlohmann::json());
    router.queue(kRuntime, interface_document("tunnel " + kMarker));

    CHECK(delete_exact_owned_ndms_interface("Wireguard5", kMarker,
                                            router.dependencies()) ==
          Outcome::failed);
}

TEST_CASE("an interface already gone confirms without issuing a command") {
    // The postcondition holds. Refusing here would strand a rollback that has
    // nothing left to do, and absence is still proven from both documents
    // rather than assumed from one.
    ScriptedRouter router;
    router.queue(kConfig, nlohmann::json());
    router.queue(kRuntime, nlohmann::json());

    CHECK(delete_exact_owned_ndms_interface("Wireguard5", kMarker,
                                            router.dependencies()) ==
          Outcome::deleted_confirmed);
    CHECK(router.commands.empty());
}

TEST_CASE("an absent config with an unreadable runtime does not confirm") {
    ScriptedRouter router;
    router.queue(kConfig, nlohmann::json());
    router.queue(kRuntime, std::nullopt);

    CHECK(delete_exact_owned_ndms_interface("Wireguard5", kMarker,
                                            router.dependencies()) ==
          Outcome::failed);
    CHECK(router.commands.empty());
}

TEST_CASE("an empty marker cannot authorize anything") {
    ScriptedRouter router;
    router.queue(kConfig, interface_document(""));

    CHECK(delete_exact_owned_ndms_interface("Wireguard5", "",
                                            router.dependencies()) ==
          Outcome::refused);
    CHECK(router.commands.empty());
}

TEST_CASE("missing dependencies fail closed rather than crash") {
    NdmsNativeInterfaceDeleteDependencies empty;
    CHECK(delete_exact_owned_ndms_interface("Wireguard5", kMarker, empty) ==
          Outcome::failed);
}

TEST_CASE("the command spelling is pinned") {
    // A delete that names the wrong interface is unrecoverable, and this
    // string is the whole of what the router is told. No save is issued, so
    // the change lives only in the running configuration.
    CHECK(ndms_native_interface_delete_command("Wireguard5") ==
          "no interface Wireguard5");
    CHECK(ndms_native_interface_delete_command("Wireguard98") ==
          "no interface Wireguard98");
}

} // namespace keen_pbr3
