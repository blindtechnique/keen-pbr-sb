// Read-only live check of the delete decision. The mutating dependency is
// replaced by a recorder that REFUSES to run anything: this binary proves the
// decision refuses on the live router without being able to delete at all.
#include "../src/keenetic/ndms_native_interface_delete.hpp"
#include <cstdio>
#include <array>
#include <string>
namespace keen_pbr3 { namespace {
std::optional<nlohmann::json> live_read(const std::string& path) {
    std::string out; std::array<char,8192> buf{};
    FILE* p = ::popen(("curl -s --max-time 6 'http://127.0.0.1:79/rci/" + path + "'").c_str(), "r");
    if (!p) return std::nullopt;
    while (auto n = std::fread(buf.data(),1,buf.size(),p)) out.append(buf.data(), n);
    if (::pclose(p) != 0) return std::nullopt;
    if (out.empty()) return nlohmann::json();
    try { return nlohmann::json::parse(out); } catch (...) { return std::nullopt; }
}
}}
int main() {
    using namespace keen_pbr3;
    NdmsNativeInterfaceDeleteDependencies deps;
    deps.read_document = live_read;
    bool attempted = false;
    deps.run_command = [&](const std::string& c) {
        attempted = true;
        std::printf("  !! WOULD RUN: %s  (refused by dry-run)\n", c.c_str());
        return false;
    };
    const std::string marker = "kpbr-ni-v1-" + std::string(32U,'a');
    const char* names[] = {"Wireguard0","Wireguard3","Wireguard5","Wireguard99"};
    for (const char* n : names) {
        const auto r = delete_exact_owned_ndms_interface(n, marker, deps);
        const char* s = r == NdmsNativeImportRecoveryDeleteOutcome::deleted_confirmed ? "deleted_confirmed"
                      : r == NdmsNativeImportRecoveryDeleteOutcome::refused ? "refused" : "failed";
        std::printf("%-12s -> %s\n", n, s);
    }
    std::printf("\ncommand attempted on a live interface: %s\n", attempted ? "YES" : "no");
    return 0;
}
