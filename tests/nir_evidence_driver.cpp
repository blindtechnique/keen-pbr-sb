// Live-document driver for the native-import target evidence builder.
//
// Not part of any test target: cross-compiled by hand and run on the router,
// where the documents are real. The unit tests replay one captured fixture;
// this feeds the builder what the firmware answers right now, for every
// occupied slot, and reports what the production code decides.
//
//   nir-evidence-driver scan <config.json>
//       Prints every JSON path whose key the production secret guard matches.
//       Diagnostic only: shows what the guard actually sees on live data,
//       which is not the same question as what is actually a secret.
//   nir-evidence-driver verdict <name> <config> <status> <asc>
//       Runs the real builder on the documents as read.
//   nir-evidence-driver filtered <name> <config> <status> <asc>
//       Drops the keys the guard matches - the filtering the header tells the
//       caller to do - then runs the same builder and prints the revision.
//
// Exit code is 0 whenever the run itself completed; the verdict is on stdout,
// so a sweep over several interfaces does not stop at the first refusal.

#include "../src/keenetic/ndms_native_target_evidence.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <string>

namespace keen_pbr3 {
namespace {

// Deliberately duplicates the production predicate rather than exporting it:
// the driver must not be able to drift the thing it is measuring.
bool key_matches_guard(const std::string& key) {
    std::string lowered = key;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                   [](const unsigned char ch) {
                       return static_cast<char>(std::tolower(ch));
                   });
    return lowered.find("private") != std::string::npos ||
           lowered.find("preshared") != std::string::npos ||
           lowered.find("secret") != std::string::npos;
}

void scan(const nlohmann::json& document, const std::string& path) {
    if (document.is_object()) {
        for (const auto& [key, value] : document.items()) {
            const auto here = path + "/" + key;
            if (key_matches_guard(key)) {
                std::printf("  matched %s (%s)\n", here.c_str(),
                            value.type_name());
            }
            scan(value, here);
        }
        return;
    }
    if (document.is_array()) {
        for (std::size_t i = 0U; i < document.size(); ++i) {
            scan(document[i], path + "/" + std::to_string(i));
        }
    }
}

nlohmann::json without_matched_keys(const nlohmann::json& document) {
    if (document.is_object()) {
        auto copy = nlohmann::json::object();
        for (const auto& [key, value] : document.items()) {
            if (key_matches_guard(key)) continue;
            copy[key] = without_matched_keys(value);
        }
        return copy;
    }
    if (document.is_array()) {
        auto copy = nlohmann::json::array();
        for (const auto& element : document) {
            copy.push_back(without_matched_keys(element));
        }
        return copy;
    }
    return document;
}

nlohmann::json load(const char* path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        std::printf("  unreadable %s\n", path);
        return nlohmann::json();
    }
    try {
        nlohmann::json parsed;
        input >> parsed;
        return parsed;
    } catch (const std::exception& error) {
        std::printf("  unparsable %s (%s)\n", path, error.what());
        return nlohmann::json();
    }
}

void report(const std::string& name,
            const NdmsNativeTargetEvidenceResult& result) {
    if (result.failure) {
        std::printf("%s result=refused reason=%s\n", name.c_str(),
                    ndms_native_target_read_failure_name(
                        result.failure->reason));
        return;
    }
    std::printf("%s result=ok link_down=%s asc=%s revision=%s\n",
                name.c_str(), result.evidence->link_down ? "yes" : "no",
                result.asc_class
                    ? ndms_native_asc_class_name(*result.asc_class)
                    : "absent",
                result.evidence->full_revision.c_str());
}

} // namespace
} // namespace keen_pbr3

int main(int argc, char** argv) {
    using namespace keen_pbr3;
    if (argc < 3) {
        std::printf("usage: nir-evidence-driver scan <config>\n"
                    "       nir-evidence-driver verdict|filtered <name> "
                    "<config> <status> <asc>\n");
        return 2;
    }
    const std::string mode = argv[1];
    if (mode == "scan") {
        std::printf("scan %s\n", argv[2]);
        scan(load(argv[2]), "");
        return 0;
    }
    if (argc < 6) return 2;
    const std::string name = argv[2];
    auto config = load(argv[3]);
    const auto status = load(argv[4]);
    const auto asc = load(argv[5]);
    if (mode == "filtered") config = without_matched_keys(config);
    report(name, build_ndms_native_target_evidence(name, config, status, asc));
    return 0;
}
