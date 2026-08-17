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
//       Runs the production redactor over the config first - the sanitizing
//       the header tells the caller to do - then the same builder, and prints
//       the revision. This is the whole real path: firmware document in,
//       revision out, with nothing hand-written in between.
//
// Exit code is 0 whenever the run itself completed; the verdict is on stdout,
// so a sweep over several interfaces does not stop at the first refusal.

#include "../src/keenetic/ndms_native_secret_redaction.hpp"
#include "../src/keenetic/ndms_native_target_evidence.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

namespace keen_pbr3 {
namespace {

void scan(const nlohmann::json& document, const std::string& path) {
    if (document.is_object()) {
        for (const auto& [key, value] : document.items()) {
            const auto here = path + "/" + key;
            if (ndms_key_could_name_a_secret(key)) {
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

unsigned count_secret_named_keys(const nlohmann::json& document) {
    unsigned total = 0U;
    if (document.is_object()) {
        for (const auto& [key, value] : document.items()) {
            if (ndms_key_could_name_a_secret(key)) ++total;
            total += count_secret_named_keys(value);
        }
    } else if (document.is_array()) {
        for (const auto& element : document) {
            total += count_secret_named_keys(element);
        }
    }
    return total;
}

// Every secret-named key that could carry material holds a marker. Booleans
// are skipped for the same reason the guard skips them.
bool all_secret_keys_are_markers(const nlohmann::json& document) {
    if (document.is_object()) {
        for (const auto& [key, value] : document.items()) {
            if (ndms_key_could_name_a_secret(key) && !value.is_boolean() &&
                !value.is_number() && !value.is_null() &&
                !(value.is_string() && is_ndms_secret_redaction_marker(
                                           value.get<std::string>()))) {
                return false;
            }
            if (!all_secret_keys_are_markers(value)) return false;
        }
    } else if (document.is_array()) {
        for (const auto& element : document) {
            if (!all_secret_keys_are_markers(element)) return false;
        }
    }
    return true;
}

// The check that matters most: not "did the expected field change" but "is any
// string the firmware gave us still present in the bytes we are about to
// hash". Collects every string in the raw document and looks for it in the
// redacted dump.
void collect_secret_strings(const nlohmann::json& document,
                            bool under_secret_key,
                            std::vector<std::string>& into) {
    if (document.is_object()) {
        for (const auto& [key, value] : document.items()) {
            collect_secret_strings(
                value, under_secret_key || ndms_key_could_name_a_secret(key),
                into);
        }
        return;
    }
    if (document.is_array()) {
        for (const auto& element : document) {
            collect_secret_strings(element, under_secret_key, into);
        }
        return;
    }
    if (under_secret_key && document.is_string()) {
        into.push_back(document.get<std::string>());
    }
}

bool raw_secret_values_absent(const nlohmann::json& raw,
                              const nlohmann::json& redacted) {
    std::vector<std::string> secrets;
    collect_secret_strings(raw, false, secrets);
    const auto bytes = redacted.dump();
    for (const auto& secret : secrets) {
        if (!secret.empty() &&
            bytes.find(secret) != std::string::npos) {
            return false;
        }
    }
    return true;
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
    if (mode == "filtered") {
        const auto raw = config;
        config = redact_ndms_secret_material(config, name);
        // Reported, because a driver that silently printed a revision over a
        // document still holding secrets would be the worst possible result.
        std::printf("%s redaction: %u secret-named keys, all markers=%s, "
                    "raw values gone=%s\n",
                    name.c_str(), count_secret_named_keys(config),
                    all_secret_keys_are_markers(config) ? "yes" : "no",
                    raw_secret_values_absent(raw, config) ? "yes" : "no");
    }
    report(name, build_ndms_native_target_evidence(name, config, status, asc));
    return 0;
}
