#include <filesystem>
#include <fstream>
#include <iostream>

int main() {
    // Mirror the __FILE__-relative lookup used by existing C++ fixture readers.
    const auto root = std::filesystem::path(__FILE__)
                          .parent_path().parent_path().parent_path()
                          .parent_path().parent_path();
    for (const char* relative : {
             "tests/fixtures/config-migrations/pre-hex-fwmark.json",
             "extensions/transport-manager/internal/transport/testdata/"
             "subscription_link_fingerprint_v1.txt",
             "packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/"
             "nfqws-strategies/02 balanced/nfqws2.conf"}) {
        const auto path = root / relative;
        std::ifstream input(path);
        if (!input.good()) {
            std::cerr << "Cannot read source fixture: " << path << '\n';
            return 1;
        }
    }
}
