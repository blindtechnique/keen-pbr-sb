#include "../src/runtime/nfqws_runtime_contract.hpp"

#include <doctest/doctest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace keen_pbr3 {
namespace {

namespace fs = std::filesystem;

class RuntimeContractFixture {
public:
    RuntimeContractFixture() {
        const auto nonce = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        root = fs::temp_directory_path() /
               ("keen-pbr-nfqws-runtime-contract-" +
                std::to_string(nonce));
        fs::create_directories(root / "proc");
        paths.active_config = (root / "nfqws2.conf").string();
        paths.proc_root = (root / "proc").string();
        paths.nfqueue_table = (root / "nfnetlink_queue").string();
    }

    ~RuntimeContractFixture() {
        std::error_code error;
        fs::remove_all(root, error);
    }

    void write_config(int queue = 411, bool quic = true,
                      const std::string& tcp = "443") const {
        std::ofstream output(paths.active_config, std::ios::binary);
        output << "TCP_PORTS=" << tcp << "\n"
               << "UDP_PORTS=443,49152:65535\n"
               << "NFQWS_ARGS=\"--filter-tcp=" << tcp
               << " --lua-desync=fake\"\n";
        if (quic) {
            output << "NFQWS_ARGS_QUIC=\"--filter-udp=443 "
                      "--filter-l7=quic --lua-desync=fake\"\n";
        }
        output << "NFQUEUE_NUM=" << queue << "\n";
    }

    void add_process(const std::string& pid,
                     int queue = 411,
                     const std::string& tcp = "443",
                     bool quic = true) const {
        const auto process = root / "proc" / pid;
        fs::create_directories(process);
        {
            std::ofstream comm(process / "comm", std::ios::binary);
            comm << "nfqws2\n";
        }
        write_starttime(pid, 1000U + static_cast<unsigned long long>(std::stoull(pid)));
        std::vector<std::string> argv{
            "/opt/usr/bin/nfqws2", "--qnum=" + std::to_string(queue),
            "--filter-tcp=" + tcp, "--lua-desync=fake"};
        if (quic) {
            argv.insert(argv.end(),
                        {"--new", "--filter-udp=443", "--filter-l7=quic",
                         "--lua-desync=fake"});
        }
        std::ofstream cmdline(process / "cmdline", std::ios::binary);
        for (const auto& token : argv) {
            cmdline.write(token.data(),
                          static_cast<std::streamsize>(token.size()));
            cmdline.put('\0');
        }
    }

    void write_starttime(const std::string& pid,
                         unsigned long long starttime) const {
        std::ofstream stat(root / "proc" / pid / "stat", std::ios::binary);
        stat << pid << " (nfqws2 worker) S 1 2 3 4 5 6 7 8 9 10 11 12 13 "
             << "14 15 16 17 18 " << starttime << " 23 24\n";
    }

    void bind_queue(int queue) const {
        std::ofstream output(paths.nfqueue_table, std::ios::binary);
        output << queue << " 123 0 2 65531 0 0 0 1\n";
    }

    fs::path root;
    NfqwsRuntimeContractPaths paths;
};

} // namespace

TEST_CASE("nfqws runtime PPE contract requires one matching process and queue") {
    RuntimeContractFixture fixture;
    fixture.write_config();
    fixture.add_process("123");
    fixture.bind_queue(411);

    const auto observed = observe_nfqws_ppe_runtime_contract(fixture.paths);
    REQUIRE(observed.available);
    CHECK(observed.diagnostic.empty());
    CHECK(observed.process_count == 1U);
    CHECK(observed.queue_bound);
    CHECK(observed.config_runtime_match);
    CHECK(observed.contract.queue_number == 411);
    CHECK(observed.contract.tcp_ranges ==
          std::vector<NfqwsPpePortRange>{{443, 443}});
    CHECK(observed.contract.quic_udp_443);
}

TEST_CASE("nfqws runtime PPE contract reports an absent process") {
    RuntimeContractFixture fixture;
    fixture.write_config();
    fixture.bind_queue(411);

    const auto observed = observe_nfqws_ppe_runtime_contract(fixture.paths);
    CHECK_FALSE(observed.available);
    CHECK(observed.process_count == 0U);
    CHECK(observed.diagnostic.find("not running") != std::string::npos);
}

TEST_CASE("nfqws runtime PPE contract rejects an inactive configured queue") {
    RuntimeContractFixture fixture;
    fixture.write_config();
    fixture.add_process("123");
    fixture.bind_queue(412);

    const auto observed = observe_nfqws_ppe_runtime_contract(fixture.paths);
    CHECK_FALSE(observed.available);
    CHECK(observed.config_runtime_match);
    CHECK_FALSE(observed.queue_bound);
    CHECK(observed.diagnostic.find("not bound") != std::string::npos);
}

TEST_CASE("nfqws runtime PPE contract rejects a saved file not running yet") {
    RuntimeContractFixture fixture;
    fixture.write_config(411, true, "443");
    fixture.add_process("123", 412, "443", true);
    fixture.bind_queue(411);

    auto observed = observe_nfqws_ppe_runtime_contract(fixture.paths);
    CHECK_FALSE(observed.available);
    CHECK_FALSE(observed.config_runtime_match);
    CHECK(observed.diagnostic.find("config_runtime_mismatch") !=
          std::string::npos);

    fs::remove_all(fixture.root / "proc" / "123");
    fixture.add_process("123", 411, "80", true);
    observed = observe_nfqws_ppe_runtime_contract(fixture.paths);
    CHECK_FALSE(observed.available);
    CHECK(observed.diagnostic.find("config_runtime_mismatch") !=
          std::string::npos);

    fs::remove_all(fixture.root / "proc" / "123");
    fixture.add_process("123", 411, "443", false);
    observed = observe_nfqws_ppe_runtime_contract(fixture.paths);
    CHECK_FALSE(observed.available);
    CHECK(observed.diagnostic.find("config_runtime_mismatch") !=
          std::string::npos);
}

TEST_CASE("nfqws runtime PPE contract rejects multiple ambiguous processes") {
    RuntimeContractFixture fixture;
    fixture.write_config();
    fixture.add_process("123");
    fixture.add_process("124");
    fixture.bind_queue(411);

    const auto observed = observe_nfqws_ppe_runtime_contract(fixture.paths);
    CHECK_FALSE(observed.available);
    CHECK(observed.process_count == 2U);
    CHECK(observed.diagnostic.find("multiple") != std::string::npos);
}

TEST_CASE("nfqws runtime PPE contract fences PID identity across observation") {
    RuntimeContractFixture fixture;
    fixture.write_config();
    fixture.add_process("123");
    fixture.bind_queue(411);
    bool changed = false;
    fixture.paths.after_identity_read = [&](const std::string& process_path) {
        if (changed || fs::path(process_path).filename() != "123") return;
        changed = true;
        fixture.write_starttime("123", 999999U);
    };

    const auto observed = observe_nfqws_ppe_runtime_contract(fixture.paths);
    CHECK_FALSE(observed.available);
    CHECK(observed.diagnostic.find("identity changed") != std::string::npos);
}

} // namespace keen_pbr3
