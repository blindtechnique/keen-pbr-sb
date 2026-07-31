#include <doctest/doctest.h>

#include "../src/config/config.hpp"
#include "../src/config/routing_state.hpp"
#include "../src/firewall/ipset_restore_pipe.hpp"
#include "../src/firewall/iptables.hpp"
#include "../src/lists/list_entry_visitor.hpp"
#include "../src/util/last_command_failure.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iterator>
#include <optional>
#include <string>
#include <set>
#include <array>
#include <algorithm>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace keen_pbr3 {

namespace {

L4Proto parse_test_proto(const std::string& proto) {
  if (proto.empty()) return L4Proto::Any;
  if (proto == "tcp") return L4Proto::Tcp;
  if (proto == "udp") return L4Proto::Udp;
  if (proto == "tcp/udp") return L4Proto::TcpUdp;
  throw std::invalid_argument("unexpected proto in test: " + proto);
}

class IptablesTestEnvironment {
public:
  explicit IptablesTestEnvironment(std::string name)
      : name_(std::move(name)) {
    if (const char* value = std::getenv(name_.c_str())) {
      previous_ = value;
    }
  }
  ~IptablesTestEnvironment() {
    if (previous_) {
      setenv(name_.c_str(), previous_->c_str(), 1);
    } else {
      unsetenv(name_.c_str());
    }
  }
  void set(const std::string& value) {
    if (setenv(name_.c_str(), value.c_str(), 1) != 0) {
      throw std::runtime_error("setenv failed");
    }
  }
private:
  std::string name_;
  std::optional<std::string> previous_;
};

class IptablesTestTempDir {
public:
  IptablesTestTempDir() {
    char path_template[] = "/tmp/keen-pbr-iptables-XXXXXX";
    const char* created = mkdtemp(path_template);
    if (created == nullptr) {
      throw std::runtime_error("mkdtemp failed");
    }
    path_ = created;
  }
  ~IptablesTestTempDir() {
    std::error_code error;
    std::filesystem::remove_all(path_, error);
  }
  const std::filesystem::path& path() const { return path_; }
private:
  std::filesystem::path path_;
};

class IptablesFailurePathGuard {
public:
  explicit IptablesFailurePathGuard(const std::filesystem::path& path) {
    set_last_command_failure_path_for_testing(path.string());
  }
  ~IptablesFailurePathGuard() {
    set_last_command_failure_path_for_testing(std::nullopt);
  }
};

void write_iptables_test_executable(
    const std::filesystem::path& path,
    const std::string& content) {
  std::ofstream output(path);
  output << content;
  output.close();
  if (!output || chmod(path.c_str(), 0700) != 0) {
    throw std::runtime_error("failed to create test executable");
  }
}

std::string read_iptables_test_file(const std::filesystem::path& path) {
  std::ifstream input(path);
  return {std::istreambuf_iterator<char>(input),
          std::istreambuf_iterator<char>()};
}

void use_iptables_test_path(
    IptablesTestEnvironment& guard,
    const std::filesystem::path& directory) {
  const char* current = std::getenv("PATH");
  guard.set(directory.string() + ":" + (current == nullptr ? "" : current));
}

} // namespace

TEST_CASE("raw prerouting selection does not perform a racy constructor probe") {
  // The Keenetic init script capability-gates raw PREROUTING before launching
  // the daemon. Repeating `iptables -t raw -S` here used to turn a transient
  // xtables lock during firmware startup into a fatal daemon startup failure.
  // The real transactional restore remains the authoritative capability check
  // and its failure is handled by the daemon's scheduled firewall retry.
  IptablesFirewall firewall(/*use_raw_prerouting=*/true);
  CHECK(firewall.uses_raw_prerouting());
}

// Friend class with test access to IptablesFirewall private methods.
class IptablesBuilderTest {
public:
  using State = IptablesFirewall::LiveGenerationState;

  // Public mirror of PendingRule for use in test functions.
  struct RuleDesc {
    std::string set_name;
    bool ipv6;
    bool direct = false;
    enum Action { Mark, Drop, Pass } action;
    uint32_t fwmark;
    ProtoPortFilter filter;
  };

  static std::string build_ipset_create_line(const std::string &name,
                                             const std::string &family_str,
                                             uint32_t timeout) {
    IptablesFirewall::PendingSet ps;
    ps.name = name;
    ps.family_str = family_str;
    ps.timeout = timeout;
    return IptablesFirewall::build_ipset_create_line(ps);
  }

  static bool is_dynamic_set_name(const std::string& name) {
    return IptablesFirewall::is_dynamic_set_name(name);
  }

  static bool dynamic_set_schema_compatible(
      const std::string& xml,
      const std::string& name,
      const std::string& family,
      uint32_t timeout) {
    IptablesFirewall::PendingSet expected;
    expected.name = name;
    expected.family_str = family;
    expected.timeout = timeout;
    return IptablesFirewall::dynamic_set_schema_compatible(xml, expected);
  }

  static std::string build_ipt_script(bool ipv6,
                                      const std::vector<RuleDesc> &descs,
                                      FirewallGlobalPrefilter prefilter = {}) {
    std::vector<IptablesFirewall::PendingRule> rules;
    rules.reserve(descs.size());
    for (const auto &d : descs) {
      IptablesFirewall::PendingRule pr;
      pr.ipv6 = d.ipv6;
      if (d.action == RuleDesc::Mark) {
        pr.action = IptablesFirewall::PendingRule::Mark;
      } else if (d.action == RuleDesc::Drop) {
        pr.action = IptablesFirewall::PendingRule::Drop;
      } else {
        pr.action = IptablesFirewall::PendingRule::Pass;
      }
      pr.fwmark = d.fwmark;
      pr.criteria = d.filter;
      if (!d.set_name.empty()) {
        pr.criteria.dst_set_name = d.set_name;
      }
      rules.push_back(std::move(pr));
    }
    return IptablesFirewall::build_ipt_script(ipv6, rules, prefilter);
  }

  static std::string build_ipt_script_for_rule(bool ipv6,
                                               RuleDesc::Action action,
                                               uint32_t fwmark,
                                               FirewallRuleCriteria criteria,
                                               bool list_backed,
                                               uint32_t fwmark_mask = 0xFFFFFFFFu,
                                               FirewallGlobalPrefilter prefilter = {}) {
    IptablesFirewall fw;
    fw.set_fwmark_mask(fwmark_mask);
    if (list_backed) {
      criteria.dst_set_name = "pairwise_set";
      fw.created_sets_["pairwise_set"] = ipv6 ? AF_INET6 : AF_INET;
    }

    IptablesFirewall::PendingRule::Action mapped_action =
        IptablesFirewall::PendingRule::Mark;
    if (action == RuleDesc::Drop) {
      mapped_action = IptablesFirewall::PendingRule::Drop;
    } else if (action == RuleDesc::Pass) {
      mapped_action = IptablesFirewall::PendingRule::Pass;
    }

    fw.append_rules_for_family(ipv6, mapped_action, fwmark, criteria);
    return IptablesFirewall::build_ipt_script(ipv6, fw.pending_rules_, prefilter);
  }

  static std::string build_proto_port_fragment(const std::string &proto,
                                               const std::string &src_port,
                                               const std::string &dst_port,
                                               bool negate_src = false,
                                               bool negate_dst = false) {
    const auto fragments = IptablesFirewall::build_proto_port_fragments(
        parse_test_proto(proto), PortSpec(src_port), PortSpec(dst_port),
        negate_src, negate_dst);
    if (fragments.size() != 1) {
      throw std::invalid_argument(
          "Port specification requires multiple iptables rules");
    }
    return fragments.front();
  }

  static std::string build_output_mark_script(
      uint32_t fwmark,
      const FirewallRuleCriteria &criteria,
      const FirewallGlobalPrefilter &prefilter) {
    IptablesFirewall fw;
    fw.create_output_mark_rule(fwmark, criteria);
    return IptablesFirewall::build_ipt_script(false, fw.pending_rules_, prefilter);
  }

  static std::string build_dns_nat_script(
      const FirewallGlobalPrefilter &prefilter,
      bool dns_redirect = true,
      bool router_origin_snat = false,
      const std::vector<std::string> &snat_interfaces = {},
      bool ipv6 = false,
      uint32_t fwmark_mask = 0xFFFFFFFFu,
      const std::vector<FirewallSourceEgressSnatSelector>
          &source_egress_snat_selectors = {}) {
    return IptablesFirewall::build_dns_nat_script(
        prefilter,
        dns_redirect,
        router_origin_snat,
        snat_interfaces,
        ipv6,
        fwmark_mask,
        source_egress_snat_selectors);
  }

  static OwnedSnatState inspect_owned_snat_state(
      bool expected = false,
      const std::vector<std::string>& expected_interfaces = {},
      uint32_t expected_fwmark_mask = 0xFFFFFFFFu,
      const std::vector<FirewallSourceEgressSnatSelector>
          &expected_source_egress_selectors = {}) {
    return IptablesFirewall::inspect_owned_snat_state(
        "iptables",
        expected,
        expected_interfaces,
        expected_source_egress_selectors,
        expected_fwmark_mask);
  }

  static OwnedSnatState combine_owned_snat_states(
      OwnedSnatState ipv4,
      OwnedSnatState ipv6) {
    return IptablesFirewall::combine_owned_snat_states(ipv4, ipv6);
  }

  static OwnedSnatState inspect_owned_snat_families(
      bool ipv4_expected,
      bool ipv6_expected,
      bool ipv6_managed) {
    IptablesFirewall fw;
    fw.last_applied_snat_v4_expected_ = ipv4_expected;
    fw.last_applied_snat_v6_expected_ = ipv6_expected;
    fw.last_applied_snat_v6_managed_ = ipv6_managed;
    return fw.inspect_owned_snat_state();
  }

  static std::size_t tunnel_snat_interface_count(
      const std::vector<std::string> &interfaces) {
    IptablesFirewall fw;
    fw.create_tunnel_snat_rules(interfaces);
    return fw.snat_interfaces_.size();
  }

  static std::vector<FirewallSourceEgressSnatSelector>
  source_egress_snat_selectors(
      const std::vector<FirewallSourceEgressSnatSelector> &selectors) {
    IptablesFirewall fw;
    fw.create_source_egress_snat_rules(selectors);
    return fw.source_egress_snat_selectors_;
  }

  static bool source_egress_snat_requested(
      const std::vector<FirewallSourceEgressSnatSelector> &selectors) {
    IptablesFirewall fw;
    fw.create_source_egress_snat_rules(selectors);
    return fw.router_origin_snat_requested_;
  }

  static std::string build_output_mark_script_with_snat(
      uint32_t fwmark, const FirewallRuleCriteria &criteria,
      uint32_t fwmark_mask) {
    IptablesFirewall fw;
    fw.set_fwmark_mask(fwmark_mask);
    fw.create_output_mark_rule(fwmark, criteria);
    return IptablesFirewall::build_ipt_script(false, fw.pending_rules_, {});
  }

  static std::string build_generation_script(
      bool replace_active,
      const FirewallGlobalPrefilter &prefilter = {}) {
    IptablesFirewall fw;
    FirewallRuleCriteria output_criteria;
    output_criteria.proto = L4Proto::Udp;
    output_criteria.dst_port = "53";
    fw.create_output_mark_rule(0x10000, output_criteria);
    return IptablesFirewall::build_generation_ipt_script(
        false, "KeenPbrTable_A", "KeenPbrOutput_A",
        replace_active, fw.pending_rules_, prefilter);
  }

  static std::pair<std::string, std::string> build_raw_generation_scripts(
      bool replace_active,
      const FirewallGlobalPrefilter &prefilter = {}) {
    IptablesFirewall fw;
    FirewallRuleCriteria route_criteria;
    route_criteria.dst_set_name = "kpbr4s_test";
    fw.create_mark_rule(0x10000, route_criteria);
    FirewallRuleCriteria output_criteria;
    output_criteria.proto = L4Proto::Udp;
    output_criteria.dst_port = "53";
    fw.create_output_mark_rule(0x20000, output_criteria);
    return {
        IptablesFirewall::build_raw_prerouting_script(
            "KeenPbrRaw_A", replace_active, fw.pending_rules_, prefilter),
        IptablesFirewall::build_output_generation_script(
            "KeenPbrOutput_A", replace_active, fw.pending_rules_, prefilter),
    };
  }

  static std::string build_raw_conntrack_script(
      bool replace_active,
      const FirewallGlobalPrefilter& prefilter = {}) {
    return IptablesFirewall::build_raw_conntrack_script(
        replace_active, prefilter);
  }

  static std::pair<std::string, std::string> generation_set_names() {
    IptablesFirewall fw;
    fw.prepare_apply(FirewallApplyMode::Destructive);
    const std::string first = fw.static_set_name("abcdefghijklmnopqrstuvwx", AF_INET);
    fw.target_v4_generation_ = FirewallSetGeneration::B;
    const std::string second = fw.static_set_name("abcdefghijklmnopqrstuvwx", AF_INET);
    return {first, second};
  }

  static State parse_live_generation(
      const std::string& rules,
      const std::string& dispatcher,
      const std::string& generation_a,
      const std::string& generation_b) {
    return IptablesFirewall::parse_live_generation(
        rules, dispatcher, generation_a, generation_b);
  }

  static FirewallSetGeneration target_generation_for_states(
      State primary,
      State secondary) {
    return IptablesFirewall::target_generation_for_states(primary, secondary);
  }

  static std::size_t count_exact_jump(
      const std::string& rules,
      const std::string& source,
      const std::string& target) {
    return IptablesFirewall::count_exact_jump(rules, source, target);
  }

  static void publish_dispatcher(
      bool ipv6,
      bool output,
      FirewallSetGeneration generation) {
    IptablesFirewall fw;
    fw.publish_dispatcher(ipv6, output, generation);
  }

  static State inspect_dispatcher(
      const char* command,
      const char* table,
      const std::string& dispatcher,
      const std::string& generation_a,
      const std::string& generation_b) {
    IptablesFirewall fw;
    return fw.inspect_dispatcher(
        command, table, dispatcher, generation_a, generation_b);
  }

  static void reconcile_hook(
      const char* command,
      const char* table,
      const char* builtin_chain,
      const char* target_chain) {
    IptablesFirewall::reconcile_hook(
        command, table, builtin_chain, target_chain);
  }

  static void verify_applied_generation(
      FirewallSetGeneration generation,
      bool use_raw_prerouting = false) {
    IptablesFirewall fw(use_raw_prerouting);
    fw.verify_applied_generation(false, generation);
  }

  static void apply_preserve_with_existing_nat_and_raw_hook_failure() {
    IptablesFirewall fw(/*use_raw_prerouting=*/true);
    fw.set_ipv6_enabled(false);
    fw.apply_prepared_ = true;
    fw.target_v4_generation_ = FirewallSetGeneration::B;
    fw.dns_nat_v4_created_ = true;
    fw.router_origin_snat_requested_ = true;
    fw.snat_interfaces_ = {"nwg2"};
    fw.apply(FirewallApplyMode::PreserveSets);
  }

  static std::string build_nat_validation_script(
      const std::string& nat_script) {
    return IptablesFirewall::build_nat_validation_script(nat_script);
  }

  static OwnedSnatState apply_preserve_nat_for_test() {
    IptablesFirewall fw;
    fw.set_ipv6_enabled(false);
    fw.dns_nat_v4_created_ = true;
    fw.dns_redirect_requested_ = true;
    fw.router_origin_snat_requested_ = true;
    fw.snat_interfaces_ = {"nwg2"};
    fw.apply_nat_rules(
        /*effective_ipv6=*/false,
        FirewallApplyMode::PreserveSets);
    return fw.inspect_owned_snat_state();
  }

  static void apply_preserve_ipv6_nat_for_test() {
    IptablesFirewall fw;
    fw.dns_redirect_requested_ = true;
    fw.apply_nat_rules(
        /*effective_ipv6=*/true,
        FirewallApplyMode::PreserveSets);
  }

  static bool apply_preserve_nat_cleans_untracked_ipv6_for_test() {
    IptablesFirewall fw;
    fw.dns_redirect_requested_ = true;
    fw.apply_nat_rules(
        /*effective_ipv6=*/false,
        FirewallApplyMode::PreserveSets);
    return fw.dns_nat_v6_created_;
  }

  static void apply_preserve_without_nat_for_test() {
    IptablesFirewall fw;
    fw.apply_nat_rules(
        /*effective_ipv6=*/false,
        FirewallApplyMode::PreserveSets);
  }

  static std::pair<bool, bool>
  cleanup_nat_failure_retains_ownership_for_test() {
    IptablesFirewall fw;
    fw.dns_nat_v4_created_ = true;
    try {
      fw.cleanup_nat_rules_impl();
    } catch (const TransientFirewallError&) {
      return {true, fw.dns_nat_v4_created_};
    }
    return {false, fw.dns_nat_v4_created_};
  }
};

} // namespace keen_pbr3

using namespace keen_pbr3;
using T = IptablesBuilderTest;
using Rule = IptablesBuilderTest::RuleDesc;

TEST_CASE("preserve apply keeps existing NAT when raw companion hook fails") {
  IptablesTestTempDir temp;
  const auto calls = temp.path() / "iptables-calls";
  write_iptables_test_executable(
      temp.path() / "iptables",
      "#!/bin/sh\n"
      "printf '%s\\n' \"$*\" >> \"$KPBR_IPTABLES_CALLS\"\n"
      "case \"$*\" in\n"
      "  '-t raw -S')\n"
      "    printf '%s\\n' '-N KeenPbrRaw' '-A KeenPbrRaw -j KeenPbrRaw_A'\n"
      "    ;;\n"
      "  '-t mangle -S')\n"
      "    printf '%s\\n' '-N KeenPbrOutput' "
      "'-A KeenPbrOutput -j KeenPbrOutput_A'\n"
      "    ;;\n"
      "  '-t raw -S PREROUTING')\n"
      "    printf '%s\\n' '-A PREROUTING -j KeenPbrRaw'\n"
      "    ;;\n"
      "  '-t mangle -S OUTPUT')\n"
      "    printf '%s\\n' '-A OUTPUT -j KeenPbrOutput'\n"
      "    ;;\n"
      "  '-t mangle -S PREROUTING')\n"
      "    echo 'invalid argument' >&2\n"
      "    exit 2\n"
      "    ;;\n"
      "esac\n"
      "exit 0\n");
  write_iptables_test_executable(
      temp.path() / "iptables-restore",
      "#!/bin/sh\n"
      "if [ \"$1\" = -w ] && [ \"$2\" = 0 ]; then exit 0; fi\n"
      "/bin/cat >/dev/null\n"
      "exit 0\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_IPTABLES_CALLS");
  use_iptables_test_path(path, temp.path());
  calls_env.set(calls.string());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  testing::reset_restore_wait_option_probe_for_test();
  CHECK_THROWS_AS(
      T::apply_preserve_with_existing_nat_and_raw_hook_failure(),
      FirewallError);
  const std::string command_log = read_iptables_test_file(calls);
  CHECK(command_log.find("-t mangle -S PREROUTING") != std::string::npos);
  CHECK(command_log.find("-t nat ") == std::string::npos);
  testing::reset_restore_wait_option_probe_for_test();
}

TEST_CASE("NAT legacy preflight uses deterministic unhooked validation chains") {
  const std::string active = T::build_dns_nat_script(
      {}, /*dns_redirect=*/true, /*router_origin_snat=*/true, {"nwg2"});
  const std::string validation = T::build_nat_validation_script(active);

  CHECK(validation.find(":KeenPbrDnsValidate - [0:0]\n") !=
        std::string::npos);
  CHECK(validation.find(":KeenPbrSnatValidate - [0:0]\n") !=
        std::string::npos);
  CHECK(validation.find(
            "-A KeenPbrDnsValidate -p udp --dport 53 "
            "-j REDIRECT --to-ports 53\n") != std::string::npos);
  CHECK(validation.find(
            "-A KeenPbrSnatValidate -o nwg2 -m mark ! "
            "--mark 0x0/0xffffffff -j MASQUERADE\n") !=
        std::string::npos);
  CHECK(validation.find("-F KeenPbrDnsValidate\n") != std::string::npos);
  CHECK(validation.find("-F KeenPbrSnatValidate\n") != std::string::npos);
  CHECK(validation.find("-A PREROUTING -j") == std::string::npos);
  CHECK(validation.find("-A POSTROUTING -j") == std::string::npos);
  CHECK(validation.find("KeenPbrDnsRdr") == std::string::npos);
  CHECK(validation.find("KeenPbrSnat\n") == std::string::npos);
}

TEST_CASE("failed exact NAT preflight does not clean up active NAT") {
  IptablesTestTempDir temp;
  const auto calls = temp.path() / "iptables-calls";
  write_iptables_test_executable(
      temp.path() / "iptables",
      "#!/bin/sh\n"
      "printf '%s\\n' \"$*\" >> \"$KPBR_IPTABLES_CALLS\"\n"
      "exit 0\n");
  write_iptables_test_executable(
      temp.path() / "iptables-restore",
      "#!/bin/sh\n"
      "[ \"$1\" = --test ] && [ \"$#\" -eq 1 ] && exit 0\n"
      "[ \"$1\" = -w ] && [ \"$2\" = 0 ] && exit 0\n"
      "/bin/cat >/dev/null\n"
      "echo 'iptables-restore: line 4 failed' >&2\n"
      "exit 1\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_IPTABLES_CALLS");
  path.set(temp.path().string());
  calls_env.set(calls.string());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  testing::reset_restore_wait_option_probe_for_test();
  CHECK_THROWS_AS(T::apply_preserve_nat_for_test(), FirewallError);
  CHECK(read_iptables_test_file(calls).empty());
  testing::reset_restore_wait_option_probe_for_test();
}

TEST_CASE("failed NAT commit keeps previously hooked active NAT") {
  IptablesTestTempDir temp;
  const auto calls = temp.path() / "iptables-calls";
  write_iptables_test_executable(
      temp.path() / "iptables",
      "#!/bin/sh\n"
      "printf '%s\\n' \"$*\" >> \"$KPBR_IPTABLES_CALLS\"\n"
      "exit 0\n");
  write_iptables_test_executable(
      temp.path() / "iptables-restore",
      "#!/bin/sh\n"
      "[ \"$1\" = --test ] && [ \"$#\" -eq 1 ] && exit 0\n"
      "[ \"$1\" = -w ] && [ \"$2\" = 0 ] && exit 0\n"
      "/bin/cat >/dev/null\n"
      "case \" $* \" in\n"
      "  *' --test '*) exit 0 ;;\n"
      "esac\n"
      "echo 'iptables-restore: line 4 failed' >&2\n"
      "exit 1\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_IPTABLES_CALLS");
  path.set(temp.path().string());
  calls_env.set(calls.string());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  testing::reset_restore_wait_option_probe_for_test();
  CHECK_THROWS_AS(T::apply_preserve_nat_for_test(), FirewallError);
  // The new restore transaction failed before hook reconciliation. No
  // iptables -D/-F/-X cleanup touched the previously working NAT chains.
  CHECK(read_iptables_test_file(calls).empty());
  testing::reset_restore_wait_option_probe_for_test();
}

TEST_CASE("failed legacy NAT preflight only cleans validation chains") {
  IptablesTestTempDir temp;
  const auto calls = temp.path() / "iptables-calls";
  write_iptables_test_executable(
      temp.path() / "iptables",
      "#!/bin/sh\n"
      "printf '%s\\n' \"$*\" >> \"$KPBR_IPTABLES_CALLS\"\n"
      "exit 0\n");
  write_iptables_test_executable(
      temp.path() / "iptables-restore",
      "#!/bin/sh\n"
      "[ \"$1\" = --test ] && "
      "{ echo \"unrecognized option '--test'\" >&2; exit 1; }\n"
      "[ \"$1\" = -w ] && exit 1\n"
      "/bin/cat >/dev/null\n"
      "echo 'iptables-restore: line 4 failed' >&2\n"
      "exit 1\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_IPTABLES_CALLS");
  path.set(temp.path().string());
  calls_env.set(calls.string());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  testing::reset_restore_wait_option_probe_for_test();
  CHECK_THROWS_AS(T::apply_preserve_nat_for_test(), FirewallError);
  const std::string command_log = read_iptables_test_file(calls);
  CHECK(command_log.find("KeenPbrDnsValidate") != std::string::npos);
  CHECK(command_log.find("KeenPbrSnatValidate") != std::string::npos);
  CHECK(command_log.find("KeenPbrDnsRdr") == std::string::npos);
  CHECK(command_log.find("-F KeenPbrSnat\n") == std::string::npos);
  CHECK(command_log.find("-X KeenPbrSnat\n") == std::string::npos);
  testing::reset_restore_wait_option_probe_for_test();
}

TEST_CASE("transient IPv6 nat inspection is not downgraded to unsupported") {
  IptablesTestTempDir temp;
  write_iptables_test_executable(
      temp.path() / "ip6tables",
      "#!/bin/sh\n"
      "echo 'xtables lock is temporarily unavailable' >&2\n"
      "exit 4\n");
  IptablesTestEnvironment path("PATH");
  use_iptables_test_path(path, temp.path());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  CHECK_THROWS_AS(
      T::apply_preserve_ipv6_nat_for_test(),
      TransientFirewallError);
}

TEST_CASE("partial IPv6 NAT hook reconciliation is surfaced") {
  IptablesTestTempDir temp;
  write_iptables_test_executable(
      temp.path() / "iptables",
      "#!/bin/sh\n"
      "case \"$*\" in\n"
      "  '-t nat -S PREROUTING')\n"
      "    echo '-A PREROUTING -j KeenPbrDnsRdr'\n"
      "    ;;\n"
      "  '-t nat -S KeenPbrSnat')\n"
      "    echo 'iptables: No chain/target/match by that name.' >&2\n"
      "    exit 1\n"
      "    ;;\n"
      "esac\n"
      "exit 0\n");
  write_iptables_test_executable(
      temp.path() / "ip6tables",
      "#!/bin/sh\n"
      "# The table exists, but the PREROUTING hook never becomes visible\n"
      "# after a nominally successful mutation.\n"
      "exit 0\n");
  for (const auto* name : {"iptables-restore", "ip6tables-restore"}) {
    write_iptables_test_executable(
        temp.path() / name,
        "#!/bin/sh\n"
        "/bin/cat >/dev/null\n"
        "exit 0\n");
  }
  IptablesTestEnvironment path("PATH");
  use_iptables_test_path(path, temp.path());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  testing::reset_restore_wait_option_probe_for_test();
  CHECK_THROWS_AS(
      T::apply_preserve_ipv6_nat_for_test(),
      TransientFirewallError);
  testing::reset_restore_wait_option_probe_for_test();
}

TEST_CASE("fresh daemon removes retained IPv6 NAT when disabled") {
  IptablesTestTempDir temp;
  const auto calls = temp.path() / "ip6tables-calls";
  const auto removed = temp.path() / "ipv6-dns-hook-removed";
  write_iptables_test_executable(
      temp.path() / "iptables",
      "#!/bin/sh\n"
      "case \"$*\" in\n"
      "  '-t nat -S PREROUTING')\n"
      "    echo '-A PREROUTING -j KeenPbrDnsRdr'\n"
      "    ;;\n"
      "  '-t nat -S KeenPbrSnat')\n"
      "    echo 'iptables: No chain/target/match by that name.' >&2\n"
      "    exit 1\n"
      "    ;;\n"
      "esac\n"
      "exit 0\n");
  write_iptables_test_executable(
      temp.path() / "ip6tables",
      "#!/bin/sh\n"
      "printf '%s\\n' \"$*\" >> \"$KPBR_IP6TABLES_CALLS\"\n"
      "case \"$*\" in\n"
      "  '-t nat -S PREROUTING')\n"
      "    [ -f \"$KPBR_IP6_HOOK_REMOVED\" ] || "
      "echo '-A PREROUTING -j KeenPbrDnsRdr'\n"
      "    ;;\n"
      "  '-t nat -D PREROUTING -j KeenPbrDnsRdr')\n"
      "    : > \"$KPBR_IP6_HOOK_REMOVED\"\n"
      "    ;;\n"
      "  '-t nat -S POSTROUTING')\n"
      "    ;;\n"
      "  '-t nat -S KeenPbrDnsRdr'|'-t nat -S KeenPbrSnat')\n"
      "    echo 'ip6tables: No chain/target/match by that name.' >&2\n"
      "    exit 1\n"
      "    ;;\n"
      "esac\n"
      "exit 0\n");
  write_iptables_test_executable(
      temp.path() / "iptables-restore",
      "#!/bin/sh\n"
      "/bin/cat >/dev/null\n"
      "exit 0\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_IP6TABLES_CALLS");
  IptablesTestEnvironment removed_env("KPBR_IP6_HOOK_REMOVED");
  use_iptables_test_path(path, temp.path());
  calls_env.set(calls.string());
  removed_env.set(removed.string());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  testing::reset_restore_wait_option_probe_for_test();
  CHECK_FALSE(T::apply_preserve_nat_cleans_untracked_ipv6_for_test());
  const std::string command_log = read_iptables_test_file(calls);
  CHECK(command_log.find(
            "-t nat -D PREROUTING -j KeenPbrDnsRdr") !=
        std::string::npos);
  testing::reset_restore_wait_option_probe_for_test();
}

TEST_CASE("failed live NAT removal retains ownership for retry") {
  IptablesTestTempDir temp;
  write_iptables_test_executable(
      temp.path() / "iptables",
      "#!/bin/sh\n"
      "echo 'xtables lock is temporarily unavailable' >&2\n"
      "exit 4\n");
  IptablesTestEnvironment path("PATH");
  use_iptables_test_path(path, temp.path());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  const auto [caught_transient, still_owned] =
      T::cleanup_nat_failure_retains_ownership_for_test();
  CHECK(caught_transient);
  CHECK(still_owned);
}

TEST_CASE("fresh daemon removes untracked IPv4 and IPv6 NAT when disabled") {
  IptablesTestTempDir temp;
  const auto v4_calls = temp.path() / "v4-calls";
  const auto v6_calls = temp.path() / "v6-calls";
  const auto v4_removed = temp.path() / "v4-removed";
  const auto v6_removed = temp.path() / "v6-removed";
  const std::string script =
      "#!/bin/sh\n"
      "case \"$0\" in\n"
      "  *ip6tables) calls=\"$KPBR_V6_CALLS\"; "
      "removed=\"$KPBR_V6_REMOVED\" ;;\n"
      "  *) calls=\"$KPBR_V4_CALLS\"; removed=\"$KPBR_V4_REMOVED\" ;;\n"
      "esac\n"
      "printf '%s\\n' \"$*\" >> \"$calls\"\n"
      "case \"$*\" in\n"
      "  '-t nat -S PREROUTING')\n"
      "    [ -f \"$removed\" ] || "
      "echo '-A PREROUTING -j KeenPbrDnsRdr'\n"
      "    ;;\n"
      "  '-t nat -D PREROUTING -j KeenPbrDnsRdr')\n"
      "    : > \"$removed\"\n"
      "    ;;\n"
      "  '-t nat -S POSTROUTING')\n"
      "    ;;\n"
      "  '-t nat -S KeenPbrDnsRdr'|'-t nat -S KeenPbrSnat')\n"
      "    echo 'iptables: No chain/target/match by that name.' >&2\n"
      "    exit 1\n"
      "    ;;\n"
      "esac\n"
      "exit 0\n";
  write_iptables_test_executable(temp.path() / "iptables", script);
  write_iptables_test_executable(temp.path() / "ip6tables", script);
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment v4_calls_env("KPBR_V4_CALLS");
  IptablesTestEnvironment v6_calls_env("KPBR_V6_CALLS");
  IptablesTestEnvironment v4_removed_env("KPBR_V4_REMOVED");
  IptablesTestEnvironment v6_removed_env("KPBR_V6_REMOVED");
  use_iptables_test_path(path, temp.path());
  v4_calls_env.set(v4_calls.string());
  v6_calls_env.set(v6_calls.string());
  v4_removed_env.set(v4_removed.string());
  v6_removed_env.set(v6_removed.string());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  CHECK_NOTHROW(T::apply_preserve_without_nat_for_test());
  CHECK(read_iptables_test_file(v4_calls).find(
            "-t nat -D PREROUTING -j KeenPbrDnsRdr") !=
        std::string::npos);
  CHECK(read_iptables_test_file(v6_calls).find(
            "-t nat -D PREROUTING -j KeenPbrDnsRdr") !=
        std::string::npos);
}

TEST_CASE("IPv4 NAT apply succeeds when ip6tables is absent") {
  IptablesTestTempDir temp;
  const auto restore_calls = temp.path() / "restore-calls";
  write_iptables_test_executable(
      temp.path() / "iptables",
      "#!/bin/sh\n"
      "case \"$*\" in\n"
      "  '-t nat -S PREROUTING')\n"
      "    echo '-A PREROUTING -j KeenPbrDnsRdr'\n"
      "    ;;\n"
      "  '-t nat -S POSTROUTING')\n"
      "    echo '-A POSTROUTING -j KeenPbrSnat'\n"
      "    ;;\n"
  "  '-t nat -S KeenPbrSnat')\n"
      "    printf '%s\\n' "
      "'-N KeenPbrSnat' "
      "'-A KeenPbrSnat -m mark --mark "
      "0x1000000/0x1000000 -j MASQUERADE' "
      "'-A KeenPbrSnat -o nwg2 -m mark ! "
      "--mark 0x0/0xffffffff -j MASQUERADE'\n"
      "    ;;\n"
      "esac\n"
      "exit 0\n");
  write_iptables_test_executable(
      temp.path() / "iptables-restore",
      "#!/bin/sh\n"
      "printf x >> \"$KPBR_V4_RESTORE_CALLS\"\n"
      "/bin/cat >/dev/null\n"
      "exit 0\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_V4_RESTORE_CALLS");
  // Deliberately exclude the host PATH so the execvp probe observes the same
  // missing-ip6tables exit 127 as an IPv4-only Entware installation.
  path.set(temp.path().string());
  calls_env.set(restore_calls.string());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  testing::reset_restore_wait_option_probe_for_test();
  CHECK(T::apply_preserve_nat_for_test() == OwnedSnatState::healthy);
  CHECK_FALSE(read_iptables_test_file(restore_calls).empty());
  testing::reset_restore_wait_option_probe_for_test();
}

TEST_CASE("preserve apply restores an externally removed SNAT chain and hook") {
  IptablesTestTempDir temp;
  const auto dns_hook = temp.path() / "dns-hook";
  const auto snat_hook = temp.path() / "snat-hook";
  const auto snat_chain = temp.path() / "snat-chain";
  write_iptables_test_executable(
      temp.path() / "iptables",
      "#!/bin/sh\n"
      "case \"$*\" in\n"
      "  '-t nat -S PREROUTING')\n"
      "    [ -f \"$KPBR_DNS_HOOK\" ] && "
      "echo '-A PREROUTING -j KeenPbrDnsRdr'\n"
      "    ;;\n"
      "  '-t nat -A PREROUTING -j KeenPbrDnsRdr')\n"
      "    : > \"$KPBR_DNS_HOOK\"\n"
      "    ;;\n"
      "  '-t nat -S POSTROUTING')\n"
      "    [ -f \"$KPBR_SNAT_HOOK\" ] && "
      "echo '-A POSTROUTING -j KeenPbrSnat'\n"
      "    ;;\n"
      "  '-t nat -A POSTROUTING -j KeenPbrSnat')\n"
      "    : > \"$KPBR_SNAT_HOOK\"\n"
      "    ;;\n"
      "  '-t nat -S KeenPbrSnat')\n"
      "    if [ -f \"$KPBR_SNAT_CHAIN\" ]; then\n"
      "      printf '%s\\n' "
      "'-N KeenPbrSnat' "
      "'-A KeenPbrSnat -m mark --mark "
      "0x1000000/0x1000000 -j MASQUERADE' "
      "'-A KeenPbrSnat -o nwg2 -m mark ! "
      "--mark 0x0/0xffffffff -j MASQUERADE'\n"
      "    else\n"
      "      echo 'iptables: No chain/target/match by that name.' >&2\n"
      "      exit 1\n"
      "    fi\n"
      "    ;;\n"
      "esac\n"
      "exit 0\n");
  write_iptables_test_executable(
      temp.path() / "iptables-restore",
      "#!/bin/sh\n"
      "payload=\"$KPBR_SNAT_CHAIN.payload\"\n"
      "/bin/cat > \"$payload\"\n"
      "if /bin/grep -q '^:KeenPbrSnat ' \"$payload\"; then\n"
      "  : > \"$KPBR_SNAT_CHAIN\"\n"
      "fi\n"
      "exit 0\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment dns_hook_env("KPBR_DNS_HOOK");
  IptablesTestEnvironment snat_hook_env("KPBR_SNAT_HOOK");
  IptablesTestEnvironment snat_chain_env("KPBR_SNAT_CHAIN");
  path.set(temp.path().string());
  dns_hook_env.set(dns_hook.string());
  snat_hook_env.set(snat_hook.string());
  snat_chain_env.set(snat_chain.string());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  testing::reset_restore_wait_option_probe_for_test();
  CHECK(T::inspect_owned_snat_state(
            /*expected=*/true,
            /*expected_interfaces=*/{"nwg2"}) ==
        OwnedSnatState::missing);
  CHECK(T::apply_preserve_nat_for_test() == OwnedSnatState::healthy);
  CHECK(T::inspect_owned_snat_state(
            /*expected=*/true,
            /*expected_interfaces=*/{"nwg2"}) ==
        OwnedSnatState::healthy);
  CHECK(std::filesystem::exists(snat_chain));
  CHECK(std::filesystem::exists(snat_hook));
  testing::reset_restore_wait_option_probe_for_test();
}

TEST_CASE("NAT cleanup succeeds when ip6tables is absent") {
  IptablesTestTempDir temp;
  write_iptables_test_executable(
      temp.path() / "iptables",
      "#!/bin/sh\n"
      "case \"$*\" in\n"
      "  '-t nat -S KeenPbrDnsRdr'|'-t nat -S KeenPbrSnat')\n"
      "    echo 'iptables: No chain/target/match by that name.' >&2\n"
      "    exit 1\n"
      "    ;;\n"
      "esac\n"
      "exit 0\n");
  IptablesTestEnvironment path("PATH");
  path.set(temp.path().string());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  CHECK_NOTHROW(T::apply_preserve_without_nat_for_test());
}

TEST_CASE("transient restore test probe is not cached as unsupported") {
  IptablesTestTempDir temp;
  const auto calls = temp.path() / "calls";
  write_iptables_test_executable(
      temp.path() / "iptables-restore",
      "#!/bin/sh\n"
      "printf x >> \"$KPBR_TEST_PROBE_CALLS\"\n"
      "/bin/cat >/dev/null\n"
      "echo 'xtables lock is temporarily unavailable' >&2\n"
      "exit 4\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_TEST_PROBE_CALLS");
  use_iptables_test_path(path, temp.path());
  calls_env.set(calls.string());

  testing::reset_restore_wait_option_probe_for_test();
  CHECK_THROWS_AS(
      testing::restore_test_option_supported_for_test("iptables-restore"),
      TransientFirewallError);
  CHECK_THROWS_AS(
      testing::restore_test_option_supported_for_test("iptables-restore"),
      TransientFirewallError);
  CHECK(read_iptables_test_file(calls) == "xx");
  testing::reset_restore_wait_option_probe_for_test();
}

TEST_CASE("explicit unsupported restore test option is cached") {
  IptablesTestTempDir temp;
  const auto calls = temp.path() / "calls";
  write_iptables_test_executable(
      temp.path() / "iptables-restore",
      "#!/bin/sh\n"
      "printf x >> \"$KPBR_TEST_PROBE_CALLS\"\n"
      "/bin/cat >/dev/null\n"
      "echo \"unrecognized option '--test'\" >&2\n"
      "exit 2\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_TEST_PROBE_CALLS");
  use_iptables_test_path(path, temp.path());
  calls_env.set(calls.string());

  testing::reset_restore_wait_option_probe_for_test();
  CHECK_FALSE(
      testing::restore_test_option_supported_for_test("iptables-restore"));
  CHECK_FALSE(
      testing::restore_test_option_supported_for_test("iptables-restore"));
  CHECK(read_iptables_test_file(calls) == "x");
  testing::reset_restore_wait_option_probe_for_test();
}

TEST_CASE("xtables kernel matcher inventory requires an exact registration") {
  IptablesTestTempDir temp;
  const auto inventory = temp.path() / "ip_tables_matches";
  const auto modprobe_calls = temp.path() / "modprobe-calls";
  write_iptables_test_executable(
      temp.path() / "modprobe",
      "#!/bin/sh\n"
      "printf x >> \"$KPBR_TEST_MODPROBE_CALLS\"\n"
      "exit 0\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_TEST_MODPROBE_CALLS");
  use_iptables_test_path(path, temp.path());
  calls_env.set(modprobe_calls.string());
  {
    std::ofstream output(inventory);
    output << "mark\nphysdev_extra\nconntrack\n";
  }

  CHECK_FALSE(testing::xtables_match_registered_for_test(
      inventory.string(), "physdev"));
  CHECK_FALSE(testing::xtables_match_registered_for_test(
      (temp.path() / "missing").string(), "physdev"));

  FirewallGlobalPrefilter bridged_sstp;
  bridged_sstp.bypass_bridge_source_selectors_v4 = {
      {"br0", "sstp-br-link", "172.16.1.0/24"}};
  CHECK_THROWS_WITH_AS(
      testing::iptables_effective_prefilter_for_test(
          bridged_sstp,
          /*effective_ipv6=*/false,
          inventory.string(),
          (temp.path() / "ip6_tables_matches").string()),
      "Cannot exclude clients of a bridged SSTP server: this firmware "
      "kernel does not provide the iptables physdev matcher. The previous "
      "firewall ruleset was kept unchanged.",
      FirewallError);
  CHECK_FALSE(std::filesystem::exists(modprobe_calls));

  FirewallGlobalPrefilter direct_sstp;
  direct_sstp.bypass_source_selectors_v4 = {
      {"sstp0", "172.16.1.0/24"}};
  CHECK_NOTHROW(testing::iptables_effective_prefilter_for_test(
      direct_sstp,
      /*effective_ipv6=*/false,
      (temp.path() / "missing").string(),
      (temp.path() / "ip6_tables_matches").string()));
  CHECK_FALSE(std::filesystem::exists(modprobe_calls));

  {
    std::ofstream output(inventory, std::ios::app);
    output << "physdev\n";
  }
  CHECK(testing::xtables_match_registered_for_test(
      inventory.string(), "physdev"));
  const auto effective =
      testing::iptables_effective_prefilter_for_test(
          bridged_sstp,
          /*effective_ipv6=*/false,
          inventory.string(),
          (temp.path() / "ip6_tables_matches").string());
  REQUIRE(effective.bypass_bridge_source_selectors_v4.size() == 1U);
  CHECK(
      effective.bypass_bridge_source_selectors_v4.front().interface ==
      "br0");
  CHECK(
      effective.bypass_bridge_source_selectors_v4.front().bridge_port ==
      "sstp-br-link");
  CHECK(
      effective.bypass_bridge_source_selectors_v4.front().cidr ==
      "172.16.1.0/24");
}

TEST_CASE("iptables restore wait capability cache is independent per tool") {
  IptablesTestTempDir temp;
  const auto v4_calls = temp.path() / "v4-calls";
  const auto v6_calls = temp.path() / "v6-calls";
  write_iptables_test_executable(
      temp.path() / "iptables-restore",
      "#!/bin/sh\nprintf x >> \"$KPBR_V4_CALLS\"\nexit 0\n");
  write_iptables_test_executable(
      temp.path() / "ip6tables-restore",
      "#!/bin/sh\nprintf x >> \"$KPBR_V6_CALLS\"\nexit 1\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment v4("KPBR_V4_CALLS");
  IptablesTestEnvironment v6("KPBR_V6_CALLS");
  use_iptables_test_path(path, temp.path());
  v4.set(v4_calls.string());
  v6.set(v6_calls.string());

  testing::reset_restore_wait_option_probe_for_test();
  CHECK(testing::restore_wait_option_supported_for_test("iptables-restore"));
  CHECK_FALSE(testing::restore_wait_option_supported_for_test("ip6tables-restore"));
  CHECK(testing::restore_wait_option_supported_for_test("iptables-restore"));
  CHECK_FALSE(testing::restore_wait_option_supported_for_test("ip6tables-restore"));
  CHECK(read_iptables_test_file(v4_calls) == "x");
  CHECK(read_iptables_test_file(v6_calls) == "x");
  testing::reset_restore_wait_option_probe_for_test();
}

TEST_CASE("legacy iptables restore retries a transient COMMIT race") {
  IptablesTestTempDir temp;
  const auto calls = temp.path() / "calls";
  write_iptables_test_executable(
      temp.path() / "iptables-restore",
      "#!/bin/sh\n"
      "if [ \"$1\" = -w ]; then exit 1; fi\n"
      "count=0\n"
      "[ -f \"$KPBR_RESTORE_CALLS\" ] && count=$(/bin/cat \"$KPBR_RESTORE_CALLS\")\n"
      "count=$((count + 1))\n"
      "printf '%s\\n' \"$count\" > \"$KPBR_RESTORE_CALLS\"\n"
      "/bin/cat >/dev/null\n"
      "if [ \"$count\" -lt 3 ]; then\n"
      "  echo 'iptables-restore: line 5 failed' >&2\n"
      "  exit 1\n"
      "fi\n"
      "exit 0\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_RESTORE_CALLS");
  use_iptables_test_path(path, temp.path());
  calls_env.set(calls.string());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  testing::reset_restore_wait_option_probe_for_test();
  CHECK_NOTHROW(T::publish_dispatcher(
      false, false, FirewallSetGeneration::A));
  CHECK(read_iptables_test_file(calls) == "3\n");
  testing::reset_restore_wait_option_probe_for_test();
}

TEST_CASE("wait-capable iptables restore also retries a transient COMMIT race") {
  IptablesTestTempDir temp;
  const auto calls = temp.path() / "calls";
  write_iptables_test_executable(
      temp.path() / "iptables-restore",
      "#!/bin/sh\n"
      "if [ \"$1\" = -w ] && [ \"$2\" = 0 ]; then exit 0; fi\n"
      "[ \"$1\" = -w ] && [ \"$2\" = 10 ] || exit 64\n"
      "count=0\n"
      "[ -f \"$KPBR_RESTORE_CALLS\" ] && count=$(/bin/cat \"$KPBR_RESTORE_CALLS\")\n"
      "count=$((count + 1))\n"
      "printf '%s\\n' \"$count\" > \"$KPBR_RESTORE_CALLS\"\n"
      "/bin/cat >/dev/null\n"
      "if [ \"$count\" -eq 1 ]; then\n"
      "  echo 'iptables-restore: line 5 failed' >&2\n"
      "  exit 1\n"
      "fi\n"
      "exit 0\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_RESTORE_CALLS");
  use_iptables_test_path(path, temp.path());
  calls_env.set(calls.string());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  testing::reset_restore_wait_option_probe_for_test();
  CHECK_NOTHROW(T::publish_dispatcher(
      false, false, FirewallSetGeneration::A));
  CHECK(read_iptables_test_file(calls) == "2\n");
  testing::reset_restore_wait_option_probe_for_test();
}

TEST_CASE("wait-capable restore hands an exhausted lock wait to outer recovery") {
  IptablesTestTempDir temp;
  const auto calls = temp.path() / "calls";
  write_iptables_test_executable(
      temp.path() / "iptables-restore",
      "#!/bin/sh\n"
      "if [ \"$1\" = -w ] && [ \"$2\" = 0 ]; then exit 0; fi\n"
      "[ \"$1\" = -w ] && [ \"$2\" = 10 ] || exit 64\n"
      "count=0\n"
      "[ -f \"$KPBR_RESTORE_CALLS\" ] && count=$(/bin/cat \"$KPBR_RESTORE_CALLS\")\n"
      "count=$((count + 1))\n"
      "printf '%s\\n' \"$count\" > \"$KPBR_RESTORE_CALLS\"\n"
      "/bin/cat >/dev/null\n"
      "exit 4\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_RESTORE_CALLS");
  use_iptables_test_path(path, temp.path());
  calls_env.set(calls.string());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  testing::reset_restore_wait_option_probe_for_test();
  CHECK_THROWS_AS(
      T::publish_dispatcher(false, false, FirewallSetGeneration::A),
      TransientFirewallError);
  CHECK(read_iptables_test_file(calls) == "1\n");
  testing::reset_restore_wait_option_probe_for_test();
}

TEST_CASE("exhausted COMMIT retries remain typed as transient") {
  IptablesTestTempDir temp;
  const auto calls = temp.path() / "calls";
  write_iptables_test_executable(
      temp.path() / "iptables-restore",
      "#!/bin/sh\n"
      "if [ \"$1\" = -w ]; then exit 1; fi\n"
      "count=0\n"
      "[ -f \"$KPBR_RESTORE_CALLS\" ] && count=$(/bin/cat \"$KPBR_RESTORE_CALLS\")\n"
      "count=$((count + 1))\n"
      "printf '%s\\n' \"$count\" > \"$KPBR_RESTORE_CALLS\"\n"
      "/bin/cat >/dev/null\n"
      "echo 'iptables-restore: line 5 failed' >&2\n"
      "exit 1\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_RESTORE_CALLS");
  use_iptables_test_path(path, temp.path());
  calls_env.set(calls.string());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  testing::reset_restore_wait_option_probe_for_test();
  CHECK_THROWS_AS(
      T::publish_dispatcher(false, false, FirewallSetGeneration::A),
      TransientFirewallError);
  CHECK(read_iptables_test_file(calls) == "5\n");
  testing::reset_restore_wait_option_probe_for_test();
}

TEST_CASE("legacy iptables restore does not retry a permanent rule error") {
  IptablesTestTempDir temp;
  const auto calls = temp.path() / "calls";
  write_iptables_test_executable(
      temp.path() / "iptables-restore",
      "#!/bin/sh\n"
      "if [ \"$1\" = -w ]; then exit 1; fi\n"
      "count=0\n"
      "[ -f \"$KPBR_RESTORE_CALLS\" ] && count=$(/bin/cat \"$KPBR_RESTORE_CALLS\")\n"
      "count=$((count + 1))\n"
      "printf '%s\\n' \"$count\" > \"$KPBR_RESTORE_CALLS\"\n"
      "/bin/cat >/dev/null\n"
      "echo 'iptables-restore: line 4 failed' >&2\n"
      "exit 1\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_RESTORE_CALLS");
  use_iptables_test_path(path, temp.path());
  calls_env.set(calls.string());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  testing::reset_restore_wait_option_probe_for_test();
  CHECK_THROWS_AS(
      T::publish_dispatcher(false, false, FirewallSetGeneration::A),
      FirewallError);
  CHECK(read_iptables_test_file(calls) == "1\n");
  testing::reset_restore_wait_option_probe_for_test();
}

TEST_CASE("dispatcher inspection retries a transient snapshot failure") {
  IptablesTestTempDir temp;
  const auto calls = temp.path() / "calls";
  write_iptables_test_executable(
      temp.path() / "iptables",
      "#!/bin/sh\n"
      "count=0\n"
      "[ -f \"$KPBR_INSPECT_CALLS\" ] && count=$(/bin/cat \"$KPBR_INSPECT_CALLS\")\n"
      "count=$((count + 1))\n"
      "printf '%s\\n' \"$count\" > \"$KPBR_INSPECT_CALLS\"\n"
      "[ \"$count\" -eq 1 ] && exit 4\n"
      "echo '-A KeenPbrTable -j KeenPbrTable_A'\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_INSPECT_CALLS");
  use_iptables_test_path(path, temp.path());
  calls_env.set(calls.string());

  CHECK(T::inspect_dispatcher(
            "iptables",
            "mangle",
            "KeenPbrTable",
            "KeenPbrTable_A",
            "KeenPbrTable_B") == T::State::A);
  CHECK(read_iptables_test_file(calls) == "2\n");
}

TEST_CASE("iptables restore exit four is retried as a transient resource race") {
  IptablesTestTempDir temp;
  const auto calls = temp.path() / "calls";
  write_iptables_test_executable(
      temp.path() / "iptables-restore",
      "#!/bin/sh\n"
      "if [ \"$1\" = -w ]; then exit 1; fi\n"
      "count=0\n"
      "[ -f \"$KPBR_RESTORE_CALLS\" ] && count=$(/bin/cat \"$KPBR_RESTORE_CALLS\")\n"
      "count=$((count + 1))\n"
      "printf '%s\\n' \"$count\" > \"$KPBR_RESTORE_CALLS\"\n"
      "/bin/cat >/dev/null\n"
      "exit 4\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_RESTORE_CALLS");
  use_iptables_test_path(path, temp.path());
  calls_env.set(calls.string());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  testing::reset_restore_wait_option_probe_for_test();
  CHECK_THROWS_AS(
      T::publish_dispatcher(false, false, FirewallSetGeneration::A),
      TransientFirewallError);
  CHECK(read_iptables_test_file(calls) == "5\n");
  testing::reset_restore_wait_option_probe_for_test();
}

TEST_CASE("hook reconciliation re-reads after a transient inspection") {
  IptablesTestTempDir temp;
  const auto calls = temp.path() / "calls";
  write_iptables_test_executable(
      temp.path() / "iptables",
      "#!/bin/sh\n"
      "count=0\n"
      "[ -f \"$KPBR_HOOK_CALLS\" ] && count=$(/bin/cat \"$KPBR_HOOK_CALLS\")\n"
      "count=$((count + 1))\n"
      "printf '%s\\n' \"$count\" > \"$KPBR_HOOK_CALLS\"\n"
      "[ \"$count\" -eq 1 ] && exit 4\n"
      "echo '-A OUTPUT -j KeenPbrOutput'\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_HOOK_CALLS");
  use_iptables_test_path(path, temp.path());
  calls_env.set(calls.string());

  CHECK_NOTHROW(T::reconcile_hook(
      "iptables", "mangle", "OUTPUT", "KeenPbrOutput"));
  CHECK(read_iptables_test_file(calls) == "2\n");
}

TEST_CASE("hook reconciliation verifies state after an ambiguous mutation") {
  IptablesTestTempDir temp;
  const auto calls = temp.path() / "calls";
  const auto arguments = temp.path() / "arguments";
  write_iptables_test_executable(
      temp.path() / "iptables",
      "#!/bin/sh\n"
      "printf '%s\\n' \"$*\" >> \"$KPBR_HOOK_ARGUMENTS\"\n"
      "count=0\n"
      "[ -f \"$KPBR_HOOK_CALLS\" ] && count=$(/bin/cat \"$KPBR_HOOK_CALLS\")\n"
      "count=$((count + 1))\n"
      "printf '%s\\n' \"$count\" > \"$KPBR_HOOK_CALLS\"\n"
      "[ \"$count\" -eq 1 ] && exit 0\n"
      "[ \"$count\" -eq 2 ] && exit 1\n"
      "echo '-A OUTPUT -j KeenPbrOutput'\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_HOOK_CALLS");
  IptablesTestEnvironment arguments_env("KPBR_HOOK_ARGUMENTS");
  use_iptables_test_path(path, temp.path());
  calls_env.set(calls.string());
  arguments_env.set(arguments.string());

  CHECK_NOTHROW(T::reconcile_hook(
      "iptables", "mangle", "OUTPUT", "KeenPbrOutput"));
  CHECK(read_iptables_test_file(calls) == "3\n");
  CHECK(read_iptables_test_file(arguments) ==
        "-t mangle -S OUTPUT\n"
        "-t mangle -A OUTPUT -j KeenPbrOutput\n"
        "-t mangle -S OUTPUT\n");
}

TEST_CASE("vanished hook target is a transient publication race") {
  IptablesTestTempDir temp;
  const auto calls = temp.path() / "calls";
  write_iptables_test_executable(
      temp.path() / "iptables",
      "#!/bin/sh\n"
      "printf '%s\\n' \"$*\" >> \"$KPBR_HOOK_CALLS\"\n"
      "case \"$*\" in\n"
      "  '-t mangle -S PREROUTING') exit 0 ;;\n"
      "  '-t mangle -A PREROUTING -j KeenPbrTable')\n"
      "    echo 'iptables: No chain/target/match by that name.' >&2\n"
      "    exit 2\n"
      "    ;;\n"
      "esac\n"
      "exit 0\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_HOOK_CALLS");
  use_iptables_test_path(path, temp.path());
  calls_env.set(calls.string());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  CHECK_THROWS_AS(
      T::reconcile_hook(
          "iptables", "mangle", "PREROUTING", "KeenPbrTable"),
      TransientFirewallError);
  CHECK(read_iptables_test_file(calls) ==
        "-t mangle -S PREROUTING\n"
        "-t mangle -A PREROUTING -j KeenPbrTable\n");
}

TEST_CASE("legacy Keenetic iptables reports vanished hook target as transient") {
  IptablesTestTempDir temp;
  const auto calls = temp.path() / "calls";
  write_iptables_test_executable(
      temp.path() / "iptables",
      "#!/bin/sh\n"
      "printf '%s\\n' \"$*\" >> \"$KPBR_HOOK_CALLS\"\n"
      "case \"$*\" in\n"
      "  '-t mangle -S PREROUTING') exit 0 ;;\n"
      "  '-t mangle -A PREROUTING -j KeenPbrTable')\n"
      "    printf 'iptables v1.4.21: Couldn\\047t load target "
      "\\140KeenPbrTable\\047:No such file or directory\\n' >&2\n"
      "    exit 2\n"
      "    ;;\n"
      "esac\n"
      "exit 0\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_HOOK_CALLS");
  use_iptables_test_path(path, temp.path());
  calls_env.set(calls.string());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  CHECK_THROWS_AS(
      T::reconcile_hook(
          "iptables", "mangle", "PREROUTING", "KeenPbrTable"),
      TransientFirewallError);
  CHECK(read_iptables_test_file(calls) ==
        "-t mangle -S PREROUTING\n"
        "-t mangle -A PREROUTING -j KeenPbrTable\n");
}

TEST_CASE("vanished duplicate hook target is a transient publication race") {
  IptablesTestTempDir temp;
  const auto calls = temp.path() / "calls";
  write_iptables_test_executable(
      temp.path() / "iptables",
      "#!/bin/sh\n"
      "printf '%s\\n' \"$*\" >> \"$KPBR_HOOK_CALLS\"\n"
      "case \"$*\" in\n"
      "  '-t mangle -S OUTPUT')\n"
      "    echo '-A OUTPUT -j KeenPbrOutput'\n"
      "    echo '-A OUTPUT -j KeenPbrOutput'\n"
      "    exit 0\n"
      "    ;;\n"
      "  '-t mangle -D OUTPUT -j KeenPbrOutput')\n"
      "    echo 'iptables: No chain/target/match by that name.' >&2\n"
      "    exit 2\n"
      "    ;;\n"
      "esac\n"
      "exit 0\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_HOOK_CALLS");
  use_iptables_test_path(path, temp.path());
  calls_env.set(calls.string());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  CHECK_THROWS_AS(
      T::reconcile_hook(
          "iptables", "mangle", "OUTPUT", "KeenPbrOutput"),
      TransientFirewallError);
  CHECK(read_iptables_test_file(calls) ==
        "-t mangle -S OUTPUT\n"
        "-t mangle -D OUTPUT -j KeenPbrOutput\n");
}

TEST_CASE("hook reconciliation surfaces permanent command failures immediately") {
  IptablesTestTempDir temp;
  const auto calls = temp.path() / "calls";
  write_iptables_test_executable(
      temp.path() / "iptables",
      "#!/bin/sh\n"
      "printf x >> \"$KPBR_HOOK_CALLS\"\n"
      "exit 2\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_HOOK_CALLS");
  use_iptables_test_path(path, temp.path());
  calls_env.set(calls.string());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  CHECK_THROWS_AS(
      T::reconcile_hook(
          "iptables", "mangle", "OUTPUT", "KeenPbrOutput"),
      FirewallError);
  CHECK(read_iptables_test_file(calls) == "x");
}

TEST_CASE("generation verification retries a coherent publication mismatch") {
  IptablesTestTempDir temp;
  const auto calls = temp.path() / "calls";
  write_iptables_test_executable(
      temp.path() / "iptables",
      "#!/bin/sh\n"
      "count=0\n"
      "[ -f \"$KPBR_VERIFY_CALLS\" ] && count=$(/bin/cat \"$KPBR_VERIFY_CALLS\")\n"
      "count=$((count + 1))\n"
      "printf '%s\\n' \"$count\" > \"$KPBR_VERIFY_CALLS\"\n"
      "generation=B\n"
      "[ \"$count\" -gt 2 ] && generation=A\n"
      "echo \"-A KeenPbrTable -j KeenPbrTable_${generation}\"\n"
      "echo '-A PREROUTING -j KeenPbrTable'\n"
      "echo \"-A KeenPbrOutput -j KeenPbrOutput_${generation}\"\n"
      "echo '-A OUTPUT -j KeenPbrOutput'\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_VERIFY_CALLS");
  use_iptables_test_path(path, temp.path());
  calls_env.set(calls.string());

  CHECK_NOTHROW(T::verify_applied_generation(
      FirewallSetGeneration::A));
  CHECK(read_iptables_test_file(calls) == "4\n");
}

TEST_CASE("persistent generation verification mismatch stays transient") {
  IptablesTestTempDir temp;
  const auto calls = temp.path() / "calls";
  write_iptables_test_executable(
      temp.path() / "iptables",
      "#!/bin/sh\n"
      "printf x >> \"$KPBR_VERIFY_CALLS\"\n"
      "echo '-A KeenPbrTable -j KeenPbrTable_B'\n"
      "echo '-A PREROUTING -j KeenPbrTable'\n"
      "echo '-A KeenPbrOutput -j KeenPbrOutput_B'\n"
      "echo '-A OUTPUT -j KeenPbrOutput'\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment calls_env("KPBR_VERIFY_CALLS");
  use_iptables_test_path(path, temp.path());
  calls_env.set(calls.string());

  CHECK_THROWS_AS(
      T::verify_applied_generation(FirewallSetGeneration::A),
      TransientFirewallError);
  CHECK(read_iptables_test_file(calls).size() == 10);
}

TEST_CASE("generation ipset names alternate and stay within the kernel limit") {
  const auto [first, second] = T::generation_set_names();
  CHECK(first == "kpbr4s_abcdefghijklmnopqrstuvwx");
  CHECK(second == "kpbr4S_abcdefghijklmnopqrstuvwx");
  CHECK(first.size() == 31);
  CHECK(second.size() == 31);
}

TEST_CASE("live dispatcher parser distinguishes A B missing and invalid") {
  using State = T::State;
  CHECK(T::parse_live_generation(
            "-A KeenPbrRaw -j KeenPbrRaw_A\n",
            "KeenPbrRaw", "KeenPbrRaw_A", "KeenPbrRaw_B") == State::A);
  CHECK(T::parse_live_generation(
            "-A KeenPbrRaw -j KeenPbrRaw_B\n",
            "KeenPbrRaw", "KeenPbrRaw_A", "KeenPbrRaw_B") == State::B);
  CHECK(T::parse_live_generation(
            "-N KeenPbrRaw\n",
            "KeenPbrRaw", "KeenPbrRaw_A", "KeenPbrRaw_B") ==
        State::Missing);
  CHECK(T::parse_live_generation(
            "-A KeenPbrRaw -j KeenPbrRaw_A\n"
            "-A KeenPbrRaw -j KeenPbrRaw_A\n",
            "KeenPbrRaw", "KeenPbrRaw_A", "KeenPbrRaw_B") ==
        State::Invalid);
  CHECK(T::parse_live_generation(
            "-A KeenPbrRaw -j foreign\n",
            "KeenPbrRaw", "KeenPbrRaw_A", "KeenPbrRaw_B") ==
        State::Invalid);
}

TEST_CASE("target generation stages opposite a valid authoritative dispatcher") {
  using State = T::State;
  CHECK(T::target_generation_for_states(State::A, State::A) ==
        FirewallSetGeneration::B);
  CHECK(T::target_generation_for_states(State::B, State::B) ==
        FirewallSetGeneration::A);
  CHECK(T::target_generation_for_states(State::A, State::Missing) ==
        FirewallSetGeneration::B);
  CHECK(T::target_generation_for_states(State::Missing, State::A) ==
        FirewallSetGeneration::B);
  CHECK(T::target_generation_for_states(State::Missing, State::B) ==
        FirewallSetGeneration::A);
  // A valid counterpart is authoritative even when the other dispatcher is
  // malformed. select_target_generation() first synchronizes the damaged
  // dispatcher to this generation, then stages the opposite slot.
  CHECK(T::target_generation_for_states(State::Invalid, State::A) ==
        FirewallSetGeneration::B);
  CHECK(T::target_generation_for_states(State::B, State::Invalid) ==
        FirewallSetGeneration::A);
}

TEST_CASE("two missing dispatchers safely bootstrap slot A") {
  using State = T::State;
  CHECK(T::target_generation_for_states(
            State::Missing, State::Missing) ==
        FirewallSetGeneration::A);
}

TEST_CASE("target generation fails closed without an authoritative dispatcher") {
  using State = T::State;
  CHECK_THROWS_AS(
      T::target_generation_for_states(
          State::Invalid, State::Missing),
      FirewallError);
  CHECK_THROWS_AS(
      T::target_generation_for_states(
          State::Missing, State::Invalid),
      FirewallError);
  CHECK_THROWS_AS(
      T::target_generation_for_states(
          State::Invalid, State::Invalid),
      FirewallError);
}

TEST_CASE("hook counter only accepts exact unconditional jumps") {
  const std::string rules =
      "-A PREROUTING -j KeenPbrRaw\n"
      "-A PREROUTING -i br0 -j KeenPbrRaw\n"
      "-A PREROUTING -j KeenPbrRawExtra\n"
      "-A PREROUTING -j KeenPbrRaw\n";
  CHECK(T::count_exact_jump(rules, "PREROUTING", "KeenPbrRaw") == 2);
}

TEST_CASE("generation script dispatches prerouting and output independently") {
  const auto first = T::build_generation_script(false);
  CHECK(first.find("-A KeenPbrTable -j KeenPbrTable_A") != std::string::npos);
  CHECK(first.find("-A KeenPbrOutput -j KeenPbrOutput_A") != std::string::npos);
  CHECK(first.find("-A KeenPbrOutput_A -p udp --dport 53") != std::string::npos);
  CHECK(first.find("-A PREROUTING -j KeenPbrTable") == std::string::npos);
  CHECK(first.find("-A OUTPUT -j KeenPbrOutput") == std::string::npos);

  const auto replacement = T::build_generation_script(true);
  CHECK(replacement.find("-F KeenPbrTable") != std::string::npos);
  CHECK(replacement.find("-F KeenPbrOutput") != std::string::npos);
  CHECK(replacement.find("-A KeenPbrTable -j KeenPbrTable_A") != std::string::npos);
  CHECK(replacement.find("-A KeenPbrOutput -j KeenPbrOutput_A") != std::string::npos);
  CHECK(replacement.find("-A PREROUTING -j KeenPbrTable") == std::string::npos);
  CHECK(replacement.find("-R KeenPbrTable") == std::string::npos);
}

TEST_CASE("raw prerouting is isolated and omits unavailable conntrack matching") {
  FirewallGlobalPrefilter prefilter;
  prefilter.skip_established_or_dnat = true;
  prefilter.skip_marked_packets = true;
  const auto [raw, output] =
      T::build_raw_generation_scripts(false, prefilter);

  CHECK(raw.find("*raw\n") != std::string::npos);
  CHECK(raw.find("-A PREROUTING -j KeenPbrRaw") == std::string::npos);
  CHECK(raw.find("-A KeenPbrRaw -j KeenPbrRaw_A") != std::string::npos);
  CHECK(raw.find("--match-set kpbr4s_test dst") != std::string::npos);
  CHECK(raw.find("-m conntrack") == std::string::npos);
  CHECK(raw.find("--ctstate") == std::string::npos);
  CHECK(raw.find("KeenPbrOutput") == std::string::npos);

  CHECK(output.find("*mangle\n") != std::string::npos);
  CHECK(output.find("-A OUTPUT -j KeenPbrOutput") == std::string::npos);
  CHECK(output.find("-A KeenPbrOutput_A -p udp --dport 53") !=
        std::string::npos);
  CHECK(output.find("KeenPbrRaw") == std::string::npos);
}

namespace {

Config parse_valid_config(const std::string& json) {
  Config cfg = parse_config(json);
  if (!cfg.dns.has_value()) {
    cfg.dns = DnsConfig{};
  }
  if (!cfg.dns->servers.has_value()) {
    DnsServer fallback_server;
    fallback_server.tag = "default_dns";
    fallback_server.address = "127.0.0.1";
    cfg.dns->servers = std::vector<DnsServer>{fallback_server};
  }
  if (!cfg.dns->fallback.has_value()) {
    cfg.dns->fallback = std::vector<std::string>{"default_dns"};
  }
  if (!cfg.dns->system_resolver.has_value()) {
    api::SystemResolver resolver;
    resolver.address = "127.0.0.1";
    cfg.dns->system_resolver = resolver;
  }
  validate_config(cfg);
  return cfg;
}

} // namespace

static Rule mark_rule(const std::string &set_name, bool ipv6, uint32_t fwmark,
                      ProtoPortFilter filter = {}) {
  Rule r;
  r.set_name = set_name;
  r.ipv6 = ipv6;
  r.action = Rule::Mark;
  r.fwmark = fwmark;
  r.filter = filter;
  return r;
}

static Rule drop_rule(const std::string &set_name, bool ipv6,
                      ProtoPortFilter filter = {}) {
  Rule r;
  r.set_name = set_name;
  r.ipv6 = ipv6;
  r.action = Rule::Drop;
  r.fwmark = 0;
  r.filter = filter;
  return r;
}

static Rule pass_rule(const std::string &set_name, bool ipv6,
                      ProtoPortFilter filter = {}) {
  Rule r;
  r.set_name = set_name;
  r.ipv6 = ipv6;
  r.action = Rule::Pass;
  r.fwmark = 0;
  r.filter = filter;
  return r;
}

static FirewallGlobalPrefilter prefilter_with_interfaces(
    std::vector<std::string> interfaces,
    bool skip_established_or_dnat = true) {
  FirewallGlobalPrefilter prefilter;
  prefilter.skip_established_or_dnat = skip_established_or_dnat;
  prefilter.skip_marked_packets = true;
  prefilter.inbound_interfaces = std::move(interfaces);
  return prefilter;
}

// =============================================================================
// IpsetRestoreVisitor::on_entry tests
// =============================================================================

TEST_CASE("IpsetRestoreVisitor: IP entry without timeout") {
  std::ostringstream buf;
  IpsetRestoreVisitor v(buf, "myset");
  v.on_entry(EntryType::Ip, "10.0.0.1");
  CHECK(buf.str() == "add myset 10.0.0.1 -exist\n");
  CHECK(v.count() == 1);
}

TEST_CASE("IpsetRestoreVisitor: CIDR entry") {
  std::ostringstream buf;
  IpsetRestoreVisitor v(buf, "myset");
  v.on_entry(EntryType::Cidr, "192.168.0.0/24");
  CHECK(buf.str() == "add myset 192.168.0.0/24 -exist\n");
  CHECK(v.count() == 1);
}

TEST_CASE("IpsetRestoreVisitor: IPv4 zero prefix expands for hash:net") {
  std::ostringstream buf;
  IpsetRestoreVisitor v(buf, "myset");
  v.on_entry(EntryType::Cidr, "0.0.0.0/0");
  CHECK(buf.str() == "add myset 0.0.0.0/1 -exist\n"
                     "add myset 128.0.0.0/1 -exist\n");
  CHECK(v.count() == 2);
}

TEST_CASE("IpsetRestoreVisitor: IPv6 zero prefix expands for hash:net") {
  std::ostringstream buf;
  IpsetRestoreVisitor v(buf, "myset");
  v.on_entry(EntryType::Cidr, "::/0");
  CHECK(buf.str() == "add myset ::/1 -exist\n"
                     "add myset 8000::/1 -exist\n");
  CHECK(v.count() == 2);
}

TEST_CASE("IpsetRestoreVisitor: Domain entry is ignored") {
  std::ostringstream buf;
  IpsetRestoreVisitor v(buf, "myset");
  v.on_entry(EntryType::Domain, "example.com");
  CHECK(buf.str().empty());
  CHECK(v.count() == 0);
}

TEST_CASE("IpsetRestoreVisitor: count increments only for IP/CIDR") {
  std::ostringstream buf;
  IpsetRestoreVisitor v(buf, "myset");
  v.on_entry(EntryType::Ip, "1.2.3.4");
  v.on_entry(EntryType::Domain, "example.com");
  v.on_entry(EntryType::Cidr, "10.0.0.0/8");
  CHECK(v.count() == 2);
}

// =============================================================================
// build_ipset_create_line tests
// =============================================================================

TEST_CASE("build_ipset_create_line: IPv4 without timeout") {
  auto line = T::build_ipset_create_line("myset", "inet", 0);
  CHECK(line == "create myset hash:net family inet -exist\n");
}

TEST_CASE("build_ipset_create_line: IPv4 with timeout 60") {
  auto line = T::build_ipset_create_line("myset", "inet", 60);
  CHECK(line == "create myset hash:net family inet timeout 60 -exist\n");
}

TEST_CASE("build_ipset_create_line: IPv6 without timeout") {
  auto line = T::build_ipset_create_line("myset", "inet6", 0);
  CHECK(line == "create myset hash:net family inet6 -exist\n");
}

TEST_CASE("ipset reconcile: only dnsmasq names are dynamic") {
  CHECK(T::is_dynamic_set_name("kpbr4d_domains"));
  CHECK(T::is_dynamic_set_name("kpbr6d_domains"));
  CHECK_FALSE(T::is_dynamic_set_name("kpbr4_static"));
  CHECK_FALSE(T::is_dynamic_set_name("foreign_kpbr4d_domains"));
}

TEST_CASE("ipset reconcile: dynamic schema accepts terse ipset XML") {
  CHECK(T::dynamic_set_schema_compatible(
      R"(<?xml version="1.0" encoding="utf-8"?>
<ipsets>
  <ipset name="kpbr4d_domains">
    <type>hash:net</type>
    <revision>7</revision>
    <header>
      <family>inet</family>
      <hashsize>1024</hashsize>
      <maxelem>65536</maxelem>
      <timeout>300</timeout>
      <references>1</references>
    </header>
  </ipset>
</ipsets>)",
      "kpbr4d_domains", "inet", 300));
  CHECK(T::dynamic_set_schema_compatible(
      R"(<ipsets><ipset name="kpbr6d_domains"><type>hash:net</type><header><family>inet6</family></header></ipset></ipsets>)",
      "kpbr6d_domains", "inet6", 0));
}

TEST_CASE("ipset reconcile: dynamic schema rejects incompatible live sets") {
  CHECK_FALSE(T::dynamic_set_schema_compatible(
      R"(<ipsets><ipset name="kpbr4d_domains"><type>hash:ip</type><header><family>inet</family><timeout>300</timeout></header></ipset></ipsets>)",
      "kpbr4d_domains", "inet", 300));
  CHECK_FALSE(T::dynamic_set_schema_compatible(
      R"(<ipsets><ipset name="kpbr4d_domains"><type>hash:net</type><header><family>inet6</family><timeout>300</timeout></header></ipset></ipsets>)",
      "kpbr4d_domains", "inet", 300));
  CHECK_FALSE(T::dynamic_set_schema_compatible(
      R"(<ipsets><ipset name="kpbr4d_domains"><type>hash:net</type><header><family>inet</family><timeout>60</timeout></header></ipset></ipsets>)",
      "kpbr4d_domains", "inet", 300));
}

TEST_CASE("ipset reconcile: dynamic schema rejects malformed or ambiguous XML") {
  CHECK_FALSE(T::dynamic_set_schema_compatible(
      R"(<ipsets><ipset name="kpbr4d_domains"><type>hash:net</type><header><family>inet</family></ipset></ipsets>)",
      "kpbr4d_domains", "inet", 0));
  CHECK_FALSE(T::dynamic_set_schema_compatible(
      R"(<ipsets><ipset name="kpbr4d_domains"><type>hash:net</type><type>hash:ip</type><header><family>inet</family></header></ipset></ipsets>)",
      "kpbr4d_domains", "inet", 0));
  CHECK_FALSE(T::dynamic_set_schema_compatible(
      R"(<ipsets><ipset name="kpbr4d_domains"><type>hash:net</type><header><family>inet</family><timeout>-1</timeout></header></ipset></ipsets>)",
      "kpbr4d_domains", "inet", 0));
  CHECK_FALSE(T::dynamic_set_schema_compatible(
      R"(<ipsets><ipset name="kpbr4d_domains"><type>hash:net</type><header><family>inet</family></header></ipset><ipset name="foreign"><type>hash:net</type><header><family>inet</family></header></ipset></ipsets>)",
      "kpbr4d_domains", "inet", 0));
}

// =============================================================================
// build_ipt_script tests
// =============================================================================

TEST_CASE("build_ipt_script: IPv4 mark rule") {
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100)});
  CHECK(s.find("*mangle") != std::string::npos);
  CHECK(s.find(":KeenPbrTable") != std::string::npos);
  CHECK(s.find("-A PREROUTING -j KeenPbrTable") != std::string::npos);
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst -j MARK "
               "--set-xmark 0x100/0xffffffff") != std::string::npos);
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst -j RETURN") !=
        std::string::npos);
  CHECK(s.size() >= 7);
  CHECK(s.substr(s.size() - 7) == "COMMIT\n");
}

TEST_CASE("build_ipt_script: IPv4 drop rule") {
  auto s = T::build_ipt_script(false, {drop_rule("blacklist", false)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set blacklist dst -j DROP") !=
        std::string::npos);
}

TEST_CASE("build_ipt_script: IPv4 pass rule") {
  auto s = T::build_ipt_script(false, {pass_rule("allowlist", false)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set allowlist dst -j RETURN") !=
        std::string::npos);
}

TEST_CASE("build_ipt_script: IPv6 mark rule") {
  auto s = T::build_ipt_script(true, {mark_rule("v6set", true, 0x200)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set v6set dst -j MARK "
               "--set-xmark 0x200/0xffffffff") != std::string::npos);
  CHECK(s.find("-A KeenPbrTable -m set --match-set v6set dst -j RETURN") !=
        std::string::npos);
  CHECK(s.substr(s.size() - 7) == "COMMIT\n");
}

TEST_CASE("build_ipt_script: ipv6=false filters out IPv6 rules") {
  auto s = T::build_ipt_script(false, {mark_rule("v4set", false, 0x100),
                                       mark_rule("v6set", true, 0x200)});
  CHECK(s.find("v4set") != std::string::npos);
  CHECK(s.find("v6set") == std::string::npos);
}

TEST_CASE("build_ipt_script: ipv6=true filters out IPv4 rules") {
  auto s = T::build_ipt_script(true, {mark_rule("v4set", false, 0x100),
                                      mark_rule("v6set", true, 0x200)});
  CHECK(s.find("v6set") != std::string::npos);
  CHECK(s.find("v4set") == std::string::npos);
}

TEST_CASE("build_ipt_script: zero fwmark") {
  auto s = T::build_ipt_script(false, {mark_rule("zeroset", false, 0)});
  CHECK(s.find("--set-xmark 0x0/0xffffffff") != std::string::npos);
}

TEST_CASE("build_ipt_script: multiple rules appear in order") {
  auto s = T::build_ipt_script(
      false, {mark_rule("first", false, 0x1), drop_rule("second", false)});
  auto pos_first = s.find("first");
  auto pos_second = s.find("second");
  CHECK(pos_first != std::string::npos);
  CHECK(pos_second != std::string::npos);
  CHECK(pos_first < pos_second);
}

TEST_CASE("build_ipt_script: empty rules still build KeenPbrTable scaffold") {
  auto s = T::build_ipt_script(false, {});
  CHECK(s.find("*mangle\n") != std::string::npos);
  CHECK(s.find(":KeenPbrTable - [0:0]\n") != std::string::npos);
  CHECK(s.find("-A PREROUTING -j KeenPbrTable\n") != std::string::npos);
  CHECK(s.find("-A KeenPbrTable ") == std::string::npos);
  // The OUTPUT scaffold for router-originated traffic is always materialized.
  CHECK(s.find(":KeenPbrOutput - [0:0]\n") != std::string::npos);
  CHECK(s.find("-A OUTPUT -j KeenPbrOutput\n") != std::string::npos);
  CHECK(s == "*mangle\n:KeenPbrTable - [0:0]\n-A PREROUTING -j KeenPbrTable\n"
             ":KeenPbrOutput - [0:0]\n-A OUTPUT -j KeenPbrOutput\nCOMMIT\n");
}

TEST_CASE("create_output_mark_rule: rules land in KeenPbrOutput without iface guard") {
  FirewallRuleCriteria criteria;
  criteria.proto = L4Proto::TcpUdp;
  criteria.dst_port = "53";
  criteria.dst_addr = {"8.8.8.8"};

  FirewallGlobalPrefilter prefilter;
  prefilter.skip_marked_packets = true;
  prefilter.inbound_interfaces = std::vector<std::string>{"br0", "br1"};
  auto s = T::build_output_mark_script(0x20000, criteria, prefilter);

  // The OUTPUT chain rules must not carry inbound-interface matches.
  CHECK(s.find("-A KeenPbrOutput -d 8.8.8.8 -p udp --dport 53 -j MARK") != std::string::npos);
  CHECK(s.find("-A KeenPbrOutput -d 8.8.8.8 -p tcp --dport 53 -j MARK") != std::string::npos);
  CHECK(s.find("-A KeenPbrOutput -i ") == std::string::npos);
  CHECK(s.find("-A KeenPbrOutput -m mark ! --mark 0x0/0xffffffff -j ACCEPT") != std::string::npos);
  // Nothing about the detour rule leaks into the PREROUTING chain.
  CHECK(s.find("-A KeenPbrTable -d 8.8.8.8") == std::string::npos);
}

TEST_CASE("build_dns_nat_script: REDIRECT rules cover udp and tcp per inbound interface") {
  FirewallGlobalPrefilter prefilter;
  prefilter.inbound_interfaces = std::vector<std::string>{"br0"};
  auto s = T::build_dns_nat_script(prefilter);
  CHECK(s.find(
            "*nat\n:KeenPbrDnsRdr - [0:0]\n-F KeenPbrDnsRdr\n") !=
        std::string::npos);
  CHECK(s.find("-A PREROUTING -j KeenPbrDnsRdr\n") == std::string::npos);
  CHECK(s.find("-A KeenPbrDnsRdr -i br0 -p udp --dport 53 -j REDIRECT --to-ports 53\n") != std::string::npos);
  CHECK(s.find("-A KeenPbrDnsRdr -i br0 -p tcp --dport 53 -j REDIRECT --to-ports 53\n") != std::string::npos);
  CHECK(s.substr(s.size() - 7) == "COMMIT\n");
}

TEST_CASE("build_dns_nat_script: no inbound interfaces redirects from any interface") {
  auto s = T::build_dns_nat_script({});
  CHECK(s.find("-A KeenPbrDnsRdr -p udp --dport 53 -j REDIRECT --to-ports 53\n") != std::string::npos);
  CHECK(s.find("-i ") == std::string::npos);
}

TEST_CASE("build_dns_nat_script: internal VPN bypass precedes every DNS redirect") {
  FirewallGlobalPrefilter prefilter;
  prefilter.bypass_inbound_interfaces = {"nwg0", "nwg1"};
  const auto s = T::build_dns_nat_script(prefilter);

  const auto first_bypass =
      s.find("-A KeenPbrDnsRdr -i nwg0 -j RETURN\n");
  const auto second_bypass =
      s.find("-A KeenPbrDnsRdr -i nwg1 -j RETURN\n");
  const auto udp_redirect =
      s.find("-A KeenPbrDnsRdr -p udp --dport 53 -j REDIRECT --to-ports 53\n");
  const auto tcp_redirect =
      s.find("-A KeenPbrDnsRdr -p tcp --dport 53 -j REDIRECT --to-ports 53\n");

  REQUIRE(first_bypass != std::string::npos);
  REQUIRE(second_bypass != std::string::npos);
  REQUIRE(udp_redirect != std::string::npos);
  REQUIRE(tcp_redirect != std::string::npos);
  CHECK(first_bypass < udp_redirect);
  CHECK(second_bypass < udp_redirect);
  CHECK(first_bypass < tcp_redirect);
  CHECK(second_bypass < tcp_redirect);
}

TEST_CASE("build_dns_nat_script: service source pools extend and bypass DNS scope") {
  FirewallGlobalPrefilter prefilter;
  prefilter.inbound_interfaces =
      std::vector<std::string>{"br0"};
  prefilter.include_source_cidrs_v4 = {"172.20.8.0/23"};
  prefilter.bypass_source_selectors_v4 = {
      {"br0", "172.16.1.0/24"}};

  const auto s = T::build_dns_nat_script(prefilter);
  const auto bypass =
      s.find(
          "-A KeenPbrDnsRdr -i br0 -s 172.16.1.0/24 -j RETURN\n");
  const auto included =
      s.find("-A KeenPbrDnsRdr -s 172.20.8.0/23 -p udp --dport 53 -j REDIRECT --to-ports 53\n");
  REQUIRE(bypass != std::string::npos);
  REQUIRE(included != std::string::npos);
  CHECK(bypass < included);
  CHECK(s.find("-A KeenPbrDnsRdr -i br0 -p udp") !=
        std::string::npos);

  const auto ipv6 = T::build_dns_nat_script(
      prefilter,
      /*dns_redirect=*/true,
      /*router_origin_snat=*/false,
      {},
      /*ipv6=*/true);
  CHECK(ipv6.find("172.20.8.0/23") == std::string::npos);
  CHECK(ipv6.find("172.16.1.0/24") == std::string::npos);
}

TEST_CASE(
    "iptables addressless IKE bypass affects DNS redirect but not routing") {
  FirewallGlobalPrefilter prefilter;
  prefilter.dns_redirect_bypass_source_selectors_v4 = {
      {"xfrms1", "172.20.8.0/23"}};

  const auto dns = T::build_dns_nat_script(prefilter);
  const auto dns_bypass = dns.find(
      "-A KeenPbrDnsRdr -i xfrms1 -s 172.20.8.0/23 -j RETURN\n");
  const auto dns_redirect = dns.find(
      "-A KeenPbrDnsRdr -p udp --dport 53 -j REDIRECT "
      "--to-ports 53\n");
  REQUIRE(dns_bypass != std::string::npos);
  REQUIRE(dns_redirect != std::string::npos);
  CHECK(dns_bypass < dns_redirect);

  const auto routing = T::build_ipt_script(
      false,
      {mark_rule("kpbr4_local", false, 0x10000)},
      prefilter);
  CHECK(routing.find("xfrms1") == std::string::npos);
  CHECK(routing.find("172.20.8.0/23") == std::string::npos);
  CHECK(routing.find("kpbr4_local") != std::string::npos);
}

TEST_CASE("iptables policy rules classify verified service source pools") {
  FirewallGlobalPrefilter prefilter;
  prefilter.inbound_interfaces =
      std::vector<std::string>{"br0"};
  prefilter.include_source_cidrs_v4 = {"172.20.8.0/23"};
  prefilter.bypass_source_selectors_v4 = {
      {"xfrms1", "172.16.1.0/24"}};
  prefilter.restore_conntrack_mark = true;
  prefilter.conntrack_mark_mask = 0x00ff0000;

  const auto s = T::build_ipt_script(
      false,
      {mark_rule("kpbr4_local", false, 0x10000)},
      prefilter);

  const auto bypass =
      s.find(
          "-A KeenPbrTable -i xfrms1 -s 172.16.1.0/24 -j RETURN\n");
  const auto restore = s.find("CONNMARK --restore-mark");
  REQUIRE(bypass != std::string::npos);
  REQUIRE(restore != std::string::npos);
  CHECK(bypass < restore);
  CHECK(s.find("-A KeenPbrTable ! -i br0 -j RETURN") ==
        std::string::npos);
  CHECK(s.find(
            "-A KeenPbrTable -m set --match-set kpbr4_local dst -i br0") !=
        std::string::npos);
  CHECK(s.find(
            "-A KeenPbrTable -m set --match-set kpbr4_local dst -s 172.20.8.0/23") !=
        std::string::npos);
  CHECK(s.find(
            "-A KeenPbrTable -m set --match-set kpbr4_local dst -j MARK") ==
        std::string::npos);
}

TEST_CASE("iptables pooled VPN bypass fails closed without exact ingress") {
  FirewallGlobalPrefilter prefilter;
  prefilter.bypass_source_selectors_v4 = {
      {"", "172.16.1.0/24"}};

  const auto routing = T::build_ipt_script(
      false,
      {mark_rule("kpbr4_local", false, 0x10000)},
      prefilter);
  const auto dns = T::build_dns_nat_script(prefilter);
  CHECK(
      routing.find("-s 172.16.1.0/24 -j RETURN") ==
      std::string::npos);
  CHECK(
      dns.find("-s 172.16.1.0/24 -j RETURN") ==
      std::string::npos);
}

TEST_CASE(
    "iptables bridged SSTP bypass always matches L3 bridge and physdev port") {
  FirewallGlobalPrefilter prefilter;
  prefilter.bypass_bridge_source_selectors_v4 = {
      {"br1", "sstp-br-link", "172.16.1.0/24"}};
  prefilter.bypass_bridge_source_selectors_v6 = {
      {"br1", "sstp-br-link", "2001:db8:16::/64"}};

  const auto exact_rule = std::string{
      "-i br1 -m physdev --physdev-in sstp-br-link "
      "-s 172.16.1.0/24 -j RETURN\n"};
  const auto weak_rule = std::string{
      "-i br1 -s 172.16.1.0/24 -j RETURN\n"};

  const auto routing = T::build_ipt_script(
      false,
      {mark_rule("kpbr4_local", false, 0x10000)},
      prefilter);
  CHECK(
      routing.find("-A KeenPbrTable " + exact_rule) !=
      std::string::npos);
  CHECK(routing.find("-A KeenPbrTable " + weak_rule) ==
        std::string::npos);

  const auto raw =
      T::build_raw_generation_scripts(false, prefilter).first;
  CHECK(
      raw.find("-A KeenPbrRaw_A " + exact_rule) !=
      std::string::npos);
  CHECK(raw.find("-A KeenPbrRaw_A " + weak_rule) ==
        std::string::npos);

  const auto dns = T::build_dns_nat_script(prefilter);
  const auto exact_dns =
      dns.find("-A KeenPbrDnsRdr " + exact_rule);
  const auto redirect =
      dns.find("-A KeenPbrDnsRdr -p udp --dport 53 "
               "-j REDIRECT --to-ports 53\n");
  REQUIRE(exact_dns != std::string::npos);
  REQUIRE(redirect != std::string::npos);
  CHECK(exact_dns < redirect);
  CHECK(dns.find("-A KeenPbrDnsRdr " + weak_rule) ==
        std::string::npos);

  const auto exact_rule_v6 = std::string{
      "-i br1 -m physdev --physdev-in sstp-br-link "
      "-s 2001:db8:16::/64 -j RETURN\n"};
  const auto weak_rule_v6 = std::string{
      "-i br1 -s 2001:db8:16::/64 -j RETURN\n"};
  const auto routing_v6 = T::build_ipt_script(
      true,
      {mark_rule("kpbr6_local", true, 0x10000)},
      prefilter);
  CHECK(
      routing_v6.find("-A KeenPbrTable " + exact_rule_v6) !=
      std::string::npos);
  CHECK(routing_v6.find("-A KeenPbrTable " + weak_rule_v6) ==
        std::string::npos);

  const auto dns_v6 = T::build_dns_nat_script(
      prefilter,
      /*dns_redirect=*/true,
      /*router_origin_snat=*/false,
      {},
      /*ipv6=*/true);
  const auto exact_dns_v6 =
      dns_v6.find("-A KeenPbrDnsRdr " + exact_rule_v6);
  const auto redirect_v6 =
      dns_v6.find("-A KeenPbrDnsRdr -p udp --dport 53 "
                  "-j REDIRECT --to-ports 53\n");
  REQUIRE(exact_dns_v6 != std::string::npos);
  REQUIRE(redirect_v6 != std::string::npos);
  CHECK(exact_dns_v6 < redirect_v6);
  CHECK(dns_v6.find("-A KeenPbrDnsRdr " + weak_rule_v6) ==
        std::string::npos);
}

TEST_CASE("build_dns_nat_script: router-origin traffic is masqueraded") {
  auto s = T::build_dns_nat_script({}, /*dns_redirect=*/false,
                                   /*router_origin_snat=*/true);
  CHECK(s.find(
            ":KeenPbrSnat - [0:0]\n-F KeenPbrSnat\n") !=
        std::string::npos);
  CHECK(s.find("-A POSTROUTING -j KeenPbrSnat\n") == std::string::npos);
  CHECK(s.find("-A KeenPbrSnat -m mark --mark 0x1000000/0x1000000 -j MASQUERADE\n") != std::string::npos);
  CHECK(s.find("KeenPbrDnsRdr") == std::string::npos);
}

TEST_CASE("build_dns_nat_script: tunnel interfaces masquerade forwarded traffic") {
  // Clients of a VPN server on the router are not a network the firmware
  // masquerades for these interfaces, so keen-pbr has to do it itself.
  auto s = T::build_dns_nat_script({}, /*dns_redirect=*/false,
                                   /*router_origin_snat=*/true,
                                   {"nwg2", "mooo_vless"},
                                   /*ipv6=*/false,
                                   /*fwmark_mask=*/0x00FF0000u);
  CHECK(s.find(
            "-A KeenPbrSnat -o nwg2 -m mark ! "
            "--mark 0x0/0xff0000 -j MASQUERADE\n") != std::string::npos);
  CHECK(s.find(
            "-A KeenPbrSnat -o mooo_vless -m mark ! "
            "--mark 0x0/0xff0000 -j MASQUERADE\n") !=
        std::string::npos);
  CHECK(s.find("-A KeenPbrSnat -o nwg2 -j MASQUERADE\n") ==
        std::string::npos);
}

TEST_CASE("create_tunnel_snat_rules: deduplicates interfaces") {
  CHECK(T::tunnel_snat_interface_count({"nwg2", "nwg2", "nwg3"}) == 2);
}

TEST_CASE("source-egress SNAT matches an authoritative pool and egress") {
  const std::vector<FirewallSourceEgressSnatSelector> selectors{
      {"eth3", "172.16.1.0/24"},
      {"eth4", "fd00:16:1::/64"},
  };

  const auto ipv4 = T::build_dns_nat_script(
      {},
      /*dns_redirect=*/false,
      /*router_origin_snat=*/true,
      {},
      /*ipv6=*/false,
      /*fwmark_mask=*/0x00FF0000u,
      selectors);
  CHECK(ipv4.find(
            "-A KeenPbrSnat -s 172.16.1.0/24 -o eth3 "
            "-j MASQUERADE\n") != std::string::npos);
  CHECK(ipv4.find("fd00:16:1::/64") == std::string::npos);
  CHECK(ipv4.find(
            "-s 172.16.1.0/24 -o eth3 -m mark") == std::string::npos);

  const auto ipv6 = T::build_dns_nat_script(
      {},
      /*dns_redirect=*/false,
      /*router_origin_snat=*/true,
      {},
      /*ipv6=*/true,
      /*fwmark_mask=*/0x00FF0000u,
      selectors);
  CHECK(ipv6.find(
            "-A KeenPbrSnat -s fd00:16:1::/64 -o eth4 "
            "-j MASQUERADE\n") != std::string::npos);
  CHECK(ipv6.find("172.16.1.0/24") == std::string::npos);
}

TEST_CASE("source-egress SNAT selectors are filtered sorted and deduplicated") {
  const auto selectors = T::source_egress_snat_selectors({
      {"eth4", "172.16.2.0/24"},
      {"", "172.16.9.0/24"},
      {"eth3", ""},
      {"eth3", "172.16.1.0/24"},
      {"eth4", "172.16.2.0/24"},
  });
  REQUIRE(selectors.size() == 2);
  CHECK((selectors[0] ==
         FirewallSourceEgressSnatSelector{"eth3", "172.16.1.0/24"}));
  CHECK((selectors[1] ==
         FirewallSourceEgressSnatSelector{"eth4", "172.16.2.0/24"}));
  CHECK(T::source_egress_snat_requested(
      {{"eth3", "172.16.1.0/24"}}));
  CHECK_FALSE(T::source_egress_snat_requested(
      {{"", "172.16.1.0/24"}, {"eth3", ""}}));
}

TEST_CASE("owned SNAT inspection distinguishes healthy missing and unknown") {
  IptablesTestTempDir temp;
  const auto mode = temp.path() / "snat-state";
  write_iptables_test_executable(
      temp.path() / "iptables",
      "#!/bin/sh\n"
      "case \"$(cat \"$KPBR_SNAT_STATE\" 2>/dev/null)\" in\n"
      "  healthy)\n"
      "    case \"$*\" in\n"
      "      '-t nat -S POSTROUTING')\n"
      "        echo '-A POSTROUTING -j KeenPbrSnat' ;;\n"
      "      '-t nat -S KeenPbrSnat')\n"
      "        printf '%s\\n' '-N KeenPbrSnat' "
      "'-A KeenPbrSnat -m mark --mark "
      "0x1000000/0x1000000 -j MASQUERADE' ;;\n"
      "    esac\n"
      "    exit 0\n"
      "    ;;\n"
      "  interface)\n"
      "    case \"$*\" in\n"
      "      '-t nat -S POSTROUTING')\n"
      "        echo '-A POSTROUTING -j KeenPbrSnat' ;;\n"
      "      '-t nat -S KeenPbrSnat')\n"
      "        printf '%s\\n' '-N KeenPbrSnat' "
      "'-A KeenPbrSnat -m mark --mark "
      "0x1000000/0x1000000 -j MASQUERADE' "
      "'-A KeenPbrSnat -o nwg2 -m mark ! "
      "--mark 0x0/0xff0000 -j MASQUERADE' ;;\n"
      "    esac\n"
      "    exit 0\n"
      "    ;;\n"
      "  source-egress)\n"
      "    case \"$*\" in\n"
      "      '-t nat -S POSTROUTING')\n"
      "        echo '-A POSTROUTING -j KeenPbrSnat' ;;\n"
      "      '-t nat -S KeenPbrSnat')\n"
      "        printf '%s\\n' '-N KeenPbrSnat' "
      "'-A KeenPbrSnat -m mark --mark "
      "0x1000000/0x1000000 -j MASQUERADE' "
      "'-A KeenPbrSnat -s 172.16.1.0/24 -o eth3 "
      "-j MASQUERADE' ;;\n"
      "    esac\n"
      "    exit 0\n"
      "    ;;\n"
      "  interfaces-reversed)\n"
      "    case \"$*\" in\n"
      "      '-t nat -S POSTROUTING')\n"
      "        echo '-A POSTROUTING -j KeenPbrSnat' ;;\n"
      "      '-t nat -S KeenPbrSnat')\n"
      "        printf '%s\\n' '-N KeenPbrSnat' "
      "'-A KeenPbrSnat -m mark --mark "
      "0x1000000/0x1000000 -j MASQUERADE' "
      "'-A KeenPbrSnat -o nwg3 -m mark ! "
      "--mark 0x0/0xff0000 -j MASQUERADE' "
      "'-A KeenPbrSnat -o nwg2 -m mark ! "
      "--mark 0x0/0xff0000 -j MASQUERADE' ;;\n"
      "    esac\n"
      "    exit 0\n"
      "    ;;\n"
      "  empty)\n"
      "    case \"$*\" in\n"
      "      '-t nat -S POSTROUTING')\n"
      "        echo '-A POSTROUTING -j KeenPbrSnat' ;;\n"
      "      '-t nat -S KeenPbrSnat') echo '-N KeenPbrSnat' ;;\n"
      "    esac\n"
      "    exit 0\n"
      "    ;;\n"
      "  extra)\n"
      "    case \"$*\" in\n"
      "      '-t nat -S POSTROUTING')\n"
      "        echo '-A POSTROUTING -j KeenPbrSnat' ;;\n"
      "      '-t nat -S KeenPbrSnat')\n"
      "        printf '%s\\n' '-N KeenPbrSnat' "
      "'-A KeenPbrSnat -m mark --mark "
      "0x1000000/0x1000000 -j MASQUERADE' "
      "'-A KeenPbrSnat -j ACCEPT' ;;\n"
      "    esac\n"
      "    exit 0\n"
      "    ;;\n"
      "  conditional-hook)\n"
      "    case \"$*\" in\n"
      "      '-t nat -S POSTROUTING')\n"
      "        echo '-A POSTROUTING -p tcp -j KeenPbrSnat' ;;\n"
      "      '-t nat -S KeenPbrSnat')\n"
      "        printf '%s\\n' '-N KeenPbrSnat' "
      "'-A KeenPbrSnat -m mark --mark "
      "0x1000000/0x1000000 -j MASQUERADE' ;;\n"
      "    esac\n"
      "    exit 0\n"
      "    ;;\n"
      "  missing)\n"
      "    case \"$*\" in\n"
      "      '-t nat -S POSTROUTING') exit 0 ;;\n"
      "      '-t nat -S KeenPbrSnat')\n"
      "        echo 'iptables: No chain/target/match by that name.' >&2\n"
      "        exit 1 ;;\n"
      "    esac\n"
      "    ;;\n"
      "  *)\n"
      "    echo 'xtables lock is temporarily unavailable' >&2\n"
      "    exit 4\n"
      "    ;;\n"
      "esac\n"
      "exit 0\n");
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment state_env("KPBR_SNAT_STATE");
  use_iptables_test_path(path, temp.path());
  state_env.set(mode.string());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  {
    std::ofstream out(mode);
    out << "healthy";
  }
  CHECK(T::inspect_owned_snat_state(
            /*expected=*/true) == OwnedSnatState::healthy);
  CHECK(T::inspect_owned_snat_state(
            /*expected=*/false) == OwnedSnatState::stale);
  CHECK(T::inspect_owned_snat_state(
            /*expected=*/true,
            {"nwg2"},
            0x00FF0000u) == OwnedSnatState::missing);
  CHECK(T::inspect_owned_snat_state(
            /*expected=*/true,
            {},
            0x00FF0000u,
            {{"eth3", "172.16.1.0/24"}}) == OwnedSnatState::missing);
  {
    std::ofstream out(mode);
    out << "interface";
  }
  CHECK(T::inspect_owned_snat_state(
            /*expected=*/true,
            {"nwg2"},
            0x00FF0000u) == OwnedSnatState::healthy);
  {
    std::ofstream out(mode);
    out << "source-egress";
  }
  CHECK(T::inspect_owned_snat_state(
            /*expected=*/true,
            {},
            0x00FF0000u,
            {{"eth3", "172.16.1.0/24"}}) == OwnedSnatState::healthy);
  CHECK(T::inspect_owned_snat_state(
            /*expected=*/true,
            {},
            0x00FF0000u) == OwnedSnatState::missing);
  {
    std::ofstream out(mode);
    out << "interfaces-reversed";
  }
  CHECK(T::inspect_owned_snat_state(
            /*expected=*/true,
            {"nwg2", "nwg3"},
            0x00FF0000u) == OwnedSnatState::missing);
  CHECK(T::inspect_owned_snat_state(
            /*expected=*/true,
            {"nwg3", "nwg2"},
            0x00FF0000u) == OwnedSnatState::healthy);
  {
    std::ofstream out(mode);
    out << "empty";
  }
  CHECK(T::inspect_owned_snat_state(
            /*expected=*/true) == OwnedSnatState::missing);
  {
    std::ofstream out(mode);
    out << "extra";
  }
  CHECK(T::inspect_owned_snat_state(
            /*expected=*/true) == OwnedSnatState::missing);
  CHECK(T::inspect_owned_snat_state(
            /*expected=*/false) == OwnedSnatState::stale);
  {
    std::ofstream out(mode);
    out << "conditional-hook";
  }
  CHECK(T::inspect_owned_snat_state(
            /*expected=*/true) == OwnedSnatState::missing);
  {
    std::ofstream out(mode);
    out << "missing";
  }
  CHECK(T::inspect_owned_snat_state(
            /*expected=*/true) == OwnedSnatState::missing);
  CHECK(T::inspect_owned_snat_state(
            /*expected=*/false) == OwnedSnatState::healthy);
  {
    std::ofstream out(mode);
    out << "unknown";
  }
  CHECK(T::inspect_owned_snat_state(
            /*expected=*/true) == OwnedSnatState::unknown);
}

TEST_CASE("owned SNAT family aggregation is fail closed") {
  CHECK(T::combine_owned_snat_states(
            OwnedSnatState::healthy,
            OwnedSnatState::healthy) == OwnedSnatState::healthy);
  CHECK(T::combine_owned_snat_states(
            OwnedSnatState::stale,
            OwnedSnatState::healthy) == OwnedSnatState::stale);
  CHECK(T::combine_owned_snat_states(
            OwnedSnatState::stale,
            OwnedSnatState::missing) == OwnedSnatState::missing);
  CHECK(T::combine_owned_snat_states(
            OwnedSnatState::missing,
            OwnedSnatState::unknown) == OwnedSnatState::unknown);
}

TEST_CASE("owned SNAT inspection includes the last managed IPv6 family") {
  IptablesTestTempDir temp;
  const std::string executable =
      "#!/bin/sh\n"
      "state=\"$KPBR_SNAT_V4_STATE\"\n"
      "case \"${0##*/}\" in ip6tables) state=\"$KPBR_SNAT_V6_STATE\" ;; esac\n"
      "case \"$state:$*\" in\n"
      "  'healthy:-t nat -S POSTROUTING')\n"
      "    echo '-A POSTROUTING -j KeenPbrSnat' ;;\n"
      "  'healthy:-t nat -S KeenPbrSnat')\n"
      "    printf '%s\\n' '-N KeenPbrSnat' "
      "'-A KeenPbrSnat -m mark --mark "
      "0x1000000/0x1000000 -j MASQUERADE' ;;\n"
      "  'missing:-t nat -S POSTROUTING') exit 0 ;;\n"
      "  'missing:-t nat -S KeenPbrSnat')\n"
      "    echo 'iptables: No chain/target/match by that name.' >&2\n"
      "    exit 1 ;;\n"
      "  unknown:*) echo 'xtables lock unavailable' >&2; exit 4 ;;\n"
      "esac\n"
      "exit 0\n";
  write_iptables_test_executable(temp.path() / "iptables", executable);
  write_iptables_test_executable(temp.path() / "ip6tables", executable);
  IptablesTestEnvironment path("PATH");
  IptablesTestEnvironment ipv4("KPBR_SNAT_V4_STATE");
  IptablesTestEnvironment ipv6("KPBR_SNAT_V6_STATE");
  use_iptables_test_path(path, temp.path());
  IptablesFailurePathGuard failure_path(temp.path() / "last-failure");

  ipv4.set("healthy");
  ipv6.set("missing");
  CHECK(T::inspect_owned_snat_families(
            /*ipv4_expected=*/true,
            /*ipv6_expected=*/true,
            /*ipv6_managed=*/true) == OwnedSnatState::missing);

  ipv4.set("missing");
  ipv6.set("unknown");
  CHECK(T::inspect_owned_snat_families(
            /*ipv4_expected=*/true,
            /*ipv6_expected=*/true,
            /*ipv6_managed=*/true) == OwnedSnatState::unknown);

  // Unsupported/unmanaged IPv6 must not turn a valid IPv4-only contract into
  // an inspection failure.
  ipv4.set("healthy");
  ipv6.set("unknown");
  CHECK(T::inspect_owned_snat_families(
            /*ipv4_expected=*/true,
            /*ipv6_expected=*/false,
            /*ipv6_managed=*/false) == OwnedSnatState::healthy);
}

TEST_CASE("create_output_mark_rule: carries the router-origin bit for masquerading") {
  FirewallRuleCriteria criteria;
  criteria.proto = L4Proto::Udp;
  criteria.dst_port = "53";
  criteria.dst_addr = {"8.8.8.8"};
  auto s = T::build_output_mark_script_with_snat(0x20000, criteria, 0x00FF0000);
  // Without the extra bit the packet would leave the tunnel with the source
  // address picked before the mark existed and never get an answer back.
  CHECK(s.find("-j MARK --set-xmark 0x1020000/0x1ff0000") != std::string::npos);
}

TEST_CASE("build_ipt_script: global prefilter RETURN lines are emitted before route rules") {
  auto s = T::build_ipt_script(
      false,
      {mark_rule("myset", false, 0x100)},
      prefilter_with_interfaces({"br0"}));

  const std::string dnat =
      "-A KeenPbrTable -m conntrack --ctstate DNAT -j RETURN\n";
  const std::string marked =
      "-A KeenPbrTable -m mark ! --mark 0x0/0xffffffff -j ACCEPT\n";
  const std::string iface =
      "-A KeenPbrTable ! -i br0 -j RETURN\n";
  const std::string mark =
      "-A KeenPbrTable -m set --match-set myset dst -j MARK --set-xmark 0x100/0xffffffff\n";

  const auto dnat_pos = s.find(dnat);
  const auto marked_pos = s.find(marked);
  const auto iface_pos = s.find(iface);
  const auto mark_pos = s.find(mark);
  REQUIRE(dnat_pos != std::string::npos);
  REQUIRE(marked_pos != std::string::npos);
  REQUIRE(iface_pos != std::string::npos);
  REQUIRE(mark_pos != std::string::npos);
  CHECK(s.find("--ctstate RELATED,ESTABLISHED") == std::string::npos);
  CHECK(dnat_pos < marked_pos);
  CHECK(marked_pos < iface_pos);
  CHECK(iface_pos < mark_pos);
}

TEST_CASE("build_ipt_script: restores and saves only keen-pbr conntrack mark bits") {
  FirewallGlobalPrefilter prefilter;
  prefilter.restore_conntrack_mark = true;
  prefilter.conntrack_mark_mask = 0x00FF0000;

  const auto s = T::build_ipt_script(
      false,
      {mark_rule("myset", false, 0x00120000)},
      prefilter);

  const std::string restore =
      "-A KeenPbrTable -m conntrack --ctdir ORIGINAL "
      "-m connmark ! --mark 0/0xff0000 "
      "-j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000\n";
  const std::string restored_return =
      "-A KeenPbrTable -m conntrack --ctdir ORIGINAL "
      "-m connmark ! --mark 0/0xff0000 -j RETURN\n";
  const std::string classify =
      "-A KeenPbrTable -m set --match-set myset dst "
      "-j MARK --set-xmark 0x120000/0xffffffff\n";
  const std::string persist =
      "-A KeenPbrTable -m set --match-set myset dst "
      "-j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000\n";

  const auto restore_pos = s.find(restore);
  const auto return_pos = s.find(restored_return);
  const auto classify_pos = s.find(classify);
  const auto persist_pos = s.find(persist);
  REQUIRE(restore_pos != std::string::npos);
  REQUIRE(return_pos != std::string::npos);
  REQUIRE(classify_pos != std::string::npos);
  REQUIRE(persist_pos != std::string::npos);
  CHECK(restore_pos < return_pos);
  CHECK(return_pos < classify_pos);
  CHECK(classify_pos < persist_pos);
  CHECK(s.find("--ctdir REPLY") == std::string::npos);
}

TEST_CASE("build_ipt_script: internal VPN bypass precedes conntrack restore and classification") {
  FirewallGlobalPrefilter prefilter;
  prefilter.bypass_inbound_interfaces = {"nwg0"};
  prefilter.restore_conntrack_mark = true;
  prefilter.conntrack_mark_mask = 0x00FF0000;

  const auto s = T::build_ipt_script(
      false,
      {mark_rule("myset", false, 0x00120000)},
      prefilter);

  const auto bypass =
      s.find("-A KeenPbrTable -i nwg0 -j RETURN\n");
  const auto restore =
      s.find("-A KeenPbrTable -m conntrack --ctdir ORIGINAL "
             "-m connmark ! --mark 0/0xff0000 "
             "-j CONNMARK --restore-mark");
  const auto classify =
      s.find("-A KeenPbrTable -m set --match-set myset dst "
             "-j MARK --set-xmark 0x120000/0xffffffff\n");

  REQUIRE(bypass != std::string::npos);
  REQUIRE(restore != std::string::npos);
  REQUIRE(classify != std::string::npos);
  CHECK(bypass < restore);
  CHECK(bypass < classify);
}

TEST_CASE("raw PREROUTING never references conntrack state or CONNMARK") {
  FirewallGlobalPrefilter prefilter;
  prefilter.restore_conntrack_mark = true;
  prefilter.conntrack_mark_mask = 0x00FF0000;

  const auto [raw, output] =
      T::build_raw_generation_scripts(false, prefilter);

  CHECK(raw.find("CONNMARK") == std::string::npos);
  CHECK(raw.find("--ctdir") == std::string::npos);
  CHECK(output.find(
            "CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000") !=
        std::string::npos);
  CHECK(output.find(
            "CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000") !=
        std::string::npos);
}

TEST_CASE("raw PREROUTING uses a mangle conntrack companion for flow stickiness") {
  FirewallGlobalPrefilter prefilter;
  prefilter.restore_conntrack_mark = true;
  prefilter.conntrack_mark_mask = 0x00FF0000;

  const auto first = T::build_raw_conntrack_script(false, prefilter);
  CHECK(first.find(":KeenPbrRawCt - [0:0]") != std::string::npos);
  CHECK(first.find("-A PREROUTING -j KeenPbrRawCt") ==
        std::string::npos);
  CHECK(first.find(
            "CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000") !=
        std::string::npos);
  CHECK(first.find(
            "CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000") !=
        std::string::npos);
  CHECK(first.find("--ctdir REPLY") == std::string::npos);

  const auto replace = T::build_raw_conntrack_script(true, prefilter);
  CHECK(replace.find("-F KeenPbrRawCt") != std::string::npos);
  CHECK(replace.find("-A PREROUTING -j KeenPbrRawCt") ==
        std::string::npos);
}

TEST_CASE("raw conntrack companion bypasses internal VPN before restore") {
  FirewallGlobalPrefilter prefilter;
  prefilter.bypass_inbound_interfaces = {"nwg0"};
  prefilter.restore_conntrack_mark = true;
  prefilter.conntrack_mark_mask = 0x00FF0000;

  const auto script = T::build_raw_conntrack_script(false, prefilter);
  const auto bypass =
      script.find("-A KeenPbrRawCt -i nwg0 -j RETURN\n");
  const auto restore =
      script.find("-A KeenPbrRawCt -m conntrack --ctdir ORIGINAL "
                  "-m connmark ! --mark 0/0xff0000 "
                  "-j CONNMARK --restore-mark");

  REQUIRE(bypass != std::string::npos);
  REQUIRE(restore != std::string::npos);
  CHECK(bypass < restore);
}
TEST_CASE("build_ipt_script: skip_marked_packets prefilter can be disabled") {
  FirewallGlobalPrefilter prefilter;
  prefilter.skip_established_or_dnat = true;
  prefilter.skip_marked_packets = false;

  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100)}, prefilter);
  CHECK(s.find("-m mark ! --mark 0x0/0xffffffff -j ACCEPT") == std::string::npos);
}

TEST_CASE("iptables skip-marked guards bypass foreign NDMS marks") {
  FirewallGlobalPrefilter prefilter;
  prefilter.skip_marked_packets = true;
  prefilter.conntrack_mark_mask = 0x00FF0000;

  const auto legacy = T::build_ipt_script(
      false, {mark_rule("myset", false, 0x00120000)}, prefilter);
  CHECK(legacy.find(
            "-A KeenPbrTable -m mark ! --mark 0x0/0xffffffff -j ACCEPT\n") !=
        std::string::npos);
  CHECK(legacy.find(
            "-A KeenPbrOutput -m mark ! --mark 0x0/0xffffffff -j ACCEPT\n") !=
        std::string::npos);

  const auto generation = T::build_generation_script(false, prefilter);
  CHECK(generation.find(
            "-A KeenPbrTable_A -m mark ! --mark 0x0/0xffffffff -j ACCEPT\n") !=
        std::string::npos);
  CHECK(generation.find(
            "-A KeenPbrOutput_A -m mark ! --mark 0x0/0xffffffff -j ACCEPT\n") !=
        std::string::npos);

  const auto [raw, output] =
      T::build_raw_generation_scripts(false, prefilter);
  CHECK(raw.find(
            "-A KeenPbrRaw_A -m mark ! --mark 0x0/0xffffffff -j ACCEPT\n") !=
        std::string::npos);
  CHECK(output.find(
            "-A KeenPbrOutput_A -m mark ! --mark 0x0/0xffffffff -j ACCEPT\n") !=
        std::string::npos);

  for (const auto* script : {&legacy, &generation, &raw, &output}) {
    CHECK(script->find(
              "-m mark ! --mark 0x0/0xff0000 -j ACCEPT\n") ==
          std::string::npos);
  }
}

TEST_CASE("build_ipt_script: multi-interface prefilter expands route rules with -i matches") {
  auto s = T::build_ipt_script(
      false,
      {pass_rule("allowlist", false)},
      prefilter_with_interfaces({"br0", "wg0"}, false));

  CHECK(s.find("-A KeenPbrTable -m set --match-set allowlist dst -i br0 -j RETURN\n") !=
        std::string::npos);
  CHECK(s.find("-A KeenPbrTable -m set --match-set allowlist dst -i wg0 -j RETURN\n") !=
        std::string::npos);
}

TEST_CASE("build_ipt_script: config-derived prefilter keeps route rule body unchanged") {
  auto cfg = parse_valid_config(R"({
    "outbounds":[
      {"tag":"wan","type":"interface","interface":"eth0","gateway":"192.0.2.1"}
    ],
    "lists":{
      "local":{"ip_cidrs":["192.168.0.0/16"]}
    },
    "route":{
      "inbound_interfaces":["br0"],
      "rules":[
        {"list":["local"],"outbound":"wan"}
      ]
    }
  })");

  const auto prefilter = build_firewall_global_prefilter(cfg);
  auto s = T::build_ipt_script(false, {mark_rule("kpbr4_local", false, 0x100)}, prefilter);

  const std::string iface = "-A KeenPbrTable ! -i br0 -j RETURN\n";
  const std::string mark =
      "-A KeenPbrTable -m set --match-set kpbr4_local dst -j MARK --set-xmark 0x100/0xffffffff\n";
  const auto iface_pos = s.find(iface);
  const auto mark_pos = s.find(mark);
  REQUIRE(iface_pos != std::string::npos);
  REQUIRE(mark_pos != std::string::npos);
  CHECK(iface_pos < mark_pos);
}

TEST_CASE("build_ipt_script: config rejects interface restore injection before serialization") {
  CHECK_THROWS(parse_valid_config(
      "{\"route\":{\"inbound_interfaces\":[\"br0\\n-A KeenPbrTable -j DROP\"],"
      "\"rules\":[]}}"));
}

TEST_CASE("build_ipt_script_for_rule: masked mark rule uses set-xmark") {
  FirewallRuleCriteria criteria;
  auto s = T::build_ipt_script_for_rule(false, Rule::Mark, 0x00010000, criteria,
                                        true, 0x00FF0000);
  CHECK(s.find("-A KeenPbrTable -m set --match-set pairwise_set dst -j MARK --set-xmark 0x10000/0xff0000\n") !=
        std::string::npos);
  CHECK(s.find("[0:0] -A") == std::string::npos);
}

TEST_CASE("build_ipt_script: config-derived prefilter omits interface guard when inbound list is empty") {
  auto cfg = parse_valid_config(R"({
    "outbounds":[
      {"tag":"wan","type":"interface","interface":"eth0","gateway":"192.0.2.1"}
    ],
    "lists":{
      "local":{"ip_cidrs":["192.168.0.0/16"]}
    },
    "route":{
      "inbound_interfaces":[],
      "rules":[
        {"list":["local"],"outbound":"wan"}
      ]
    }
  })");

  const auto prefilter = build_firewall_global_prefilter(cfg);
  auto s = T::build_ipt_script(false, {mark_rule("kpbr4_local", false, 0x100)}, prefilter);

  CHECK(s.find("! -i ") == std::string::npos);
  CHECK(s.find("-A KeenPbrTable -m set --match-set kpbr4_local dst -j MARK --set-xmark 0x100/0xffffffff\n") !=
        std::string::npos);
}

// =============================================================================
// build_proto_port_fragment tests
// =============================================================================

TEST_CASE("build_proto_port_fragment: empty filter → empty string") {
  CHECK(T::build_proto_port_fragment("", "", "") == "");
}

TEST_CASE("build_proto_port_fragment: tcp + single dest_port") {
  auto frag = T::build_proto_port_fragment("tcp", "", "443");
  CHECK(frag == " -p tcp --dport 443");
}

TEST_CASE("build_proto_port_fragment: udp + port range") {
  auto frag = T::build_proto_port_fragment("udp", "", "8000-9000");
  CHECK(frag == " -p udp --dport 8000:9000");
}

TEST_CASE("build_proto_port_fragment: tcp + port list → multiport") {
  auto frag = T::build_proto_port_fragment("tcp", "", "80,443");
  CHECK(frag == " -p tcp -m multiport --dports 80,443");
}

TEST_CASE("build_proto_port_fragment: src_port + dest_port → sport and dport") {
  auto frag = T::build_proto_port_fragment("tcp", "1024-65535", "80");
  CHECK(frag == " -p tcp --sport 1024:65535 --dport 80");
}

TEST_CASE("build_proto_port_fragment: proto only, no ports") {
  auto frag = T::build_proto_port_fragment("udp", "", "");
  CHECK(frag == " -p udp");
}

// =============================================================================
// build_ipt_script with proto/port filter tests
// =============================================================================

TEST_CASE("build_ipt_script: tcp + single dest_port in rule") {
  ProtoPortFilter f;
  f.proto = L4Proto::Tcp;
  f.dst_port = "443";
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst -p tcp --dport "
               "443 -j MARK --set-xmark 0x100/0xffffffff") != std::string::npos);
}

TEST_CASE("build_ipt_script: dscp matcher is emitted") {
  ProtoPortFilter f;
  f.dscp = 46;
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst -m dscp --dscp "
               "46 -j MARK --set-xmark 0x100/0xffffffff") != std::string::npos);
}

TEST_CASE("build_ipt_script: udp + port range in rule") {
  ProtoPortFilter f;
  f.proto = L4Proto::Udp;
  f.dst_port = "8000-9000";
  auto s = T::build_ipt_script(false, {drop_rule("bl", false, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set bl dst -p udp --dport "
               "8000:9000 -j DROP") != std::string::npos);
}

TEST_CASE("build_ipt_script: tcp/udp + port list → two rules") {
  ProtoPortFilter f;
  f.proto = L4Proto::TcpUdp;
  f.dst_port = "80,443";
  // create_mark_rule expands tcp/udp, so we simulate by passing two rules
  // already expanded
  ProtoPortFilter ftcp;
  ftcp.proto = L4Proto::Tcp;
  ftcp.dst_port = "80,443";
  ProtoPortFilter fudp;
  fudp.proto = L4Proto::Udp;
  fudp.dst_port = "80,443";
  auto s = T::build_ipt_script(false, {mark_rule("s", false, 0x10, ftcp),
                                       mark_rule("s", false, 0x10, fudp)});
  CHECK(s.find("-p tcp -m multiport --dports 80,443") != std::string::npos);
  CHECK(s.find("-p udp -m multiport --dports 80,443") != std::string::npos);
}

TEST_CASE("build_ipt_script: oversized multiport list is split at 15 slots") {
  ProtoPortFilter f;
  f.proto = L4Proto::Tcp;
  f.dst_port = "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16";
  auto s = T::build_ipt_script(false, {drop_rule("bl", false, f)});
  CHECK(s.find("--dports 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 -j DROP") !=
        std::string::npos);
  CHECK(s.find("--dports 16 -j DROP") != std::string::npos);
}

TEST_CASE("build_ipt_script: multiport ranges consume two slots") {
  ProtoPortFilter f;
  f.proto = L4Proto::Udp;
  f.dst_port = "1-2,3-4,5-6,7-8,9-10,11-12,13-14,15-16";
  auto s = T::build_ipt_script(false, {drop_rule("bl", false, f)});
  CHECK(s.find("--dports 1:2,3:4,5:6,7:8,9:10,11:12,13:14 -j DROP") !=
        std::string::npos);
  CHECK(s.find("--dports 15:16 -j DROP") != std::string::npos);
}

TEST_CASE("build_ipt_script: oversized negated multiport list remains AND") {
  ProtoPortFilter f;
  f.proto = L4Proto::Tcp;
  f.dst_port = "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16";
  f.negate_dst_port = true;
  auto s = T::build_ipt_script(false, {drop_rule("bl", false, f)});
  CHECK(s.find("-m multiport ! --dports "
               "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 "
               "-m multiport ! --dports 16 -j DROP") != std::string::npos);
}

TEST_CASE("build_ipt_script: source list preserves single destination port") {
  ProtoPortFilter f;
  f.proto = L4Proto::Tcp;
  f.src_port = "80,443";
  f.dst_port = "8443";
  auto s = T::build_ipt_script(false, {drop_rule("bl", false, f)});
  CHECK(s.find("-m multiport --sports 80,443 --dport 8443 -j DROP") !=
        std::string::npos);
}

TEST_CASE("build_ipt_script: destination list preserves single source port") {
  ProtoPortFilter f;
  f.proto = L4Proto::Tcp;
  f.src_port = "1024";
  f.dst_port = "80,443";
  auto s = T::build_ipt_script(false, {drop_rule("bl", false, f)});
  CHECK(s.find("--sport 1024 -m multiport --dports 80,443 -j DROP") !=
        std::string::npos);
}

TEST_CASE("build_ipt_script: oversized positive port lists cross product") {
  ProtoPortFilter f;
  f.proto = L4Proto::Tcp;
  f.src_port = "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16";
  f.dst_port =
      "101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116";
  auto s = T::build_ipt_script(false, {drop_rule("bl", false, f)});
  const std::string src_a =
      "-m multiport --sports 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15";
  const std::string src_b = "-m multiport --sports 16";
  const std::string dst_a =
      "-m multiport --dports "
      "101,102,103,104,105,106,107,108,109,110,111,112,113,114,115";
  const std::string dst_b = "-m multiport --dports 116";
  CHECK(s.find(src_a + " " + dst_a + " -j DROP") != std::string::npos);
  CHECK(s.find(src_a + " " + dst_b + " -j DROP") != std::string::npos);
  CHECK(s.find(src_b + " " + dst_a + " -j DROP") != std::string::npos);
  CHECK(s.find(src_b + " " + dst_b + " -j DROP") != std::string::npos);
}

TEST_CASE("build_ipt_script: negated chunks combine with positive alternatives") {
  ProtoPortFilter f;
  f.proto = L4Proto::Udp;
  f.src_port = "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16";
  f.negate_src_port = true;
  f.dst_port =
      "101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116";
  auto s = T::build_ipt_script(false, {drop_rule("bl", false, f)});
  const std::string excluded =
      "-m multiport ! --sports 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 "
      "-m multiport ! --sports 16";
  CHECK(s.find(excluded + " -m multiport --dports "
                          "101,102,103,104,105,106,107,108,109,110,111,112,"
                          "113,114,115 -j DROP") != std::string::npos);
  CHECK(s.find(excluded + " -m multiport --dports 116 -j DROP") !=
        std::string::npos);
}

TEST_CASE("build_ipt_script: positive chunks combine with negated destination") {
  ProtoPortFilter f;
  f.proto = L4Proto::Udp;
  f.src_port = "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16";
  f.dst_port =
      "101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116";
  f.negate_dst_port = true;
  auto s = T::build_ipt_script(false, {drop_rule("bl", false, f)});
  const std::string excluded =
      "-m multiport ! --dports "
      "101,102,103,104,105,106,107,108,109,110,111,112,113,114,115 "
      "-m multiport ! --dports 116";
  CHECK(s.find("-m multiport --sports "
               "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 " +
               excluded + " -j DROP") != std::string::npos);
  CHECK(s.find("-m multiport --sports 16 " + excluded + " -j DROP") !=
        std::string::npos);
}

TEST_CASE("build_ipt_script: any proto + src_port expands to tcp and udp rules") {
  ProtoPortFilter f;
  f.proto = L4Proto::Any;
  f.src_port = "11111";
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst -p tcp --sport "
               "11111 -j MARK --set-xmark 0x100/0xffffffff") != std::string::npos);
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst -p udp --sport "
               "11111 -j MARK --set-xmark 0x100/0xffffffff") != std::string::npos);
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst --sport 11111")
        == std::string::npos);
}

TEST_CASE(
    "build_ipt_script: no proto, no ports → no extra flags (regression)") {
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst -j MARK "
               "--set-xmark 0x100/0xffffffff") != std::string::npos);
  CHECK(s.find("-p ") == std::string::npos);
  CHECK(s.find("--dport") == std::string::npos);
}

// =============================================================================
// build_ipt_script with src_addr / dest_addr tests
// =============================================================================

TEST_CASE("build_ipt_script: single src_addr → -s flag") {
  ProtoPortFilter f;
  f.src_addr = {"192.168.10.0/24"};
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst -s "
               "192.168.10.0/24 -j MARK --set-xmark 0x100/0xffffffff") !=
        std::string::npos);
}

TEST_CASE("build_ipt_script: single dest_addr → -d flag") {
  ProtoPortFilter f;
  f.dst_addr = {"10.0.0.0/8"};
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst -d 10.0.0.0/8 -j "
               "MARK --set-xmark 0x100/0xffffffff") != std::string::npos);
}

TEST_CASE("build_ipt_script: src_addr + dest_addr → both flags") {
  ProtoPortFilter f;
  f.src_addr = {"192.168.1.0/24"};
  f.dst_addr = {"8.8.8.0/24"};
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst -s 192.168.1.0/24 "
               "-d 8.8.8.0/24 -j MARK --set-xmark 0x100/0xffffffff") != std::string::npos);
}

TEST_CASE("build_ipt_script: src_addr + tcp/udp + dest_port → addr and proto "
          "present") {
  ProtoPortFilter f;
  f.src_addr = {"192.168.1.0/24"};
  f.proto = L4Proto::Tcp;
  f.dst_port = "443";
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst -s 192.168.1.0/24 "
               "-p tcp --dport 443 -j MARK --set-xmark 0x100/0xffffffff") !=
        std::string::npos);
}

TEST_CASE("build_ipt_script: drop rule with src_addr → -s flag on DROP") {
  ProtoPortFilter f;
  f.src_addr = {"10.10.0.0/16"};
  auto s = T::build_ipt_script(false, {drop_rule("bl", false, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set bl dst -s 10.10.0.0/16 -j "
               "DROP") != std::string::npos);
}

// =============================================================================
// build_proto_port_fragment negation tests
// =============================================================================

TEST_CASE(
    "build_proto_port_fragment: negated dest_port (single) → ! --dport 443") {
  auto frag = T::build_proto_port_fragment("tcp", "", "443", false, true);
  CHECK(frag == " -p tcp ! --dport 443");
}

TEST_CASE(
    "build_proto_port_fragment: negated port range → ! --dport 8000:9000") {
  auto frag = T::build_proto_port_fragment("udp", "", "8000-9000", false, true);
  CHECK(frag == " -p udp ! --dport 8000:9000");
}

TEST_CASE("build_proto_port_fragment: negated multiport list → -m multiport ! "
          "--dports 80,443") {
  auto frag = T::build_proto_port_fragment("tcp", "", "80,443", false, true);
  CHECK(frag == " -p tcp -m multiport ! --dports 80,443");
}

TEST_CASE("build_proto_port_fragment: negated src_port only → ! --sport 1024") {
  auto frag = T::build_proto_port_fragment("tcp", "1024", "", true, false);
  CHECK(frag == " -p tcp ! --sport 1024");
}

TEST_CASE(
    "build_proto_port_fragment: both ports negated → sport and dport") {
  auto frag =
      T::build_proto_port_fragment("tcp", "1024-65535", "80", true, true);
  CHECK(frag == " -p tcp ! --sport 1024:65535 ! --dport 80");
}

TEST_CASE(
    "build_proto_port_fragment: mixed negation → sport and dport") {
  auto frag = T::build_proto_port_fragment("tcp", "1024", "443", true, false);
  CHECK(frag == " -p tcp ! --sport 1024 --dport 443");
}

// =============================================================================
// build_ipt_script negation tests
// =============================================================================

TEST_CASE("build_ipt_script: negated src_addr → ! -s flag") {
  ProtoPortFilter f;
  f.src_addr = {"192.168.1.0/24"};
  f.negate_src_addr = true;
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst ! -s "
               "192.168.1.0/24 -j MARK --set-xmark 0x100/0xffffffff") != std::string::npos);
}

TEST_CASE("build_ipt_script: negated dest_addr → ! -d flag") {
  ProtoPortFilter f;
  f.dst_addr = {"10.0.0.0/8"};
  f.negate_dst_addr = true;
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst ! -d 10.0.0.0/8 "
               "-j MARK --set-xmark 0x100/0xffffffff") != std::string::npos);
}

TEST_CASE("build_ipt_script: negated dest_port in full rule") {
  ProtoPortFilter f;
  f.proto = L4Proto::Tcp;
  f.dst_port = "443";
  f.negate_dst_port = true;
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst -p tcp ! --dport "
               "443 -j MARK --set-xmark 0x100/0xffffffff") != std::string::npos);
}

TEST_CASE("build_ipt_script: combined negated src_addr + negated dest_port") {
  ProtoPortFilter f;
  f.src_addr = {"192.168.1.0/24"};
  f.negate_src_addr = true;
  f.proto = L4Proto::Tcp;
  f.dst_port = "443";
  f.negate_dst_port = true;
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, f)});
  CHECK(
      s.find("-A KeenPbrTable -m set --match-set myset dst ! -s 192.168.1.0/24 "
             "-p tcp ! --dport 443 -j MARK --set-xmark 0x100/0xffffffff") !=
      std::string::npos);
}

TEST_CASE("build_ipt_script: drop rule with negated src_addr") {
  ProtoPortFilter f;
  f.src_addr = {"10.10.0.0/16"};
  f.negate_src_addr = true;
  auto s = T::build_ipt_script(false, {drop_rule("bl", false, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set bl dst ! -s 10.10.0.0/16 -j "
               "DROP") != std::string::npos);
}

// =============================================================================
// Multiple CIDR / port negation tests
// (expand_and_push emits one rule per CIDR; each carries the shared negate
// flag)
// =============================================================================

TEST_CASE(
    "build_ipt_script: two negated src_addrs → two rules each with ! -s") {
  // Simulate what expand_and_push produces for negate_src_addr + two CIDRs
  ProtoPortFilter f1;
  f1.src_addr = {"192.168.1.0/24"};
  f1.negate_src_addr = true;
  ProtoPortFilter f2;
  f2.src_addr = {"10.0.0.0/8"};
  f2.negate_src_addr = true;
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, f1),
                                       mark_rule("myset", false, 0x100, f2)});
  CHECK(s.find("! -s 192.168.1.0/24") != std::string::npos);
  CHECK(s.find("! -s 10.0.0.0/8") != std::string::npos);
  // Both are mark rules
  CHECK(s.find("! -s 192.168.1.0/24 -j MARK") != std::string::npos);
  CHECK(s.find("! -s 10.0.0.0/8 -j MARK") != std::string::npos);
}

TEST_CASE(
    "build_ipt_script: two negated dst_addrs → two rules each with ! -d") {
  ProtoPortFilter f1;
  f1.dst_addr = {"8.8.8.0/24"};
  f1.negate_dst_addr = true;
  ProtoPortFilter f2;
  f2.dst_addr = {"1.1.1.0/24"};
  f2.negate_dst_addr = true;
  auto s = T::build_ipt_script(
      false, {drop_rule("bl", false, f1), drop_rule("bl", false, f2)});
  CHECK(s.find("! -d 8.8.8.0/24") != std::string::npos);
  CHECK(s.find("! -d 1.1.1.0/24") != std::string::npos);
}

TEST_CASE("build_proto_port_fragment: negated src port list → -m multiport ! "
          "--sports 80,8080") {
  auto frag = T::build_proto_port_fragment("tcp", "80,8080", "", true, false);
  CHECK(frag == " -p tcp -m multiport ! --sports 80,8080");
}

TEST_CASE(
    "build_proto_port_fragment: negated src port range → ! --sport 8000:9000") {
  auto frag = T::build_proto_port_fragment("tcp", "8000-9000", "", true, false);
  CHECK(frag == " -p tcp ! --sport 8000:9000");
}

// =============================================================================
// Mixed negation documentation tests
// (current design: negation is per-list, determined by the first element)
// =============================================================================

TEST_CASE(
    "build_ipt_script: non-negated and negated src_addrs in separate rules") {
  // A non-negated CIDR and a negated CIDR produce independent rules — each can
  // match different traffic, so there is no contradiction.
  ProtoPortFilter fpos;
  fpos.src_addr = {"172.16.0.0/12"};
  ProtoPortFilter fneg;
  fneg.src_addr = {"10.0.0.0/8"};
  fneg.negate_src_addr = true;
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, fpos),
                                       mark_rule("myset", false, 0x100, fneg)});
  CHECK(s.find(" -s 172.16.0.0/12") != std::string::npos);
  CHECK(s.find("! -s 10.0.0.0/8") != std::string::npos);
}

// =============================================================================
// Static / dynamic set split tests
// =============================================================================

TEST_CASE("static set naming: kpbr4_ prefix, no timeout") {
  auto line = T::build_ipset_create_line("kpbr4_mylist", "inet", 0);
  CHECK(line == "create kpbr4_mylist hash:net family inet -exist\n");
}

TEST_CASE("dynamic set naming: kpbr4d_ prefix, no timeout when ttl_ms=0") {
  auto line = T::build_ipset_create_line("kpbr4d_mylist", "inet", 0);
  CHECK(line == "create kpbr4d_mylist hash:net family inet -exist\n");
}

TEST_CASE("dynamic set naming: kpbr4d_ prefix, with timeout when ttl_ms set") {
  auto line = T::build_ipset_create_line("kpbr4d_mylist", "inet", 3600);
  CHECK(line == "create kpbr4d_mylist hash:net family inet timeout 3600 -exist\n");
}

TEST_CASE("dynamic set naming: kpbr6d_ IPv6 with timeout") {
  auto line = T::build_ipset_create_line("kpbr6d_mylist", "inet6", 86400);
  CHECK(line == "create kpbr6d_mylist hash:net family inet6 timeout 86400 -exist\n");
}

TEST_CASE("dual-set mark rules: both static and dynamic sets get mark rules") {
  auto s = T::build_ipt_script(false, {mark_rule("kpbr4_mylist", false, 0x100),
                                       mark_rule("kpbr4d_mylist", false, 0x100)});
  CHECK(s.find("--match-set kpbr4_mylist dst -j MARK --set-xmark 0x100/0xffffffff") != std::string::npos);
  CHECK(s.find("--match-set kpbr4d_mylist dst -j MARK --set-xmark 0x100/0xffffffff") != std::string::npos);
}

TEST_CASE("dual-set drop rules: both static and dynamic sets get drop rules") {
  auto s = T::build_ipt_script(false, {drop_rule("kpbr4_mylist", false),
                                       drop_rule("kpbr4d_mylist", false)});
  CHECK(s.find("--match-set kpbr4_mylist dst -j DROP") != std::string::npos);
  CHECK(s.find("--match-set kpbr4d_mylist dst -j DROP") != std::string::npos);
}

TEST_CASE("dual-set IPv6 mark rules: kpbr6_ and kpbr6d_ both matched") {
  auto s = T::build_ipt_script(true, {mark_rule("kpbr6_mylist", true, 0x200),
                                      mark_rule("kpbr6d_mylist", true, 0x200)});
  CHECK(s.find("--match-set kpbr6_mylist dst -j MARK --set-xmark 0x200/0xffffffff") != std::string::npos);
  CHECK(s.find("--match-set kpbr6d_mylist dst -j MARK --set-xmark 0x200/0xffffffff") != std::string::npos);
}

// Helper for direct (no-set) mark rules
static Rule direct_mark_rule(bool ipv6, uint32_t fwmark, ProtoPortFilter filter = {}) {
  Rule r;
  r.set_name = "";
  r.ipv6 = ipv6;
  r.direct = true;
  r.action = Rule::Mark;
  r.fwmark = fwmark;
  r.filter = filter;
  return r;
}

// =============================================================================
// create_direct_mark_rule / build_ipt_script with direct=true tests
// =============================================================================

TEST_CASE("build_ipt_script: direct mark rule IPv4 UDP dst port 53") {
  ProtoPortFilter f;
  f.proto = L4Proto::Udp;
  f.dst_port = "53";
  f.dst_addr = {"10.8.0.1"};
  auto s = T::build_ipt_script(false, {direct_mark_rule(false, 0x10000, f)});
  // Must NOT contain --match-set
  CHECK(s.find("--match-set") == std::string::npos);
  // Must contain dst addr and port
  CHECK(s.find("-d 10.8.0.1") != std::string::npos);
  CHECK(s.find("--dport 53") != std::string::npos);
  CHECK(s.find("-j MARK --set-xmark 0x10000/0xffffffff") != std::string::npos);
}

TEST_CASE("build_ipt_script: direct mark rule IPv4 TCP dst port 53") {
  ProtoPortFilter f;
  f.proto = L4Proto::Tcp;
  f.dst_port = "53";
  f.dst_addr = {"10.8.0.1"};
  auto s = T::build_ipt_script(false, {direct_mark_rule(false, 0x10000, f)});
  CHECK(s.find("--match-set") == std::string::npos);
  CHECK(s.find("-d 10.8.0.1") != std::string::npos);
  CHECK(s.find("-p tcp --dport 53") != std::string::npos);
  CHECK(s.find("-j MARK --set-xmark 0x10000/0xffffffff") != std::string::npos);
}

TEST_CASE("build_ipt_script: direct mark rule has no set_name reference") {
  ProtoPortFilter f;
  f.proto = L4Proto::Udp;
  f.dst_addr = {"192.0.2.1"};
  auto s = T::build_ipt_script(false, {direct_mark_rule(false, 0x20000, f)});
  CHECK(s.find("--match-set") == std::string::npos);
  CHECK(s.find("-d 192.0.2.1") != std::string::npos);
}

namespace {

enum class PairwiseRuleMode {
  ListBacked,
  Direct,
};

enum class PairwiseAction {
  Mark,
  Drop,
  Pass,
};

struct ProtoVariant {
  const char *name;
  L4Proto proto;
};

enum class PortShape {
  Empty,
  Single,
  Multi,
  Range,
};

struct PortVariant {
  const char *name;
  PortShape shape;
  const char *spec;
  const char *iptables_spec;
  bool negated;
};

struct AddrVariant {
  const char *name;
  std::vector<std::string> addrs;
  bool negated;
};

struct PairwiseIptablesCase {
  std::string name;
  PairwiseRuleMode mode;
  PairwiseAction action;
  ProtoVariant proto;
  PortVariant src_port;
  PortVariant dst_port;
  AddrVariant src_addr;
  AddrVariant dst_addr;
};

constexpr std::array<ProtoVariant, 4> kProtoVariants{{
    {"any", L4Proto::Any},
    {"tcp", L4Proto::Tcp},
    {"udp", L4Proto::Udp},
    {"tcp_udp", L4Proto::TcpUdp},
}};

constexpr std::array<PortVariant, 7> kPortVariants{{
    {"empty", PortShape::Empty, "", "", false},
    {"single", PortShape::Single, "443", "443", false},
    {"multi", PortShape::Multi, "80,443", "80,443", false},
    {"range", PortShape::Range, "8000-9000", "8000:9000", false},
    {"neg_single", PortShape::Single, "53", "53", true},
    {"neg_multi", PortShape::Multi, "53,123", "53,123", true},
    {"neg_range", PortShape::Range, "10000-10010", "10000:10010", true},
}};

const std::array<AddrVariant, 5> kAddrVariants{{
    {"empty", {}, false},
    {"single", {"192.0.2.0/24"}, false},
    {"multi", {"192.0.2.0/24", "198.51.100.0/24"}, false},
    {"neg_single", {"203.0.113.0/24"}, true},
    {"neg_multi", {"203.0.113.0/24", "198.18.0.0/15"}, true},
}};

constexpr std::array<const char *, 2> kModeNames{{"list", "direct"}};
constexpr std::array<const char *, 3> kActionNames{{"mark", "drop", "pass"}};

using PairwiseIndex = std::array<size_t, 7>;

size_t selector_count(const PairwiseIptablesCase &tc) {
  size_t count = 0;
  count += tc.src_port.shape != PortShape::Empty ? 1 : 0;
  count += tc.dst_port.shape != PortShape::Empty ? 1 : 0;
  count += tc.src_addr.addrs.empty() ? 0 : 1;
  count += tc.dst_addr.addrs.empty() ? 0 : 1;
  return count;
}

bool has_negated_selector(const PairwiseIptablesCase &tc) {
  return tc.src_port.negated || tc.dst_port.negated || tc.src_addr.negated ||
         tc.dst_addr.negated;
}

bool has_positive_selector(const PairwiseIptablesCase &tc) {
  return (tc.src_port.shape != PortShape::Empty && !tc.src_port.negated) ||
         (tc.dst_port.shape != PortShape::Empty && !tc.dst_port.negated) ||
         (!tc.src_addr.addrs.empty() && !tc.src_addr.negated) ||
         (!tc.dst_addr.addrs.empty() && !tc.dst_addr.negated);
}

std::string pairwise_combo_name(const PairwiseIndex &idx) {
  std::ostringstream os;
  os << kModeNames[idx[0]] << "__" << kActionNames[idx[1]] << "__"
     << kProtoVariants[idx[2]].name << "__srcp_" << kPortVariants[idx[3]].name
     << "__dstp_" << kPortVariants[idx[4]].name << "__srca_"
     << kAddrVariants[idx[5]].name << "__dsta_" << kAddrVariants[idx[6]].name;
  return os.str();
}

FirewallRuleCriteria build_pairwise_filter(const PairwiseIptablesCase &tc) {
  FirewallRuleCriteria filter;
  filter.proto = tc.proto.proto;
  filter.src_port = tc.src_port.spec;
  filter.dst_port = tc.dst_port.spec;
  filter.src_addr = tc.src_addr.addrs;
  filter.dst_addr = tc.dst_addr.addrs;
  filter.negate_src_port = tc.src_port.negated;
  filter.negate_dst_port = tc.dst_port.negated;
  filter.negate_src_addr = tc.src_addr.negated;
  filter.negate_dst_addr = tc.dst_addr.negated;
  return filter;
}

std::string format_fwmark(uint32_t fwmark) {
  std::ostringstream os;
  os << "0x" << std::hex << std::nouppercase << fwmark;
  return os.str();
}

std::vector<L4Proto> expand_proto(L4Proto proto,
                                  const PortVariant &src_port,
                                  const PortVariant &dst_port) {
  if (proto == L4Proto::Any &&
      (src_port.shape != PortShape::Empty || dst_port.shape != PortShape::Empty)) {
    return {L4Proto::Tcp, L4Proto::Udp};
  }
  if (proto == L4Proto::TcpUdp) {
    return {L4Proto::Tcp, L4Proto::Udp};
  }
  return {proto};
}

std::string expected_proto_port_fragment(L4Proto proto,
                                         const PortVariant &src_port,
                                         const PortVariant &dst_port) {
  if (proto == L4Proto::Any && src_port.shape == PortShape::Empty &&
      dst_port.shape == PortShape::Empty) {
    return "";
  }

  std::string frag;
  if (proto != L4Proto::Any) {
    frag += " -p ";
    frag += l4_proto_name(proto);
  }

  const bool has_src = src_port.shape != PortShape::Empty;
  const bool has_dst = dst_port.shape != PortShape::Empty;
  const bool src_list = src_port.shape == PortShape::Multi;
  const bool dst_list = dst_port.shape == PortShape::Multi;

  if (has_src || has_dst) {
    if (src_list || dst_list) {
      if (src_list) {
        frag += " -m multiport";
        if (src_port.negated) frag += " !";
        frag += " --sports ";
        frag += src_port.iptables_spec;
      } else if (has_src) {
        if (src_port.negated) frag += " !";
        frag += " --sport ";
        frag += src_port.iptables_spec;
      }
      if (dst_list) {
        frag += " -m multiport";
        if (dst_port.negated) frag += " !";
        frag += " --dports ";
        frag += dst_port.iptables_spec;
      } else if (has_dst) {
        if (dst_port.negated) frag += " !";
        frag += " --dport ";
        frag += dst_port.iptables_spec;
      }
    } else {
      if (has_src) {
        if (src_port.negated) frag += " !";
        frag += " --sport ";
        frag += src_port.iptables_spec;
      }
      if (has_dst) {
        if (dst_port.negated) frag += " !";
        frag += " --dport ";
        frag += dst_port.iptables_spec;
      }
    }
  }

  return frag;
}

std::vector<std::string> expected_rule_lines(const PairwiseIptablesCase &tc,
                                             uint32_t fwmark) {
  std::vector<std::string> lines;
  const std::vector<std::string> src_addrs =
      tc.src_addr.addrs.empty() ? std::vector<std::string>{""}
                                : tc.src_addr.addrs;
  const std::vector<std::string> dst_addrs =
      tc.dst_addr.addrs.empty() ? std::vector<std::string>{""}
                                : tc.dst_addr.addrs;

  for (L4Proto proto : expand_proto(tc.proto.proto, tc.src_port, tc.dst_port)) {
    const std::string proto_port_frag =
        expected_proto_port_fragment(proto, tc.src_port, tc.dst_port);
    for (const auto &src_addr : src_addrs) {
      for (const auto &dst_addr : dst_addrs) {
        std::string prefix = "-A KeenPbrTable";
        if (tc.mode == PairwiseRuleMode::ListBacked) {
          prefix += " -m set --match-set pairwise_set dst";
        }

        if (!src_addr.empty()) {
          prefix += tc.src_addr.negated ? " ! -s " : " -s ";
          prefix += src_addr;
        }
        if (!dst_addr.empty()) {
          prefix += tc.dst_addr.negated ? " ! -d " : " -d ";
          prefix += dst_addr;
        }

        prefix += proto_port_frag;

        if (tc.action == PairwiseAction::Mark) {
          lines.push_back("[0:0] " + prefix + " -j MARK --set-xmark " + format_fwmark(fwmark) +
                          "/0xffffffff" +
                          "\n");
          lines.push_back(prefix + " -j RETURN\n");
        } else if (tc.action == PairwiseAction::Drop) {
          lines.push_back(prefix + " -j DROP\n");
        } else {
          lines.push_back(prefix + " -j RETURN\n");
        }
      }
    }
  }

  return lines;
}

std::vector<std::string> extract_rule_lines(const std::string &script) {
  std::vector<std::string> lines;
  std::istringstream input(script);
  std::string line;
  while (std::getline(input, line)) {
    if (line.rfind("-A KeenPbrTable", 0) == 0) {
      lines.push_back(line + "\n");
    }
  }
  return lines;
}

std::set<std::string> build_uncovered_pairs() {
  const std::array<size_t, 7> axis_sizes{
      kModeNames.size(),      kActionNames.size(), kProtoVariants.size(),
      kPortVariants.size(),   kPortVariants.size(), kAddrVariants.size(),
      kAddrVariants.size(),
  };

  std::set<std::string> uncovered;
  for (size_t a = 0; a < axis_sizes.size(); ++a) {
    for (size_t b = a + 1; b < axis_sizes.size(); ++b) {
      for (size_t va = 0; va < axis_sizes[a]; ++va) {
        for (size_t vb = 0; vb < axis_sizes[b]; ++vb) {
          uncovered.insert(std::to_string(a) + ":" + std::to_string(va) + "|" +
                           std::to_string(b) + ":" + std::to_string(vb));
        }
      }
    }
  }
  return uncovered;
}

std::vector<std::string> coverage_keys(const PairwiseIndex &idx) {
  std::vector<std::string> keys;
  for (size_t a = 0; a < idx.size(); ++a) {
    for (size_t b = a + 1; b < idx.size(); ++b) {
      keys.push_back(std::to_string(a) + ":" + std::to_string(idx[a]) + "|" +
                     std::to_string(b) + ":" + std::to_string(idx[b]));
    }
  }
  return keys;
}

std::vector<PairwiseIndex> generate_pairwise_indices() {
  std::vector<PairwiseIndex> all_combos;
  for (size_t mode = 0; mode < kModeNames.size(); ++mode) {
    for (size_t action = 0; action < kActionNames.size(); ++action) {
      for (size_t proto = 0; proto < kProtoVariants.size(); ++proto) {
        for (size_t src_port = 0; src_port < kPortVariants.size(); ++src_port) {
          for (size_t dst_port = 0; dst_port < kPortVariants.size(); ++dst_port) {
            for (size_t src_addr = 0; src_addr < kAddrVariants.size(); ++src_addr) {
              for (size_t dst_addr = 0; dst_addr < kAddrVariants.size(); ++dst_addr) {
                all_combos.push_back(
                    {mode, action, proto, src_port, dst_port, src_addr, dst_addr});
              }
            }
          }
        }
      }
    }
  }

  std::set<std::string> uncovered = build_uncovered_pairs();
  std::vector<PairwiseIndex> selected;
  std::set<std::string> seen;

  const std::vector<PairwiseIndex> seeds{
      {0, 0, 1, 0, 1, 0, 0},
      {1, 1, 2, 0, 3, 1, 0},
      {0, 2, 3, 5, 1, 3, 2},
      {1, 0, 1, 4, 2, 3, 1},
  };

  auto add_combo = [&](const PairwiseIndex &combo) {
    const std::string key = pairwise_combo_name(combo);
    if (!seen.insert(key).second) {
      return;
    }
    selected.push_back(combo);
    for (const auto &coverage : coverage_keys(combo)) {
      uncovered.erase(coverage);
    }
  };

  for (const auto &seed : seeds) {
    add_combo(seed);
  }

  while (!uncovered.empty()) {
    size_t best_score = 0;
    size_t best_index = 0;
    for (size_t i = 0; i < all_combos.size(); ++i) {
      if (seen.count(pairwise_combo_name(all_combos[i])) != 0) {
        continue;
      }
      size_t score = 0;
      for (const auto &coverage : coverage_keys(all_combos[i])) {
        score += uncovered.count(coverage);
      }
      if (score > best_score) {
        best_score = score;
        best_index = i;
      }
    }
    add_combo(all_combos[best_index]);
  }

  return selected;
}

std::vector<PairwiseIptablesCase> generate_pairwise_cases() {
  std::vector<PairwiseIptablesCase> cases;
  for (const auto &idx : generate_pairwise_indices()) {
    cases.push_back({
        pairwise_combo_name(idx),
        idx[0] == 0 ? PairwiseRuleMode::ListBacked : PairwiseRuleMode::Direct,
        idx[1] == 0 ? PairwiseAction::Mark
                    : (idx[1] == 1 ? PairwiseAction::Drop : PairwiseAction::Pass),
        kProtoVariants[idx[2]],
        kPortVariants[idx[3]],
        kPortVariants[idx[4]],
        kAddrVariants[idx[5]],
        kAddrVariants[idx[6]],
    });
  }
  return cases;
}

bool pairwise_is_complete(const std::vector<PairwiseIndex> &cases) {
  std::set<std::string> uncovered = build_uncovered_pairs();
  for (const auto &combo : cases) {
    for (const auto &coverage : coverage_keys(combo)) {
      uncovered.erase(coverage);
    }
  }
  return uncovered.empty();
}

} // namespace
