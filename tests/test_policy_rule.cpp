#include <doctest/doctest.h>

#include "../src/routing/policy_rule.hpp"

#include <algorithm>
#include <functional>
#include <iterator>
#include <netinet/in.h>
#include <stdexcept>
#include <vector>

namespace keen_pbr3 {
namespace {

class FakeRuleNetlink : public RuleNetlinkOperations {
public:
    RuleAddResult add_rule_for_family(const RuleSpec& spec, int family) override {
        added.push_back(family);
        added_specs.push_back(spec);
        if (add_hook) {
            return add_hook(spec, family);
        }
        if (family == failing_family) {
            throw std::runtime_error("injected failure");
        }
        if (family == existing_family || has_live(spec, family)) {
            add_live(spec, family);
            return RuleAddResult::AlreadyPresent;
        }
        add_live(spec, family);
        return RuleAddResult::Created;
    }

    void delete_rule_for_family(const RuleSpec& spec, int family) override {
        deleted.push_back(family);
        deleted_specs.push_back(spec);
        erase_live(spec, family);
    }

    std::vector<DumpedRule> dump_policy_rules(int family = 0) override {
        if (family == 0) {
            return live;
        }
        std::vector<DumpedRule> result;
        std::copy_if(
            live.begin(),
            live.end(),
            std::back_inserter(result),
            [family](const DumpedRule& rule) {
                return rule.family == family;
            });
        return result;
    }

    void add_live(const RuleSpec& spec, int family) {
        if (has_live(spec, family)) {
            return;
        }
        live.push_back({
            spec.priority,
            spec.fwmark,
            spec.fwmask,
            spec.table,
            family,
        });
    }

    void erase_live(const RuleSpec& spec, int family) {
        live.erase(
            std::remove_if(
                live.begin(),
                live.end(),
                [&](const DumpedRule& rule) {
                    return matches(rule, spec, family);
                }),
            live.end());
    }

    int failing_family{0};
    int existing_family{0};
    std::function<RuleAddResult(const RuleSpec&, int)> add_hook;
    std::vector<int> added;
    std::vector<int> deleted;
    std::vector<RuleSpec> added_specs;
    std::vector<RuleSpec> deleted_specs;
    std::vector<DumpedRule> live;

private:
    static bool matches(const DumpedRule& live_rule,
                        const RuleSpec& spec,
                        int family) {
        return live_rule.priority == spec.priority &&
               live_rule.fwmark == spec.fwmark &&
               live_rule.fwmask == spec.fwmask &&
               live_rule.table == spec.table &&
               live_rule.family == family;
    }

    bool has_live(const RuleSpec& spec, int family) const {
        return std::any_of(
            live.begin(),
            live.end(),
            [&](const DumpedRule& rule) {
                return matches(rule, spec, family);
            });
    }
};

RuleSpec dual_stack_rule() {
    RuleSpec rule;
    rule.fwmark = 10;
    rule.table = 110;
    rule.priority = 10010;
    return rule;
}

RuleSpec ipv4_rule(std::uint32_t fwmark,
                   std::uint32_t table,
                   std::uint32_t priority) {
    RuleSpec rule;
    rule.fwmark = fwmark;
    rule.table = table;
    rule.priority = priority;
    rule.family = AF_INET;
    return rule;
}

} // namespace

TEST_CASE("PolicyRuleManager rolls back IPv4 when IPv6 add fails") {
    FakeRuleNetlink netlink;
    netlink.failing_family = AF_INET6;
    PolicyRuleManager rules(netlink);

    CHECK_THROWS(rules.add(dual_stack_rule()));
    CHECK(rules.size() == 0);
    REQUIRE(netlink.deleted.size() == 1);
    CHECK(netlink.deleted.front() == AF_INET);
}

TEST_CASE("PolicyRuleManager does not delete a pre-existing rule during rollback") {
    FakeRuleNetlink netlink;
    netlink.existing_family = AF_INET;
    netlink.failing_family = AF_INET6;
    PolicyRuleManager rules(netlink);

    CHECK_THROWS(rules.add(dual_stack_rule()));
    CHECK(netlink.deleted.empty());
}

TEST_CASE("PolicyRuleManager clears only concrete rules it created") {
    FakeRuleNetlink netlink;
    netlink.existing_family = AF_INET6;
    PolicyRuleManager rules(netlink);
    rules.add(dual_stack_rule());
    rules.clear();

    REQUIRE(netlink.deleted.size() == 1);
    CHECK(netlink.deleted.front() == AF_INET);
}

TEST_CASE("PolicyRuleManager reconciliation leaves an identical plan untouched") {
    FakeRuleNetlink netlink;
    PolicyRuleManager rules(netlink);
    const auto rule = dual_stack_rule();
    rules.add(rule);
    netlink.added.clear();
    netlink.deleted.clear();

    rules.reconcile({rule});

    CHECK(netlink.added.empty());
    CHECK(netlink.deleted.empty());
}

TEST_CASE("PolicyRuleManager failed reconcile keeps the installed prefix and obsolete rules") {
    FakeRuleNetlink netlink;
    PolicyRuleManager rules(netlink);
    const auto old_first = ipv4_rule(10, 110, 10010);
    const auto old_second = ipv4_rule(20, 120, 10020);
    const auto new_first = ipv4_rule(30, 130, 10030);
    const auto failing = ipv4_rule(40, 140, 10040);
    const auto never_attempted = ipv4_rule(50, 150, 10050);

    rules.add(old_first);
    rules.add(old_second);
    netlink.added.clear();
    netlink.added_specs.clear();
    netlink.add_hook = [&](const RuleSpec& spec, int) {
        if (spec.priority == failing.priority) {
            throw std::runtime_error("injected batch failure");
        }
        netlink.add_live(spec, spec.family);
        return RuleAddResult::Created;
    };

    CHECK_THROWS_WITH(
        rules.reconcile({new_first, failing, never_attempted}),
        "injected batch failure");

    REQUIRE(netlink.added_specs.size() == 2);
    CHECK(netlink.added_specs[0].priority == new_first.priority);
    CHECK(netlink.added_specs[1].priority == failing.priority);
    CHECK(netlink.deleted.empty());
    const auto installed = rules.get_rules();
    REQUIRE(installed.size() == 3);
    const auto contains_priority = [&](const std::uint32_t priority) {
        return std::any_of(
            installed.begin(), installed.end(), [&](const RuleSpec& spec) {
                return spec.priority == priority;
            });
    };
    CHECK(contains_priority(old_first.priority));
    CHECK(contains_priority(old_second.priority));
    CHECK(contains_priority(new_first.priority));

    // The successful prefix is intentionally not rolled back.  Shutdown
    // cleanup still owns it and removes all owned rules in reverse order.
    netlink.add_hook = {};
    rules.clear();

    REQUIRE(netlink.deleted_specs.size() == 3);
    CHECK(netlink.deleted_specs[0].priority == new_first.priority);
    CHECK(netlink.deleted_specs[1].priority == old_second.priority);
    CHECK(netlink.deleted_specs[2].priority == old_first.priority);
}

TEST_CASE("PolicyRuleManager adopts desired state without claiming ownership") {
    FakeRuleNetlink netlink;
    PolicyRuleManager rules(netlink);

    rules.adopt_desired({dual_stack_rule()});
    rules.clear();

    CHECK(netlink.deleted.empty());
}

TEST_CASE("PolicyRuleManager restores a vanished IPv4 rule without claiming live IPv6") {
    FakeRuleNetlink netlink;
    const auto rule = dual_stack_rule();
    netlink.add_live(rule, AF_INET6);
    PolicyRuleManager rules(netlink);
    rules.adopt_desired({rule});

    rules.reconcile({rule});

    REQUIRE(netlink.added.size() == 1);
    CHECK(netlink.added.front() == AF_INET);

    rules.clear();
    REQUIRE(netlink.deleted.size() == 1);
    CHECK(netlink.deleted.front() == AF_INET);
}

TEST_CASE("PolicyRuleManager restores a vanished IPv6 rule without touching live IPv4") {
    FakeRuleNetlink netlink;
    const auto rule = dual_stack_rule();
    netlink.add_live(rule, AF_INET);
    PolicyRuleManager rules(netlink);
    rules.adopt_desired({rule});

    rules.reconcile({rule});

    REQUIRE(netlink.added.size() == 1);
    CHECK(netlink.added.front() == AF_INET6);

    rules.clear();
    REQUIRE(netlink.deleted.size() == 1);
    CHECK(netlink.deleted.front() == AF_INET6);
}

TEST_CASE("PolicyRuleManager leaves complete foreign live state unowned") {
    FakeRuleNetlink netlink;
    const auto rule = dual_stack_rule();
    netlink.add_live(rule, AF_INET);
    netlink.add_live(rule, AF_INET6);
    PolicyRuleManager rules(netlink);
    rules.adopt_desired({rule});

    rules.reconcile({rule});
    rules.clear();

    CHECK(netlink.added.empty());
    CHECK(netlink.deleted.empty());
}

TEST_CASE("PolicyRuleManager keeps owned IPv4 while expanding to dual stack") {
    FakeRuleNetlink netlink;
    RuleSpec ipv4 = dual_stack_rule();
    ipv4.family = AF_INET;
    const RuleSpec dual_stack = dual_stack_rule();
    PolicyRuleManager rules(netlink);

    rules.add(ipv4);
    REQUIRE(netlink.live.size() == 1);

    rules.reconcile({dual_stack});

    CHECK(std::any_of(
        netlink.live.begin(),
        netlink.live.end(),
        [&](const DumpedRule& rule) {
            return rule.family == AF_INET &&
                   rule.fwmark == dual_stack.fwmark;
        }));
    CHECK(std::any_of(
        netlink.live.begin(),
        netlink.live.end(),
        [&](const DumpedRule& rule) {
            return rule.family == AF_INET6 &&
                   rule.fwmark == dual_stack.fwmark;
        }));
    CHECK(netlink.deleted.empty());

    rules.clear();
    CHECK(netlink.live.empty());
}

TEST_CASE("PolicyRuleManager removes only IPv6 while narrowing to IPv4") {
    FakeRuleNetlink netlink;
    const RuleSpec dual_stack = dual_stack_rule();
    RuleSpec ipv4 = dual_stack;
    ipv4.family = AF_INET;
    PolicyRuleManager rules(netlink);

    rules.add(dual_stack);
    REQUIRE(netlink.live.size() == 2);

    rules.reconcile({ipv4});

    REQUIRE(netlink.live.size() == 1);
    CHECK(netlink.live.front().family == AF_INET);
    REQUIRE(netlink.deleted.size() == 1);
    CHECK(netlink.deleted.front() == AF_INET6);

    rules.clear();
    CHECK(netlink.live.empty());
}

TEST_CASE("PolicyRuleManager removes a corroborated stale mark generation") {
    FakeRuleNetlink netlink;
    const auto desired = ipv4_rule(0x50000, 155, 155);
    const auto stale = ipv4_rule(0x50000, 152, 152);
    netlink.add_live(desired, AF_INET);
    netlink.add_live(stale, AF_INET);
    PolicyRuleManager rules(netlink);
    rules.adopt_desired({desired});

    rules.remove_orphaned_generated({desired}, {152, 155});

    REQUIRE(netlink.deleted_specs.size() == 1);
    CHECK(netlink.deleted_specs.front().table == stale.table);
    REQUIRE(netlink.live.size() == 1);
    CHECK(netlink.live.front().table == desired.table);
}

TEST_CASE("PolicyRuleManager preserves a stale-looking rule without route evidence") {
    FakeRuleNetlink netlink;
    const auto desired = ipv4_rule(0x50000, 155, 155);
    const auto ambiguous = ipv4_rule(0x50000, 152, 152);
    netlink.add_live(ambiguous, AF_INET);
    PolicyRuleManager rules(netlink);

    rules.remove_orphaned_generated({desired}, {155});

    CHECK(netlink.deleted_specs.empty());
    REQUIRE(netlink.live.size() == 1);
    CHECK(netlink.live.front().table == ambiguous.table);
}

TEST_CASE("PolicyRuleManager preserves non-generated rule shapes") {
    FakeRuleNetlink netlink;
    const auto desired = ipv4_rule(0x50000, 155, 155);
    auto foreign_priority = ipv4_rule(0x50000, 152, 10052);
    auto foreign_mask = ipv4_rule(0x50000, 152, 152);
    foreign_mask.fwmask = 0xFFFF0000;
    netlink.add_live(foreign_priority, AF_INET);
    netlink.add_live(foreign_mask, AF_INET);
    PolicyRuleManager rules(netlink);

    rules.remove_orphaned_generated({desired}, {152, 155});

    CHECK(netlink.deleted_specs.empty());
    CHECK(netlink.live.size() == 2);
}

} // namespace keen_pbr3
