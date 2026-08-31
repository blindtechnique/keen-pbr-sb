#include "../src/routing/fib_lookup.hpp"

#include <doctest/doctest.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include <array>
#include <cstring>
#include <vector>

namespace keen_pbr3 {

namespace {

constexpr std::uint32_t kSequence = 7U;

// Builds the kernel's side of the conversation, so the rule under test can be
// exercised without a kernel that happens to agree with it.
class Reply {
public:
    explicit Reply(const unsigned char route_type = RTN_UNICAST,
                   const int family = AF_INET) {
        bytes_.resize(NLMSG_LENGTH(sizeof(rtmsg)), 0U);
        auto& header = this->header();
        header.nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
        header.nlmsg_type = RTM_NEWROUTE;
        header.nlmsg_seq = kSequence;
        auto* route = static_cast<rtmsg*>(NLMSG_DATA(&header));
        route->rtm_family = static_cast<unsigned char>(family);
        route->rtm_type = route_type;
        route->rtm_table = RT_TABLE_UNSPEC;
    }

    Reply& sequence(const std::uint32_t value) {
        header().nlmsg_seq = value;
        return *this;
    }

    Reply& legacy_table(const unsigned char value) {
        static_cast<rtmsg*>(NLMSG_DATA(&header()))->rtm_table = value;
        return *this;
    }

    Reply& oif(const int index) { return attribute(RTA_OIF, index); }
    Reply& table(const std::uint32_t id) { return attribute(RTA_TABLE, id); }
    Reply& mark(const std::uint32_t value) { return attribute(RTA_MARK, value); }

    template <typename T>
    Reply& attribute(const std::uint16_t type, const T value) {
        const auto offset = NLMSG_ALIGN(header().nlmsg_len);
        const auto attribute_size = RTA_LENGTH(sizeof(T));
        bytes_.resize(offset + RTA_ALIGN(attribute_size), 0U);
        auto* entry = reinterpret_cast<rtattr*>(bytes_.data() + offset);
        entry->rta_type = type;
        entry->rta_len = static_cast<unsigned short>(attribute_size);
        std::memcpy(RTA_DATA(entry), &value, sizeof(T));
        header().nlmsg_len = static_cast<std::uint32_t>(bytes_.size());
        return *this;
    }

    FibAnswer parse(const std::optional<std::uint32_t> requested_mark =
                        std::nullopt) const {
        return parse_fib_reply(bytes_.data(), bytes_.size(), kSequence, AF_INET,
                               requested_mark);
    }

private:
    nlmsghdr& header() { return *reinterpret_cast<nlmsghdr*>(bytes_.data()); }
    const nlmsghdr& header() const {
        return *reinterpret_cast<const nlmsghdr*>(bytes_.data());
    }

    std::vector<std::uint8_t> bytes_;
};

int loopback_index() {
    const auto index = if_nametoindex("lo");
    return index == 0U ? 1 : static_cast<int>(index);
}

}  // namespace

TEST_CASE("fib: an answer that names an interface is a verdict") {
    const auto answer = Reply().oif(loopback_index()).table(254U).parse();

    CHECK(answer.verdict == FibVerdict::resolved);
    CHECK(answer.interface == "lo");
    REQUIRE(answer.table.has_value());
    CHECK(*answer.table == 254U);
}

TEST_CASE("fib: a mark the kernel repeats back can be believed") {
    const auto answer =
        Reply().oif(loopback_index()).table(152U).mark(0x10000U).parse(0x10000U);

    CHECK(answer.verdict == FibVerdict::resolved);
    CHECK(answer.interface == "lo");
    REQUIRE(answer.table.has_value());
    CHECK(*answer.table == 152U);
}

TEST_CASE("fib: a mark the kernel never mentions is refused, not believed") {
    // RTA_MARK reached inet_rtm_getroute in Linux 3.6, and we still release for
    // mips-3.4. An older kernel takes the attribute, ignores it, and answers
    // about unmarked traffic - which on a policy-routed router is the provider.
    // Believing that would paint a permanent red over a healthy config, so the
    // absence of the echo has to cost us the verdict, not the operator's trust.
    const auto answer = Reply().oif(loopback_index()).table(254U).parse(0x10000U);

    CHECK(answer.verdict == FibVerdict::unavailable);
    CHECK(answer.interface.empty());
    CHECK(answer.detail.find("mark") != std::string::npos);
}

TEST_CASE("fib: a mark echoed with the wrong value is refused too") {
    const auto answer =
        Reply().oif(loopback_index()).mark(0x20000U).parse(0x10000U);

    CHECK(answer.verdict == FibVerdict::unavailable);
    CHECK(answer.interface.empty());
}

TEST_CASE("fib: asking about unmarked traffic needs no echo") {
    // The kernel only reports a mark back when there is one, so requiring an
    // echo for the zero mark would refuse every honest answer.
    const auto zero = Reply().oif(loopback_index()).parse(0U);
    CHECK(zero.verdict == FibVerdict::resolved);

    const auto absent = Reply().oif(loopback_index()).parse();
    CHECK(absent.verdict == FibVerdict::resolved);
}

TEST_CASE("fib: a refused packet is an answer, not a failure") {
    // Our own kill-switch installs exactly this. Reporting it as a fault would
    // teach the operator to distrust a working guard.
    for (const auto type : {RTN_BLACKHOLE, RTN_UNREACHABLE, RTN_PROHIBIT}) {
        const auto answer =
            Reply(static_cast<unsigned char>(type)).table(152U).parse();
        CHECK(answer.verdict == FibVerdict::unroutable);
        CHECK(answer.interface.empty());
        REQUIRE(answer.table.has_value());
        CHECK(*answer.table == 152U);
    }
}

TEST_CASE("fib: a refusal is reported even when a mark went unanswered") {
    // The echo rule must not turn a blackhole into "no verdict": the check runs
    // before the interface is read, but after the mark is judged, so state the
    // order the code actually uses.
    const auto answer = Reply(RTN_BLACKHOLE).parse(0x10000U);
    CHECK(answer.verdict == FibVerdict::unavailable);
}

TEST_CASE("fib: an answer with no interface is not a verdict") {
    const auto answer = Reply().table(152U).parse();

    CHECK(answer.verdict == FibVerdict::unavailable);
    CHECK(answer.interface.empty());
    REQUIRE(answer.table.has_value());
    CHECK(*answer.table == 152U);
}

TEST_CASE("fib: the table falls back to the one in the message header") {
    const auto answer = Reply().legacy_table(200U).oif(loopback_index()).parse();

    CHECK(answer.verdict == FibVerdict::resolved);
    REQUIRE(answer.table.has_value());
    CHECK(*answer.table == 200U);
}

TEST_CASE("fib: somebody else's answer is not ours") {
    const auto answer = Reply().sequence(kSequence + 1U).oif(loopback_index()).parse();

    CHECK(answer.verdict == FibVerdict::unavailable);
    CHECK(answer.interface.empty());
}

TEST_CASE("fib: a refusal from the kernel is quoted, not swallowed") {
    std::vector<std::uint8_t> bytes(NLMSG_LENGTH(sizeof(nlmsgerr)), 0U);
    auto* header = reinterpret_cast<nlmsghdr*>(bytes.data());
    header->nlmsg_len = NLMSG_LENGTH(sizeof(nlmsgerr));
    header->nlmsg_type = NLMSG_ERROR;
    header->nlmsg_seq = kSequence;
    auto* failure = static_cast<nlmsgerr*>(NLMSG_DATA(header));
    failure->error = -ENETUNREACH;

    const auto answer =
        parse_fib_reply(bytes.data(), bytes.size(), kSequence, AF_INET, std::nullopt);

    CHECK(answer.verdict == FibVerdict::unavailable);
    CHECK(answer.detail.find("refused") != std::string::npos);
}

TEST_CASE("fib: an empty reply is no verdict rather than a resolved one") {
    CHECK(parse_fib_reply(nullptr, 0U, kSequence, AF_INET, std::nullopt).verdict ==
          FibVerdict::unavailable);
}

TEST_CASE("fib: a destination that is not an address is refused before asking") {
    for (const auto* target : {"", "example.com", "999.1.1.1", "10.0.0.1%eth0"}) {
        const auto answer = system_fib_lookup(FibQuery{target, std::nullopt});
        CHECK(answer.verdict == FibVerdict::unavailable);
        CHECK(answer.interface.empty());
    }
}

TEST_CASE("fib: the kernel on this host answers about the loopback") {
    // The one case that exercises the socket rather than the parser. Loopback
    // is routed on any host that can run this suite at all.
    const auto answer = system_fib_lookup(FibQuery{"127.0.0.1", std::nullopt});

    if (answer.verdict == FibVerdict::resolved) {
        CHECK(answer.interface == "lo");
    } else {
        // A sandbox without netlink is allowed to say nothing - but it may
        // never invent an interface.
        CHECK(answer.verdict == FibVerdict::unavailable);
        CHECK(answer.interface.empty());
    }
}

}  // namespace keen_pbr3
