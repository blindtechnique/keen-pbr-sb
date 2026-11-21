#include <doctest/doctest.h>
#include "../src/netfilter/set_reader.hpp"
#include "../src/netfilter/uapi_compat.hpp"
#include <cerrno>
#include <deque>

using namespace keen_pbr3;
using namespace keen_pbr3::nfnl;
namespace {
struct ReadTransport final : SetWriterTransport {
    struct Reply { int err{0}; bool data{false}; bool ack{true}; bool wrong_name{false}; };
    std::deque<Reply> replies;
    unsigned calls{}, seq{};
    uint32_t next_seq() override { return ++seq; }
    int transact(const uint8_t* request, size_t size, uint32_t first, uint32_t last, int timeout,
                 const std::function<void(const MsgView&)>& on_message,
                 const std::function<void(uint32_t,int)>& on_ack) override {
        ++calls; CHECK(first == last); CHECK(timeout > 0); CHECK(timeout <= 150);
        uint16_t type = 0;
        REQUIRE(for_each_msg(ByteView(request, size), [&](const MsgView& msg) {
            type = msg.type & 255;
            CHECK((msg.flags & NLM_F_CREATE) == 0);
            CHECK((msg.flags & NLM_F_DUMP) == 0);
            return true;
        }));
        REQUIRE_FALSE(replies.empty()); auto reply = replies.front(); replies.pop_front();
        if (reply.data) {
            MsgBuilder b;
            const bool get_set = type == NFT_MSG_GETSET;
            b.begin((NFNL_SUBSYS_NFTABLES << 8) | (get_set ? NFT_MSG_NEWSET : NFT_MSG_NEWSETELEM), 0, first, NFPROTO_INET, 0);
            b.put_strz(get_set ? int(NFTA_SET_TABLE) : int(NFTA_SET_ELEM_LIST_TABLE), "KeenPbrTable");
            b.put_strz(get_set ? int(NFTA_SET_NAME) : int(NFTA_SET_ELEM_LIST_SET), reply.wrong_name ? "wrong" : "test");
            if (!get_set) {
                const auto elements = b.nest_begin(NFTA_SET_ELEM_LIST_ELEMENTS);
                const auto element = b.nest_begin(NFTA_LIST_ELEM);
                const auto key = b.nest_begin(NFTA_SET_ELEM_KEY);
                const uint8_t addr[]{203,0,113,5}; b.put(NFTA_DATA_VALUE, addr, 4);
                b.nest_end(key); b.nest_end(element); b.nest_end(elements);
            }
            b.end(); CHECK(for_each_msg(ByteView(b.data(), b.size()), [&](const MsgView& m) { on_message(m); return true; }));
        }
        if (reply.ack) on_ack(first, reply.err);
        return reply.err;
    }
};
}
TEST_CASE("set membership: ipset TEST distinguishes absence from missing set or errors") {
    for (int error : {0, int(IPSET_ERR_EXIST), ENOENT, EACCES, EINVAL, ETIMEDOUT, ENOBUFS}) {
        CAPTURE(error);
        auto transport = std::make_unique<ReadTransport>(); transport->replies.push_back({error});
        SetMembershipReader reader(false, std::move(transport));
        const auto found = reader.contains("test", "203.0.113.5", std::chrono::steady_clock::now() + std::chrono::seconds(1));
        if (!error) CHECK(found == std::optional<bool>{true});
        else if (error == IPSET_ERR_EXIST) CHECK(found == std::optional<bool>{false});
        else CHECK_FALSE(found.has_value());
    }
}
TEST_CASE("set membership: nft needs target data as well as ACK") {
    auto transport = std::make_unique<ReadTransport>();
    ReadTransport::Reply reply;
    SUBCASE("valid") { reply.data = true; }
    SUBCASE("ACK only") {}
    SUBCASE("data without ACK") { reply.data = true; reply.ack = false; }
    SUBCASE("different target") { reply.data = true; reply.wrong_name = true; }
    const bool expected = reply.data && reply.ack && !reply.wrong_name;
    transport->replies.push_back(reply); SetMembershipReader reader(true, std::move(transport));
    auto found = reader.contains("test", "203.0.113.5", std::chrono::steady_clock::now() + std::chrono::seconds(1));
    if (expected) CHECK(found == std::optional<bool>{true}); else CHECK_FALSE(found.has_value());
}
TEST_CASE("set membership: nft ENOENT must prove set still exists") {
    auto transport = std::make_unique<ReadTransport>(); transport->replies.push_back({ENOENT});
    ReadTransport::Reply set;
    SUBCASE("exists") { set.data = true; }
    SUBCASE("missing") { set.err = ENOENT; }
    SUBCASE("unreadable") { set.err = EACCES; }
    SUBCASE("incomplete") {}
    transport->replies.push_back(set); SetMembershipReader reader(true, std::move(transport));
    const auto found = reader.contains("test", "203.0.113.5", std::chrono::steady_clock::now() + std::chrono::seconds(1));
    if (set.data) CHECK(found == std::optional<bool>{false}); else CHECK_FALSE(found.has_value());
}
TEST_CASE("set membership: invalid selectors and elapsed budget issue no I/O") {
    auto transport = std::make_unique<ReadTransport>(); auto* raw = transport.get();
    SetMembershipReader reader(false, std::move(transport));
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    CHECK_FALSE(reader.contains("test", "203.0.113.5/24", deadline).has_value());
    CHECK_FALSE(reader.contains("bad set", "203.0.113.5", deadline).has_value());
    CHECK_FALSE(reader.contains("test", "203.0.113.5", {}).has_value()); CHECK(raw->calls == 0);
}
