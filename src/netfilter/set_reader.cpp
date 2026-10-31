#include "set_reader.hpp"
#include "uapi_compat.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <algorithm>

namespace keen_pbr3::nfnl {
std::optional<bool> SetMembershipReader::contains(const std::string& set, const std::string& ip,
                                                std::chrono::steady_clock::time_point deadline) {
    if (!transport_ || set.empty() || set.size() > 255 ||
        set.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != std::string::npos) return {};
    std::array<uint8_t, 16> address{};
    const bool v6 = ip.find(':') != std::string::npos;
    if (inet_pton(v6 ? AF_INET6 : AF_INET, ip.c_str(), address.data()) != 1) return {};
    const auto transact = [&](MsgBuilder& b, uint32_t seq, uint16_t reply_type, bool& data) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0) return ETIMEDOUT;
        int ack = -1;
        bool malformed = false;
        const int err = transport_->transact(b.data(), b.size(), seq, seq, static_cast<int>(std::min<int64_t>(left, 150)),
            [&](const MsgView& msg) {
                if (msg.seq != seq || msg.type != reply_type || msg.family != NFPROTO_INET) { malformed = true; return; }
                // A successful targeted NFT GET must carry a well-formed reply,
                // never just the generic zero ACK used by mutating requests.
                bool table_seen = false, set_seen = false, element_seen = false;
                const bool get_set = reply_type == ((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSET);
                const auto text_is = [](const Attr& a, const std::string& expected) {
                    return a.payload.size() == expected.size() + 1 &&
                        std::equal(expected.begin(), expected.end(), a.payload.data()) && a.payload.data()[expected.size()] == 0;
                };
                const bool parsed = for_each_attr(msg.attrs, [&](const Attr& a) {
                    if (a.type == (get_set ? int(NFTA_SET_TABLE) : int(NFTA_SET_ELEM_LIST_TABLE))) {
                        if (table_seen || !text_is(a, "KeenPbrTable")) malformed = true;
                        table_seen = true;
                    } else if (a.type == (get_set ? int(NFTA_SET_NAME) : int(NFTA_SET_ELEM_LIST_SET))) {
                        if (set_seen || !text_is(a, set)) malformed = true;
                        set_seen = true;
                    } else if (!get_set && a.type == NFTA_SET_ELEM_LIST_ELEMENTS) {
                        if (!for_each_attr(a.payload, [&](const Attr& entry) {
                            if (entry.type != NFTA_LIST_ELEM) return true;
                            if (!for_each_attr(entry.payload, [&](const Attr& field) {
                                if (field.type == NFTA_SET_ELEM_KEY && !for_each_attr(field.payload, [&](const Attr& key) {
                                    if (key.type == NFTA_DATA_VALUE && key.payload.size() == (v6 ? 16U : 4U)) element_seen = true;
                                    return true;
                                })) malformed = true;
                                return true;
                            })) malformed = true;
                            return true;
                        })) malformed = true;
                    }
                    return true;
                });
                if (!parsed || !table_seen || !set_seen || (!get_set && !element_seen)) malformed = true;
                else data = true;
            }, [&](uint32_t id, int code) { if (id == seq && ack == -1) ack = code; else malformed = true; });
        if (malformed || ack < 0) return EPROTO;
        return err != 0 ? err : ack;
    };
    MsgBuilder b;
    const auto seq = transport_->next_seq();
    if (!nftables_) {
        b.begin((NFNL_SUBSYS_IPSET << 8) | IPSET_CMD_TEST, NLM_F_REQUEST | NLM_F_ACK, seq, NFPROTO_IPV4, 0);
        b.put_u8(IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL_MIN);
        b.put_strz(IPSET_ATTR_SETNAME, set);
        const auto data = b.nest_begin(IPSET_ATTR_DATA);
        const auto nested_ip = b.nest_begin(IPSET_ATTR_IP);
        b.put((v6 ? IPSET_ATTR_IPADDR_IPV6 : IPSET_ATTR_IPADDR_IPV4) | NLA_F_NET_BYTEORDER, address.data(), v6 ? 16 : 4);
        b.nest_end(nested_ip); b.nest_end(data); b.end();
        bool data_seen = false;
        const int err = transact(b, seq, 0, data_seen);
        if (err == 0) return true;
        if (err == IPSET_ERR_EXIST) return false; // TEST's explicit not-in-set result
        return {};
    }
    b.begin((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETSETELEM, NLM_F_REQUEST | NLM_F_ACK, seq, NFPROTO_INET, 0);
    b.put_strz(NFTA_SET_ELEM_LIST_TABLE, "KeenPbrTable");
    b.put_strz(NFTA_SET_ELEM_LIST_SET, set);
    const auto elems = b.nest_begin(NFTA_SET_ELEM_LIST_ELEMENTS);
    const auto elem = b.nest_begin(NFTA_LIST_ELEM);
    const auto key = b.nest_begin(NFTA_SET_ELEM_KEY);
    b.put(NFTA_DATA_VALUE, address.data(), v6 ? 16 : 4);
    b.nest_end(key); b.nest_end(elem); b.nest_end(elems); b.end();
    bool data = false;
    const int err = transact(b, seq, (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM, data);
    if (err == 0) return data ? std::optional<bool>{true} : std::nullopt;
    if (err != ENOENT) return {};
    // ENOENT alone may mean that the table/set vanished, not that the address
    // is absent. Establish that the exact committed set still exists.
    b.clear();
    const auto set_seq = transport_->next_seq();
    b.begin((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETSET, NLM_F_REQUEST | NLM_F_ACK, set_seq, NFPROTO_INET, 0);
    b.put_strz(NFTA_SET_TABLE, "KeenPbrTable"); b.put_strz(NFTA_SET_NAME, set); b.end();
    data = false;
    const int set_err = transact(b, set_seq, (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSET, data);
    return set_err == 0 && data ? std::optional<bool>{false} : std::nullopt;
}
} // namespace keen_pbr3::nfnl
