// NFLOG-only subset of upstream test_nfnetfilter_wrappers.cpp (413331c).
#include <doctest/doctest.h>
#include "../src/netfilter/nflog.hpp"
#include "../src/netfilter/uapi_compat.hpp"
#include <linux/if_ether.h>
#include <cstring>
using namespace keen_pbr3;
using namespace keen_pbr3::nfnl;
namespace {
MsgView one_message(const MsgBuilder& builder) {
    MsgView result;
    REQUIRE(for_each_msg(ByteView(builder.data(), builder.size()), [&](const MsgView& message) {
        result = message;
        return false;
    }));
    return result;
}

}
TEST_CASE("nflog: config uses scoped group and copy range") {
    NfLogOptions options;
    options.group = 9054;
    options.copy_range = 2048;
    MsgBuilder builder;
    build_nflog_config(builder, 9, options);
    const MsgView message = one_message(builder);
    CHECK(message.type == ((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG));
    CHECK(message.res_id == 9054);
    Attr attrs[NFULA_CFG_MAX + 1]{};
    REQUIRE(parse_attrs(message.attrs, attrs, NFULA_CFG_MAX + 1));
    REQUIRE(attrs[NFULA_CFG_MODE].payload.size() == sizeof(nfulnl_msg_config_mode));
    nfulnl_msg_config_mode mode{};
    std::memcpy(&mode, attrs[NFULA_CFG_MODE].payload.data(), sizeof(mode));
    CHECK(ntohl(mode.copy_range) == 2048);
    CHECK(mode.copy_mode == NFULNL_COPY_PACKET);
    CHECK(attr_u32_be(attrs[NFULA_CFG_QTHRESH]) == 1);
    CHECK(attr_u32_be(attrs[NFULA_CFG_TIMEOUT]) == 1);
}

TEST_CASE("nflog: packet parser accepts metadata and payload") {
    MsgBuilder builder;
    builder.begin(static_cast<uint16_t>((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET),
                  0, 10, AF_INET, 9054);
    nfulnl_msg_packet_hdr header{};
    header.hw_protocol = htons(ETH_P_IP);
    header.hook = 3;
    builder.put(NFULA_PACKET_HDR, &header, sizeof(header));
    builder.put_u32_be(NFULA_MARK, 0xfeedbeef);
    builder.put_u32_be(NFULA_IFINDEX_INDEV, 2);
    const uint8_t payload[] = {0x45, 0x00, 0x00, 0x14};
    builder.put(NFULA_PAYLOAD, payload, sizeof(payload));
    builder.end();
    LoggedPacket packet;
    REQUIRE(parse_nflog_packet(one_message(builder), packet));
    CHECK(packet.hw_protocol == ETH_P_IP);
    CHECK(packet.hook == 3);
    CHECK(packet.mark == 0xfeedbeef);
    CHECK(packet.indev == 2);
    CHECK(packet.payload.size() == sizeof(payload));
}

TEST_CASE("nflog: malformed packet is rejected") {
    MsgBuilder builder;
    builder.begin(static_cast<uint16_t>((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET),
                  0, 10, AF_INET, 9054);
    const uint8_t short_header[] = {1, 2};
    builder.put(NFULA_PACKET_HDR, short_header, sizeof(short_header));
    builder.end();
    LoggedPacket packet;
    CHECK_FALSE(parse_nflog_packet(one_message(builder), packet));
}
