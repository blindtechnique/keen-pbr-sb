#pragma once

#include "netlink.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace keen_pbr3 {

// One recv() block may contain zero or more dump objects followed by
// NLMSG_DONE.  Only `more` and `done` carry usable objects; every other state
// is a fail-closed classification and returns an empty object vector.
enum class RawRtnetlinkDumpState {
    more,
    done,
    kernel_error,
    malformed,
    sequence_mismatch,
    port_id_mismatch,
    unexpected_message,
    dump_interrupted,
};

// RTM_NEWROUTE carries an ifindex rather than an interface name.  Keeping the
// lookup table as borrowed input makes the codec deterministic and free of
// socket/ioctl side effects.  The parser copies a matched name into the
// DumpedRoute before returning.
struct RawRtnetlinkInterfaceName {
    std::uint32_t index{0};
    const char* name{nullptr};
};

struct RawRtnetlinkDumpOptions {
    std::uint32_t sequence{0};
    // Expected nlmsghdr::nlmsg_pid. The socket adapter must independently
    // prove that recvmsg() reported sockaddr_nl::nl_pid == 0 (the kernel).
    std::uint32_t port_id{0};
    const RawRtnetlinkInterfaceName* interface_names{nullptr};
    std::size_t interface_name_count{0};
};

struct RawRtnetlinkRouteDumpBlock {
    RawRtnetlinkDumpState state{RawRtnetlinkDumpState::malformed};
    // The signed errno from nlmsgerr.  Linux reports failures as negative
    // values; zero means that no kernel error was present.
    int kernel_error{0};
    std::vector<DumpedRoute> routes;
};

struct RawRtnetlinkRuleDumpBlock {
    RawRtnetlinkDumpState state{RawRtnetlinkDumpState::malformed};
    int kernel_error{0};
    std::vector<DumpedRule> rules;
};

// Parse exactly one raw rtnetlink recv() block.  The functions do not retain
// pointers into `bytes` or `options`, perform I/O, or mutate process state.
RawRtnetlinkRouteDumpBlock parse_raw_rtnetlink_route_dump_block(
    const void* bytes,
    std::size_t size,
    const RawRtnetlinkDumpOptions& options);

RawRtnetlinkRuleDumpBlock parse_raw_rtnetlink_rule_dump_block(
    const void* bytes,
    std::size_t size,
    const RawRtnetlinkDumpOptions& options);

}  // namespace keen_pbr3
