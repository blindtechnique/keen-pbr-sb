#pragma once
#include "set_writer.hpp"
#include <chrono>
#include <optional>

namespace keen_pbr3::nfnl {

// Read-only exact membership. Missing set, permission/transport errors and
// incomplete replies are unknown, NOT absence. No shell and no dump.
class SetMembershipReader {
public:
    SetMembershipReader(bool nftables, std::unique_ptr<SetWriterTransport> transport)
        : nftables_(nftables), transport_(std::move(transport)) {}
    std::optional<bool> contains(const std::string& set, const std::string& ip,
                                std::chrono::steady_clock::time_point deadline);
private:
    bool nftables_;
    std::unique_ptr<SetWriterTransport> transport_;
};
} // namespace keen_pbr3::nfnl
