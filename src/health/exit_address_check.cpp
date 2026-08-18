#include "exit_address_check.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>

namespace keen_pbr3 {

namespace {

// Longest textual IPv6 form, including an embedded IPv4 tail and a zone that
// this build does not accept anyway. Anything longer is not an address, and
// bounding before parsing keeps a large body from being walked at all.
constexpr std::size_t kMaxAddressLength = 45U;

std::string trimmed(const std::string& value) {
    const auto is_space = [](unsigned char character) {
        return std::isspace(character) != 0;
    };
    auto begin = value.begin();
    while (begin != value.end() && is_space(static_cast<unsigned char>(*begin))) {
        ++begin;
    }
    auto end = value.end();
    while (end != begin && is_space(static_cast<unsigned char>(*(end - 1)))) {
        --end;
    }
    return std::string(begin, end);
}

}  // namespace

const char* exit_check_verdict_name(ExitCheckVerdict verdict) noexcept {
    switch (verdict) {
        case ExitCheckVerdict::working:
            return "working";
        case ExitCheckVerdict::unattributed:
            return "unattributed";
        case ExitCheckVerdict::unreachable:
            return "unreachable";
    }
    return "unattributed";
}

const char* exit_address_change_name(ExitAddressChange change) noexcept {
    switch (change) {
        case ExitAddressChange::changed:
            return "changed";
        case ExitAddressChange::same:
            return "same";
        case ExitAddressChange::unknown:
            return "unknown";
    }
    return "unknown";
}

std::optional<std::string> parse_echoed_address(const std::string& body) {
    const std::string candidate = trimmed(body);
    if (candidate.empty() || candidate.size() > kMaxAddressLength) {
        return std::nullopt;
    }

    // inet_pton is the whole validation. A hand-rolled check would have to
    // reject "1.2.3.4.5", "999.1.1.1" and "::ffff:garbage" on its own, and the
    // one it forgot would be the one an operator is shown as their address.
    in_addr ipv4{};
    if (inet_pton(AF_INET, candidate.c_str(), &ipv4) == 1) {
        return candidate;
    }
    in6_addr ipv6{};
    if (inet_pton(AF_INET6, candidate.c_str(), &ipv6) == 1) {
        return candidate;
    }
    return std::nullopt;
}

ExitCheckVerdict exit_check_verdict(const ExitProbeOutcome& through) noexcept {
    if (!through.attributed) {
        return ExitCheckVerdict::unattributed;
    }
    if (!through.ok || through.address.empty()) {
        return ExitCheckVerdict::unreachable;
    }
    return ExitCheckVerdict::working;
}

ExitAddressChange exit_address_change(const ExitProbeOutcome& through,
                                      const ExitProbeOutcome& direct) noexcept {
    // Both halves must be real measurements. Comparing against a missing
    // reference and calling the result "changed" would turn a failed control
    // into evidence for the thing it was supposed to control.
    if (!through.ok || through.address.empty()) {
        return ExitAddressChange::unknown;
    }
    if (!direct.ok || direct.address.empty()) {
        return ExitAddressChange::unknown;
    }
    return through.address == direct.address ? ExitAddressChange::same
                                             : ExitAddressChange::changed;
}

}  // namespace keen_pbr3
