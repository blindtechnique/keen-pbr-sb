#include <doctest/doctest.h>

#include "../src/health/exit_address_check.hpp"

using namespace keen_pbr3;

namespace {

ExitProbeOutcome pinned(const std::string& address) {
    ExitProbeOutcome outcome;
    outcome.ok = true;
    outcome.attributed = true;
    outcome.address = address;
    outcome.latency_ms = 120U;
    return outcome;
}

ExitProbeOutcome direct(const std::string& address) {
    ExitProbeOutcome outcome;
    outcome.ok = true;
    outcome.attributed = false;  // the control is not bound to any tunnel
    outcome.address = address;
    return outcome;
}

}  // namespace

TEST_CASE("a probe that could not be pinned proves nothing about the transport") {
    ExitProbeOutcome answered_anyway = pinned("203.0.113.7");
    answered_anyway.attributed = false;

    // It succeeded - over some route. Reporting that as the tunnel working is
    // exactly the false green this check exists to refuse.
    CHECK(exit_check_verdict(answered_anyway) == ExitCheckVerdict::unattributed);
}

TEST_CASE("an unbindable probe that also failed still reports the absence of evidence") {
    ExitProbeOutcome nothing;
    nothing.ok = false;
    nothing.attributed = false;
    nothing.error = "SO_BINDTODEVICE(kpbr9786265a) failed: No such device";

    // Not "unreachable": that would send the operator to debug a tunnel this
    // check never touched.
    CHECK(exit_check_verdict(nothing) == ExitCheckVerdict::unattributed);
}

TEST_CASE("a pinned probe with no answer is unreachable") {
    ExitProbeOutcome failed;
    failed.attributed = true;
    failed.ok = false;
    failed.error = "timeout";

    CHECK(exit_check_verdict(failed) == ExitCheckVerdict::unreachable);
}

TEST_CASE("a pinned probe that answered without an address is not working") {
    ExitProbeOutcome empty;
    empty.attributed = true;
    empty.ok = true;
    empty.address.clear();

    CHECK(exit_check_verdict(empty) == ExitCheckVerdict::unreachable);
}

TEST_CASE("a pinned probe with an address is the only working verdict") {
    CHECK(exit_check_verdict(pinned("203.0.113.7")) == ExitCheckVerdict::working);
}

TEST_CASE("a different exit address is reported as changed") {
    CHECK(exit_address_change(pinned("203.0.113.7"), direct("198.51.100.9")) ==
          ExitAddressChange::changed);
}

TEST_CASE("the same address on both sides means the tunnel is not carrying it") {
    CHECK(exit_address_change(pinned("198.51.100.9"), direct("198.51.100.9")) ==
          ExitAddressChange::same);
}

TEST_CASE("a failed control never becomes evidence of a change") {
    ExitProbeOutcome no_control;
    no_control.ok = false;

    CHECK(exit_address_change(pinned("203.0.113.7"), no_control) ==
          ExitAddressChange::unknown);
    CHECK(exit_address_change(pinned("203.0.113.7"), direct("")) ==
          ExitAddressChange::unknown);
}

TEST_CASE("echoed bodies are validated as addresses rather than trusted") {
    CHECK(parse_echoed_address("203.0.113.7") ==
          std::optional<std::string>{"203.0.113.7"});
    CHECK(parse_echoed_address(" 203.0.113.7\n") ==
          std::optional<std::string>{"203.0.113.7"});
    CHECK(parse_echoed_address("2001:db8::1") ==
          std::optional<std::string>{"2001:db8::1"});

    // A captive portal answers 200 with a page. Rendering that as an address
    // would dress a hijacked request as a measurement.
    CHECK_FALSE(parse_echoed_address("<html>Sign in to continue</html>").has_value());
    CHECK_FALSE(parse_echoed_address("").has_value());
    CHECK_FALSE(parse_echoed_address("   ").has_value());
    CHECK_FALSE(parse_echoed_address("999.1.1.1").has_value());
    CHECK_FALSE(parse_echoed_address("1.2.3.4.5").has_value());
    CHECK_FALSE(parse_echoed_address(std::string(200U, '7')).has_value());
}
