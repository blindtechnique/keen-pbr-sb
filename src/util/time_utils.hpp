#pragma once

#include <chrono>
#include <cstdint>

namespace keen_pbr3 {

inline std::int64_t unix_timestamp_now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// Wall-clock milliseconds for an instant that was captured earlier. Anything
// published as a per-observation timestamp has to convert the instant it was
// actually measured at, never "now at serialization time" - re-reading the
// clock while building a response is what turns independent measurements into
// one indistinguishable batch.
inline std::int64_t unix_timestamp_ms(
    std::chrono::system_clock::time_point instant) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        instant.time_since_epoch()).count();
}

inline std::int64_t unix_timestamp_now_ms() {
    return unix_timestamp_ms(std::chrono::system_clock::now());
}

} // namespace keen_pbr3
