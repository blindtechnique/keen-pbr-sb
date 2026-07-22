#include "../src/util/base64.hpp"

#include <doctest/doctest.h>

#include <stdexcept>

TEST_CASE("base64 round-trips binary content") {
    const std::string gzip_header{"\x1f\x8b\x08\x00\xff\x00", 6};
    const auto encoded = keen_pbr3::base64_encode(gzip_header);
    CHECK(encoded == "H4sIAP8A");
    CHECK(keen_pbr3::base64_decode(encoded) == gzip_header);
}

TEST_CASE("base64 handles padding and rejects malformed input") {
    CHECK(keen_pbr3::base64_encode("a") == "YQ==");
    CHECK(keen_pbr3::base64_encode("ab") == "YWI=");
    CHECK(keen_pbr3::base64_decode("YWJj") == "abc");
    CHECK_THROWS_AS(keen_pbr3::base64_decode("abc"), std::invalid_argument);
    CHECK_THROWS_AS(keen_pbr3::base64_decode("ab=c"), std::invalid_argument);
}
