#include <doctest/doctest.h>

#include "api/update_version.hpp"

using keen_pbr3::is_newer_fork_version;
using keen_pbr3::safe_github_tag;

TEST_CASE("fork release comparison does not offer downgrades") {
    CHECK(is_newer_fork_version("v3.0.7-sb.4", "v3.0.7-sb.3"));
    CHECK_FALSE(is_newer_fork_version("v3.0.7-sb.3", "v3.0.7-sb.4"));
    CHECK_FALSE(is_newer_fork_version("v3.0.7-sb.4", "v3.0.7-sb.4"));
}

TEST_CASE("fork release comparison supports historical and future tags") {
    CHECK(is_newer_fork_version("v3.0.7-sb.3", "3.0.7-sb1"));
    CHECK(is_newer_fork_version("v3.0.8-sb.1", "v3.0.7-sb.99"));
    CHECK(is_newer_fork_version("v4.0-sb.1", "v3.99.99-sb.99"));
    CHECK_FALSE(is_newer_fork_version("not-a-version", "v3.0.7-sb.4"));
}

TEST_CASE("only path-safe GitHub tags are accepted for changelog links") {
    CHECK(safe_github_tag("v3.0.7-sb.4"));
    CHECK(safe_github_tag("3.0.7-sb1"));
    CHECK_FALSE(safe_github_tag("v3.0.7/../../main"));
    CHECK_FALSE(safe_github_tag(""));
}
