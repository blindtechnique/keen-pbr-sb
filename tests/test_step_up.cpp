#include <doctest/doctest.h>

#include "api/step_up.hpp"

#include <algorithm>
#include <string>
#include <vector>

namespace keen_pbr3 {

namespace {

// Every route the API registers today, taken from the handler registrations
// rather than from memory. It exists so a typo in the protected list is a
// failing test instead of a guard that silently matches nothing.
const std::vector<std::string>& registered_routes() {
    static const std::vector<std::string> routes = {
        "/api/backup",
        "/api/backup/restore",
        "/api/backup/rollback",
        "/api/catalog",
        "/api/catalog/refresh",
        "/api/config",
        "/api/connections",
        "/api/connections/active",
        "/api/diagnostics/tasks",
        "/api/dns/test",
        "/api/health/routing",
        "/api/health/service",
        "/api/lists/refresh",
        "/api/logs",
        "/api/logs/settings",
        "/api/nfqws",
        "/api/routing/test",
        "/api/runtime/interfaces",
        "/api/runtime/inventory",
        "/api/runtime/outbounds",
        "/api/service/restart",
        "/api/service/start",
        "/api/service/stop",
        "/api/status/events",
        "/api/system/geo",
        "/api/system/naive-component",
        "/api/system/remote-access",
        "/api/system/router",
        "/api/system/update",
        "/api/system/update/check",
        "/api/system/update/rollback",
        "/api/system/update/status",
        "/api/transports",
        "/api/transports/config",
        "/api/transports/config/export",
        "/api/transports/environment",
        "/api/transports/settings",
    };
    return routes;
}

} // namespace

TEST_CASE("every protected path is a route that actually exists") {
    for (const auto& route : step_up_protected_routes()) {
        const auto& known = registered_routes();
        // A misspelled entry matches no request, so the endpoint it was meant
        // to protect goes unguarded and nothing anywhere reports it.
        CHECK_MESSAGE(
            std::find(known.begin(), known.end(), route.path) != known.end(),
            "protected path is not a registered route: " << route.path);
    }
}

TEST_CASE("the package and access operations require a step-up") {
    CHECK(requires_step_up("POST", "/api/system/update"));
    CHECK(requires_step_up("POST", "/api/system/update/rollback"));
    CHECK(requires_step_up("POST", "/api/system/naive-component"));
    CHECK(requires_step_up("POST", "/api/nfqws"));
    CHECK(requires_step_up("POST", "/api/backup/restore"));
    CHECK(requires_step_up("POST", "/api/backup/rollback"));
    CHECK(requires_step_up("POST", "/api/system/remote-access"));
    // A read, but the archive carries credentials and the whole routing state,
    // so handing it out is closer to exfiltration than to a status query.
    CHECK(requires_step_up("GET", "/api/backup"));
}

TEST_CASE("reading what an update would do costs nothing") {
    // Prompting for a password to read a status field teaches the operator to
    // type it without reading the prompt, which is how a step-up stops being a
    // control at all.
    CHECK_FALSE(requires_step_up("GET", "/api/system/update/check"));
    CHECK_FALSE(requires_step_up("GET", "/api/system/update/status"));
    CHECK_FALSE(requires_step_up("POST", "/api/system/update/check"));
    CHECK_FALSE(requires_step_up("POST", "/api/system/update/status"));
}

TEST_CASE("a prefix of a protected path is not itself protected") {
    // The reason the predicate matches exactly rather than by prefix: as a
    // prefix, "/api/system/update" would also swallow its own status route,
    // and "/api/backup" would swallow every route beneath it.
    CHECK_FALSE(requires_step_up("GET", "/api/system"));
    CHECK_FALSE(requires_step_up("GET", "/api"));
    CHECK_FALSE(requires_step_up("POST", "/api/system/updates"));
    CHECK_FALSE(requires_step_up("POST", "/api/nfqws-extra"));
}

TEST_CASE("ordinary routes are untouched") {
    CHECK_FALSE(requires_step_up("GET", "/api/config"));
    CHECK_FALSE(requires_step_up("GET", "/api/health/routing"));
    CHECK_FALSE(requires_step_up("POST", "/api/service/restart"));
    CHECK_FALSE(requires_step_up("GET", "/api/status/events"));
}

TEST_CASE("the method is part of the decision") {
    // Reading the update endpoint is not applying an update.
    CHECK_FALSE(requires_step_up("GET", "/api/system/update"));
    CHECK_FALSE(requires_step_up("GET", "/api/nfqws"));
    // And the backup archive is privileged on the way out, not on the way in.
    CHECK_FALSE(requires_step_up("POST", "/api/backup"));
}

TEST_CASE("a spare slash or a query string is not a way past the guard") {
    CHECK(requires_step_up("POST", "/api/nfqws/"));
    CHECK(requires_step_up("POST", "/api/nfqws///"));
    CHECK(requires_step_up("GET", "/api/backup?format=tar"));
    CHECK(requires_step_up("POST", "/api/backup/restore/?force=1"));
}

TEST_CASE("an unknown route is not protected, and that is deliberate") {
    // The list is exact, so an endpoint nobody added to it is unguarded. That
    // is the cost of exact matching, and the coverage test above is what makes
    // the omission visible instead of silent.
    CHECK_FALSE(requires_step_up("POST", "/api/something/nobody/listed"));
}

} // namespace keen_pbr3
