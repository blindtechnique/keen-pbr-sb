#include <doctest/doctest.h>

#include "api/step_up.hpp"

#include <algorithm>
#include <string>
#include <vector>

namespace keen_pbr3 {

namespace {

// Method and path of every route the protected list names, taken from the
// handler registrations rather than from memory.
//
// The method matters as much as the path, and this list exists because getting
// it wrong is silent: an entry naming a method the endpoint does not serve
// matches no request, so the operation it was meant to guard stays open while
// the list reads as though it is covered. That is exactly what "GET
// /api/backup" did - the archive is exported by POST, the body selecting which
// groups to include.
const std::vector<StepUpProtectedRoute>& registered_privileged_routes() {
    static const std::vector<StepUpProtectedRoute> routes = {
        {"POST", "/api/backup"},
        {"POST", "/api/backup/restore"},
        {"POST", "/api/backup/rollback"},
        {"GET", "/api/backup/rollback"},
        {"POST", "/api/nfqws"},
        {"GET", "/api/nfqws"},
        {"POST", "/api/system/naive-component"},
        {"GET", "/api/system/naive-component"},
        {"POST", "/api/system/remote-access"},
        {"GET", "/api/system/remote-access"},
        {"POST", "/api/system/update"},
        {"GET", "/api/system/update"},
        {"POST", "/api/system/update/check"},
        {"POST", "/api/system/update/rollback"},
        {"GET", "/api/system/update/status"},
    };
    return routes;
}

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

TEST_CASE("every protected entry names a method that endpoint serves") {
    const auto& registered = registered_privileged_routes();

    for (const auto& route : step_up_protected_routes()) {
        const auto found = std::find_if(
            registered.begin(), registered.end(),
            [&](const StepUpProtectedRoute& known) {
                return known.method == route.method &&
                       known.path == route.path;
            });
        // Guarding a method the endpoint does not serve is worse than not
        // guarding it: the list reads as covered while the real operation
        // stays open.
        CHECK_MESSAGE(found != registered.end(),
                      "protected entry serves no such method: "
                          << route.method << " " << route.path);
    }
}

TEST_CASE("the package and access operations require a step-up") {
    CHECK(requires_step_up("POST", "/api/system/update"));
    CHECK(requires_step_up("POST", "/api/system/update/rollback"));
    CHECK(requires_step_up("POST", "/api/system/naive-component"));
    CHECK(requires_step_up("POST", "/api/nfqws", "upgrade"));
    CHECK(requires_step_up("POST", "/api/backup/restore"));
    CHECK(requires_step_up("POST", "/api/backup/rollback"));
    CHECK(requires_step_up("POST", "/api/system/remote-access"));
    // Exporting the archive: it carries credentials and the whole routing
    // state, so handing it out is closer to exfiltration than to a status
    // query. A POST because the body selects which groups to export.
    CHECK(requires_step_up("POST", "/api/backup"));
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
    CHECK_FALSE(requires_step_up("GET", "/api/nfqws", "upgrade"));
    // There is no GET /api/backup. Guarding the method the endpoint merely
    // looks like it should use protects nothing and reads as if it does.
    CHECK_FALSE(requires_step_up("GET", "/api/backup"));
}

TEST_CASE("a spare slash or a query string is not a way past the guard") {
    CHECK(requires_step_up("POST", "/api/nfqws/", "upgrade"));
    CHECK(requires_step_up("POST", "/api/nfqws///", "upgrade"));
    // Normalisation must also reach the check that decides whether to read the
    // body at all, or a spare slash would skip the action lookup entirely.
    CHECK(path_dispatches_on_action("/api/nfqws///"));
    CHECK(requires_step_up("POST", "/api/backup?groups=all"));
    CHECK(requires_step_up("POST", "/api/backup/restore/?force=1"));
}

TEST_CASE("the everyday nfqws actions never ask for a password") {
    // Every action POST /api/nfqws dispatches on, taken from the handler.
    // Guarding the route wholesale put a password prompt in front of reading a
    // list and opening settings - the owner found it by using the panel, and
    // nothing here would have caught it, because the route list could not say
    // that one route is sixteen operations.
    const std::vector<std::string> everyday = {
        "check_update", "read_file",      "save_file",      "create_file",
        "delete_file",  "clear_log",      "service",        "save_strategy",
        "apply_strategy", "save_files",   "delete_strategy", "import_lists",
        "import_bundle", "check_url",
    };

    for (const auto& action : everyday) {
        CHECK_MESSAGE(!requires_step_up("POST", "/api/nfqws", action),
                      "everyday nfqws action now demands a step-up: "
                          << action);
    }
}

TEST_CASE("installing nfqws software is what demands a step-up") {
    CHECK(requires_step_up("POST", "/api/nfqws", "upgrade"));
    // Putting an older binary back is installing software too, and an attacker
    // who can reach the panel would rather downgrade a component to a version
    // with known holes than upgrade it.
    CHECK(requires_step_up("POST", "/api/nfqws", "restore_component"));
    // Reading the route without naming an action must not demand one either,
    // or the same breakage returns through the front door.
    CHECK_FALSE(requires_step_up("POST", "/api/nfqws", ""));
    CHECK_FALSE(requires_step_up("POST", "/api/nfqws"));
}

TEST_CASE("only the multiplexing route needs its body read") {
    CHECK(path_dispatches_on_action("/api/nfqws"));
    CHECK(path_dispatches_on_action("/api/nfqws/"));
    // Everything else is decided by method and path, so the pre-routing guard
    // must not parse their bodies to find out.
    CHECK_FALSE(path_dispatches_on_action("/api/backup"));
    CHECK_FALSE(path_dispatches_on_action("/api/config"));
    CHECK_FALSE(path_dispatches_on_action("/api/system/update"));
}

TEST_CASE("an action-scoped entry names an action the handler dispatches on") {
    // The handler's own list, so a protected action that no longer exists -
    // renamed, removed - fails here instead of silently guarding nothing.
    const std::vector<std::string> dispatched = {
        "check_update", "read_file",       "save_file",     "create_file",
        "delete_file",  "clear_log",       "service",       "upgrade",
        "save_strategy", "apply_strategy", "save_files",    "delete_strategy",
        "import_lists", "import_bundle",   "check_url",     "restore_component",
    };

    for (const auto& entry : step_up_protected_actions()) {
        CHECK_MESSAGE(
            std::find(dispatched.begin(), dispatched.end(), entry.action) !=
                dispatched.end(),
            "protected action is not dispatched by the handler: "
                << entry.action);
    }
}

TEST_CASE("an unknown route is not protected, and that is deliberate") {
    // The list is exact, so an endpoint nobody added to it is unguarded. That
    // is the cost of exact matching, and the coverage test above is what makes
    // the omission visible instead of silent.
    CHECK_FALSE(requires_step_up("POST", "/api/something/nobody/listed"));
}

} // namespace keen_pbr3
