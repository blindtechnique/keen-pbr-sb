#pragma once

#include <chrono>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace keen_pbr3 {

// A step-up grant is deliberately short. It exists to bound the window in
// which a session left open on an unattended browser can install packages or
// rewrite the router's access configuration - not to be a second login the
// user resents.
inline constexpr std::chrono::seconds kStepUpGrantTtl{300};
inline constexpr std::size_t kStepUpGrantCapacity = 64;

// Whether an endpoint needs a recent reauthentication on top of a valid
// session.
//
// The predicate is exact-match rather than prefix-match, and that is the whole
// design. A prefix rule reads as if it fails safe, but it does the opposite in
// both directions: "/api/system/update" as a prefix would also swallow
// "/api/system/update/status", nagging for a password to read a status field,
// while any privileged endpoint added under a path nobody thought to list
// would silently need nothing at all. Exact entries make the omission visible
// in review instead of leaving it to a string comparison.
//
// The list therefore has to be maintained by hand when routes are added. That
// is a real cost, and it is the reason `step_up_protected_routes()` is exposed:
// a test walks the registered routes against it, so a new privileged endpoint
// shows up as a failing test rather than as an unguarded one.
bool requires_step_up(std::string_view method, std::string_view path);

struct StepUpProtectedRoute {
    std::string method;
    std::string path;
};

// Every route that requires a step-up grant, in one place so it can be
// reviewed and tested as a list rather than inferred from control flow.
const std::vector<StepUpProtectedRoute>& step_up_protected_routes();

// Some routes are not one operation. POST /api/nfqws multiplexes many actions
// behind a JSON "action" field: a small privileged subset and ordinary reads
// and edits the panel performs constantly.
//
// Guarding such a route wholesale is what broke it: a password prompt landed in
// front of opening a list and reading settings. For these the unit of privilege
// is the action, not the path, and treating the path as the unit was a mistake
// the route list could not express.
struct StepUpProtectedAction {
    std::string method;
    std::string path;
    std::string action;
};

const std::vector<StepUpProtectedAction>& step_up_protected_actions();

// Whether this path dispatches on an action field, so the caller knows it must
// supply one. Paths outside this set are decided by method and path alone.
bool path_dispatches_on_action(std::string_view path);

// Action-aware form. `action` is the value of the request body's "action"
// field; empty when absent or unparseable.
//
// An unrecognised action on a multiplexing path requires no step-up. That is
// deliberate: the alternative is prompting for a password on every action
// nobody listed, which is how the panel broke. The listed action is the
// privileged one, and a test walks the list against the handler's dispatch so a
// new privileged action shows up as a failure rather than as an omission.
bool requires_step_up(std::string_view method,
                      std::string_view path,
                      std::string_view action);

} // namespace keen_pbr3
