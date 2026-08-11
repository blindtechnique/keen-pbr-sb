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

} // namespace keen_pbr3
