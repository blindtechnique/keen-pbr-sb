#include "step_up.hpp"

#include <algorithm>

namespace keen_pbr3 {

namespace {

// Trailing slashes are normalised away before comparison. httplib would not
// route "/api/nfqws/" to the "/api/nfqws" handler today, so this changes
// nothing now; it means a future router that is more forgiving cannot turn a
// spare slash into a way past the guard.
std::string_view normalised_path(std::string_view path) {
    const auto query = path.find('?');
    if (query != std::string_view::npos) path = path.substr(0, query);
    while (path.size() > 1U && path.back() == '/') {
        path.remove_suffix(1);
    }
    return path;
}

} // namespace

const std::vector<StepUpProtectedRoute>& step_up_protected_routes() {
    // Two families, exactly as the roadmap scopes them.
    //
    // Package operations, because they install or replace software on the
    // router and their failure mode is a device that no longer boots into a
    // working state:
    //   POST /api/system/update           - applies a component update
    //   POST /api/system/update/rollback  - replaces the running component set
    //   POST /api/system/naive-component  - installs a component
    //   POST /api/nfqws                   - installs or updates nfqws
    //   POST /api/backup/restore          - replaces configuration wholesale
    //   POST /api/backup/rollback         - the same, in the other direction
    //
    // NDMS/access operations, because they change how the router itself can be
    // reached:
    //   POST /api/system/remote-access
    //
    // And one that reads rather than writes:
    //   POST /api/backup - the archive carries credentials and the complete
    //   routing state, so handing it out is closer to an exfiltration than to
    //   a status query. The pre-routing handler already refuses to let it be
    //   cached for the same reason. It is a POST because the request body
    //   selects which groups to export; guarding the GET it looks like it
    //   ought to be would have protected a route that does not exist.
    //
    // Deliberately absent: /api/system/update/check and
    // /api/system/update/status report what is available and what happened.
    // Asking for a password to read them would train the operator to type it
    // without reading the prompt, which is how a step-up stops being a
    // control.
    static const std::vector<StepUpProtectedRoute> routes = {
        {"POST", "/api/system/update"},
        {"POST", "/api/system/update/rollback"},
        {"POST", "/api/system/naive-component"},
        {"POST", "/api/backup/restore"},
        {"POST", "/api/backup/rollback"},
        {"POST", "/api/system/remote-access"},
        {"POST", "/api/backup"},
    };
    return routes;
}

const std::vector<StepUpProtectedAction>& step_up_protected_actions() {
    // POST /api/nfqws dispatches on an "action" field. Two of them install
    // software; the rest read files, save strategies, clear logs and restart
    // the service - things the panel does constantly and which must not ask
    // for a password.
    //
    // `restore_component` is here for the same reason as `upgrade` and not a
    // weaker one: putting an older binary back is installing software, and an
    // attacker who can reach the panel would rather downgrade a component to a
    // version with known holes than upgrade it.
    //
    // `import_bundle` was considered and left out: it writes nfqws lists and
    // configuration, which is an edit like the others, not an install.
    static const std::vector<StepUpProtectedAction> actions = {
        {"POST", "/api/nfqws", "upgrade"},
        {"POST", "/api/nfqws", "restore_component"},
    };
    return actions;
}

bool path_dispatches_on_action(const std::string_view path) {
    const auto candidate = normalised_path(path);
    const auto& actions = step_up_protected_actions();
    return std::any_of(
        actions.begin(), actions.end(),
        [&](const StepUpProtectedAction& entry) {
            return entry.path == candidate;
        });
}

bool requires_step_up(const std::string_view method,
                      const std::string_view path) {
    const auto candidate = normalised_path(path);
    const auto& routes = step_up_protected_routes();
    return std::any_of(
        routes.begin(), routes.end(),
        [&](const StepUpProtectedRoute& route) {
            return route.method == method && route.path == candidate;
        });
}

bool requires_step_up(const std::string_view method,
                      const std::string_view path,
                      const std::string_view action) {
    if (requires_step_up(method, path)) {
        return true;
    }
    const auto candidate = normalised_path(path);
    const auto& actions = step_up_protected_actions();
    return std::any_of(
        actions.begin(), actions.end(),
        [&](const StepUpProtectedAction& entry) {
            return entry.method == method && entry.path == candidate &&
                   entry.action == action;
        });
}

} // namespace keen_pbr3
