#include "runtime_state_store.hpp"

namespace keen_pbr3 {

RuntimeStateSnapshot RuntimeStateStore::snapshot() const {
    KPBR_SHARED_LOCK(lock, mutex_);
    return snapshot_;
}

void RuntimeStateStore::publish(RuntimeStateSnapshot snapshot) {
    KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);
    // The store owns this field; a rebuilt snapshot does not get to answer
    // for it. See the header for why the carry-forward lives here and not in
    // the caller that happens to remember.
    snapshot.routing_runtime_active = snapshot_.routing_runtime_active;
    snapshot_ = std::move(snapshot);
}

bool RuntimeStateStore::routing_runtime_active() const {
    KPBR_SHARED_LOCK(lock, mutex_);
    return snapshot_.routing_runtime_active;
}

void RuntimeStateStore::set_routing_runtime_active(bool active) {
    KPBR_SHARED_UNIQUE_LOCK(lock, mutex_);
    snapshot_.routing_runtime_active = active;
}

} // namespace keen_pbr3
