#include "runtime_resolver_publication.hpp"

#include <type_traits>
#include <utility>

namespace keen_pbr3 {

void publish_runtime_resolver_checkpoint(
    RuntimeResolverPublicationTarget target,
    RuntimeResolverPublicationSource source,
    RuntimeResolverGenerationPublication generation_publication) noexcept {
    static_assert(
        std::is_nothrow_copy_assignable_v<
            std::shared_ptr<const ResolverGenerationSnapshot>>,
        "resolver generation publication must not throw");

    if (generation_publication ==
        RuntimeResolverGenerationPublication::exchange_preimage) {
        target.generation.swap(source.generation);
    } else {
        target.generation = source.generation;
    }
    target.sync.restore(std::move(source.sync));
    target.retry_attempt = source.retry_attempt;
    target.apply_started_ts.store(
        source.apply_started_ts,
        std::memory_order_release);
}

} // namespace keen_pbr3
