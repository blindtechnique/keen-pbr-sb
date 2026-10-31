#include "intercept_snapshot.hpp"

#include <map>
#include <stdexcept>

namespace keen_pbr3 {
namespace {

using BindingsByName = std::map<std::string, const InterceptListBinding*>;

BindingsByName validate(const std::vector<InterceptListBinding>& bindings) {
    BindingsByName result;
    for (const auto& binding : bindings) {
        if (binding.name.empty() || binding.content_signature.empty()) {
            throw std::invalid_argument("intercept binding requires a name and content signature");
        }
        if (!result.emplace(binding.name, &binding).second) {
            throw std::invalid_argument("duplicate intercept list: " + binding.name);
        }
    }
    return result;
}

void apply_policy(InterceptSnapshot& snapshot, const InterceptSnapshotPolicy& policy) {
    snapshot.cleanup = policy.cleanup;
    snapshot.max_ttl_s = policy.max_ttl_s;
    snapshot.ipv6_enabled = policy.ipv6_enabled;
    snapshot.tls = policy.tls;
    snapshot.http = policy.http;
    snapshot.quic = policy.quic;
    snapshot.marker_domain = policy.marker_domain;
    snapshot.marker_ipv4 = policy.marker_ipv4;
}

InterceptListTarget target_for(const InterceptListBinding& binding,
                               const InterceptSnapshotPolicy& policy) {
    auto target = binding.target;
    if (!policy.ipv6_enabled) target.set_v6.clear();
    return target;
}

} // namespace

std::shared_ptr<const InterceptSnapshot> build_intercept_snapshot(
    const std::vector<InterceptListBinding>& bindings,
    const InterceptSnapshotPolicy& policy, const InterceptDomainReader& read_domains) {
    validate(bindings);
    if (!read_domains && !bindings.empty()) {
        throw std::invalid_argument("intercept domain reader is required");
    }
    auto result = std::make_shared<InterceptSnapshot>();
    apply_policy(*result, policy);
    DomainIndex::Builder index;
    for (const auto& binding : bindings) {
        const auto id = index.add_list(binding.name);
        if (!read_domains(binding, [&](std::string_view domain) { index.add_domain(id, domain); })) {
            throw std::runtime_error("intercept domain source unavailable: " + binding.name);
        }
        result->targets.push_back(target_for(binding, policy));
        result->list_signatures.push_back(binding.content_signature);
    }
    result->index = std::make_shared<DomainIndex>(std::move(index).build());
    return result;
}

std::shared_ptr<const InterceptSnapshot> rebind_intercept_snapshot(
    const std::shared_ptr<const InterceptSnapshot>& previous,
    const std::vector<InterceptListBinding>& bindings,
    const InterceptSnapshotPolicy& policy) {
    const auto by_name = validate(bindings);
    if (!previous || !previous->index) return nullptr;
    auto result = std::make_shared<InterceptSnapshot>();
    apply_policy(*result, policy);
    result->index = previous->index;
    const auto& names = result->index->list_names();
    result->targets.resize(names.size());
    result->list_signatures.resize(names.size());
    for (std::size_t id = 0; id < names.size(); ++id) {
        if (id >= previous->list_signatures.size()) continue;
        // Preserve what the INDEX was built from, not the new signature. Without
        // this, a second rebind could mistakenly reactivate obsolete content.
        result->list_signatures[id] = previous->list_signatures[id];
        const auto found = by_name.find(names[id]);
        if (found == by_name.end()) continue;
        const auto& binding = *found->second;
        if (binding.content_signature != result->list_signatures[id]) continue;
        result->targets[id] = target_for(binding, policy);
    }
    return result;
}

} // namespace keen_pbr3
