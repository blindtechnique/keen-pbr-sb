#include "host_coverage.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <cctype>

namespace keen_pbr3 {

namespace {

bool is_address(const std::string& target) noexcept {
    if (target.empty() || target.size() >= INET6_ADDRSTRLEN) return false;
    std::array<unsigned char, 16> bytes{};
    if (inet_pton(AF_INET, target.c_str(), bytes.data()) == 1) return true;
    return inet_pton(AF_INET6, target.c_str(), bytes.data()) == 1;
}

std::string lowercased(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](const unsigned char c) {
                       return static_cast<char>(std::tolower(c));
                   });
    return value;
}

}  // namespace

const char* coverage_source_name(const CoverageSource source) noexcept {
    switch (source) {
        case CoverageSource::routing_list:
            return "routing_list";
        case CoverageSource::nfqws_exclude:
            return "nfqws_exclude";
        case CoverageSource::none:
            break;
    }
    return "none";
}

bool coverage_excludes_candidate(const CoverageVerdict& verdict) noexcept {
    return verdict.source != CoverageSource::none;
}

CoverageVerdict classify_coverage(const CoverageIndex& index,
                                  const std::string& target) {
    CoverageVerdict verdict;
    if (target.empty()) return verdict;

    const bool address = is_address(target);
    const auto normalized = address ? target : lowercased(target);

    for (const auto& list : index.routing_lists) {
        const auto match = address
                               ? nfqws::match_ipset(list.addresses, normalized)
                               : nfqws::match_hostlist(list.domains, normalized);
        if (!match) continue;
        verdict.source = CoverageSource::routing_list;
        verdict.list_name = list.name;
        verdict.entry = match->entry;
        verdict.exact = match->exact;
        return verdict;
    }

    // Addresses are not looked for in the hostlists: nfqws2 keeps names and
    // addresses in separate files, and a name-shaped entry never covers an
    // address.
    if (!address) {
        if (const auto match =
                nfqws::match_hostlist(index.nfqws_excluded, normalized)) {
            verdict.source = CoverageSource::nfqws_exclude;
            verdict.entry = match->entry;
            verdict.exact = match->exact;
            return verdict;
        }
    }

    return verdict;
}

bool nfqws_was_asked_about(const CoverageIndex& index,
                           const std::string& target) {
    if (target.empty() || is_address(target)) return false;
    return nfqws::match_hostlist(index.nfqws_handled, lowercased(target))
        .has_value();
}

std::function<bool(const std::string&)> coverage_predicate(
    const CoverageIndex& index) {
    return [&index](const std::string& target) {
        return coverage_excludes_candidate(classify_coverage(index, target));
    };
}

}  // namespace keen_pbr3
