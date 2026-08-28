#pragma once

// What the operator has already decided about, so a candidate queue does not
// propose it again.
//
// The matching itself is not written here. nfqws::match_hostlist already walks
// a domain and its parents with the dot as the boundary - "youtube.com" covers
// "www.youtube.com" and never "notyoutube.com" - and returns the most specific
// entry; nfqws::match_ipset already returns the narrowest covering prefix and
// refuses to cross address families. Our own lists normalize to the same shape
// (ListParser::normalize_domain strips a "*." prefix), and dnsmasq expands a
// list entry over its subdomains exactly the way an nfqws hostlist entry does.
// One matcher, both sides.
//
// What is written here is the one decision that is not mechanical: which of
// those files count as "already decided".

#include "../nfqws/list_match.hpp"

#include <functional>
#include <string>
#include <vector>

namespace keen_pbr3 {

enum class CoverageSource {
    // Nobody has an opinion about this host yet.
    none,
    // One of our routing lists names it. Whatever that list routes to, the
    // operator already chose it, and proposing a tunnel would argue with them.
    routing_list,
    // nfqws2's --hostlist-exclude names it: "keep away from this". That is an
    // instruction about nfqws2 rather than about routing, but it is still an
    // explicit hands-off, and a queue that ignored it would keep offering the
    // one host its operator has already refused twice.
    nfqws_exclude,
};

struct CoverageVerdict {
    CoverageSource source{CoverageSource::none};
    // Which of our lists, when the source is routing_list.
    std::string list_name;
    // The entry as written, so a panel can show what matched rather than only
    // that something did.
    std::string entry;
    // True when the entry is the host itself rather than a parent of it.
    bool exact{false};
};

struct CoverageIndex {
    struct RoutingList {
        std::string name;
        // Normalized, wildcard prefix stripped, lower case.
        std::vector<std::string> domains;
        // Bare addresses or CIDRs.
        std::vector<std::string> addresses;
    };

    // Consulted in order; the first list that covers the target wins, so the
    // answer is stable for a given configuration rather than dependent on how
    // a map happened to iterate.
    std::vector<RoutingList> routing_lists;

    // nfqws2 --hostlist-exclude entries.
    std::vector<std::string> nfqws_excluded;

    // nfqws2 --hostlist entries (user.list and any other file the operator gave
    // that flag).
    //
    // DELIBERATELY NOT COVERAGE. Proved on the owner's router: with
    // thumbnails.libretro.com added to user.list, nfqws2 restarted and the
    // rotator given a full cycle of eight strategies, the host stayed
    // unreachable through sixteen attempts - while linkedin.com out of the same
    // file opened directly in the same minute. A host nfqws2 was asked to
    // handle and could not is the strongest candidate there is, not an excluded
    // one. It is carried here so the panel can say "nfqws2 is already trying",
    // which changes what the operator reads, not what the queue offers.
    std::vector<std::string> nfqws_handled;
};

// Domains and addresses both: an address is recognised as one and matched
// against the address entries, because a connection with no name in it keys on
// the address and still deserves an answer.
CoverageVerdict classify_coverage(const CoverageIndex& index,
                                  const std::string& target);

// True when the verdict means "leave this alone".
bool coverage_excludes_candidate(const CoverageVerdict& verdict) noexcept;

// The annotation described above: nfqws2 was told to work on this host. Never a
// reason to drop a candidate.
bool nfqws_was_asked_about(const CoverageIndex& index, const std::string& target);

const char* coverage_source_name(CoverageSource source) noexcept;

// Ready to hand to ProbeCandidateQueue. Holds a reference to the index, which
// must outlive the queue.
std::function<bool(const std::string&)> coverage_predicate(
    const CoverageIndex& index);

}  // namespace keen_pbr3
