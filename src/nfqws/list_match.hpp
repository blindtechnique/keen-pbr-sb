#pragma once

#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3::nfqws {

// One entry of an nfqws hostlist that covers a queried domain.
struct HostlistMatch {
    // The entry as written in the file, so the panel can show what matched
    // rather than only that something did.
    std::string entry;
    // True when the entry is the domain itself rather than a parent of it.
    // "youtube.com" matching youtube.com is exact; matching www.youtube.com is
    // not, and an operator reading the result cares which.
    bool exact{false};
};

// What a list does, taken from the flag that names it in nfqws2.conf rather
// than from its filename: an operator may add lists of their own, and
// "user.list" is a convention, not a contract.
enum class ListRole {
    hostlist,          // --hostlist=
    hostlist_auto,     // --hostlist-auto=
    hostlist_exclude,  // --hostlist-exclude=
    ipset,             // --ipset=
    ipset_exclude,     // --ipset-exclude=
};

struct ListReference {
    std::string path;
    ListRole role{ListRole::hostlist};
};

// True for the roles that make nfqws act on traffic, false for the two that
// keep it away from it.
bool role_includes(ListRole role) noexcept;
// True for the roles whose entries are domains rather than addresses.
bool role_is_hostlist(ListRole role) noexcept;

// Finds every list file named by the effective nfqws argv, with the role each
// flag gives it. The caller must derive this argv from the parsed active
// assignments (build_nfqws_dry_run_args does that); scanning nfqws2.conf as
// plain text would count comments and inactive MODE_* definitions. A file
// named by several flags appears once per role, because the same file can
// legitimately be both.
std::vector<ListReference> parse_list_references(
    const std::vector<std::string>& arguments);

// Parses one nfqws list. Blank lines and comments are dropped; nfqws reads the
// file the same way, so a commented-out entry must not be reported as covering
// anything. Used for address lists too - their comment syntax is the same.
std::vector<std::string> parse_hostlist(const std::string& contents);

// Finds the entry that covers `domain`, or nothing.
//
// nfqws matches a hostlist entry against a domain and all of its subdomains,
// so "youtube.com" covers "www.youtube.com" but never "notyoutube.com" - the
// boundary is a dot, not a substring. When several entries cover the domain the
// most specific one is returned, because that is the one an operator would edit.
std::optional<HostlistMatch> match_hostlist(
    const std::vector<std::string>& entries,
    const std::string& domain);

// Finds the address-list entry that covers `ip`, or nothing.
//
// Entries are CIDRs or bare addresses; a bare address is its own /32 or /128.
// Families never cross: a v4 address is not covered by a v6 prefix, however
// the bits line up. The narrowest covering prefix is returned, because that is
// the entry that decided the outcome.
std::optional<HostlistMatch> match_ipset(
    const std::vector<std::string>& entries,
    const std::string& ip);

} // namespace keen_pbr3::nfqws
