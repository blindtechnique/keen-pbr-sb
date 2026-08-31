#pragma once

// Refusing a list update that lost most of its contents.
//
// A remote list can come back truncated, empty or replaced by an error page
// that happens to parse: the source moved, a CDN served a stub, a generator
// upstream broke. Publishing that quietly unroutes everything the list carried,
// and nothing says so - the download succeeded, the file is valid, the traffic
// simply stops going where it went yesterday.
//
// The comparison is made on **decoded and normalised entries**, never on the
// size of the response. A compressed body, a changed encoding or a reformatted
// SRS all move the byte count without meaning anything; the number of hosts a
// list actually contributes is the only figure that answers the question.

#include <cstdint>
#include <istream>
#include <string>

namespace keen_pbr3 {

// What a list contributed, counted after decoding and normalisation.
struct ListEntryCounts {
    std::int64_t domains{0};
    std::int64_t cidrs{0};
    std::int64_t ips{0};

    std::int64_t total() const noexcept { return domains + cidrs + ips; }
};

// Counts a cache body the way the list streamer will later read it.
//
// Deliberately measured on the written body rather than tallied inside each
// converter: there are two of those, one for SRS and one for plain text, and a
// count taken anywhere but here would be a count of something slightly other
// than what the list ends up contributing. Comments, blanks and entries the
// parser rejects are not entries and are not counted.
ListEntryCounts count_list_entries(std::istream& input);

// How much a list may lose before an update is refused.
//
// A threshold belongs to the source, not to the guard: a hand-maintained list
// of a dozen domains legitimately halves, while a published category set that
// loses half of itself has almost certainly broken. The defaults below suit a
// catalogue-sized remote list; a caller with a smaller or more volatile source
// says so rather than being overruled by a constant.
struct ListShrinkPolicy {
    // Below this many previous entries the guard stays silent. Relative change
    // means little in the small: three entries becoming one is a normal edit,
    // not a failure.
    std::int64_t min_previous_entries{50};
    // Refuse when the candidate keeps less than this share of what was there.
    double min_retained_fraction{0.5};
};

enum class ListShrinkVerdict {
    // Nothing to object to, or nothing to compare against.
    publish,
    // The candidate lost too much to be believed.
    refuse,
};

struct ListShrinkDecision {
    ListShrinkVerdict verdict{ListShrinkVerdict::publish};
    // Share of the previous entries the candidate kept. Zero when the previous
    // count was unknown, which is not the same as "kept nothing".
    double retained_fraction{0.0};
    // One sentence for the journal, empty when the candidate is published.
    std::string reason;
};

// The whole rule, with no filesystem and no network in sight.
//
// `previous` of zero total means "no usable last known good", and a first
// download is always published: there is nothing to shrink from.
ListShrinkDecision decide_list_shrink(const ListEntryCounts& previous,
                                      const ListEntryCounts& candidate,
                                      const ListShrinkPolicy& policy = {});

}  // namespace keen_pbr3
