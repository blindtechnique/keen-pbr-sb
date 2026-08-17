#include <doctest/doctest.h>

#include "../src/keenetic/ndms_credential_generation.hpp"

#include <string>

namespace keen_pbr3 {

namespace {

using Verdict = NdmsCredentialGenerationVerdict;
using Change = NdmsCredentialChange;

// The shape measured on NC-1812 running 5.1.1, with the hashes replaced.
// Two users, both carrying password material, each with an access tag list.
std::string user_document(const char* admin_hash = "aaaa",
                          const char* second_hash = "bbbb") {
    return std::string(R"({
  "admin": {
    "password": { "nt": { "hash": ")") +
           admin_hash + R"(" }, "md5": { "hash": ")" + admin_hash +
           R"(" } },
    "tag": [ "cli", "http", "opt" ]
  },
  "sdd": {
    "password": { "nt": { "hash": ")" +
           second_hash + R"(" } },
    "tag": [ "http" ]
  }
})";
}

} // namespace

TEST_CASE("a user document yields a generation") {
    const auto generation = ndms_credential_generation(user_document());
    CHECK(generation.verdict == Verdict::known);
    CHECK(generation.digest.size() == 64U);
    for (const char ch : generation.digest) {
        CHECK(((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')));
    }
}

TEST_CASE("the generation is the credential state and nothing else") {
    // Byte-identical documents agree; a changed hash disagrees. This is the
    // whole contract: the digest moves when, and only when, the firmware's
    // answer moves.
    CHECK(ndms_credential_generation(user_document()).digest ==
          ndms_credential_generation(user_document()).digest);
    CHECK(ndms_credential_generation(user_document()).digest !=
          ndms_credential_generation(user_document("cccc")).digest);
    // A change to any user's material counts, not only the first one's.
    CHECK(ndms_credential_generation(user_document()).digest !=
          ndms_credential_generation(user_document("aaaa", "dddd")).digest);
}

TEST_CASE("the generation carries no part of the document it read") {
    // The document holds the admin's password hashes. Only the digest
    // survives, and a digest of a secret is not the secret.
    const auto generation =
        ndms_credential_generation(user_document("s3cr3thash"));
    CHECK(generation.digest.find("s3cr3thash") == std::string::npos);
    CHECK(generation.digest.find("admin") == std::string::npos);
}

TEST_CASE("a read that produced nothing is unreadable, not empty") {
    // An empty body is what a failed read looks like, and on this firmware it
    // is also what an absent `show/rc/...` path answers with - HTTP 404 and
    // no body at all.
    for (const char* body : {"", "   ", "not json", "[]", "{}", "null",
                             "\"admin\"", "42"}) {
        const auto generation = ndms_credential_generation(body);
        CHECK(generation.verdict == Verdict::unreadable);
        CHECK(generation.digest.empty());
    }
}

TEST_CASE("an error envelope cannot pass as a user document") {
    // The other RCI family in this codebase answers absence with a JSON
    // envelope rather than a 404. Digesting one would produce a perfectly
    // stable generation - of the error - and the authority would sit there
    // looking healthy while witnessing nothing.
    for (const char* body :
         {R"({"status":[{"status":"error","message":"no such element"}]})",
          R"({"status":{"error":"denied"}})"}) {
        CHECK(ndms_credential_generation(body).verdict ==
              Verdict::unreadable);
    }
}

TEST_CASE("a document with no password material cannot be a generation") {
    // The defect this closes: such a document digests perfectly stably, so the
    // authority would report "unchanged" across the exact event it exists to
    // catch. Silent inertness is worse than an absent feature - the absent
    // feature does not claim to be working.
    const char* tags_only = R"({
  "admin": { "tag": [ "cli", "http" ] },
  "sdd": { "tag": [ "http" ] }
})";
    CHECK(ndms_credential_generation(tags_only).verdict ==
          Verdict::unreadable);

    // An empty password object is no material either.
    const char* empty_password = R"({ "admin": { "password": {} } })";
    CHECK(ndms_credential_generation(empty_password).verdict ==
          Verdict::unreadable);

    // ...but one user with material is enough: a router may carry accounts
    // that have none.
    const char* mixed = R"({
  "admin": { "password": { "nt": { "hash": "aa" } }, "tag": [ "cli" ] },
  "guest": { "tag": [ "http" ] }
})";
    CHECK(ndms_credential_generation(mixed).verdict == Verdict::known);
}

TEST_CASE("only a comparison of two readings can say anything") {
    const auto first = ndms_credential_generation(user_document());
    const auto same = ndms_credential_generation(user_document());
    const auto other = ndms_credential_generation(user_document("cccc"));
    const NdmsCredentialGeneration absent;

    CHECK(ndms_credential_change(first, same) == Change::unchanged);
    CHECK(ndms_credential_change(first, other) == Change::changed);

    // A failed read is not evidence that nothing changed - revoking on it
    // would turn a firmware hiccup into an outage that logs every operator
    // out - and it is not evidence that something did.
    CHECK(ndms_credential_change(first, absent) == Change::unknown);
    // Nor is a first successful read after an outage a change: there is no
    // baseline to have moved away from.
    CHECK(ndms_credential_change(absent, first) == Change::unknown);
    CHECK(ndms_credential_change(absent, absent) == Change::unknown);
}

TEST_CASE("a change survives an outage that spans it") {
    // The reason a failed read must not become the stored baseline. The
    // caller stores only `known` readings, so a change that happens while the
    // firmware is unreachable is still seen when it comes back.
    const auto before = ndms_credential_generation(user_document());
    const NdmsCredentialGeneration during;
    const auto after = ndms_credential_generation(user_document("cccc"));

    CHECK(ndms_credential_change(before, during) == Change::unknown);
    // The caller kept `before`, because `during` was not known.
    CHECK(ndms_credential_change(before, after) == Change::changed);
}

TEST_CASE("every verdict and change has a name") {
    for (const auto verdict : {Verdict::known, Verdict::unreadable}) {
        CHECK(std::string(
                  ndms_credential_generation_verdict_name(verdict))
                  .size() > 0U);
    }
    for (const auto change :
         {Change::unchanged, Change::changed, Change::unknown}) {
        CHECK(std::string(ndms_credential_change_name(change)).size() > 0U);
    }
}

} // namespace keen_pbr3
