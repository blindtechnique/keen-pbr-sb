#include <doctest/doctest.h>

#include "../src/config/subscription_import_plan.hpp"

#include <set>
#include <string>

namespace keen_pbr3 {

namespace {

using Kind = SubscriptionDocumentKind;
using Disposition = SubscriptionCandidateDisposition;

const std::set<std::string> kNoTags;
const std::set<std::string> kNoFingerprints;

std::string base64_of(const std::string& value) {
    static const char* alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    std::size_t i = 0U;
    while (i + 2U < value.size()) {
        const auto a = static_cast<unsigned char>(value[i]);
        const auto b = static_cast<unsigned char>(value[i + 1U]);
        const auto c = static_cast<unsigned char>(value[i + 2U]);
        encoded.push_back(alphabet[a >> 2]);
        encoded.push_back(alphabet[((a & 0x03) << 4) | (b >> 4)]);
        encoded.push_back(alphabet[((b & 0x0F) << 2) | (c >> 6)]);
        encoded.push_back(alphabet[c & 0x3F]);
        i += 3U;
    }
    if (i + 1U == value.size()) {
        const auto a = static_cast<unsigned char>(value[i]);
        encoded.push_back(alphabet[a >> 2]);
        encoded.push_back(alphabet[(a & 0x03) << 4]);
        encoded.append("==");
    } else if (i + 2U == value.size()) {
        const auto a = static_cast<unsigned char>(value[i]);
        const auto b = static_cast<unsigned char>(value[i + 1U]);
        encoded.push_back(alphabet[a >> 2]);
        encoded.push_back(alphabet[((a & 0x03) << 4) | (b >> 4)]);
        encoded.push_back(alphabet[(b & 0x0F) << 2]);
        encoded.push_back('=');
    }
    return encoded;
}

} // namespace

TEST_CASE("a plain link list is planned entry by entry") {
    const std::string body =
        "vless://11111111-1111-1111-1111-111111111111@a.example:443?security=tls#NL%2001\n"
        "trojan://secret@b.example:8443#DE%2001\n";
    const auto plan = plan_subscription_import(body, kNoTags, kNoFingerprints);

    CHECK(plan.kind == Kind::link_list);
    REQUIRE(plan.candidates.size() == 2U);
    CHECK(plan.candidates[0].scheme == "vless");
    CHECK(plan.candidates[0].endpoint == "a.example:443");
    CHECK(plan.candidates[0].remark == "NL 01");
    CHECK(plan.candidates[0].suggested_tag == "nl_01");
    CHECK(plan.candidates[0].disposition == Disposition::importable);
    CHECK(plan.candidates[0].source_line == 1U);
    CHECK(plan.candidates[1].scheme == "trojan");
    CHECK(plan.candidates[1].endpoint == "b.example:8443");
    CHECK(plan.candidates[1].suggested_tag == "de_01");
}

TEST_CASE("a candidate has nowhere to put a credential") {
    // The class of defect this shape exists to prevent: a preview response
    // built from candidates cannot carry a UUID or a password, because no
    // field of a candidate can hold one. The links come back separately so
    // that using them is a deliberate act.
    const std::string body =
        "vless://11111111-1111-1111-1111-111111111111@a.example:443#A\n";
    const auto plan = plan_subscription_import(body, kNoTags, kNoFingerprints);

    REQUIRE(plan.candidates.size() == 1U);
    const auto& candidate = plan.candidates[0];
    for (const std::string& field :
         {candidate.scheme, candidate.endpoint, candidate.remark,
          candidate.suggested_tag}) {
        CHECK(field.find("11111111-1111") == std::string::npos);
    }
    REQUIRE(plan.links.size() == plan.candidates.size());
    CHECK(plan.links[0] == body.substr(0U, body.size() - 1U));
}

TEST_CASE("vmess and legacy shadowsocks keep their payload closed") {
    // Both carry the whole outbound, credential included, where a URI would
    // have its authority. Publishing that blob as an "endpoint" would publish
    // the credential with it.
    const std::string body =
        "vmess://eyJhZGQiOiJjLmV4YW1wbGUiLCJpZCI6InNlY3JldC11dWlkIn0=#VM\n"
        "ss://YWVzLTI1Ni1nY206c2VjcmV0QGQuZXhhbXBsZTo4Mzg4#SSLEGACY\n"
        "ss://YWVzLTI1Ni1nY206c2VjcmV0@e.example:8388#SSMODERN\n";
    const auto plan = plan_subscription_import(body, kNoTags, kNoFingerprints);

    REQUIRE(plan.candidates.size() == 3U);
    CHECK(plan.candidates[0].scheme == "vmess");
    CHECK(plan.candidates[0].endpoint.empty());
    CHECK(plan.candidates[0].disposition == Disposition::importable);
    CHECK(plan.candidates[1].scheme == "ss");
    CHECK(plan.candidates[1].endpoint.empty());
    // The modern form puts the host in the clear after '@', so it can be shown.
    CHECK(plan.candidates[2].endpoint == "e.example:8388");
}

TEST_CASE("a base64 subscription body is decoded") {
    const std::string plain =
        "vless://11111111-1111-1111-1111-111111111111@a.example:443#NL\n"
        "trojan://secret@b.example:8443#DE\n";
    const auto plan =
        plan_subscription_import(base64_of(plain), kNoTags, kNoFingerprints);

    CHECK(plan.kind == Kind::base64_link_list);
    REQUIRE(plan.candidates.size() == 2U);
    CHECK(plan.candidates[0].endpoint == "a.example:443");
    CHECK(plan.candidates[1].endpoint == "b.example:8443");
}

TEST_CASE("the url-safe base64 alphabet and missing padding are accepted") {
    // Providers use every combination of the four; a body we decline to decode
    // reaches the operator as an unreadable subscription.
    std::string encoded = base64_of(
        "vless://11111111-1111-1111-1111-111111111111@a.example:443?x=a%2Fb#NL\n");
    for (auto& ch : encoded) {
        if (ch == '+') ch = '-';
        if (ch == '/') ch = '_';
    }
    while (!encoded.empty() && encoded.back() == '=') encoded.pop_back();

    const auto plan = plan_subscription_import(encoded, kNoTags, kNoFingerprints);
    CHECK(plan.kind == Kind::base64_link_list);
    REQUIRE(plan.candidates.size() == 1U);
    CHECK(plan.candidates[0].endpoint == "a.example:443");
}

TEST_CASE("repeated entries are offered once") {
    // Subscriptions routinely repeat, and a label is not an identity: the same
    // proxy listed twice under two names is still one proxy.
    const std::string body =
        "vless://u@a.example:443#First\n"
        "vless://u@a.example:443#First\n"
        "vless://u@a.example:443#Renamed%20later\n"
        "vless://u@b.example:443#Different\n";
    const auto plan = plan_subscription_import(body, kNoTags, kNoFingerprints);

    REQUIRE(plan.candidates.size() == 4U);
    CHECK(plan.candidates[0].disposition == Disposition::importable);
    CHECK(plan.candidates[1].disposition == Disposition::duplicate_in_document);
    CHECK(plan.candidates[1].duplicate_of == 0U);
    CHECK(plan.candidates[2].disposition == Disposition::duplicate_in_document);
    CHECK(plan.candidates[2].duplicate_of == 0U);
    CHECK(plan.candidates[3].disposition == Disposition::importable);
}

TEST_CASE("an entry already configured is reported, not offered again") {
    // The comparison is against a digest, because the other half of it can be
    // nothing else: transport-manager blanks the stored link in its redacted
    // state, since the link carries the credential.
    const std::string link = "vless://u@a.example:443#NL";
    const std::string body = link + "\nvless://u@b.example:443#DE\n";
    const auto plan = plan_subscription_import(
        body,
        kNoTags,
        std::set<std::string>{subscription_link_fingerprint(link)});

    REQUIRE(plan.candidates.size() == 2U);
    CHECK(plan.candidates[0].disposition == Disposition::already_configured);
    CHECK(plan.candidates[1].disposition == Disposition::importable);
}

TEST_CASE("a configured entry is recognised through a renamed label") {
    // The provider relabels entries between fetches. If a label changed the
    // identity, every refetch would offer to import what is already there.
    const std::string configured = "vless://u@a.example:443#Netherlands%2001";
    const std::string body = "vless://u@a.example:443#NL-2\n";
    const auto plan = plan_subscription_import(
        body,
        kNoTags,
        std::set<std::string>{subscription_link_fingerprint(configured)});

    REQUIRE(plan.candidates.size() == 1U);
    CHECK(plan.candidates[0].disposition == Disposition::already_configured);
}

TEST_CASE("the link fingerprint is the contract transport-manager mirrors") {
    // LinkFingerprint in singbox.go derives the same value from the same rule.
    // Nothing at build time couples them, so both sides pin it: a drift here
    // does not fail loudly, it just stops ever matching.
    const std::string identity = "vless://u@a.example:443?security=tls";
    const std::string fingerprint = subscription_link_fingerprint(identity);

    // The exact value transport.LinkFingerprint produces for this link. A
    // shared rule stated twice is not a shared rule until one side's answer is
    // written down where the other side's tests can see it.
    CHECK(fingerprint ==
          "6005eaff07bcbb5ec4fb1c8d192197f961c9c369a74b39861a2e5d37d4bffb50");
    CHECK(fingerprint.size() == 64U);
    CHECK(fingerprint == subscription_link_fingerprint(identity + "#NL"));
    CHECK(fingerprint ==
          subscription_link_fingerprint("  " + identity + "#other  "));
    CHECK(fingerprint !=
          subscription_link_fingerprint("vless://u@b.example:443?security=tls"));
    // A transport built from outbound JSON has no share link, and a
    // subscription - a list of links - can never collide with one.
    for (const char* empty : {"", "   ", "#only-a-fragment"}) {
        CHECK(subscription_link_fingerprint(empty).empty());
    }
}

TEST_CASE("without any known transports nothing is called already configured") {
    // An empty fingerprint set means the transports could not be read, not
    // that there are no conflicts. The plan must not invent the difference;
    // saying so is the caller's job.
    const std::string body = "vless://u@a.example:443#NL\n";
    const auto plan = plan_subscription_import(body, kNoTags, kNoFingerprints);

    REQUIRE(plan.candidates.size() == 1U);
    CHECK(plan.candidates[0].disposition == Disposition::importable);
}

TEST_CASE("a tag an existing transport owns is a conflict, not a rename") {
    // Silently renaming would hide that the operator's own naming collided
    // with the provider's, and the operator is the one who has to decide.
    const std::string body = "vless://u@a.example:443#NL\n";
    const auto plan = plan_subscription_import(
        body, std::set<std::string>{"nl"}, kNoFingerprints);

    REQUIRE(plan.candidates.size() == 1U);
    CHECK(plan.candidates[0].disposition == Disposition::tag_conflict);
    CHECK(plan.candidates[0].suggested_tag == "nl");
}

TEST_CASE("two entries of one document may not claim one tag") {
    // Within a single import the collision is the provider's, not the
    // operator's, so it is broken here rather than referred back.
    const std::string body =
        "vless://u@a.example:443#NL\n"
        "vless://u@b.example:443#nl\n"
        "vless://u@c.example:443#nL\n";
    const auto plan = plan_subscription_import(body, kNoTags, kNoFingerprints);

    REQUIRE(plan.candidates.size() == 3U);
    CHECK(plan.candidates[0].suggested_tag == "nl");
    CHECK(plan.candidates[1].suggested_tag == "nl_2");
    CHECK(plan.candidates[2].suggested_tag == "nl_3");
    for (const auto& candidate : plan.candidates) {
        CHECK(candidate.disposition == Disposition::importable);
    }
}

TEST_CASE("a derived tag always satisfies the transport tag pattern") {
    struct Sample {
        const char* remark;
        const char* expected;
    };
    const Sample samples[] = {
        {"NL 01", "nl_01"},
        // Punctuation is a separator, so a differently punctuated label is a
        // different tag rather than a collision to be broken.
        {"N.L.", "n_l"},
        {"01 Netherlands", "netherlands"},
        {"\xF0\x9F\x87\xB3\xF0\x9F\x87\xB1 Amsterdam", "amsterdam"},
        {"---", "sub_7"},
        {"", "sub_7"},
        {"\xD0\xA0\xD0\xBE\xD1\x81\xD1\x81\xD0\xB8\xD1\x8F", "sub_7"},
        {"a-very-long-remark-that-will-not-fit-in-a-tag",
         "a_very_long_remark_that"},
    };
    for (const auto& sample : samples) {
        const std::string tag = derive_subscription_tag(sample.remark, 7U);
        CHECK(tag == sample.expected);
        REQUIRE_FALSE(tag.empty());
        CHECK(tag.size() <= kSubscriptionMaximumTagLength);
        CHECK(tag.front() >= 'a');
        CHECK(tag.front() <= 'z');
        for (const char ch : tag) {
            CHECK(((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
                   ch == '_'));
        }
    }
}

TEST_CASE("a uniquifying suffix cannot push a tag past the pattern") {
    // Truncating the suffix instead of the base would reintroduce exactly the
    // collision the suffix exists to break.
    const std::string remark = "a-very-long-remark-that-will-not-fit";
    const std::string body =
        "vless://u@a.example:443#" + remark + "\n" +
        "vless://u@b.example:443#" + remark + "\n";
    const auto plan = plan_subscription_import(body, kNoTags, kNoFingerprints);

    REQUIRE(plan.candidates.size() == 2U);
    CHECK(plan.candidates[0].suggested_tag.size() <=
          kSubscriptionMaximumTagLength);
    CHECK(plan.candidates[1].suggested_tag.size() <=
          kSubscriptionMaximumTagLength);
    CHECK(plan.candidates[0].suggested_tag !=
          plan.candidates[1].suggested_tag);
    CHECK(plan.candidates[1].disposition == Disposition::importable);
}

TEST_CASE("a remark may not lie about the entry it labels") {
    // A right-to-left override inside a label can make a preview render an
    // endpoint the import will not use. A preview that can be made to show the
    // wrong thing is worse than no preview.
    const std::string body =
        "vless://u@evil.example:443#safe\xE2\x80\xAE""elpmaxe.dog\n"
        "vless://u@a.example:443#tab\there\n";
    const auto plan = plan_subscription_import(body, kNoTags, kNoFingerprints);

    REQUIRE(plan.candidates.size() == 2U);
    CHECK(plan.candidates[0].remark.find("\xE2\x80\xAE") == std::string::npos);
    CHECK(plan.candidates[0].endpoint == "evil.example:443");
    CHECK(plan.candidates[1].remark.find('\t') == std::string::npos);
}

TEST_CASE("a scheme transport-manager will not accept is named as such") {
    // Reported now rather than as a create failure after the operator has
    // selected it.
    const std::string body =
        "ssr://legacy-scheme\n"
        "wireguard://not-a-real-share-link\n"
        "vless://u@a.example:443#ok\n";
    const auto plan = plan_subscription_import(body, kNoTags, kNoFingerprints);

    REQUIRE(plan.candidates.size() == 3U);
    CHECK(plan.candidates[0].disposition == Disposition::scheme_not_supported);
    CHECK(plan.candidates[0].scheme == "ssr");
    CHECK(plan.candidates[1].disposition == Disposition::scheme_not_supported);
    CHECK(plan.candidates[2].disposition == Disposition::importable);
}

TEST_CASE("the supported scheme list tracks the parser that runs") {
    for (const char* scheme :
         {"vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic",
          "anytls", "naive", "naive+https", "naive+quic", "socks", "socks5",
          "http", "https"}) {
        CHECK(subscription_scheme_supported(scheme));
    }
    for (const char* scheme : {"ssr", "wireguard", "file", "data", "", "vle"}) {
        CHECK_FALSE(subscription_scheme_supported(scheme));
    }
}

TEST_CASE("comments and blank lines do not become entries") {
    const std::string body =
        "# provider banner\n"
        "\n"
        "   \n"
        "vless://u@a.example:443#NL\n"
        "\n";
    const auto plan = plan_subscription_import(body, kNoTags, kNoFingerprints);

    REQUIRE(plan.candidates.size() == 1U);
    // ...but they still count: the line reported is the one in the document
    // the provider serves, not the one in our filtered view of it.
    CHECK(plan.candidates[0].source_line == 4U);
    CHECK(plan.candidates[0].disposition == Disposition::importable);
}

TEST_CASE("a fragment '#' inside a link is a remark, not a comment") {
    const std::string body = "vless://u@a.example:443#NL\n";
    const auto plan = plan_subscription_import(body, kNoTags, kNoFingerprints);
    REQUIRE(plan.candidates.size() == 1U);
    CHECK(plan.candidates[0].remark == "NL");
}

TEST_CASE("a sing-box configuration document is named, not called garbage") {
    for (const char* body : {"{\"outbounds\": []}", "  [ {\"type\": \"vless\"} ]"}) {
        const auto plan = plan_subscription_import(body, kNoTags, kNoFingerprints);
        CHECK(plan.kind == Kind::json_document);
        CHECK(plan.candidates.empty());
    }
}

TEST_CASE("a body that is not a subscription is refused, not half-read") {
    const auto empty = plan_subscription_import("", kNoTags, kNoFingerprints);
    CHECK(empty.kind == Kind::empty);
    CHECK(empty.candidates.empty());

    const auto blank = plan_subscription_import("\n \n\n", kNoTags, kNoFingerprints);
    CHECK(blank.kind == Kind::empty);

    const auto html = plan_subscription_import(
        "<html><body>Login required</body></html>", kNoTags, kNoFingerprints);
    CHECK(html.kind == Kind::unrecognized);
    CHECK(html.candidates.empty());
}

TEST_CASE("an oversized body is refused whole rather than truncated") {
    // A silently shortened import is a worse answer than a refused one: the
    // operator would have no way to see what was dropped.
    const std::string oversized(kSubscriptionMaximumBytes + 1U, 'a');
    const auto plan = plan_subscription_import(oversized, kNoTags, kNoFingerprints);
    CHECK(plan.kind == Kind::too_large);
    CHECK(plan.candidates.empty());
    CHECK(plan.links.empty());

    std::string many;
    for (std::size_t i = 0U; i <= kSubscriptionMaximumEntries; ++i) {
        many += "vless://u@h" + std::to_string(i) + ".example:443#n\n";
    }
    REQUIRE(many.size() <= kSubscriptionMaximumBytes);
    const auto crowded = plan_subscription_import(many, kNoTags, kNoFingerprints);
    CHECK(crowded.kind == Kind::too_large);
    CHECK(crowded.candidates.empty());
    CHECK(crowded.links.empty());
}

TEST_CASE("links stay positionally aligned with candidates") {
    // A preview the operator acts on is indexed into this pair; a shift would
    // import a different proxy than the one they chose.
    const std::string body =
        "not a link at all\n"
        "ssr://unsupported\n"
        "vless://u@a.example:443#NL\n"
        "vless://u@a.example:443#NL\n";
    const auto plan = plan_subscription_import(body, kNoTags, kNoFingerprints);

    REQUIRE(plan.candidates.size() == 4U);
    REQUIRE(plan.links.size() == plan.candidates.size());
    for (std::size_t i = 0U; i < plan.candidates.size(); ++i) {
        CHECK(plan.candidates[i].source_line == i + 1U);
    }
    CHECK(plan.candidates[0].disposition == Disposition::malformed);
    CHECK(plan.links[2] == "vless://u@a.example:443#NL");
}

TEST_CASE("every kind and disposition has a name") {
    for (const auto kind :
         {Kind::link_list, Kind::base64_link_list, Kind::json_document,
          Kind::empty, Kind::unrecognized, Kind::too_large}) {
        CHECK(std::string(subscription_document_kind_name(kind)).size() > 0U);
    }
    for (const auto disposition :
         {Disposition::importable, Disposition::duplicate_in_document,
          Disposition::already_configured, Disposition::tag_conflict,
          Disposition::scheme_not_supported, Disposition::malformed}) {
        CHECK(std::string(
                  subscription_candidate_disposition_name(disposition))
                  .size() > 0U);
    }
}

} // namespace keen_pbr3
