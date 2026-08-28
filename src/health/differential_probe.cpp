#include "differential_probe.hpp"

#include <algorithm>
#include <cctype>

namespace keen_pbr3 {

namespace {

std::string lowercased(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

const std::string* find_header(const HttpTransportResponse& response,
                               const std::string& name) {
    const auto it = response.headers.find(name);
    return it == response.headers.end() ? nullptr : &it->second;
}

bool is_redirect(const long status_code) noexcept {
    return status_code >= 300 && status_code < 400;
}

// The last two labels, which is as close to "the same site" as this can get
// without carrying a public suffix list. It is deliberately generous: calling
// an ordinary move interference would invent a block, while missing an
// interceptor that redirects within the same registrable domain only costs us
// one candidate.
//
// Found by live data, not by reasoning: facebook.com answers 301 to
// www.facebook.com, and exact host comparison called that interference.
std::string registrable_suffix(const std::string& host) {
    const auto last_dot = host.rfind('.');
    if (last_dot == std::string::npos || last_dot == 0U) return host;
    const auto previous_dot = host.rfind('.', last_dot - 1U);
    if (previous_dot == std::string::npos) return host;
    return host.substr(previous_dot + 1U);
}

bool same_site(const std::string& left, const std::string& right) {
    if (left == right) return true;
    return registrable_suffix(left) == registrable_suffix(right);
}

}  // namespace

std::string differential_url_host(const std::string& url) noexcept {
    const auto scheme = url.find("://");
    const auto start = scheme == std::string::npos ? 0U : scheme + 3U;
    if (start >= url.size()) return {};
    auto authority = url.substr(start);
    const auto end = authority.find_first_of("/?#");
    if (end != std::string::npos) authority.resize(end);
    const auto at = authority.rfind('@');
    if (at != std::string::npos) authority = authority.substr(at + 1U);
    if (!authority.empty() && authority.front() == '[') {
        const auto closing = authority.find(']');
        if (closing == std::string::npos) return {};
        return lowercased(authority.substr(1U, closing - 1U));
    }
    const auto colon = authority.find(':');
    if (colon != std::string::npos) authority.resize(colon);
    return lowercased(authority);
}

DifferentialVerdict classify_differential(
    const DifferentialObservation observation) noexcept {
    // An unattributed leg is not a soft failure to be averaged in. It means the
    // probe cannot say which path it took, so the comparison it belongs to has
    // no meaning at all.
    if (observation.direct == PathOutcome::unattributed ||
        observation.tunnel == PathOutcome::unattributed) {
        return DifferentialVerdict::inconclusive;
    }
    const bool direct_ok = observation.direct == PathOutcome::reachable;
    const bool tunnel_ok = observation.tunnel == PathOutcome::reachable;
    if (!direct_ok && tunnel_ok) return DifferentialVerdict::blocked_here;
    if (!direct_ok && !tunnel_ok) return DifferentialVerdict::down_everywhere;
    if (direct_ok && tunnel_ok) return DifferentialVerdict::works_without_help;
    return DifferentialVerdict::tunnel_broken;
}

const char* differential_verdict_name(const DifferentialVerdict verdict) noexcept {
    switch (verdict) {
        case DifferentialVerdict::blocked_here:
            return "blocked_here";
        case DifferentialVerdict::down_everywhere:
            return "down_everywhere";
        case DifferentialVerdict::works_without_help:
            return "works_without_help";
        case DifferentialVerdict::tunnel_broken:
            return "tunnel_broken";
        case DifferentialVerdict::inconclusive:
            break;
    }
    return "inconclusive";
}

bool differential_verdict_justifies_tunnel(
    const DifferentialVerdict verdict) noexcept {
    return verdict == DifferentialVerdict::blocked_here;
}

DifferentialLeg probe_one_path(HttpTransport& transport,
                               const std::string& url,
                               const DifferentialPath& path,
                               const std::uint32_t timeout_ms) {
    DifferentialLeg leg;
    if (path.interface.empty()) {
        // Refused before any packet leaves. Performing the request anyway would
        // produce an outcome about whatever routing the mark happened to pick,
        // and there would be no way to tell afterwards.
        leg.outcome = PathOutcome::unattributed;
        leg.detail = "no device to pin this leg to, so it proves nothing";
        return leg;
    }

    HttpTransportRequest request;
    request.url = url;
    request.timeout_ms = static_cast<long>(timeout_ms);
    request.user_agent = "keen-pbr-differential";
    request.fwmark = path.fwmark;
    request.bind_interface = path.interface;
    // Not followed on purpose: an interceptor answers with a redirect to its
    // own page, and following it would turn interference into "reachable".
    request.max_redirects = 0;
    request.discard_body = true;

    try {
        const auto response = transport.perform(request);
        leg.status_code = response.status_code;
        if (is_redirect(response.status_code)) {
            const auto* location = find_header(response, "location");
            const auto target_host = differential_url_host(url);
            const auto redirect_host =
                location == nullptr ? std::string{} : differential_url_host(*location);
            if (!redirect_host.empty() && !target_host.empty() &&
                !same_site(redirect_host, target_host)) {
                leg.outcome = PathOutcome::unreachable;
                leg.detail = "redirected to " + redirect_host +
                             " instead of answering - the shape nfqws2 treats "
                             "as interference";
                return leg;
            }
        }
        leg.outcome = PathOutcome::reachable;
        leg.detail = "the server answered";
        return leg;
    } catch (const HttpTransportBindError& error) {
        // The one error that must never be read as a failure of the target.
        leg.outcome = PathOutcome::unattributed;
        leg.detail = std::string{"could not pin the probe to "} + path.interface +
                     ": " + error.what();
        return leg;
    } catch (const HttpTransportError& error) {
        leg.outcome = PathOutcome::unreachable;
        leg.detail = error.what();
        return leg;
    }
}

DifferentialProbeReport run_differential_probe(
    HttpTransport& transport, const DifferentialProbeRequest& request) {
    DifferentialProbeReport report;
    report.direct = probe_one_path(transport, request.url, request.direct,
                                   request.timeout_ms);
    report.tunnel = probe_one_path(transport, request.url, request.tunnel,
                                   request.timeout_ms);
    report.verdict = classify_differential(
        DifferentialObservation{report.direct.outcome, report.tunnel.outcome});
    return report;
}

}  // namespace keen_pbr3
