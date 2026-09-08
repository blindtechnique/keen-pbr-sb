#include "tunnel_probe_review.hpp"

#include "../config/config_writer.hpp"
#include "../nfqws/list_match.hpp"

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <nlohmann/json.hpp>
#include <set>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace keen_pbr3 {
namespace {

constexpr std::size_t kMaxContextBytes = 4096U;

bool valid_host(const std::string& host) {
    if (host.empty() || host.size() > 253U || host.front() == '.' ||
        host.back() == '.' || host.find('.') == std::string::npos) return false;
    return std::all_of(host.begin(), host.end(), [](unsigned char value) {
        return (value >= 'a' && value <= 'z') ||
               (value >= 'A' && value <= 'Z') ||
               (value >= '0' && value <= '9') || value == '.' ||
               value == '-' || value == '_';
    });
}

std::set<std::string> membership(const std::vector<std::string>& routed,
                                  const std::vector<std::string>& excluded) {
    std::set<std::string> current;
    for (const auto& host : routed) {
        if (valid_host(host) && !nfqws::match_hostlist(excluded, host)) {
            current.insert(host);
        }
    }
    return current;
}

auto find_entry(TunnelProbeReviewState& state, const std::string& host) {
    return std::find_if(state.entries.begin(), state.entries.end(),
                        [&host](const auto& entry) {
                            return entry.record.host == host;
                        });
}

void reset_observations(TunnelProbeReviewEntry& entry,
                         std::uint64_t now_unix_ms) {
    entry.record.direct_successes = 0U;
    entry.record.blocked_confirmations = 0U;
    entry.record.last = DifferentialVerdict::inconclusive;
    entry.last_observation = DifferentialVerdict::inconclusive;
    entry.eligible = false;
    entry.last_checked_unix_ms = 0U;
    entry.next_due_unix_ms = entry.active ? now_unix_ms : 0U;
    entry.updated_at_unix_ms = now_unix_ms;
}

bool make_room(TunnelProbeReviewState& state) {
    if (state.entries.size() < kTunnelProbeReviewMaxEntries) return true;
    auto oldest = state.entries.end();
    for (auto it = state.entries.begin(); it != state.entries.end(); ++it) {
        if (it->active) continue;
        if (oldest == state.entries.end() ||
            it->updated_at_unix_ms < oldest->updated_at_unix_ms ||
            (it->updated_at_unix_ms == oldest->updated_at_unix_ms &&
             it->record.host < oldest->record.host)) oldest = it;
    }
    if (oldest == state.entries.end()) return false;
    state.entries.erase(oldest);
    return true;
}

std::uint64_t unsigned_field(const nlohmann::json& value, const char* name,
                              std::uint64_t maximum = UINT64_MAX) {
    const auto& field = value.at(name);
    if (!field.is_number_integer() ||
        (!field.is_number_unsigned() && field.get<std::int64_t>() < 0)) {
        throw std::runtime_error("Invalid review numeric field");
    }
    const auto number = field.get<std::uint64_t>();
    if (number > maximum) throw std::runtime_error("Review numeric field exceeds limit");
    return number;
}

DifferentialVerdict verdict_field(const nlohmann::json& value,
                                   const char* name) {
    const auto text = value.at(name).get<std::string>();
    if (text == "blocked_here") return DifferentialVerdict::blocked_here;
    if (text == "down_everywhere") return DifferentialVerdict::down_everywhere;
    if (text == "works_without_help") return DifferentialVerdict::works_without_help;
    if (text == "tunnel_broken") return DifferentialVerdict::tunnel_broken;
    if (text == "inconclusive") return DifferentialVerdict::inconclusive;
    throw std::runtime_error("Invalid review verdict");
}

nlohmann::json encode_state(const TunnelProbeReviewState& state) {
    if (state.entries.size() > kTunnelProbeReviewMaxEntries ||
        state.context.size() > kMaxContextBytes) {
        throw std::length_error("Review metadata exceeds limit");
    }
    nlohmann::json entries = nlohmann::json::array();
    std::set<std::string> hosts;
    for (const auto& entry : state.entries) {
        if (!valid_host(entry.record.host) ||
            !hosts.insert(entry.record.host).second) {
            throw std::runtime_error("Invalid review host");
        }
        entries.push_back({
            {"host", entry.record.host},
            {"active", entry.active},
            {"eligible", entry.eligible},
            {"direct_successes", entry.record.direct_successes},
            {"blocked_confirmations", entry.record.blocked_confirmations},
            {"retirements", entry.record.retirements},
            {"last", differential_verdict_name(entry.record.last)},
            {"last_observation", differential_verdict_name(entry.last_observation)},
            {"last_checked_unix_ms", entry.last_checked_unix_ms},
            {"next_due_unix_ms", entry.next_due_unix_ms},
            {"updated_at_unix_ms", entry.updated_at_unix_ms},
        });
    }
    return {{"version", 1}, {"context", state.context},
            {"limited", state.limited}, {"entries", std::move(entries)}};
}

TunnelProbeReviewState decode_state(const nlohmann::json& document) {
    if (!document.is_object() || unsigned_field(document, "version") != 1U) {
        throw std::runtime_error("Unknown review metadata format");
    }
    TunnelProbeReviewState state;
    state.context = document.at("context").get<std::string>();
    state.limited = document.value("limited", false);
    const auto& entries = document.at("entries");
    if (state.context.size() > kMaxContextBytes || !entries.is_array() ||
        entries.size() > kTunnelProbeReviewMaxEntries) {
        throw std::length_error("Review metadata exceeds limit");
    }
    std::set<std::string> hosts;
    for (const auto& value : entries) {
        TunnelProbeReviewEntry entry;
        entry.record.host = value.at("host").get<std::string>();
        if (!valid_host(entry.record.host) ||
            !hosts.insert(entry.record.host).second) {
            throw std::runtime_error("Invalid review host");
        }
        entry.active = value.at("active").get<bool>();
        entry.eligible = value.at("eligible").get<bool>();
        entry.record.direct_successes = static_cast<std::uint32_t>(
            unsigned_field(value, "direct_successes", UINT32_MAX));
        entry.record.blocked_confirmations = static_cast<std::uint32_t>(
            unsigned_field(value, "blocked_confirmations", UINT32_MAX));
        entry.record.retirements = static_cast<std::uint32_t>(
            unsigned_field(value, "retirements", UINT32_MAX));
        entry.record.last = verdict_field(value, "last");
        entry.last_observation = verdict_field(value, "last_observation");
        entry.last_checked_unix_ms = unsigned_field(value, "last_checked_unix_ms");
        entry.next_due_unix_ms = unsigned_field(value, "next_due_unix_ms");
        entry.updated_at_unix_ms = unsigned_field(value, "updated_at_unix_ms");
        // Proposal status follows counters, not an independently editable flag.
        entry.eligible = entry.active && entry.eligible &&
            entry.record.direct_successes >= effective_retire_after(entry.record, {});
        state.entries.push_back(std::move(entry));
    }
    return state;
}

} // namespace

std::mutex& tunnel_probe_list_io_mutex() {
    static std::mutex mutex;
    return mutex;
}

std::string tunnel_probe_review_path(const std::string& list_file) {
    return list_file + ".review";
}

std::string tunnel_probe_review_context(const std::string& outbound_tag,
                                       const std::string& interface,
                                       const std::string& isp_interface,
                                       const std::string& list_name,
                                       const std::string& list_file) {
    std::string result;
    for (const auto* part : {&outbound_tag, &interface, &isp_interface,
                             &list_name, &list_file}) {
        result += std::to_string(part->size()) + ':' + *part;
    }
    return result;
}

TunnelProbeReviewState load_tunnel_probe_review(
    const std::string& list_file, std::string& error) {
    error.clear();
    try {
        const auto path = tunnel_probe_review_path(list_file);
        std::ifstream input(path, std::ios::binary);
        if (!input) {
            std::error_code status_error;
            if (!std::filesystem::exists(path, status_error) && !status_error) return {};
            error = "Could not read tunnel review metadata";
            return {};
        }
        std::string body;
        std::array<char, 4096U> buffer{};
        while (input && body.size() <= kTunnelProbeReviewMaxBytes) {
            const auto count = std::min(buffer.size(),
                kTunnelProbeReviewMaxBytes + 1U - body.size());
            input.read(buffer.data(), static_cast<std::streamsize>(count));
            body.append(buffer.data(), static_cast<std::size_t>(input.gcount()));
        }
        if (body.size() > kTunnelProbeReviewMaxBytes) {
            error = "Tunnel review metadata exceeds size limit";
            return {};
        }
        if (input.bad()) {
            error = "Could not read tunnel review metadata";
            return {};
        }
        return decode_state(nlohmann::json::parse(body));
    } catch (const std::exception&) {
        error = "Invalid or unreadable tunnel review metadata";
        return {};
    }
}

bool save_tunnel_probe_review(const std::string& list_file,
                             const TunnelProbeReviewState& state,
                             std::string& error) {
    error.clear();
    try {
        const auto body = encode_state(state).dump();
        if (body.size() > kTunnelProbeReviewMaxBytes) {
            error = "Tunnel review metadata exceeds size limit";
            return false;
        }
        write_file_atomically(tunnel_probe_review_path(list_file), body);
        return true;
    } catch (const std::exception&) {
        error = "Could not save tunnel review metadata";
        return false;
    }
}

bool sync_tunnel_probe_review(TunnelProbeReviewState& state,
                             const std::string& context,
                             const std::vector<std::string>& routed,
                             const std::vector<std::string>& excluded,
                             std::uint64_t now_unix_ms) {
    const auto current = membership(routed, excluded);
    const bool context_changed = state.context != context;
    bool changed = context_changed;
    if (context_changed) state.context = context;
    const bool limited = current.size() > kTunnelProbeReviewMaxEntries;
    if (state.limited != limited) {
        state.limited = limited;
        changed = true;
    }
    for (auto& entry : state.entries) {
        const bool active = current.count(entry.record.host) != 0U;
        if (context_changed || entry.active != active) {
            entry.active = active;
            reset_observations(entry, now_unix_ms);
            changed = true;
        }
    }
    for (const auto& host : current) {
        if (find_entry(state, host) != state.entries.end()) continue;
        if (!make_room(state)) continue;
        TunnelProbeReviewEntry entry;
        entry.record.host = host;
        entry.active = true;
        entry.next_due_unix_ms = now_unix_ms;
        entry.updated_at_unix_ms = now_unix_ms;
        state.entries.push_back(std::move(entry));
        changed = true;
    }
    return changed;
}

std::vector<std::string> due_tunnel_probe_reviews(
    const TunnelProbeReviewState& state, std::uint64_t now_unix_ms,
    std::size_t limit) {
    std::vector<const TunnelProbeReviewEntry*> due;
    for (const auto& entry : state.entries) {
        if (entry.active && entry.next_due_unix_ms <= now_unix_ms) due.push_back(&entry);
    }
    std::sort(due.begin(), due.end(), [](const auto* left, const auto* right) {
        if (left->next_due_unix_ms != right->next_due_unix_ms) {
            return left->next_due_unix_ms < right->next_due_unix_ms;
        }
        return left->record.host < right->record.host;
    });
    std::vector<std::string> hosts;
    for (std::size_t i = 0U; i < std::min(limit, due.size()); ++i) {
        hosts.push_back(due[i]->record.host);
    }
    return hosts;
}

std::vector<TunnelProbeReviewEntry> filter_tunnel_probe_reviews(
    const TunnelProbeReviewState& state,
    const std::vector<std::string>& routed,
    const std::vector<std::string>& excluded) {
    const auto current = membership(routed, excluded);
    std::vector<TunnelProbeReviewEntry> entries;
    for (const auto& entry : state.entries) {
        if (entry.active && current.count(entry.record.host) != 0U) entries.push_back(entry);
    }
    return entries;
}

bool observe_tunnel_probe_review(
    TunnelProbeReviewState& state, const std::string& context,
    const std::string& host, DifferentialVerdict verdict,
    std::uint64_t now_unix_ms, const ReviewPolicy& policy) {
    if (context.empty() || state.context != context) return false;
    const auto found = find_entry(state, host);
    if (found == state.entries.end() || !found->active ||
        found->next_due_unix_ms > now_unix_ms) return false;
    const auto action = review_step(found->record, verdict, policy);
    if (action != ReviewAction::hold) {
        found->eligible = action == ReviewAction::propose_retirement;
    }
    found->last_observation = verdict;
    found->last_checked_unix_ms = now_unix_ms;
    found->updated_at_unix_ms = now_unix_ms;
    const auto minutes = next_review_interval(found->record, policy).count();
    const auto maximum = std::numeric_limits<std::uint64_t>::max();
    const auto positive_minutes = static_cast<std::uint64_t>(minutes);
    const auto delay = positive_minutes > maximum / 60000U
        ? maximum : positive_minutes * 60000U;
    found->next_due_unix_ms = now_unix_ms > maximum - delay
        ? maximum : now_unix_ms + delay;
    return true;
}

void note_tunnel_probe_review_removal(TunnelProbeReviewState& state,
                                    const std::string& host,
                                    std::uint64_t now_unix_ms) {
    if (!valid_host(host)) return;
    auto found = find_entry(state, host);
    if (found == state.entries.end()) {
        if (!make_room(state)) return;
        TunnelProbeReviewEntry entry;
        entry.record.host = host;
        state.entries.push_back(std::move(entry));
        found = std::prev(state.entries.end());
    } else if (!found->active && found->record.retirements > 0U) {
        return;
    }
    note_retirement(found->record);
    found->active = false;
    reset_observations(*found, now_unix_ms);
}

} // namespace keen_pbr3
