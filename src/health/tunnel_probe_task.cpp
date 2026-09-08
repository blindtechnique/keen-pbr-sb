#include "tunnel_probe_task.hpp"

#include <algorithm>
#include <mutex>
#include <sstream>
#include <utility>

namespace keen_pbr3 {

TunnelProbeTask::TunnelProbeTask(Io io) : io_(std::move(io)) {}

TunnelProbeTask::PassOutcome TunnelProbeTask::run(const Config& config) {
    PassOutcome outcome;

    const auto setup_result = resolve_tunnel_probe_setup(config);
    if (!setup_result.setup.has_value()) {
        outcome.refusal = setup_result.refusal;
        return outcome;
    }
    const auto& setup = *setup_result.setup;

    const auto read_limited = [this](const std::string& path) {
        if (io_.read_limited_file) {
            return io_.read_limited_file(path, kListReadBudget);
        }
        auto text = io_.read_file(path);
        return text.size() <= kListReadBudget
                   ? std::optional<std::string>{std::move(text)}
                   : std::nullopt;
    };
    const auto current_setup_matches = [this, &setup]() {
        if (!io_.current_setup) return true;
        const auto current = io_.current_setup();
        return current && current->outbound_tag == setup.outbound_tag &&
               current->interface == setup.interface &&
               current->list_name == setup.list_name &&
               current->list_file == setup.list_file &&
               current->exclude_file == setup.exclude_file &&
               current->require_registry_confirmation ==
                   setup.require_registry_confirmation;
    };
    if (!current_setup_matches()) {
        outcome.target_changed = true;
        return outcome;
    }

    std::optional<std::string> existing;
    std::optional<std::string> excluded;
    {
        // The same short file mutex is used by explicit panel list edits.
        // Never hold it while following logs or making network requests.
        std::lock_guard<std::mutex> guard(tunnel_probe_list_io_mutex());
        if (io_.ensure_file) io_.ensure_file(setup.list_file);
        existing = read_limited(setup.list_file);
        excluded = read_limited(setup.exclude_file);
    }
    if (!existing || !excluded) {
        outcome.write_failed = true;
        return outcome;
    }

    const auto source_config = read_limited(kNfqwsConfigPath);
    if (!source_config) {
        outcome.source_error = NfqwsScanSourceError::config_unreadable;
        return outcome;
    }
    const auto source_result = read_nfqws_scan_source(
        kNfqwsConfigPath, [this, &source_config](const std::string& path) {
            return path == kNfqwsConfigPath ? *source_config : io_.read_file(path);
        });
    NfqwsScanSource source;
    if (source_result.source) {
        source = *source_result.source;
    } else {
        outcome.source_error = source_result.error;
        // Reviews need the provider device, not nfqws's evidence log. An
        // already routed host deliberately no longer produces that evidence.
        if (source_result.error != NfqwsScanSourceError::no_debug_log) {
            return outcome;
        }
        source.isp_interface = nfqws_flag_value(*source_config, "ISP_INTERFACE");
        if (source.isp_interface.empty()) {
            outcome.source_error = NfqwsScanSourceError::no_isp_interface;
            return outcome;
        }
    }

    const auto target_is_current = [&]() {
        if (!current_setup_matches()) return false;
        const auto text = read_limited(kNfqwsConfigPath);
        return text && nfqws_flag_value(*text, "ISP_INTERFACE") == source.isp_interface;
    };
    const std::string context = tunnel_probe_review_context(
        setup.outbound_tag, setup.interface, source.isp_interface,
        setup.list_name, setup.list_file);
    const std::string key = context + '\n' + source.log_path + '\n' +
                            std::to_string(setup.max_probes_per_pass) + '\n' +
                            (setup.require_registry_confirmation ? "registry" : "all");
    if (scan_key_ != key) {
        scan_.reset();
        scan_key_ = key;
        log_position_ = LogPosition{};
        single_probe_review_turn_ = true;
    }
    if (source_result.source) {
        auto coverage = build_scan_coverage(config, source);
        CoverageIndex::RoutingList routed;
        routed.name = setup.list_name;
        routed.domains = parse_host_list_file(*existing);
        coverage.routing_lists.push_back(std::move(routed));

        // Excluded hosts count as covered, so they are never even probed.
        // Refusing them only at the moment of writing would still cost two
        // requests each, every pass, to ask a question already answered.
        CoverageIndex::RoutingList never;
        never.name = setup.list_name + " (excluded)";
        never.domains = parse_host_list_file(*excluded);
        coverage.routing_lists.push_back(std::move(never));

        if (scan_) {
            scan_->update_coverage(std::move(coverage));
        } else {
            TunnelScanConfig scan_config;
            scan_config.max_probes_per_pass = setup.max_probes_per_pass;
            scan_ = std::make_unique<TunnelCandidateScan>(std::move(coverage),
                                                          scan_config);
            if (setup.require_registry_confirmation && io_.registry_lookup) {
                scan_->set_registry_lookup(io_.registry_lookup);
            }
        }
    }

    if (scan_) {
        std::uint64_t log_size = 0;
        std::string fingerprint;
        if (!io_.stat_log || !io_.stat_log(source.log_path, log_size, fingerprint) ||
            log_size == 0) {
            outcome.log_empty = true;
        } else {
            const auto decision = decide_follow(log_position_, log_size, fingerprint);
            if (decision == FollowDecision::restart) {
                log_position_ = LogPosition{};
                outcome.log_restarted = true;
            }
            if (decision != FollowDecision::nothing_new) {
                const auto chunk = io_.read_log_from(
                    source.log_path, log_position_.offset, kLogReadBudget);
                auto followed = split_followed_lines(log_position_, chunk, kLogReadBudget);
                log_position_ = std::move(followed.position);
                log_position_.fingerprint = fingerprint;
                outcome.new_log_lines = followed.lines.size();
                scan_->observe(followed.lines);
            }
        }
    }

    std::vector<std::string> due_reviews;
    const bool reviews_enabled = io_.clock_unix_ms && io_.load_review && io_.save_review;
    if (reviews_enabled) {
        std::lock_guard<std::mutex> guard(tunnel_probe_list_io_mutex());
        if (!target_is_current()) {
            outcome.target_changed = true;
            return outcome;
        }
        existing = read_limited(setup.list_file);
        excluded = read_limited(setup.exclude_file);
        if (!existing || !excluded) {
            outcome.write_failed = true;
            return outcome;
        }
        std::string error;
        auto state = io_.load_review(setup.list_file, error);
        const auto now = io_.clock_unix_ms();
        if (sync_tunnel_probe_review(state, context, parse_host_list_file(*existing),
                                    parse_host_list_file(*excluded), now)) {
            outcome.review_write_failed = !io_.save_review(setup.list_file, state, error);
        }
        // If the initial history cannot be saved, spending network work on
        // the same new record each minute would produce no durable progress.
        // Candidate discovery keeps its full budget and continues normally.
        if (!outcome.review_write_failed) {
            due_reviews = due_tunnel_probe_reviews(state, now, 1U);
        }
    }

    std::size_t candidate_budget = setup.max_probes_per_pass;
    bool review_this_pass = !due_reviews.empty();
    if (review_this_pass && candidate_budget == 1U && scan_ && scan_->queued() > 0U) {
        review_this_pass = single_probe_review_turn_;
        single_probe_review_turn_ = !single_probe_review_turn_;
    }
    if (review_this_pass) --candidate_budget;

    const auto probe = [this, &source, &setup, &outcome, &target_is_current,
                        &read_limited](const std::string& host, bool review) {
        if (!target_is_current()) {
            outcome.target_changed = true;
            return DifferentialProbeReport{};
        }
        std::optional<std::string> current_list;
        std::optional<std::string> current_excluded;
        {
            std::lock_guard<std::mutex> guard(tunnel_probe_list_io_mutex());
            current_list = read_limited(setup.list_file);
            current_excluded = read_limited(setup.exclude_file);
        }
        if (!current_list || !current_excluded) return DifferentialProbeReport{};
        const auto routed_hosts = parse_host_list_file(*current_list);
        const auto excluded_hosts = parse_host_list_file(*current_excluded);
        if (nfqws::match_hostlist(excluded_hosts, host)) return DifferentialProbeReport{};
        if (review) {
            if (std::find(routed_hosts.begin(), routed_hosts.end(), host) == routed_hosts.end()) {
                return DifferentialProbeReport{};
            }
        } else if (nfqws::match_hostlist(routed_hosts, host)) {
            return DifferentialProbeReport{};
        }
        DifferentialProbeRequest request;
        request.url = "https://" + host + "/";
        request.direct = DifferentialPath{0U, source.isp_interface};
        request.tunnel = DifferentialPath{0U, setup.interface};
        ++outcome.probed;
        outcome.ran = true;
        return io_.run_probe(request);
    };

    if (review_this_pass) {
        const auto& host = due_reviews.front();
        const auto before_probe = outcome.probed;
        const auto answer = probe(host, true);
        if (outcome.target_changed) return outcome;
        const bool request_observed = outcome.probed != before_probe;
        if (request_observed) ++outcome.reviewed;
        else ++candidate_budget;
        std::lock_guard<std::mutex> guard(tunnel_probe_list_io_mutex());
        if (!target_is_current()) {
            outcome.target_changed = true;
            return outcome;
        }
        const auto current_list = read_limited(setup.list_file);
        const auto current_excluded = read_limited(setup.exclude_file);
        if (current_list && current_excluded) {
            std::string error;
            auto state = io_.load_review(setup.list_file, error);
            const auto now = io_.clock_unix_ms();
            const bool synced = sync_tunnel_probe_review(
                state, context, parse_host_list_file(*current_list),
                parse_host_list_file(*current_excluded), now);
            const bool observed = request_observed && observe_tunnel_probe_review(
                state, context, host, answer.verdict, now);
            if ((synced || observed) && !io_.save_review(setup.list_file, state, error)) {
                outcome.review_write_failed = true;
            }
        } else {
            outcome.review_write_failed = true;
        }
    }

    TunnelScanReport report;
    if (scan_ && target_is_current()) {
        report = scan_->run_pass(
            [&](const std::string& host) { return probe(host, false); }, candidate_budget);
        outcome.ran = outcome.ran || !outcome.log_empty;
        outcome.remaining = report.remaining;
    }
    if (report.proposals.empty()) return outcome;

    {
        std::lock_guard<std::mutex> guard(tunnel_probe_list_io_mutex());
        if (!target_is_current()) {
            outcome.target_changed = true;
            return outcome;
        }
        // Re-read after the network work: keep panel edits, comments and
        // exclusions, and never write the pass's stale pre-probe snapshot.
        const auto current_list = read_limited(setup.list_file);
        const auto current_excluded = read_limited(setup.exclude_file);
        if (!current_list || !current_excluded) {
            outcome.write_failed = true;
            return outcome;
        }
        auto plan = plan_host_append(*current_list, *current_excluded,
                                     report.proposals, setup.require_registry_confirmation);
        outcome.unconfirmed = std::move(plan.unconfirmed);
        outcome.already_present = std::move(plan.already_present);
        if (plan.to_append.empty()) return outcome;
        const auto rendered = render_appended_list(*current_list, plan.to_append);
        if (!io_.write_file || !io_.write_file(setup.list_file, rendered)) {
            outcome.write_failed = true;
            return outcome;
        }
        outcome.appended = std::move(plan.to_append);
    }
    if (io_.on_list_changed) io_.on_list_changed(setup);
    return outcome;
}

std::string TunnelProbeTask::describe(const PassOutcome& outcome) {
    if (outcome.refusal != TunnelProbeRefusal::none) {
        return describe_tunnel_probe_refusal(outcome.refusal);
    }
    if (outcome.target_changed) {
        return "the probe target changed during the pass; old results were not applied";
    }
    std::string source_note;
    switch (outcome.source_error) {
        case NfqwsScanSourceError::config_unreadable:
            source_note = "nfqws2's configuration could not be read";
            break;
        case NfqwsScanSourceError::no_debug_log:
            source_note = "nfqws2 is not writing its auto-hostlist decisions anywhere";
            break;
        case NfqwsScanSourceError::no_isp_interface:
            source_note = "nfqws2's configuration does not say which device faces the "
                          "provider";
            break;
        case NfqwsScanSourceError::ok:
            break;
    }
    if (!outcome.ran && !source_note.empty()) return source_note;
    if (outcome.log_empty && !outcome.ran) {
        return "nfqws2 has recorded nothing to look at yet";
    }

    std::ostringstream out;
    out << "read " << outcome.new_log_lines << " new log line(s)";
    if (outcome.log_restarted) out << " (log was rotated, re-read from the start)";
    out << "; probed " << outcome.probed << ", " << outcome.remaining
        << " left for the next pass";
    if (outcome.reviewed > 0U) {
        out << "; reviewed " << outcome.reviewed << " already routed host(s)";
    }
    if (outcome.review_write_failed) out << "; review metadata could not be saved";
    if (!source_note.empty()) out << "; " << source_note;
    if (outcome.log_empty) out << "; no new nfqws log evidence";
    if (!outcome.appended.empty()) {
        out << "; routed " << outcome.appended.size() << " host(s):";
        for (const auto& host : outcome.appended) out << ' ' << host;
    } else if (outcome.write_failed) {
        out << "; the list file could not be written, so nothing was routed";
    } else {
        out << "; nothing to route";
    }
    if (!outcome.unconfirmed.empty()) {
        // Named, not counted. These are the hosts a tunnel would fix and the
        // registry does not name - the ones worth a human deciding about, and
        // "2 held back" tells that human nothing.
        out << "; held back by the registry check:";
        constexpr std::size_t kMaxNamed = 8U;
        std::size_t named = 0;
        for (const auto& host : outcome.unconfirmed) {
            if (named == kMaxNamed) {
                out << " and " << (outcome.unconfirmed.size() - named)
                    << " more";
                break;
            }
            out << ' ' << host;
            ++named;
        }
    }
    if (!outcome.already_present.empty()) {
        out << "; " << outcome.already_present.size() << " already listed";
    }
    return out.str();
}

}  // namespace keen_pbr3
