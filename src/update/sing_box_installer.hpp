#pragma once

#include "sing_box_release_plan.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace keen_pbr3 {

// Performs the install the policy authorised, in the order that keeps the
// running binary untouched until the replacement has proved itself.
//
// Nothing here decides whether the install is allowed - that is the policy's
// job, and this refuses to duplicate it. What this owns is the sequence, and
// the sequence is the correctness: fetch, verify against the published digest,
// unpack, ask the unpacked binary its version, and only then put it in place.
// A failure at any step leaves the router exactly as it was, which is what
// "the current runtime is not changed until a confirmed operation" means once
// the operation is confirmed.
//
// Every step is injected. The orchestration is what has to be right, and it is
// testable without a network, an archive, or a router.

enum class SingBoxInstallOutcome : std::uint8_t {
    installed,
    // The release document could not be turned into a plan. Carries the
    // release verdict's own reason, including a refusal to install a release
    // that publishes no checksums.
    release_refused,
    // A URL in the plan could not be fetched.
    download_failed,
    // The archive did not match its published digest.
    checksum_mismatch,
    // Nothing usable came out of the archive.
    archive_unusable,
    // The unpacked binary does not report the pinned version. Caught before
    // anything is replaced, which is the entire reason the check happens on
    // the staged copy rather than after installing.
    staged_version_mismatch,
    // The verified, validated binary could not be put in place. The old one
    // is still there.
    install_failed,
    // Installed, but the marker that records the binary as ours was not
    // written. Reported apart from success: without the marker the next
    // capability read calls this binary the operator's and refuses to touch
    // it, which is a real state an operator has to be told about.
    marker_not_written,
    // The operator stopped it while stopping was still free. Distinct from
    // download_failed, which is what the fetch reports when it is aborted:
    // "the download failed" would send somebody looking for a network problem
    // they caused on purpose.
    cancelled,
};

const char* sing_box_install_outcome_name(
    SingBoxInstallOutcome outcome) noexcept;

// The step the install is about to attempt. Named by the sequence itself
// rather than by the caller: a phase list assembled around the calls can drift
// from the calls, and this one cannot, because it is emitted from between them.
//
// There is no byte count here and no percentage, because there is no honest
// one to report - HttpClient::download returns a body and exposes no transfer
// callback (src/http/http_client.hpp:68). What an operator gets is which step
// is running, which is exactly enough to tell a slow download from a hung one,
// and that is the question a progress display exists to answer.
enum class SingBoxInstallPhase : std::uint8_t {
    reading_release,
    downloading_archive,
    downloading_checksums,
    verifying_archive,
    unpacking,
    checking_staged_version,
    installing,
    recording_marker,
};

const char* sing_box_install_phase_name(SingBoxInstallPhase phase) noexcept;

// Whether stopping during this phase leaves the router as it was.
//
// Everything up to and including unpacking happens in memory or in a staging
// directory nobody runs from, so abandoning it changes nothing. From
// `installing` onwards the binary is being replaced, and there is no version
// of "cancel" that improves on waiting: a half-written binary is worse than an
// unwanted new one, and the operator who asked to stop wanted their router
// working, not broken faster.
//
// `checking_staged_version` is reversible: it runs the staged copy, and the
// installed binary is still the old one.
bool sing_box_install_phase_is_reversible(SingBoxInstallPhase phase) noexcept;

// Called immediately BEFORE the phase it names is attempted. Before, not
// after, is the whole point: a phase that never advances is how a hung step
// looks, and a phase reported on completion would leave the display sitting on
// the previous step while the stuck one is invisible.
using SingBoxInstallProgress = std::function<void(SingBoxInstallPhase)>;

struct SingBoxInstallReport {
    SingBoxInstallOutcome outcome{SingBoxInstallOutcome::release_refused};
    // Set when `outcome` is release_refused or checksum_mismatch, so the
    // caller can say which of the several refusals happened.
    SingBoxReleaseVerdict release_verdict{
        SingBoxReleaseVerdict::release_unreadable};
    // What the staged binary reported, when it was asked and answered.
    std::string staged_version;
};

struct SingBoxInstallSteps {
    // Empty result means the fetch failed. A fetch that returns an empty body
    // successfully is indistinguishable from a failure here, and that is the
    // safe direction: an empty archive is not installable either.
    std::function<std::optional<std::string>(const std::string& url)> fetch;
    // Lowercase SHA-256 hex of the bytes.
    std::function<std::string(const std::string& bytes)> digest;
    // Unpacks into a staging area and returns the path of the sing-box binary
    // inside it. Empty when the archive yielded none.
    std::function<std::string(const std::string& archive_bytes)>
        stage_archive;
    // `<staged> version`, parsed. Empty when it would not run or would not say.
    std::function<std::string(const std::string& staged_binary)>
        read_staged_version;
    // Puts the staged binary at the target path, atomically enough that a
    // crash leaves either the old file or the new one.
    std::function<bool(const std::string& staged_binary)> install_atomically;
    std::function<bool()> write_managed_marker;
};

// `release_json_url` is fetched first; the pinned version and asset
// architecture come from the caller, which has already measured them.
//
// `progress` is optional and observes only - it cannot change the outcome, and
// an install must not fail because nobody was listening. It is deliberately
// not wrapped in a catch here: the only production observer forwards to
// publish_sing_box_install_progress (handler_transports.cpp), which is
// noexcept and swallows, so a guard around this call could never fire in
// production - and a guard that cannot fire is a promise the code does not
// keep.
SingBoxInstallReport install_pinned_sing_box(
    const SingBoxInstallSteps& steps,
    const std::string& release_json_url,
    const std::string& pinned_version,
    const std::string& asset_architecture,
    const SingBoxInstallProgress& progress = {});

} // namespace keen_pbr3
