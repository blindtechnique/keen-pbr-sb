// Read-only preflight for the native WireGuard import, run on the router.
//
// The production executor (execute_ndms_native_import_transaction) cannot
// reach transport on KeeneticOS 5.1.1 by design: the allocator fence provider
// returns nullopt, so the receipt is absent and the executor stops at
// fence_required before any POST. A live write therefore needs a separate
// audited probe - and before that probe may exist, the entire pre-write
// pipeline has to be shown correct against the real firmware.
//
// This binary is that demonstration and NOTHING more. It:
//   * parses a plain .conf through the production request maker,
//   * reads the live interface catalog through ndmc/rci,
//   * builds the production baseline and reports the first-free managed slot,
//   * computes the request-binding digest,
// and prints a go/no-go manifest. It never opens a socket to the RCI create
// endpoint, never constructs a dispatch capability, and never mutates the
// router. The live POST is deliberately a separate tool that does not exist
// yet and will not be run without an explicit operator decision.
//
//   nir-import-preflight <conf-file>
//
// The .conf is expected to be a disposable TEST tunnel: its private key is
// consumed by the production secret path and never printed. Exit 0 means the
// pipeline reports READY; non-zero means BLOCKED (with a printed reason) or a
// probe error.

#include "../src/keenetic/ndms_native_import_baseline.hpp"
#include "../src/keenetic/ndms_native_import_request.hpp"
#include "../src/keenetic/ndms_native_import_wal.hpp"
#include "../src/keenetic/ndms_wireguard_identity.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <optional>
#include <string>

#include <cstdlib>

namespace keen_pbr3 {
namespace {

std::string read_whole_file(const char* path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    return {std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
}

// The live interface catalog, straight from the firmware. Read-only: this is
// the same show/interface document every module in the chain consumes, and it
// mutates nothing.
std::optional<nlohmann::json> read_live_interfaces() {
    // popen so the probe carries no assumption about the RCI port beyond the
    // one the daemon itself uses; ndmc speaks to the same NDMS core.
    FILE* pipe = ::popen(
        "curl -s --max-time 6 http://127.0.0.1:79/rci/show/interface",
        "r");
    if (pipe == nullptr) return std::nullopt;
    std::string out;
    std::array<char, 4096> chunk{};
    while (const auto read =
               std::fread(chunk.data(), 1U, chunk.size(), pipe)) {
        out.append(chunk.data(), read);
    }
    const int status = ::pclose(pipe);
    if (status != 0 || out.empty()) return std::nullopt;
    try {
        return nlohmann::json::parse(out);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<std::uint8_t> first_free_managed_slot(
    const NdmsInterfaceCatalog& catalog) {
    for (std::size_t slot = 0U; slot < catalog.wireguard_slots.size();
         ++slot) {
        if (catalog.wireguard_slots[slot].state ==
            NdmsWireguardCatalogSlotState::absent) {
            return static_cast<std::uint8_t>(slot);
        }
    }
    return std::nullopt;
}

int fail(const char* reason) {
    std::printf("VERDICT: BLOCKED (%s)\n", reason);
    return 1;
}

} // namespace
} // namespace keen_pbr3

int main(int argc, char** argv) {
    using namespace keen_pbr3;
    if (argc < 2) {
        std::printf("usage: nir-import-preflight <conf-file>\n");
        return 2;
    }

    std::string conf = read_whole_file(argv[1]);
    if (conf.empty()) {
        std::printf("cannot read conf: %s\n", argv[1]);
        return 2;
    }

    // Production request maker: canonicalizes, strips labels, injects a random
    // ownership marker, derives the filename, and wipes the caller's bytes.
    std::optional<NdmsNativeWireguardImportRequest> request;
    try {
        request = make_ndms_native_wireguard_import_request(std::move(conf));
    } catch (const std::exception& error) {
        return fail(error.what());
    }
    std::printf("request:\n");
    std::printf("  operation        %.*s\n",
                static_cast<int>(request->operation().size()),
                request->operation().data());
    std::printf("  transaction_id   %.*s\n",
                static_cast<int>(request->transaction_id().size()),
                request->transaction_id().data());
    std::printf("  marker           %.*s\n",
                static_cast<int>(request->marker().size()),
                request->marker().data());
    std::printf("  derived filename %.*s\n",
                static_cast<int>(request->filename().size()),
                request->filename().data());
    std::printf("  candidate rev    %.*s\n",
                static_cast<int>(request->candidate_revision().size()),
                request->candidate_revision().data());
    std::printf("  content length   %zu bytes (secret body, not shown)\n",
                request->content_length());

    const auto interfaces = read_live_interfaces();
    if (!interfaces) return fail("live interface catalog unreadable");
    auto catalog = parse_ndms_interface_catalog(*interfaces);
    if (!catalog.firmware_available) {
        return fail("firmware reported no interface catalog");
    }

    const auto first_free = first_free_managed_slot(catalog);
    if (!first_free) return fail("no free WireGuard slot");
    const bool eligible =
        *first_free >= 5U && *first_free <= 98U;
    std::printf("catalog:\n");
    std::printf("  first-free slot  Wireguard%u (%s)\n",
                static_cast<unsigned>(*first_free),
                eligible ? "managed, eligible"
                         : "PROTECTED - import blocks here");
    if (!eligible) {
        // This is not a probe failure: it is the create-policy fence working.
        // first_free_slot scans from zero, so a freed protected slot legally
        // blocks every import until it is occupied again.
        return fail("first-free slot is protected");
    }

    NdmsCatalogSnapshot snapshot;
    snapshot.catalog = std::move(catalog);
    snapshot.status = NdmsCatalogCacheStatus::fresh;
    snapshot.refreshed = true;
    // The instant the catalog was read. The builder requires it because every
    // live counter in the document is a duration; the preflight consumes none
    // of them, but the field must be present and honest, so stamp it now.
    snapshot.observed_at = std::chrono::steady_clock::now();
    snapshot.observation_generation = 1U;
    snapshot.observation_epoch = 1U;
    snapshot.invalidation_epoch = 1U;

    const std::string target =
        "Wireguard" + std::to_string(static_cast<unsigned>(*first_free));
    auto built = build_ndms_native_import_baseline(snapshot, target, 1U, 1U);
    if (!built.success() || !built.evidence) {
        std::string reason = "baseline build refused: ";
        reason += ndms_native_import_baseline_build_error_name(built.error);
        return fail(reason.c_str());
    }
    std::printf("baseline:\n");
    std::printf("  expected target  %s\n",
                built.evidence->expected_created_interface().c_str());
    std::printf("  protected digest %s\n",
                built.evidence->protected_catalog_sha256().c_str());
    std::printf("  baseline digest  %s\n",
                built.evidence->baseline_sha256().c_str());

    // The string overload from the WAL codec, fed the request's own non-secret
    // fields. This is exactly what the executor's request overload computes;
    // taking it here keeps the probe off the transport/libcurl object graph,
    // which it has no business linking - it posts nothing.
    std::string binding;
    try {
        binding = ndms_native_import_request_binding_digest(
            std::string(request->transaction_id()),
            std::string(request->marker()),
            std::string(request->candidate_revision()),
            request->kind(), target);
    } catch (const std::exception& error) {
        return fail(error.what());
    }
    std::printf("  request binding  %s\n", binding.c_str());

    std::printf(
        "\nVERDICT: READY - the pre-write pipeline accepts this conf against\n"
        "the live firmware and would create %s. No socket to the RCI create\n"
        "endpoint was opened; this binary cannot post. The live write is a\n"
        "separate audited step awaiting an explicit operator decision.\n",
        target.c_str());
    return 0;
}
