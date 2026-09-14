#pragma once

#ifdef WITH_API

#include "handlers.hpp"
#include "handler_config.hpp"
#include "server.hpp"

#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

void register_transports_handler(ApiServer& server, ApiContext& ctx);

// One transport and the interface outbound which exposes it to routing. A
// subscription supplies several of these to one PreparedConfigCommit, so the
// whole selection uses the existing durable transport/core transaction rather
// than staging a second browser operation.
struct LinkedTransportCreate {
    nlohmann::json transport;
    std::optional<std::string> display_name;
    std::optional<bool> strict_enforcement;
};

PreparedConfigCommit prepare_linked_transport_creates(
    ApiContext& ctx,
    std::vector<LinkedTransportCreate> creates,
    bool batch_manager_api = true);

// Delete the manager transport and its exact linked routing dependencies from
// active state. An unrelated draft is rebased, never applied by this action.
PreparedConfigCommit prepare_linked_transport_delete(
    ApiContext& ctx, const std::string& tag);

// One pass of the existing background maintenance task. Only obsolete,
// unreferenced WG/AWG metadata is retired; no firmware delete is dispatched.
void reconcile_deleted_native_transports(ApiContext& ctx);

// Runs one loopback manager request and returns one parser verdict per item.
// It never forwards manager error text, which may contain share-link secrets.
std::vector<bool> validate_linked_transport_create_items(
    ApiContext& ctx,
    const std::vector<LinkedTransportCreate>& creates);

#ifdef KEEN_PBR3_TESTING
void register_transports_handler_for_test(
    ApiServer& server,
    ApiContext& ctx,
    ConfigFileWriterForTest write_config_file,
    ConfigSaveTestOptions options = {});

nlohmann::json sing_box_install_result_body_for_test(
    bool binary_committed,
    bool binary_durable);
#endif

} // namespace keen_pbr3

#endif // WITH_API
