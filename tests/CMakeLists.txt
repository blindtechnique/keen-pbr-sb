add_executable(keen-pbr-tests
  test_main.cpp
  test_firewall_verifier.cpp
  test_firewall_runtime.cpp
  test_nftables_builder.cpp
  test_iptables_builder.cpp
  test_cron.cpp
  test_addr_spec.cpp
  test_base64.cpp
  test_dnsmasq_gen.cpp
  test_dnsmasq_access_policy.cpp
  test_dnsmasq_helper_packages.cpp
  test_dns_txt_client.cpp
  test_dns_server.cpp
  test_test_routing.cpp
  test_keenetic_dns.cpp
  test_keenetic_dns_refresh_coordinator.cpp
  test_resolver_stream_coordinator.cpp
  test_ndms_interface_inventory.cpp
  test_internal_vpn_server_resolver.cpp
  test_ndms_vpn_server_service.cpp
  test_internal_vpn_service_resolver.cpp
  test_ndms_interface_management.cpp
  test_ndms_rci_observation.cpp
  test_ndms_rci_restorable_snapshot.cpp
  test_dns_probe_server.cpp
  test_list_set_usage.cpp
  test_list_service.cpp
  test_cache_manager_durability.cpp
  test_control_protocol.cpp
  test_status_command.cpp
  test_resolver_fallback.cpp
  test_list_parser.cpp
  test_list_streamer.cpp
  test_srs_decoder.cpp
  test_http_client.cpp
  test_interface_probe.cpp
  test_config_validation.cpp
  test_config_store.cpp
  test_catalog_setup_planner.cpp
  test_config_writer.cpp
  test_dependency_analysis.cpp
  test_list_delete_planner.cpp
  test_routing_state.cpp
  test_runtime_interface_inventory.cpp
  test_api_ndms_names.cpp
  test_api_runtime_interfaces.cpp
  test_api_runtime_inventory.cpp
  test_api_diagnostic_tasks.cpp
  test_api_dependency_analysis.cpp
  test_connection_query.cpp
  test_conntrack_event_monitor.cpp
  test_conntrack_manager.cpp
  test_idle_stall_detector.cpp
  test_udp_call_affinity.cpp
  test_interface_traffic_sampler.cpp
  test_periodic_task_metrics.cpp
  test_daemon_link_contract.cpp
  test_api_status_events.cpp
  test_api_logs.cpp
  test_api_remote_access.cpp
  test_api_transports.cpp
  test_update_version.cpp
  test_api_test_routing.cpp
  test_api_auth.cpp
  test_api_config.cpp
  test_backup_restore.cpp
  test_persistent_snapshot.cpp
  test_backup_restore_journal.cpp
  test_restore_transaction.cpp
  test_recovery_coordinator.cpp
  test_recover_persistent_state.cpp
  test_maintenance_lock.cpp
  test_update_lock_protocol.cpp
  test_rescue_update.cpp
  test_rescue_integrity.cpp
  test_api_static.cpp
  test_resolver_health.cpp
  test_system_resolver_hook.cpp
  test_system_info.cpp
  test_network_routes.cpp
  test_netlink_errors.cpp
  test_nfqws_config.cpp
  test_nfqws_file_writer.cpp
  test_nfqws_strategy_assets.cpp
  test_safe_exec.cpp
  test_ndmc.cpp
  test_trace_logging.cpp
  test_interface_monitor.cpp
  test_status_stream.cpp
  test_lifecycle_operation.cpp
  test_list_refresh_task.cpp
  test_runtime_state_machine.cpp
  test_urltest_manager.cpp
  test_port_spec_util.cpp
  test_policy_rule.cpp
  test_route_table.cpp
  test_pid_file.cpp
  test_crash_diagnostics.cpp
  ../src/config/config.cpp
  ../src/daemon/config_store.cpp
  ../src/daemon/daemon_core.cpp
  ../src/daemon/daemon_runtime.cpp
  ../src/daemon/daemon_resolver.cpp
  ../src/daemon/keenetic_dns_refresh_coordinator.cpp
  ../src/daemon/resolver_stream_coordinator.cpp
  ../src/daemon/daemon_api.cpp
  ../src/daemon/daemon_dns_probe.cpp
  ../src/setup/catalog_setup_planner.cpp
  ../src/config/config_writer.cpp
  ../src/util/last_command_failure.cpp
  ../src/backup/persistent_snapshot.cpp
  ../src/backup/restore_journal.cpp
  ../src/backup/restore_transaction.cpp
  ../src/backup/recovery_coordinator.cpp
  ../src/cmd/recover_persistent_state.cpp
  ../src/update/maintenance_lock.cpp
  ../src/config/dependency_analysis.cpp
  ../src/config/list_delete_planner.cpp
  ../src/crash/crash_diagnostics.cpp
  ../src/config/routing_state.cpp
  ../src/firewall/iptables_verifier.cpp
  ../src/firewall/nftables_verifier.cpp
  ../src/firewall/firewall_verifier.cpp
  ../src/firewall/firewall.cpp
  ../src/firewall/firewall_runtime.cpp
  ../src/firewall/port_spec_util.cpp
  ../src/firewall/nftables.cpp
  ../src/firewall/nft_batch_pipe.cpp
  ../src/firewall/iptables.cpp
  ../src/firewall/ipset_restore_pipe.cpp
  ../src/log/logger.cpp
  ../src/log/trace.cpp
  ../src/dns/dnsmasq_gen.cpp
  ../src/dns/dnsmasq_access_policy.cpp
  ../src/dns/dns_txt_client.cpp
  ../src/dns/dns_router.cpp
  ../src/dns/dns_server.cpp
  ../src/dns/keenetic_dns.cpp
  ../src/daemon/system_resolver_hook.cpp
  ../src/dns/dns_probe_server.cpp
  ../src/cache/cache_manager.cpp
  ../src/ipc/control_protocol.cpp
  ../src/ipc/control_client.cpp
  ../src/ipc/resolver_fallback.cpp
  ../src/connections/conntrack_event_monitor.cpp
  ../src/runtime/conntrack_manager.cpp
  ../src/runtime/interface_traffic_sampler.cpp
  ../src/runtime/periodic_task_metrics.cpp
  ../src/lists/ipset.cpp
  ../src/lists/kernel_set_tester.cpp
  ../src/lists/list_streamer.cpp
  ../src/lists/list_set_usage.cpp
  ../src/lists/srs_decoder.cpp
  ../src/config/list_parser.cpp
  ../src/cmd/test_routing.cpp
  ../src/cmd/status.cpp
  ../src/daemon/list_service.cpp
  ../src/daemon/pid_file.cpp
  ../src/daemon/resolver_health.cpp
  ../src/daemon/resolver_sync_state_machine.cpp
  ../src/daemon/runtime_state_store.cpp
  ../src/daemon/scheduler.cpp
  ../src/http/http_client.cpp
  ../src/api/update_version.cpp
  ../src/http/http_transport.cpp
  ../src/http/curl_runtime.cpp
  ../src/keenetic/ndms_interface_inventory.cpp
  ../src/keenetic/ndms_catalog_cache.cpp
  ../src/keenetic/internal_vpn_server_resolver.cpp
  ../src/keenetic/ndms_vpn_server_service.cpp
  ../src/keenetic/ndms_vpn_server_service_cache.cpp
  ../src/keenetic/internal_vpn_service_resolver.cpp
  ../src/keenetic/internal_vpn_ingress_resolver.cpp
  ../src/keenetic/ndms_interface_management.cpp
  ../src/keenetic/ndms_rci_observation.cpp
  ../src/keenetic/ndms_rci_restorable_snapshot.cpp
  ../src/health/url_tester.cpp
  ../src/health/circuit_breaker.cpp
  ../src/health/interface_probe.cpp
  ../src/health/routing_health_checker.cpp
  ../src/routing/firewall_state.cpp
  ../src/routing/urltest_manager.cpp
  ../src/routing/netlink.cpp
  ../src/routing/interface_monitor.cpp
  ../src/util/blocking_executor.cpp
  ../src/util/base64.cpp
  ../src/util/firewall_backend_utils.cpp
  ../src/util/ipv6_support.cpp
  ../src/util/network_routes.cpp
  ../src/util/nfqws_config.cpp
  ../src/util/nfqws_file_writer.cpp
  ../src/util/nfqws_strategy_assets.cpp
  ../src/util/system_info.cpp
  ../src/util/traced_mutex.cpp
  ../src/runtime/lifecycle_operation.cpp
  ../src/runtime/list_refresh_task.cpp
  ../src/runtime/runtime_state_machine.cpp
  ../src/routing/policy_rule.cpp
  ../src/routing/route_table.cpp
  ../src/routing/routing_verifier.cpp
  ../src/routing/target.cpp
)

# Keep immutable cache-generation and ListStreamer snapshot invariants in a
# small target. It avoids relinking the daemon/API test binary for focused
# cache lifetime and GC race checks.
add_executable(keen-pbr-cache-generation-tests
  test_main.cpp
  test_cache_manager_durability.cpp
  test_list_streamer.cpp
  ../src/cache/cache_manager.cpp
  ../src/config/config_writer.cpp
  ../src/config/list_parser.cpp
  ../src/http/http_client.cpp
  ../src/http/http_transport.cpp
  ../src/http/curl_runtime.cpp
  ../src/lists/list_streamer.cpp
  ../src/lists/srs_decoder.cpp
  ../src/log/logger.cpp
  ../src/log/trace.cpp
)
set_target_properties(keen-pbr-cache-generation-tests PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
  CXX_EXTENSIONS NO
)
target_compile_definitions(
  keen-pbr-cache-generation-tests PRIVATE KEEN_PBR3_TESTING
)
target_include_directories(keen-pbr-cache-generation-tests PRIVATE
  ${KEEN_PBR_GENERATED_INCLUDE_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/third_party/doctest
)
target_link_libraries(keen-pbr-cache-generation-tests PRIVATE
  nlohmann_json::nlohmann_json
  fmt::fmt-header-only
  ${KEEN_PBR_CURL_TARGET}
  PkgConfig::ZLIB
  Threads::Threads
)
keen_pbr_apply_project_options(keen-pbr-cache-generation-tests)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
  target_link_libraries(keen-pbr-cache-generation-tests PRIVATE stdc++fs)
endif()
add_test(
  NAME keen-pbr-cache-generation-tests
  COMMAND keen-pbr-cache-generation-tests
)

# Keep runtime mutation admission independently buildable. The contract is
# intentionally header-only and does not need the daemon or kernel backends.
add_executable(keen-pbr-runtime-mutation-admission-tests
  test_main.cpp
  test_owned_conntrack_cleanup_operation.cpp
  test_runtime_mutation_admission.cpp
)
set_target_properties(keen-pbr-runtime-mutation-admission-tests PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
  CXX_EXTENSIONS NO
)
# `test_owned_conntrack_cleanup_operation.cpp` тянет через
# `owned_conntrack_cleanup_operation.hpp` -> `runtime_recovery_policy.hpp` ->
# `config.hpp` сгенерированный `api_types.hpp`, а тот — <nlohmann/json.hpp>.
# Без каталога generated и без самой библиотеки цель не собирается вовсе.
target_include_directories(keen-pbr-runtime-mutation-admission-tests PRIVATE
  ${KEEN_PBR_GENERATED_INCLUDE_DIR}
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/third_party/doctest
)
target_link_libraries(keen-pbr-runtime-mutation-admission-tests PRIVATE
  nlohmann_json::nlohmann_json
  fmt::fmt-header-only
  Threads::Threads
)
keen_pbr_apply_project_options(keen-pbr-runtime-mutation-admission-tests)
add_test(
  NAME keen-pbr-runtime-mutation-admission-tests
  COMMAND keen-pbr-runtime-mutation-admission-tests
)

# Keep the package-rescue suite independently buildable. It intentionally has
# no daemon/API dependencies, so recovery invariants remain testable even when
# an unrelated in-progress backend change temporarily breaks the monolithic
# unit-test target.
add_executable(keen-pbr-rescue-tests
  test_main.cpp
  test_rescue_update.cpp
  test_rescue_integrity.cpp
)
set_target_properties(keen-pbr-rescue-tests PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
  CXX_EXTENSIONS NO
)
target_include_directories(keen-pbr-rescue-tests PRIVATE
  ${CMAKE_SOURCE_DIR}/third_party/doctest
)
target_compile_definitions(keen-pbr-rescue-tests PRIVATE
  KEEN_PBR_RESCUE_SCRIPT_PATH="${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/rescue-update.sh"
  KEEN_PBR_RESCUE_STARTUP_GUARD_PATH="${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/rescue-startup-guard.sh"
  KEEN_PBR_UPDATE_LOCK_SCRIPT_PATH="${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/update-lock.sh"
  KEEN_PBR_PORTABLE_STAT_SCRIPT_PATH="${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/portable-stat.sh"
  KEEN_PBR_TRANSPORT_INIT_PATH="${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/opt/etc/init.d/S79transport-manager"
  KEEN_PBR_INSTALL_SCRIPT_PATH="${CMAKE_SOURCE_DIR}/install.sh"
  KEEN_PBR_POSTINST_SCRIPT_PATH="${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/postinst"
  KEEN_PBR_POSTRM_SCRIPT_PATH="${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/postrm"
)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
  target_link_libraries(keen-pbr-rescue-tests PRIVATE stdc++fs)
endif()
add_test(NAME keen-pbr-rescue-tests COMMAND keen-pbr-rescue-tests)

# Keep the asynchronous Keenetic DNS coordinator independently buildable.
# This exercises its concurrency and generation-fence contract without
# relinking the large daemon test binary on a Windows bind mount.
add_executable(keen-pbr-keenetic-dns-refresh-tests
  test_main.cpp
  test_config_reload_coordinator.cpp
  test_keenetic_dns_refresh_coordinator.cpp
  test_keenetic_dns_refresh_transaction.cpp
  ../src/daemon/keenetic_dns_refresh_coordinator.cpp
  ../src/runtime/periodic_task_metrics.cpp
  ../src/util/blocking_executor.cpp
  ../src/util/traced_mutex.cpp
  ../src/log/logger.cpp
  ../src/log/trace.cpp
)
set_target_properties(keen-pbr-keenetic-dns-refresh-tests PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
  CXX_EXTENSIONS NO
)
# Как и у admission-цели: `test_config_reload_coordinator.cpp` доходит до
# `config.hpp` и сгенерированного `api_types.hpp`, которому нужен nlohmann.
target_include_directories(keen-pbr-keenetic-dns-refresh-tests PRIVATE
  ${KEEN_PBR_GENERATED_INCLUDE_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/third_party/doctest
)
target_link_libraries(keen-pbr-keenetic-dns-refresh-tests PRIVATE
  nlohmann_json::nlohmann_json
  fmt::fmt-header-only
  Threads::Threads
)
keen_pbr_apply_project_options(keen-pbr-keenetic-dns-refresh-tests)
add_test(
  NAME keen-pbr-keenetic-dns-refresh-tests
  COMMAND keen-pbr-keenetic-dns-refresh-tests
)

# Keep the resolver hook handoff independently buildable. These tests cover
# exact attempt/epoch correlation and terminal ownership without relinking the
# daemon-wide suite on the Windows bind mount.
add_executable(keen-pbr-resolver-stream-tests
  test_main.cpp
  test_resolver_stream_coordinator.cpp
  ../src/daemon/resolver_stream_coordinator.cpp
  ../src/util/blocking_executor.cpp
  ../src/util/traced_mutex.cpp
  ../src/log/logger.cpp
  ../src/log/trace.cpp
)
set_target_properties(keen-pbr-resolver-stream-tests PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
  CXX_EXTENSIONS NO
)
target_include_directories(keen-pbr-resolver-stream-tests PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/third_party/doctest
)
target_link_libraries(keen-pbr-resolver-stream-tests PRIVATE
  fmt::fmt-header-only
  Threads::Threads
)
keen_pbr_apply_project_options(keen-pbr-resolver-stream-tests)
add_test(
  NAME keen-pbr-resolver-stream-tests
  COMMAND keen-pbr-resolver-stream-tests
)

add_test(
  NAME keen-pbr-dnsmasq-attempt-receipt-debian-test
  COMMAND /bin/sh
          ${CMAKE_CURRENT_SOURCE_DIR}/test_dnsmasq_attempt_receipt.sh
          ${CMAKE_SOURCE_DIR}/packages/debian/files/usr/lib/keen-pbr/dnsmasq.sh
)
add_test(
  NAME keen-pbr-dnsmasq-attempt-receipt-keenetic-test
  COMMAND /bin/sh
          ${CMAKE_CURRENT_SOURCE_DIR}/test_dnsmasq_attempt_receipt.sh
          ${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/dnsmasq.sh
)
add_test(
  NAME keen-pbr-dnsmasq-attempt-receipt-openwrt-test
  COMMAND /bin/sh
          ${CMAKE_CURRENT_SOURCE_DIR}/test_dnsmasq_attempt_receipt.sh
          ${CMAKE_SOURCE_DIR}/packages/openwrt/keen-pbr/files/usr/lib/keen-pbr/dnsmasq.sh
)

# Keep the restore journal independently buildable. It deliberately has no
# API, lifecycle, or startup dependencies, so crash-boundary tests remain
# runnable while handler and startup integration is still under development.
add_executable(keen-pbr-backup-restore-journal-tests
  test_main.cpp
  test_backup_restore_journal.cpp
  test_restore_transaction.cpp
  ../src/backup/restore_journal.cpp
  ../src/backup/restore_transaction.cpp
  ../src/config/config_writer.cpp
)
set_target_properties(keen-pbr-backup-restore-journal-tests PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
  CXX_EXTENSIONS NO
)
target_compile_definitions(
  keen-pbr-backup-restore-journal-tests PRIVATE KEEN_PBR3_TESTING
)
target_include_directories(keen-pbr-backup-restore-journal-tests PRIVATE
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/third_party/doctest
  ${CMAKE_SOURCE_DIR}/third_party/nlohmann_json/include
)
target_link_libraries(
  keen-pbr-backup-restore-journal-tests PRIVATE
  nlohmann_json::nlohmann_json
)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
  target_link_libraries(
    keen-pbr-backup-restore-journal-tests PRIVATE stdc++fs
  )
endif()
add_test(
  NAME keen-pbr-backup-restore-journal-tests
  COMMAND keen-pbr-backup-restore-journal-tests
)

# Keep the C++ protocol-3 guardian client independently buildable. Handler and
# startup integration intentionally depend on this target only after its
# process-lifetime and CAS boundaries are proven in isolation.
add_executable(keen-pbr-maintenance-lock-tests
  test_main.cpp
  test_maintenance_lock.cpp
  ../src/update/maintenance_lock.cpp
)
set_target_properties(keen-pbr-maintenance-lock-tests PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
  CXX_EXTENSIONS NO
)
target_compile_definitions(keen-pbr-maintenance-lock-tests PRIVATE
  KEEN_PBR3_TESTING
  KEEN_PBR_UPDATE_LOCK_SCRIPT_PATH="${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/update-lock.sh"
  KEEN_PBR_PORTABLE_STAT_SCRIPT_PATH="${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/portable-stat.sh"
)
target_include_directories(keen-pbr-maintenance-lock-tests PRIVATE
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/third_party/doctest
)
add_test(
  NAME keen-pbr-maintenance-lock-tests
  COMMAND keen-pbr-maintenance-lock-tests
)

# Keep the shell wire protocol independently testable. These tests exercise
# publication races and hostile on-disk metadata without any daemon linkage.
add_executable(keen-pbr-update-lock-protocol-tests
  test_main.cpp
  test_update_lock_protocol.cpp
)
set_target_properties(keen-pbr-update-lock-protocol-tests PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
  CXX_EXTENSIONS NO
)
target_compile_definitions(keen-pbr-update-lock-protocol-tests PRIVATE
  KEEN_PBR_UPDATE_LOCK_SCRIPT_PATH="${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/update-lock.sh"
  KEEN_PBR_PORTABLE_STAT_SCRIPT_PATH="${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/portable-stat.sh"
)
target_include_directories(keen-pbr-update-lock-protocol-tests PRIVATE
  ${CMAKE_SOURCE_DIR}/third_party/doctest
)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
  target_link_libraries(keen-pbr-update-lock-protocol-tests PRIVATE stdc++fs)
endif()
add_test(
  NAME keen-pbr-update-lock-protocol-tests
  COMMAND keen-pbr-update-lock-protocol-tests
)

add_test(
  NAME keen-pbr-dnsmasq-helper-lkg
  COMMAND /bin/sh
    ${CMAKE_SOURCE_DIR}/tests/package_it/run-dnsmasq-helper-lkg.sh
    ${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/dnsmasq.sh
    ${CMAKE_SOURCE_DIR}/packages/openwrt/keen-pbr/files/usr/lib/keen-pbr/dnsmasq.sh
    ${CMAKE_SOURCE_DIR}/packages/debian/files/usr/lib/keen-pbr/dnsmasq.sh
)

add_test(
  NAME keen-pbr-netfilter-hook-signals
  COMMAND /bin/sh
    ${CMAKE_SOURCE_DIR}/tests/package_it/run-netfilter-hook-signals.sh
    ${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/opt/etc/ndm/netfilter.d/50-keen-pbr-routing.sh
    ${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/opt/etc/init.d/S80keen-pbr
    ${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/rescue-startup-guard.sh
    ${CMAKE_SOURCE_DIR}/packages/openwrt/keen-pbr/files/etc/init.d/keen-pbr
    ${CMAKE_SOURCE_DIR}/packages/openwrt/keen-pbr/files/usr/lib/keen-pbr/firewall.sh
    ${CMAKE_SOURCE_DIR}/packages/openwrt/keen-pbr/files/etc/hotplug.d/firewall/70-keen-pbr
)

add_test(
  NAME keen-pbr-keenetic-fastnat-lifecycle
  COMMAND /bin/sh
    ${CMAKE_SOURCE_DIR}/tests/package_it/run-keenetic-fastnat-lifecycle.sh
    ${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/opt/etc/init.d/S80keen-pbr
    ${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/prerm
)

add_test(
  NAME keen-pbr-keenetic-iptables-wait
  COMMAND /bin/sh
    ${CMAKE_SOURCE_DIR}/tests/package_it/run-keenetic-iptables-wait.sh
    ${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/opt/etc/init.d/S80keen-pbr
)

add_test(
  NAME keen-pbr-keenetic-meta-udp443-cleanup
  COMMAND /bin/sh
    ${CMAKE_SOURCE_DIR}/tests/package_it/run-keenetic-meta-udp443-cleanup.sh
    ${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/opt/etc/init.d/S80keen-pbr
)

set_target_properties(keen-pbr-tests PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
  CXX_EXTENSIONS NO
)

target_compile_definitions(keen-pbr-tests PRIVATE
  KEEN_PBR3_TESTING
  KEEN_PBR_DEFAULT_CONFIG_PATH="${KEEN_PBR_DEFAULT_CONFIG_PATH}"
  KEEN_PBR_RESCUE_SCRIPT_PATH="${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/rescue-update.sh"
  KEEN_PBR_RESCUE_STARTUP_GUARD_PATH="${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/rescue-startup-guard.sh"
  KEEN_PBR_UPDATE_LOCK_SCRIPT_PATH="${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/update-lock.sh"
  KEEN_PBR_PORTABLE_STAT_SCRIPT_PATH="${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/portable-stat.sh"
  KEEN_PBR_TRANSPORT_INIT_PATH="${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/opt/etc/init.d/S79transport-manager"
  KEEN_PBR_INSTALL_SCRIPT_PATH="${CMAKE_SOURCE_DIR}/install.sh"
  KEEN_PBR_POSTINST_SCRIPT_PATH="${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/postinst"
  KEEN_PBR_POSTRM_SCRIPT_PATH="${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/postrm"
  KEEN_PBR_KEENETIC_DNSMASQ_HELPER_PATH="${CMAKE_SOURCE_DIR}/packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/dnsmasq.sh"
  KEEN_PBR_OPENWRT_DNSMASQ_HELPER_PATH="${CMAKE_SOURCE_DIR}/packages/openwrt/keen-pbr/files/usr/lib/keen-pbr/dnsmasq.sh"
  KEEN_PBR_OPENWRT_UCI_HELPER_PATH="${CMAKE_SOURCE_DIR}/packages/openwrt/keen-pbr/files/usr/lib/keen-pbr/uci.sh"
  KEEN_PBR_DEBIAN_DNSMASQ_HELPER_PATH="${CMAKE_SOURCE_DIR}/packages/debian/files/usr/lib/keen-pbr/dnsmasq.sh"
)

# Reuse include paths from the main target so generated headers such as
# <keen-pbr/version.hpp> are always visible to tests.
target_include_directories(keen-pbr-tests PRIVATE
  $<TARGET_PROPERTY:keen-pbr,INCLUDE_DIRECTORIES>
)

target_include_directories(keen-pbr-tests PRIVATE
  ${KEEN_PBR_GENERATED_INCLUDE_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/third_party/doctest
  ${CMAKE_SOURCE_DIR}/third_party/nlohmann_json/include
  ${LIBNL_INCLUDE_DIRS}
  ${LIBNL_ROUTE_INCLUDE_DIRS}
)

target_link_libraries(keen-pbr-tests PRIVATE
  nlohmann_json::nlohmann_json
  ${KEEN_PBR_CURL_TARGET}
  PkgConfig::ZLIB
  PkgConfig::LIBNL
  PkgConfig::LIBNL_ROUTE
  cpptrace::cpptrace
  fmt::fmt-header-only
  keen_pbr_libunwind
  ${LIBRESOLV}
)
keen_pbr_apply_project_options(keen-pbr-tests)

add_executable(crash-diagnostics-smoke
  crash_diagnostics_smoke.cpp
  ../src/crash/crash_diagnostics.cpp
)
set_target_properties(crash-diagnostics-smoke PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
  CXX_EXTENSIONS NO
)
target_include_directories(crash-diagnostics-smoke PRIVATE
  ${KEEN_PBR_GENERATED_INCLUDE_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
)
target_link_libraries(crash-diagnostics-smoke PRIVATE
  cpptrace::cpptrace
  keen_pbr_libunwind
)
keen_pbr_apply_project_options(crash-diagnostics-smoke)

if(LIBATOMIC)
  target_link_libraries(keen-pbr-tests PRIVATE ${LIBATOMIC})
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
  target_link_libraries(keen-pbr-tests PRIVATE stdc++fs)
endif()

target_compile_definitions(keen-pbr-tests PRIVATE USE_KEENETIC_API)

if(WITH_API)
  target_compile_definitions(keen-pbr-tests PRIVATE WITH_API)
  target_sources(keen-pbr-tests PRIVATE
    test_api_reload.cpp
    test_api_lists_refresh.cpp
    test_api_catalog_setup.cpp
    test_runtime_outbound_state.cpp
    test_ndms_web_endpoint.cpp
    ../src/api/server.cpp
    ../src/api/connection_query.cpp
    ../src/api/auth_runtime.cpp
    ../src/api/keenetic_auth.cpp
    ../src/keenetic/ndms_web_endpoint.cpp
    ../src/api/sse_broadcaster.cpp
    ../src/api/status_stream.cpp
    ../src/api/health_response.cpp
    ../src/api/handler_status_events.cpp
    ../src/api/handler_health_service.cpp
    ../src/api/handler_health_routing.cpp
    ../src/api/handler_reload.cpp
    ../src/api/handler_lists_refresh.cpp
    ../src/api/handler_logs.cpp
    ../src/api/handler_remote_access.cpp
    ../src/api/handler_ndms_names.cpp
    ../src/api/handler_runtime_interfaces.cpp
    ../src/api/handler_runtime_inventory.cpp
    ../src/api/handler_runtime_outbounds.cpp
    ../src/api/handler_diagnostic_tasks.cpp
    ../src/api/handler_dependency_analysis.cpp
    ../src/api/handler_transports.cpp
    ../src/api/handler_test_routing.cpp
    ../src/api/handler_dns_test.cpp
    ../src/api/handler_connections.cpp
    ../src/api/handler_nfqws.cpp
    ../src/api/handler_router_info.cpp
    ../src/api/handler_config.cpp
    ../src/api/handler_catalog.cpp
    ../src/api/handler_catalog_setup.cpp
    ../src/api/handler_geo.cpp
    ../src/api/handler_naive.cpp
    ../src/api/handler_backup.cpp
    ../src/api/handlers.cpp
    ../src/health/runtime_interface_inventory.cpp
    ../src/health/runtime_outbound_state.cpp
    ../src/log/file_sink.cpp
  )
  target_link_libraries(keen-pbr-tests PRIVATE
    httplib::httplib
    Threads::Threads
  )
  if(HTTPLIB_ANL_LIB)
    target_link_libraries(keen-pbr-tests PRIVATE ${HTTPLIB_ANL_LIB})
  endif()
endif()

add_executable(keen-pbr-firewall-it
  firewall_integration_main.cpp
  ../src/cache/cache_manager.cpp
  ../src/config/config.cpp
  ../src/config/config_writer.cpp
  ../src/config/list_parser.cpp
  ../src/config/routing_state.cpp
  ../src/dns/dns_router.cpp
  ../src/dns/dns_probe_server.cpp
  ../src/dns/dns_server.cpp
  ../src/dns/keenetic_dns.cpp
  ../src/firewall/firewall.cpp
  ../src/firewall/firewall_runtime.cpp
  ../src/firewall/firewall_verifier.cpp
  ../src/firewall/iptables.cpp
  ../src/firewall/iptables_verifier.cpp
  ../src/firewall/ipset_restore_pipe.cpp
  ../src/firewall/nft_batch_pipe.cpp
  ../src/firewall/nftables.cpp
  ../src/firewall/nftables_verifier.cpp
  ../src/firewall/port_spec_util.cpp
  ../src/health/circuit_breaker.cpp
  ../src/health/routing_health_checker.cpp
  ../src/health/url_tester.cpp
  ../src/http/http_client.cpp
  ../src/http/http_transport.cpp
  ../src/http/curl_runtime.cpp
  ../src/lists/kernel_set_tester.cpp
  ../src/lists/list_set_usage.cpp
  ../src/lists/list_streamer.cpp
  ../src/lists/srs_decoder.cpp
  ../src/log/logger.cpp
  ../src/log/trace.cpp
  ../src/routing/firewall_state.cpp
  ../src/routing/netlink.cpp
  ../src/routing/policy_rule.cpp
  ../src/routing/route_table.cpp
  ../src/routing/routing_verifier.cpp
  ../src/routing/target.cpp
  ../src/util/blocking_executor.cpp
  ../src/util/firewall_backend_utils.cpp
  ../src/util/ipv6_support.cpp
  ../src/util/last_command_failure.cpp
  ../src/util/network_routes.cpp
  ../src/util/system_info.cpp
  ../src/util/traced_mutex.cpp
)
set_target_properties(keen-pbr-firewall-it PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
  CXX_EXTENSIONS NO
)
target_include_directories(keen-pbr-firewall-it PRIVATE
  $<TARGET_PROPERTY:keen-pbr,INCLUDE_DIRECTORIES>
)
target_include_directories(keen-pbr-firewall-it PRIVATE
  ${KEEN_PBR_GENERATED_INCLUDE_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_SOURCE_DIR}/third_party/nlohmann_json/include
  ${LIBNL_INCLUDE_DIRS}
  ${LIBNL_ROUTE_INCLUDE_DIRS}
)
target_link_libraries(keen-pbr-firewall-it PRIVATE
  nlohmann_json::nlohmann_json
  ${KEEN_PBR_CURL_TARGET}
  PkgConfig::ZLIB
  PkgConfig::LIBNL
  PkgConfig::LIBNL_ROUTE
  cpptrace::cpptrace
  fmt::fmt-header-only
  keen_pbr_libunwind
  ${LIBRESOLV}
  Threads::Threads
)
target_compile_definitions(keen-pbr-firewall-it PRIVATE USE_KEENETIC_API)
if(LIBATOMIC)
  target_link_libraries(keen-pbr-firewall-it PRIVATE ${LIBATOMIC})
endif()
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
  target_link_libraries(keen-pbr-firewall-it PRIVATE stdc++fs)
endif()

if(ENABLE_THREAD_SAFETY_ANALYSIS AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set(THREAD_SAFETY_SMOKE_SCRIPT "${CMAKE_CURRENT_BINARY_DIR}/thread_safety_smoke.cmake")
  file(WRITE "${THREAD_SAFETY_SMOKE_SCRIPT}" [=[
execute_process(
  COMMAND
    "${CLANG_CXX}"
    -std=c++17
    -I
    "${PROJECT_ROOT}/include"
    -Wthread-safety
    -Werror=thread-safety
    -fsyntax-only
    "${SOURCE_FILE}"
  RESULT_VARIABLE smoke_result
  OUTPUT_VARIABLE smoke_stdout
  ERROR_VARIABLE smoke_stderr
)

set(smoke_output "${smoke_stdout}${smoke_stderr}")

if(smoke_result EQUAL 0)
  message(FATAL_ERROR "Thread-safety smoke test unexpectedly compiled cleanly.\n${smoke_output}")
endif()

string(FIND "${smoke_output}" "requires holding" smoke_match)
if(smoke_match EQUAL -1)
  message(FATAL_ERROR "Thread-safety smoke test failed for an unexpected reason.\n${smoke_output}")
endif()
]=])

  add_custom_target(thread-safety-smoke
    COMMAND ${CMAKE_COMMAND}
      -DCLANG_CXX=${CMAKE_CXX_COMPILER}
      -DPROJECT_ROOT=${CMAKE_SOURCE_DIR}
      -DSOURCE_FILE=${CMAKE_CURRENT_SOURCE_DIR}/thread_safety_negative.cpp
      -P ${THREAD_SAFETY_SMOKE_SCRIPT}
    COMMENT "Checking that thread-safety analysis rejects an unlocked access"
    VERBATIM
  )
endif()

# Roadmap: «P1. Добавить fuzzing после санитайзеров. Отдельные libFuzzer targets
# сначала для `.srs` …»
#
# Мишени собираются только по явной опции и только Clang: libFuzzer — часть
# Clang, а санитайзеры и инструментация покрытия не должны попадать ни в
# router/IPK binary, ни в обычный тестовый прогон.
option(KEEN_PBR_FUZZ "Build libFuzzer targets (requires Clang)" OFF)

if(KEEN_PBR_FUZZ)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "KEEN_PBR_FUZZ requires Clang; libFuzzer is not available in GCC.")
  endif()

  add_executable(keen-pbr-fuzz-srs
    fuzz/fuzz_srs_decoder.cpp
    ../src/lists/srs_decoder.cpp
  )
  set_target_properties(keen-pbr-fuzz-srs PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
  )
  target_include_directories(keen-pbr-fuzz-srs PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
  )
  target_link_libraries(keen-pbr-fuzz-srs PRIVATE PkgConfig::ZLIB)
  target_compile_options(keen-pbr-fuzz-srs PRIVATE
    -fsanitize=fuzzer,address,undefined
    -fno-sanitize-recover=undefined
    -fno-omit-frame-pointer
    -g
  )
  target_link_options(keen-pbr-fuzz-srs PRIVATE
    -fsanitize=fuzzer,address,undefined
  )

  # Вторая мишень: JSON-конфигурация. Пользователь правит её руками,
  # восстанавливает из резервной копии и переносит между версиями.
  add_executable(keen-pbr-fuzz-config
    fuzz/fuzz_config_parser.cpp
    ../src/config/config.cpp
    ../src/firewall/port_spec_util.cpp
    ../src/dns/dns_server.cpp
    ../src/dns/dns_probe_server.cpp
    ../src/util/system_info.cpp
    ../src/http/http_client.cpp
    ../src/http/http_transport.cpp
    ../src/http/curl_runtime.cpp
    ../src/log/logger.cpp
    ../src/log/trace.cpp
    ../src/util/traced_mutex.cpp
  )
  set_target_properties(keen-pbr-fuzz-config PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
  )
  target_include_directories(keen-pbr-fuzz-config PRIVATE
    ${KEEN_PBR_GENERATED_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
  )
  target_link_libraries(keen-pbr-fuzz-config PRIVATE
    nlohmann_json::nlohmann_json
    fmt::fmt-header-only
    ${KEEN_PBR_CURL_TARGET}
    PkgConfig::ZLIB
    Threads::Threads
  )
  target_compile_options(keen-pbr-fuzz-config PRIVATE
    -fsanitize=fuzzer,address,undefined
    -fno-sanitize-recover=undefined
    -fno-omit-frame-pointer
    -g
  )
  target_link_options(keen-pbr-fuzz-config PRIVATE
    -fsanitize=fuzzer,address,undefined
  )

  # Третья мишень: текстовый список. Самый внешний вход из всех — скачивается
  # по URL из чужого каталога, содержимое не контролирует никто из нас.
  add_executable(keen-pbr-fuzz-list
    fuzz/fuzz_list_parser.cpp
    ../src/config/list_parser.cpp
    ../src/log/logger.cpp
    ../src/log/trace.cpp
    ../src/util/traced_mutex.cpp
  )
  set_target_properties(keen-pbr-fuzz-list PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
  )
  target_include_directories(keen-pbr-fuzz-list PRIVATE
    ${KEEN_PBR_GENERATED_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
  )
  target_link_libraries(keen-pbr-fuzz-list PRIVATE
    nlohmann_json::nlohmann_json
    fmt::fmt-header-only
    Threads::Threads
  )
  target_compile_options(keen-pbr-fuzz-list PRIVATE
    -fsanitize=fuzzer,address,undefined
    -fno-sanitize-recover=undefined
    -fno-omit-frame-pointer
    -g
  )
  target_link_options(keen-pbr-fuzz-list PRIVATE
    -fsanitize=fuzzer,address,undefined
  )

  # Четвёртая мишень: разбор вывода iptables-save. Вход не пользовательский, а
  # от чужой программы: версия iptables на роутере не наша, а на BusyBox вывод
  # бывает урезанным.
  add_executable(keen-pbr-fuzz-iptables
    fuzz/fuzz_iptables_parser.cpp
    ../src/firewall/iptables_verifier.cpp
    ../src/firewall/port_spec_util.cpp
    ../src/log/logger.cpp
    ../src/log/trace.cpp
    ../src/util/traced_mutex.cpp
  )
  set_target_properties(keen-pbr-fuzz-iptables PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
  )
  target_include_directories(keen-pbr-fuzz-iptables PRIVATE
    ${KEEN_PBR_GENERATED_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
  )
  target_link_libraries(keen-pbr-fuzz-iptables PRIVATE
    nlohmann_json::nlohmann_json
    fmt::fmt-header-only
    Threads::Threads
  )
  target_compile_options(keen-pbr-fuzz-iptables PRIVATE
    -fsanitize=fuzzer,address,undefined
    -fno-sanitize-recover=undefined
    -fno-omit-frame-pointer
    -g
  )
  target_link_options(keen-pbr-fuzz-iptables PRIVATE
    -fsanitize=fuzzer,address,undefined
  )

  # Пятая мишень: снимок conntrack. Разбор достигается через штатный внедряемый
  # SnapshotReader — тот же, которым пользуются существующие тесты, — поэтому
  # выносить внутреннюю функцию из анонимного пространства имён не потребовалось.
  add_executable(keen-pbr-fuzz-conntrack
    fuzz/fuzz_conntrack_parser.cpp
    ../src/runtime/conntrack_manager.cpp
    ../src/log/logger.cpp
    ../src/log/trace.cpp
    ../src/util/traced_mutex.cpp
  )
  set_target_properties(keen-pbr-fuzz-conntrack PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
  )
  target_include_directories(keen-pbr-fuzz-conntrack PRIVATE
    ${KEEN_PBR_GENERATED_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
  )
  target_link_libraries(keen-pbr-fuzz-conntrack PRIVATE
    nlohmann_json::nlohmann_json
    fmt::fmt-header-only
    Threads::Threads
  )
  target_compile_options(keen-pbr-fuzz-conntrack PRIVATE
    -fsanitize=fuzzer,address,undefined
    -fno-sanitize-recover=undefined
    -fno-omit-frame-pointer
    -g
  )
  target_link_options(keen-pbr-fuzz-conntrack PRIVATE
    -fsanitize=fuzzer,address,undefined
  )
endif()
