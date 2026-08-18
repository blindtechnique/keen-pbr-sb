cmake_minimum_required(VERSION 3.14)

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/version.mk" KEEN_PBR_VERSION_LINES
  REGEX "^(KEEN_PBR_(VERSION|RELEASE)|SING_BOX_PINNED_VERSION)=")

foreach(line IN LISTS KEEN_PBR_VERSION_LINES)
  if(line MATCHES "^KEEN_PBR_VERSION=([0-9]+\\.[0-9]+\\.[0-9]+)$")
    set(KEEN_PBR_VERSION_FROM_FILE "${CMAKE_MATCH_1}")
  elseif(line MATCHES "^KEEN_PBR_RELEASE=([0-9]+)$")
    set(KEEN_PBR_RELEASE_FROM_FILE "${CMAKE_MATCH_1}")
  elseif(line MATCHES "^SING_BOX_PINNED_VERSION=([0-9.]+)$")
    set(SING_BOX_PINNED_VERSION "${CMAKE_MATCH_1}")
  endif()
endforeach()

if(NOT DEFINED KEEN_PBR_VERSION OR KEEN_PBR_VERSION STREQUAL "")
  set(KEEN_PBR_VERSION "${KEEN_PBR_VERSION_FROM_FILE}")
endif()

if(DEFINED ENV{KEEN_PBR_RELEASE_OVERRIDE} AND
   NOT "$ENV{KEEN_PBR_RELEASE_OVERRIDE}" STREQUAL "")
  set(KEEN_PBR_RELEASE "$ENV{KEEN_PBR_RELEASE_OVERRIDE}")
endif()

if(NOT DEFINED KEEN_PBR_RELEASE OR KEEN_PBR_RELEASE STREQUAL "")
  set(KEEN_PBR_RELEASE "${KEEN_PBR_RELEASE_FROM_FILE}")
endif()

if(NOT DEFINED KEEN_PBR_VERSION OR KEEN_PBR_VERSION STREQUAL "" OR
   NOT DEFINED KEEN_PBR_RELEASE OR KEEN_PBR_RELEASE STREQUAL "")
  message(FATAL_ERROR "Failed to read KEEN_PBR_VERSION/KEEN_PBR_RELEASE from version.mk")
endif()

if(NOT KEEN_PBR_VERSION MATCHES "^([0-9]+)\\.([0-9]+)\\.([0-9]+)$")
  message(FATAL_ERROR "KEEN_PBR_VERSION must use semantic version format X.Y.Z")
endif()

set(KEEN_PBR_VERSION_MAJOR "${CMAKE_MATCH_1}")
set(KEEN_PBR_VERSION_MINOR "${CMAKE_MATCH_2}")
set(KEEN_PBR_VERSION_PATCH "${CMAKE_MATCH_3}")

if(NOT KEEN_PBR_RELEASE MATCHES "^[0-9]+$")
  message(FATAL_ERROR "KEEN_PBR_RELEASE must contain only digits")
endif()

# Source identity is intentionally separate from version/release. Alpha
# packages keep a stable package version, while operators still need to know
# the exact source tree that produced an installed binary.
if(NOT DEFINED KEEN_PBR_COMMIT OR KEEN_PBR_COMMIT STREQUAL "")
  set(KEEN_PBR_COMMIT "$ENV{KEEN_PBR_COMMIT}")
endif()
if(KEEN_PBR_COMMIT STREQUAL "")
  find_package(Git QUIET)
  if(GIT_FOUND)
    execute_process(
      COMMAND "${GIT_EXECUTABLE}" rev-parse --short=12 HEAD
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
      OUTPUT_VARIABLE KEEN_PBR_COMMIT
      OUTPUT_STRIP_TRAILING_WHITESPACE
      RESULT_VARIABLE KEEN_PBR_GIT_REV_PARSE_RESULT
      ERROR_QUIET)
    if(NOT "${KEEN_PBR_GIT_REV_PARSE_RESULT}" STREQUAL "0")
      set(KEEN_PBR_COMMIT "")
    elseif(NOT KEEN_PBR_COMMIT STREQUAL "")
      execute_process(
        COMMAND "${GIT_EXECUTABLE}" status --porcelain --untracked-files=no
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        OUTPUT_VARIABLE KEEN_PBR_GIT_DIRTY
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE KEEN_PBR_GIT_STATUS_RESULT
        ERROR_QUIET)
      # An unreadable worktree cannot honestly be called clean.
      if(NOT "${KEEN_PBR_GIT_STATUS_RESULT}" STREQUAL "0" OR
         NOT KEEN_PBR_GIT_DIRTY STREQUAL "")
        set(KEEN_PBR_COMMIT "${KEEN_PBR_COMMIT}-dirty")
      endif()
    endif()
  endif()
endif()
if(KEEN_PBR_COMMIT STREQUAL "")
  set(KEEN_PBR_COMMIT "unknown")
endif()

if(NOT KEEN_PBR_COMMIT STREQUAL "unknown")
  string(REGEX REPLACE "-dirty$" "" KEEN_PBR_COMMIT_BASE "${KEEN_PBR_COMMIT}")
  string(LENGTH "${KEEN_PBR_COMMIT_BASE}" KEEN_PBR_COMMIT_BASE_LENGTH)
  if(NOT "${KEEN_PBR_COMMIT_BASE}" MATCHES "^[0-9a-f]+$" OR
     KEEN_PBR_COMMIT_BASE_LENGTH LESS 12 OR
     KEEN_PBR_COMMIT_BASE_LENGTH GREATER 64 OR
     (NOT "${KEEN_PBR_COMMIT}" STREQUAL "${KEEN_PBR_COMMIT_BASE}" AND
      NOT "${KEEN_PBR_COMMIT}" STREQUAL "${KEEN_PBR_COMMIT_BASE}-dirty"))
    message(FATAL_ERROR
      "KEEN_PBR_COMMIT must be 'unknown' or 12..64 lowercase hex characters, optionally followed by '-dirty'")
  endif()
endif()
message(STATUS
  "keen-pbr build identity: ${KEEN_PBR_VERSION}-${KEEN_PBR_RELEASE} (${KEEN_PBR_COMMIT})")

project(keen-pbr VERSION ${KEEN_PBR_VERSION} LANGUAGES CXX)

include(GNUInstallDirs)

if(DEFINED CMAKE_CXX_STANDARD AND NOT CMAKE_CXX_STANDARD STREQUAL "17")
  message(FATAL_ERROR "keen-pbr requires CMAKE_CXX_STANDARD=17.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Size optimization
add_compile_options(-ffunction-sections -fdata-sections)
add_link_options(-Wl,--gc-sections)

# Export symbols so crash diagnostics can recover names in non-signal-safe paths.
add_link_options(-rdynamic)

# Enrich nlohmann::json exception messages with JSON Pointer context.
add_compile_definitions(JSON_DIAGNOSTICS=1)

# Options
option(WITH_API "Build with REST API support (cpp-httplib)" ON)
option(USE_KEENETIC_API "Enable Keenetic RCI integration (DNS server type: keenetic)" OFF)
option(ENABLE_THREAD_SAFETY_ANALYSIS "Enable Clang thread-safety diagnostics for project targets" OFF)
option(KEEN_PBR_STATIC_LIBUNWIND "Prefer linking libunwind statically when a static archive is available" ON)
set(KEEN_PBR_DEFAULT_CONFIG_PATH "${CMAKE_INSTALL_FULL_SYSCONFDIR}/keen-pbr/config.json" CACHE STRING
  "Default config file path used by keen-pbr when --config is not passed")
set(KEEN_PBR_DEFAULT_LOG_FILE "${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/log/keen-pbr.log" CACHE STRING
  "Default log file written by the service command; empty disables file logging")
set(KEEN_PBR_FRONTEND_ROOT "${CMAKE_INSTALL_FULL_DATADIR}/keen-pbr/frontend" CACHE STRING
  "Default frontend static root served by API (SPA assets)")
set(KEEN_PBR_SYSTEM_RESOLVER_HOOK "${CMAKE_INSTALL_FULL_LIBDIR}/keen-pbr/dnsmasq.sh" CACHE STRING
  "System resolver hook command path compiled into keen-pbr")
set(KEEN_PBR_CONTROL_SOCKET "/run/keen-pbr/control.sock" CACHE STRING
  "Unix SOCK_STREAM control socket used by operational CLI commands")
set(KEEN_PBR_RESOLVER_FALLBACK_CONFIG "${CMAKE_INSTALL_FULL_SYSCONFDIR}/keen-pbr/dnsmasq-fallback.conf" CACHE STRING
  "Static dnsmasq config emitted when the daemon resolver stream is unavailable")
set(KEEN_PBR_TARGET_OS "linux" CACHE STRING
  "Compile-time target OS identity exposed via /api/health/service (for example: openwrt, keenetic, debian)")
set(_keen_pbr_use_libunwind_default ON)
if(KEEN_PBR_TARGET_OS STREQUAL "keenetic" OR
   (KEEN_PBR_TARGET_OS STREQUAL "openwrt" AND
    NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|aarch64|arm.*)$"))
  set(_keen_pbr_use_libunwind_default OFF)
endif()
option(KEEN_PBR_USE_LIBUNWIND
  "Attempt to find and use external libunwind for crash diagnostics"
  ${_keen_pbr_use_libunwind_default})

# Dependencies
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
pkg_check_modules(LIBCURL IMPORTED_TARGET libcurl)
pkg_check_modules(ZLIB REQUIRED IMPORTED_TARGET zlib)
if(TARGET PkgConfig::LIBCURL)
  # Prefer the distro-provided libcurl discovered via pkg-config so CI does not
  # accidentally link against a runner-local /usr/local curl build.
  set(KEEN_PBR_CURL_TARGET PkgConfig::LIBCURL)
  message(STATUS "Using pkg-config libcurl target: ${LIBCURL_LINK_LIBRARIES}")
else()
  find_package(CURL REQUIRED)
  set(KEEN_PBR_CURL_TARGET CURL::libcurl)
  message(STATUS "Using CMake libcurl target: ${CURL_LIBRARY_RELEASE}")
endif()
add_library(keen_pbr_libunwind INTERFACE)
set(KEEN_PBR_HAS_LIBUNWIND OFF)
if(KEEN_PBR_USE_LIBUNWIND)
  set(_keen_pbr_saved_find_library_suffixes "${CMAKE_FIND_LIBRARY_SUFFIXES}")
  set(_keen_pbr_prefer_static_libunwind ${KEEN_PBR_STATIC_LIBUNWIND})
  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    # GNU libstdc++ exception unwinding can break when a static libunwind
    # archive is linked into the final executable. Prefer the shared library.
    set(_keen_pbr_prefer_static_libunwind OFF)
  endif()
  if(_keen_pbr_prefer_static_libunwind)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ".so" ".so.8")
  endif()
  unset(LIBUNWIND_LIBRARY CACHE)
  unset(LIBUNWIND_INCLUDE_DIR CACHE)
  unset(LIBUNWIND CACHE)
  unset(LIBUNWIND_INCLUDE_DIRS CACHE)
  set(_keen_pbr_libunwind_include_hints
    "$ENV{STAGING_DIR}/usr/include"
    "$ENV{STAGING_DIR}/include"
  )
  set(_keen_pbr_libunwind_library_hints
    "$ENV{STAGING_DIR}/usr/lib"
    "$ENV{STAGING_DIR}/lib"
  )
  find_path(LIBUNWIND_INCLUDE_DIR
    NAMES libunwind.h libunwind/libunwind.h
    HINTS ${_keen_pbr_libunwind_include_hints}
    PATH_SUFFIXES libunwind
  )
  find_library(LIBUNWIND_LIBRARY
    NAMES unwind libunwind libunwind.so.8
    HINTS ${_keen_pbr_libunwind_library_hints}
  )
  if(LIBUNWIND_INCLUDE_DIR AND LIBUNWIND_LIBRARY)
    set(KEEN_PBR_HAS_LIBUNWIND ON)
    get_filename_component(LIBUNWIND_LIBRARY_DIR "${LIBUNWIND_LIBRARY}" DIRECTORY)
    list(APPEND CMAKE_INCLUDE_PATH "${LIBUNWIND_INCLUDE_DIR}")
    list(APPEND CMAKE_LIBRARY_PATH "${LIBUNWIND_LIBRARY_DIR}")
    set(LIBUNWIND "${LIBUNWIND_LIBRARY}" CACHE FILEPATH "libunwind library path shared with cpptrace" FORCE)
    set(LIBUNWIND_INCLUDE_DIRS "${LIBUNWIND_INCLUDE_DIR}" CACHE PATH "libunwind include path shared with cpptrace" FORCE)
  endif()
  set(CMAKE_FIND_LIBRARY_SUFFIXES "${_keen_pbr_saved_find_library_suffixes}")
endif()
find_library(LIBRESOLV resolv)
find_library(LIBATOMIC atomic)
if(NOT LIBRESOLV)
  message(FATAL_ERROR "libresolv is required for keen-pbr DNS resolution support")
endif()
message(STATUS "Found libresolv: ${LIBRESOLV}")

# res_ninit/res_nquery/res_nclose are a glibc extension. OpenWrt's musl
# exposes only the legacy resolver entry points, so probe the target libc
# instead of assuming that every Linux toolchain has the stateful API.
include(CheckCXXSourceCompiles)
set(_keen_pbr_saved_required_libraries "${CMAKE_REQUIRED_LIBRARIES}")
set(CMAKE_REQUIRED_LIBRARIES "${LIBRESOLV}")
check_cxx_source_compiles([=[
  #include <arpa/nameser.h>
  #include <resolv.h>
  int main() {
    struct __res_state state {};
    unsigned char answer[NS_PACKETSZ] {};
    if (res_ninit(&state) != 0) return 1;
    (void)res_nquery(&state, "localhost", ns_c_in, ns_t_a,
                     answer, sizeof(answer));
    res_nclose(&state);
    return 0;
  }
]=] KEEN_PBR_HAS_RESOLVER_STATE_API)
set(CMAKE_REQUIRED_LIBRARIES "${_keen_pbr_saved_required_libraries}")
unset(_keen_pbr_saved_required_libraries)
if(KEEN_PBR_HAS_RESOLVER_STATE_API)
  add_compile_definitions(KEEN_PBR_HAS_RESOLVER_STATE_API=1)
  message(STATUS "Using stateful libresolv API")
else()
  message(STATUS "Stateful libresolv API unavailable; using serialized legacy resolver API")
endif()

if(LIBATOMIC)
  message(STATUS "Found libatomic: ${LIBATOMIC}")
else()
  message(STATUS "libatomic not found; relying on toolchain default atomic support")
endif()
pkg_check_modules(LIBNL REQUIRED IMPORTED_TARGET libnl-3.0)
pkg_check_modules(LIBNL_ROUTE REQUIRED IMPORTED_TARGET libnl-route-3.0)
set(HTTPLIB_ANL_LIB "")

if(KEEN_PBR_HAS_LIBUNWIND)
  target_include_directories(keen_pbr_libunwind INTERFACE "${LIBUNWIND_INCLUDE_DIR}")
  target_link_libraries(keen_pbr_libunwind INTERFACE "${LIBUNWIND_LIBRARY}")
  message(STATUS "Using libunwind library: ${LIBUNWIND_LIBRARY}")
elseif(NOT KEEN_PBR_USE_LIBUNWIND)
  message(STATUS "External libunwind disabled; using compiler _Unwind backend")
else()
  message(STATUS "libunwind headers/library not found; falling back to compiler _Unwind backend")
endif()

# nlohmann/json (bundled as git submodule)
set(JSON_BuildTests OFF CACHE INTERNAL "")
set(JSON_Install OFF CACHE INTERNAL "")
add_subdirectory(third_party/nlohmann_json)

# fmt (bundled as git submodule)
set(FMT_DOC OFF CACHE INTERNAL "")
set(FMT_INSTALL OFF CACHE INTERNAL "")
set(FMT_TEST OFF CACHE INTERNAL "")
set(FMT_FUZZ OFF CACHE INTERNAL "")
set(FMT_CUDA_TEST OFF CACHE INTERNAL "")
add_subdirectory(third_party/fmt)

# cpptrace (bundled as git submodule, crash diagnostics only)
set(CPPTRACE_BUILD_SHARED OFF CACHE INTERNAL "")
set(CPPTRACE_INSTALL OFF CACHE INTERNAL "")
set(CPPTRACE_UNWIND_WITH_LIBUNWIND ${KEEN_PBR_HAS_LIBUNWIND} CACHE BOOL "" FORCE)
if(KEEN_PBR_HAS_LIBUNWIND)
  set(CPPTRACE_UNWIND_WITH_UNWIND OFF CACHE BOOL "" FORCE)
else()
  set(CPPTRACE_UNWIND_WITH_UNWIND ON CACHE BOOL "" FORCE)
endif()
set(CPPTRACE_UNWIND_WITH_EXECINFO OFF CACHE BOOL "" FORCE)
set(CPPTRACE_GET_SYMBOLS_WITH_LIBDL ON CACHE BOOL "" FORCE)
set(CPPTRACE_GET_SYMBOLS_WITH_LIBDWARF OFF CACHE BOOL "" FORCE)
set(CPPTRACE_GET_SYMBOLS_WITH_ADDR2LINE OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/cpptrace EXCLUDE_FROM_ALL)
set(CMAKE_FIND_LIBRARY_SUFFIXES "${_keen_pbr_saved_find_library_suffixes}")

# cpp-httplib (bundled as git submodule, only if WITH_API — no TLS needed)
if(WITH_API)
  set(HTTPLIB_USE_OPENSSL_IF_AVAILABLE OFF CACHE INTERNAL "")
  set(HTTPLIB_INSTALL OFF CACHE INTERNAL "")
  find_library(HTTPLIB_ANL_LIB anl)
  if(HTTPLIB_ANL_LIB)
    set(HTTPLIB_USE_NON_BLOCKING_GETADDRINFO ON CACHE BOOL "" FORCE)
  else()
    set(HTTPLIB_USE_NON_BLOCKING_GETADDRINFO OFF CACHE BOOL "" FORCE)
  endif()
  add_subdirectory(third_party/cpp-httplib)
endif()

add_library(keen_pbr_project_options INTERFACE)

# Roadmap: "P0. Добавить политику предупреждений и native sanitizer job.
# Сначала включить `-Wall -Wextra` без `-Werror`, зафиксировать baseline и
# устранить реальные дефекты. Затем применять `-Werror` только к современной
# native GCC/Clang CI-сборке. Entware GCC 8.4 и cross-build не блокировать
# отличающимся набором предупреждений."
#
# Флаги висят на keen_pbr_project_options, а он применяется только к нашим
# целям: third_party собирается своими правилами, и чужие предупреждения в наш
# baseline не попадают.
option(KEEN_PBR_EXTRA_WARNINGS "Build project targets with -Wall -Wextra" ON)
option(KEEN_PBR_WERROR "Treat project warnings as errors (native CI only)" OFF)

if(KEEN_PBR_EXTRA_WARNINGS)
  target_compile_options(keen_pbr_project_options INTERFACE
    -Wall
    -Wextra
    # Единственное отключение, и оно осознанное. В C++ пропущенные члены
    # агрегата инициализируются значением, а не остаются мусором, поэтому
    # записи вида `{spec, {}}` в этом коде безопасны и намеренны. Все 28
    # срабатываний на дереве были ровно такими: оставить их значило бы утопить
    # настоящие находки в шуме и не включить `-Werror` никогда. Логическое
    # «забыл заполнить поле» ловит clang-analyzer, а не это предупреждение.
    -Wno-missing-field-initializers
  )
  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND
     CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 12)
    # Известный ложноположительный класс GCC 12+: при -O2/-O3 анализ границ
    # массива проходит сквозь инлайн nlohmann::json в libstdc++ и сообщает о
    # выходе за пределы внутри _Rb_tree. На дереве это 492 предупреждения из
    # 499, и ни одно не указывает на файл из src/ — все приходят из
    # third_party и системных заголовков через цепочку инлайна, поэтому
    # пометка их SYSTEM не помогает. Ограничено GCC 12+: у Clang и целевого
    # Entware GCC 8 этот класс не подтверждён, поэтому полезную диагностику на
    # старом компиляторе не заглушаем.
    target_compile_options(keen_pbr_project_options INTERFACE -Wno-array-bounds)
  endif()
endif()

if(KEEN_PBR_WERROR)
  target_compile_options(keen_pbr_project_options INTERFACE -Werror)
endif()

# Roadmap: «Отдельно запускать `keen-pbr-tests` и firewall IT с ASan+UBSan;
# санитайзеры никогда не входят в router/IPK binary.»
#
# Поэтому это отдельная опция, выключенная по умолчанию, и отдельный каталог
# сборки: включить её в той же сборке, из которой собирается пакет, нельзя.
option(KEEN_PBR_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

if(KEEN_PBR_SANITIZE)
  if(CMAKE_BUILD_TYPE STREQUAL "Release")
    message(WARNING
      "KEEN_PBR_SANITIZE with CMAKE_BUILD_TYPE=Release hides frames; prefer Debug or RelWithDebInfo.")
  endif()
  # -fno-sanitize-recover: первая же UB останавливает прогон. Это нарочно —
  # неопределённое поведение не бывает «частично допустимым», а без остановки
  # его легко пролистать в шуме логов.
  target_compile_options(keen_pbr_project_options INTERFACE
    -fsanitize=address,undefined
    -fno-sanitize-recover=undefined
    -fno-omit-frame-pointer
    -g
  )
  target_link_options(keen_pbr_project_options INTERFACE
    -fsanitize=address,undefined
  )
endif()

if(ENABLE_THREAD_SAFETY_ANALYSIS)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(keen_pbr_project_options INTERFACE
      -Wthread-safety
      -Werror=thread-safety
    )
  else()
    message(WARNING "ENABLE_THREAD_SAFETY_ANALYSIS is only supported with Clang; no extra diagnostics will be added.")
  endif()
endif()

function(keen_pbr_apply_project_options target_name)
  target_link_libraries(${target_name} PRIVATE keen_pbr_project_options)
endfunction()

# Sources
set(SOURCES
  src/log/logger.cpp
  src/log/file_sink.cpp
  src/log/trace.cpp
  src/http/http_client.cpp
  src/http/http_transport.cpp
  src/http/curl_runtime.cpp
  src/keenetic/ndms_catalog_cache.cpp
  src/keenetic/ndms_interface_inventory.cpp
  src/keenetic/internal_vpn_server_resolver.cpp
  src/keenetic/ndms_vpn_server_service.cpp
  src/keenetic/ndms_vpn_server_service_cache.cpp
  src/keenetic/internal_vpn_service_resolver.cpp
  src/keenetic/internal_vpn_ingress_resolver.cpp
  src/keenetic/ndms_interface_management.cpp
  src/keenetic/ndms_native_allocator_fence.cpp
  src/keenetic/ndms_native_create_policy.cpp
  src/keenetic/ndms_native_import_baseline.cpp
  src/keenetic/ndms_native_import_executor.cpp
  src/keenetic/ndms_native_import_readiness.cpp
  src/keenetic/ndms_native_import_startup_recovery.cpp
  src/keenetic/ndms_native_import_request.cpp
  src/keenetic/ndms_native_import_transport.cpp
  src/keenetic/ndms_native_import_wal.cpp
  src/keenetic/ndms_native_import_recovery_observation.cpp
  src/keenetic/ndms_native_import_recovery_lease.cpp
  src/keenetic/ndms_native_ownership_store.cpp
  src/keenetic/ndms_native_import_recovery_plan.cpp
  src/keenetic/ndms_native_import_recovery_dispatch.cpp
  src/keenetic/ndms_native_import_forward_plan.cpp
  src/keenetic/ndms_native_import_recovery_probe.cpp
  src/crypto/chacha20poly1305.cpp
  src/keenetic/ndms_native_secret_snapshot.cpp
  src/keenetic/ndms_native_secret_redaction.cpp
  src/keenetic/ndms_native_interface_delete.cpp
  src/keenetic/ndms_native_tunnel_removal.cpp
  src/keenetic/ndms_native_ownership_reconcile.cpp
  src/keenetic/ndms_native_remove_policy.cpp
  src/keenetic/ndms_native_interface_delete_production.cpp
  src/keenetic/ndms_native_target_evidence.cpp
  src/keenetic/ndms_native_import_wal_store.cpp
  src/keenetic/ndms_native_management_preflight.cpp
  src/keenetic/ndms_native_mutation_plan.cpp
  src/keenetic/ndms_native_import_response.cpp
  src/keenetic/ndms_native_reconcile_barrier.cpp
  src/keenetic/ndms_native_tunnel_import.cpp
  src/keenetic/ndms_wireguard_identity.cpp
  src/keenetic/ndms_rci_observation.cpp
  src/keenetic/ndms_rci_restorable_snapshot.cpp
  src/keenetic/ndms_web_endpoint.cpp
  src/keenetic/ndms_credential_generation.cpp
  src/keenetic/ndms_lockout_policy.cpp
  src/api/system_auth_capability.cpp
  src/api/step_up.cpp
  src/crash/crash_diagnostics.cpp
  src/backup/persistent_snapshot.cpp
  src/backup/restore_journal.cpp
  src/backup/restore_transaction.cpp
  src/backup/recovery_coordinator.cpp
  src/update/maintenance_lock.cpp
  src/update/rollback_availability.cpp
  src/update/sing_box_install_policy.cpp
  src/update/sing_box_install_observation.cpp
  src/update/sing_box_release_plan.cpp
  src/update/sing_box_installer.cpp
  src/update/sing_box_transport_pause.cpp
  src/update/sing_box_install_steps.cpp
  src/update/package_footprint.cpp
  src/update/component_transaction_journal.cpp
  src/update/component_capture.cpp
  src/util/nfqws_config_migration.cpp
  src/util/nfqws_runtime_state.cpp
  src/config/config.cpp
  src/config/config_writer.cpp
  src/config/subscription_fetch_policy.cpp
  src/config/subscription_import_plan.cpp
  src/config/subscription_transport_naming.cpp
  src/config/dependency_analysis.cpp
  src/config/list_delete_planner.cpp
  src/config/routing_state.cpp
  src/config/list_parser.cpp
  src/setup/catalog_setup_planner.cpp
  src/lists/ipset.cpp
  src/lists/kernel_set_tester.cpp
  src/lists/list_streamer.cpp
  src/lists/list_set_usage.cpp
  src/lists/srs_decoder.cpp
  src/cache/cache_manager.cpp
  src/connections/conntrack_event_monitor.cpp
  src/runtime/conntrack_manager.cpp
  src/runtime/interface_traffic_cadence.cpp
  src/runtime/interface_traffic_sampler.cpp
  src/runtime/interface_uptime_anchor.cpp
  src/runtime/periodic_task_metrics.cpp
  src/cmd/recover_persistent_state.cpp
  src/cmd/status.cpp
  src/cmd/test_routing.cpp
  src/routing/target.cpp
  src/routing/netlink.cpp
  src/routing/interface_monitor.cpp
  src/routing/route_table.cpp
  src/routing/policy_rule.cpp
  src/routing/routing_verifier.cpp
  src/health/circuit_breaker.cpp
  src/health/url_tester.cpp
  src/health/interface_probe.cpp
  src/health/routing_health_checker.cpp
  src/health/runtime_outbound_state.cpp
  src/health/runtime_interface_inventory.cpp
  src/routing/urltest_manager.cpp
  src/routing/firewall_state.cpp
  src/firewall/firewall.cpp
  src/firewall/firewall_runtime.cpp
  src/firewall/port_spec_util.cpp
  src/firewall/iptables.cpp
  src/firewall/ppe_deoffload.cpp
  src/firewall/ttl_bypass.cpp
  src/firewall/nftables.cpp
  src/firewall/ipset_restore_pipe.cpp
  src/firewall/nft_batch_pipe.cpp
  src/firewall/firewall_verifier.cpp
  src/firewall/iptables_verifier.cpp
  src/firewall/nftables_verifier.cpp
  src/dns/dns_server.cpp
  src/dns/keenetic_dns.cpp
  src/dns/dns_txt_client.cpp
  src/dns/dns_probe_server.cpp
  src/dns/dns_router.cpp
  src/dns/dnsmasq_gen.cpp
  src/dns/dnsmasq_access_policy.cpp
  src/daemon/config_store.cpp
  src/daemon/pid_file.cpp
  src/daemon/daemon_core.cpp
  src/daemon/daemon_runtime.cpp
  src/daemon/daemon_resolver.cpp
  src/daemon/keenetic_dns_refresh_coordinator.cpp
  src/daemon/resolver_stream_coordinator.cpp
  src/daemon/daemon_api.cpp
  src/daemon/daemon_dns_probe.cpp
  src/daemon/list_service.cpp
  src/runtime/list_refresh_task.cpp
  src/runtime/nfqws_runtime_contract.cpp
  src/daemon/resolver_health.cpp
  src/daemon/resolver_sync_state_machine.cpp
  src/daemon/runtime_state_store.cpp
  src/daemon/system_resolver_hook.cpp
  src/daemon/scheduler.cpp
  src/runtime/runtime_state_machine.cpp
  src/ipc/control_protocol.cpp
  src/ipc/control_client.cpp
  src/ipc/resolver_fallback.cpp
  src/util/blocking_executor.cpp
  src/util/base64.cpp
  src/util/firewall_backend_utils.cpp
  src/util/ipv6_support.cpp
  src/util/last_command_failure.cpp
  src/util/network_routes.cpp
  src/util/nfqws_config.cpp
  src/util/nfqws_file_writer.cpp
  src/util/nfqws_rotator_state.cpp
  src/util/nfqws_strategy_assets.cpp
  src/util/nfqws_validator.cpp
  src/util/system_info.cpp
  src/util/traced_mutex.cpp
  src/main.cpp
)

if(WITH_API)
  list(APPEND SOURCES
    src/api/server.cpp
    src/api/local_password_hash.cpp
    src/api/trusted_local_connection.cpp
    src/api/auth_runtime.cpp
    src/api/keenetic_auth.cpp
    src/api/connection_query.cpp
    src/api/handlers.cpp
    src/api/health_response.cpp
    src/api/sse_broadcaster.cpp
    src/api/status_stream.cpp
    src/api/handler_status_events.cpp
    src/api/handler_health_service.cpp
    src/api/update_version.cpp
    src/api/handler_reload.cpp
    src/api/handler_lists_refresh.cpp
    src/api/handler_config.cpp
    src/api/handler_dependency_analysis.cpp
    src/api/handler_health_routing.cpp
    src/api/handler_runtime_interfaces.cpp
    src/api/handler_runtime_outbounds.cpp
    src/api/handler_runtime_inventory.cpp
    src/api/handler_diagnostic_tasks.cpp
    src/api/handler_transports.cpp
    src/api/handler_subscriptions.cpp
    src/api/transport_manager_endpoint.cpp
    src/api/handler_test_routing.cpp
    src/api/handler_dns_test.cpp
    src/api/handler_connections.cpp
    src/api/handler_nfqws.cpp
    src/api/handler_logs.cpp
    src/api/handler_router_info.cpp
    src/api/handler_catalog.cpp
    src/api/handler_catalog_setup.cpp
    src/api/handler_geo.cpp
    src/api/handler_naive.cpp
    src/api/handler_ndms_names.cpp
    src/api/handler_remote_access.cpp
    src/api/handler_backup.cpp
    src/runtime/lifecycle_operation.cpp
  )
endif()

set(KEEN_PBR_GENERATED_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/include")
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/keen-pbr/version.hpp.in"
  "${KEEN_PBR_GENERATED_INCLUDE_DIR}/keen-pbr/version.hpp"
  @ONLY
)

# Executable
add_executable(keen-pbr ${SOURCES})
set_target_properties(keen-pbr PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
  CXX_EXTENSIONS NO
)
target_include_directories(keen-pbr PRIVATE
  "${KEEN_PBR_GENERATED_INCLUDE_DIR}"
  include
  src
  third_party/rapidxml
)
target_compile_definitions(keen-pbr PRIVATE
  KEEN_PBR_DEFAULT_CONFIG_PATH="${KEEN_PBR_DEFAULT_CONFIG_PATH}"
  KEEN_PBR_DEFAULT_LOG_FILE="${KEEN_PBR_DEFAULT_LOG_FILE}"
  KEEN_PBR_FRONTEND_ROOT="${KEEN_PBR_FRONTEND_ROOT}"
  KEEN_PBR_SYSTEM_RESOLVER_HOOK="${KEEN_PBR_SYSTEM_RESOLVER_HOOK}"
  KEEN_PBR_CONTROL_SOCKET="${KEEN_PBR_CONTROL_SOCKET}"
  KEEN_PBR_RESOLVER_FALLBACK_CONFIG="${KEEN_PBR_RESOLVER_FALLBACK_CONFIG}"
  KEEN_PBR_TARGET_OS="${KEEN_PBR_TARGET_OS}"
)
if(USE_KEENETIC_API)
  target_compile_definitions(keen-pbr PRIVATE USE_KEENETIC_API)
endif()
target_link_libraries(keen-pbr PRIVATE
  ${KEEN_PBR_CURL_TARGET}
  PkgConfig::ZLIB
  PkgConfig::LIBNL
  PkgConfig::LIBNL_ROUTE
  Threads::Threads
  cpptrace::cpptrace
  fmt::fmt-header-only
  keen_pbr_libunwind
  nlohmann_json::nlohmann_json
)
keen_pbr_apply_project_options(keen-pbr)

if(LIBATOMIC)
  target_link_libraries(keen-pbr PRIVATE ${LIBATOMIC})
endif()

target_link_libraries(keen-pbr PRIVATE ${LIBRESOLV})

if(WITH_API)
  target_compile_definitions(keen-pbr PRIVATE WITH_API)
  target_link_libraries(keen-pbr PRIVATE httplib::httplib)
  if(HTTPLIB_ANL_LIB)
    target_link_libraries(keen-pbr PRIVATE ${HTTPLIB_ANL_LIB})
  endif()
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
  target_link_libraries(keen-pbr PRIVATE stdc++fs)
endif()

install(TARGETS keen-pbr RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if(WITH_API)
  set(KEEN_PBR_PACKAGED_CONFIG "${CMAKE_SOURCE_DIR}/packages/common/config.full.example.json")
else()
  set(KEEN_PBR_PACKAGED_CONFIG "${CMAKE_SOURCE_DIR}/packages/common/config.headless.example.json")
endif()

install(FILES ${KEEN_PBR_PACKAGED_CONFIG}
  DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/keen-pbr
  RENAME config.json)
install(FILES ${CMAKE_SOURCE_DIR}/packages/common/local.lst
  DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/keen-pbr)

# Unit tests (optional, requires doctest submodule)
option(BUILD_TESTS "Build unit tests" OFF)
if(BUILD_TESTS)
  add_subdirectory(tests)
endif()
