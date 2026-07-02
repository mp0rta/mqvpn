cmake_minimum_required(VERSION 3.10)
project(mqvpn VERSION 0.8.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ---------- Options ----------
option(XQUIC_BUILD_DIR "Path to pre-built xquic build directory" "")
option(ENABLE_SANITIZERS "Enable ASan + UBSan" OFF)
option(ENABLE_MSAN "Enable MemorySanitizer" OFF)
option(MQVPN_DEBUG_QOS_OVERRIDE
       "Enable MQVPN_DGRAM_QOS_OVERRIDE env var for FEC ablation testing — debug only"
       OFF)
if(MQVPN_DEBUG_QOS_OVERRIDE)
    add_compile_definitions(MQVPN_DEBUG_QOS_OVERRIDE)
endif()

if(ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -Werror)
    add_link_options(-fsanitize=address,undefined)
elseif(ENABLE_MSAN)
    add_compile_options(-fsanitize=memory -fno-omit-frame-pointer -fsanitize-memory-track-origins)
    add_link_options(-fsanitize=memory)
endif()

# ---------- xquic ----------
# xquic has its own complex build system (SSL dependency, etc).
# Two modes:
#   1. XQUIC_BUILD_DIR is set → use pre-built xquic from that directory
#   2. Otherwise → try add_subdirectory (requires SSL_PATH to be set)

set(XQUIC_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/third_party/xquic/include)

if(XQUIC_BUILD_DIR)
    message(STATUS "Using pre-built xquic from: ${XQUIC_BUILD_DIR}")
    add_library(xquic SHARED IMPORTED)
    if(WIN32)
        set_target_properties(xquic PROPERTIES
            IMPORTED_LOCATION "${XQUIC_BUILD_DIR}/xquic.dll"
            IMPORTED_IMPLIB "${XQUIC_BUILD_DIR}/xquic.lib"
        )
        if(EXISTS "${XQUIC_BUILD_DIR}/xquic-static.lib")
            add_library(xquic-static STATIC IMPORTED)
            set_target_properties(xquic-static PROPERTIES
                IMPORTED_LOCATION "${XQUIC_BUILD_DIR}/xquic-static.lib"
            )
        endif()
    else()
        set_target_properties(xquic PROPERTIES
            IMPORTED_LOCATION "${XQUIC_BUILD_DIR}/libxquic.so"
        )
        if(EXISTS "${XQUIC_BUILD_DIR}/libxquic-static.a")
            add_library(xquic-static STATIC IMPORTED)
            set_target_properties(xquic-static PROPERTIES
                IMPORTED_LOCATION "${XQUIC_BUILD_DIR}/libxquic-static.a"
            )
        endif()
    endif()
else()
    message(STATUS "Building xquic from source (requires SSL_PATH or SSL_DIR)")
    add_subdirectory(third_party/xquic)
endif()

# ---------- libevent (not needed for Android / library-only builds) ----------
option(ANDROID_CROSS_COMPILE "Cross-compiling for Android (skip libevent + CLI)" OFF)

if(NOT ANDROID_CROSS_COMPILE)
    if(WIN32)
        find_package(Libevent CONFIG QUIET)
        if(NOT Libevent_FOUND)
            find_path(EVENT_INCLUDE_DIR event2/event.h)
            find_library(EVENT_LIB event)
            if(NOT EVENT_LIB)
                message(FATAL_ERROR "libevent not found. Install via vcpkg: vcpkg install libevent")
            endif()
        endif()
    else()
        find_path(EVENT_INCLUDE_DIR event2/event.h)
        find_library(EVENT_LIB event)
        if(NOT EVENT_LIB)
            message(FATAL_ERROR "libevent not found. Install: apt install libevent-dev")
        endif()
    endif()
endif()

# ---------- Hybrid mode TCP lane (lwIP, Linux-only in v1) ----------
option(MQVPN_ENABLE_HYBRID_TCP_LANE
       "Build the hybrid-mode lwIP TCP lane (Linux-only in v1)" OFF)
if(MQVPN_ENABLE_HYBRID_TCP_LANE AND NOT WIN32 AND NOT ANDROID_CROSS_COMPILE)
    set(MQVPN_HYBRID_TCP_LANE_BUILD ON)
else()
    if(MQVPN_ENABLE_HYBRID_TCP_LANE)
        message(WARNING "MQVPN_ENABLE_HYBRID_TCP_LANE requested but target "
                         "is Windows/Android — hybrid TCP lane is Linux-only "
                         "in v1, ignoring.")
    endif()
    set(MQVPN_HYBRID_TCP_LANE_BUILD OFF)
endif()

# Prefer static xquic to avoid runtime library path issues
if(TARGET xquic-static)
    set(XQUIC_LIB xquic-static)
else()
    set(XQUIC_LIB xquic)
endif()

# Find SSL libraries (same ones xquic links against)
if(NOT BORINGSSL_BUILD_DIR)
    set(BORINGSSL_BUILD_DIR "${CMAKE_SOURCE_DIR}/third_party/xquic/third_party/boringssl/build")
endif()
if(ANDROID_CROSS_COMPILE)
    # find_library doesn't work for cross-compile targets; set paths directly
    if(EXISTS "${BORINGSSL_BUILD_DIR}/ssl/libssl.a")
        set(SSL_LIB "${BORINGSSL_BUILD_DIR}/ssl/libssl.a")
        set(CRYPTO_LIB "${BORINGSSL_BUILD_DIR}/crypto/libcrypto.a")
    else()
        set(SSL_LIB "${BORINGSSL_BUILD_DIR}/libssl.a")
        set(CRYPTO_LIB "${BORINGSSL_BUILD_DIR}/libcrypto.a")
    endif()
else()
    find_library(SSL_LIB ssl
        HINTS ${BORINGSSL_BUILD_DIR} ${BORINGSSL_BUILD_DIR}/ssl /usr/local/lib /usr/local/babassl/lib)
    find_library(CRYPTO_LIB crypto
        HINTS ${BORINGSSL_BUILD_DIR} ${BORINGSSL_BUILD_DIR}/crypto /usr/local/lib /usr/local/babassl/lib)
endif()

# ---------- libmqvpn source files (shared between static and shared targets) ----------
set(MQVPN_LIB_SOURCES
    src/mqvpn_config.c
    src/mqvpn_client.c
    src/mqvpn_server.c
    src/mqvpn_conn_settings.c
    src/mqvpn_util.c
    src/path_state_machine.c
    src/flow_sched.c
    src/addr_pool.c
    src/auth.c
    src/log.c
    src/icmp.c
    src/reorder_tx.c
    src/reorder_rx.c
    src/hybrid/classifier.c
)

# ─── lwIP (hybrid mode TCP lane, Linux-only v1 — see MQVPN_HYBRID_TCP_LANE_BUILD) ───
if(MQVPN_HYBRID_TCP_LANE_BUILD)
set(LWIP_ROOT ${CMAKE_SOURCE_DIR}/third_party/lwip)
set(LWIP_PORT_DIR ${CMAKE_SOURCE_DIR}/src/hybrid/lwip_port)

set(LWIP_CORE_SOURCES
    ${LWIP_ROOT}/src/core/def.c
    ${LWIP_ROOT}/src/core/init.c
    ${LWIP_ROOT}/src/core/inet_chksum.c
    ${LWIP_ROOT}/src/core/ip.c
    ${LWIP_ROOT}/src/core/mem.c
    ${LWIP_ROOT}/src/core/memp.c
    ${LWIP_ROOT}/src/core/netif.c
    ${LWIP_ROOT}/src/core/pbuf.c
    ${LWIP_ROOT}/src/core/stats.c
    ${LWIP_ROOT}/src/core/sys.c
    ${LWIP_ROOT}/src/core/tcp.c
    ${LWIP_ROOT}/src/core/tcp_in.c
    ${LWIP_ROOT}/src/core/tcp_out.c
    ${LWIP_ROOT}/src/core/timeouts.c
    ${LWIP_ROOT}/src/core/ipv4/ip4.c
    ${LWIP_ROOT}/src/core/ipv4/ip4_addr.c
    ${LWIP_ROOT}/src/core/ipv4/ip4_frag.c
    ${LWIP_ROOT}/src/core/ipv4/icmp.c
)

add_library(lwip_core STATIC ${LWIP_CORE_SOURCES})
target_include_directories(lwip_core PUBLIC
    ${LWIP_ROOT}/src/include
    ${LWIP_PORT_DIR}
)
target_compile_definitions(lwip_core PRIVATE LWIP_NOASSERT=$<CONFIG:Release>)
# mqvpn_shared (a SHARED target) links this static lib below — its objects
# must be position-independent, same reason xquic-static is unusable there.
set_target_properties(lwip_core PROPERTIES POSITION_INDEPENDENT_CODE ON)
set(LWIP_LIB lwip_core)

# Registered into the SAME shared list classifier.c (H1) already lives in.
# Must happen here, before MQVPN_LIB_SOURCES is consumed by add_library()
# below (mqvpn_lib) and further down (mqvpn_shared) — variable expansion in
# add_library() is immediate, not deferred.
list(APPEND MQVPN_LIB_SOURCES ${CMAKE_SOURCE_DIR}/src/hybrid/lwip_glue.c)
endif() # MQVPN_HYBRID_TCP_LANE_BUILD

# ---------- libmqvpn (static library — no libevent, no platform I/O) ----------
add_library(mqvpn_lib STATIC ${MQVPN_LIB_SOURCES})
if(WIN32)
    set_target_properties(mqvpn_lib PROPERTIES OUTPUT_NAME mqvpn_lib)
else()
    set_target_properties(mqvpn_lib PROPERTIES OUTPUT_NAME mqvpn)
endif()
target_include_directories(mqvpn_lib
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    PRIVATE ${CMAKE_SOURCE_DIR}/src ${XQUIC_INCLUDE_DIR}
)
if(ANDROID_CROSS_COMPILE)
    # Android NDK: pthread is in libc, no separate -lpthread
    target_link_libraries(mqvpn_lib ${XQUIC_LIB} ${SSL_LIB} ${CRYPTO_LIB})
elseif(WIN32)
    target_link_libraries(mqvpn_lib ${XQUIC_LIB} ${SSL_LIB} ${CRYPTO_LIB} ws2_32)
else()
    target_link_libraries(mqvpn_lib ${XQUIC_LIB} ${SSL_LIB} ${CRYPTO_LIB} pthread)
endif()
if(MQVPN_HYBRID_TCP_LANE_BUILD)
    target_link_libraries(mqvpn_lib ${LWIP_LIB})
    target_compile_definitions(mqvpn_lib PRIVATE MQVPN_HYBRID_TCP_LANE_ENABLED)
endif()

# Everything below requires libevent and a platform layer — skip for Android
if(NOT ANDROID_CROSS_COMPILE)

if(WIN32)

# ---------- Wintun SDK (header only — DLL loaded at runtime) ----------
set(WINTUN_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/third_party/wintun)

# ---------- mqvpn CLI binary (Windows) ----------
add_executable(mqvpn
    src/main.c
    src/platform/windows/platform_windows.c
    src/platform/windows/tun_wintun.c
    src/platform/windows/routing.c
    src/platform/windows/firewall.c
    src/platform/windows/dns.c
    src/path_mgr.c
    src/config.c
    src/compat/getopt.c
)

target_include_directories(mqvpn PRIVATE
    ${XQUIC_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/compat
    ${CMAKE_SOURCE_DIR}/src/platform/windows
    ${WINTUN_INCLUDE_DIR}
)

if(Libevent_FOUND)
    target_link_libraries(mqvpn
        mqvpn_lib
        ${XQUIC_LIB}
        libevent::core libevent::extra
        ${SSL_LIB}
        ${CRYPTO_LIB}
        ws2_32 iphlpapi fwpuclnt ole32
    )
else()
    target_include_directories(mqvpn PRIVATE ${EVENT_INCLUDE_DIR})
    target_link_libraries(mqvpn
        mqvpn_lib
        ${XQUIC_LIB}
        ${EVENT_LIB}
        ${SSL_LIB}
        ${CRYPTO_LIB}
        ws2_32 iphlpapi fwpuclnt ole32
    )
endif()

else() # NOT WIN32 — Linux

# Shared library variant
add_library(mqvpn_shared SHARED ${MQVPN_LIB_SOURCES})
set_target_properties(mqvpn_shared PROPERTIES
    OUTPUT_NAME mqvpn
    SOVERSION 1
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
target_include_directories(mqvpn_shared
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    PRIVATE ${CMAKE_SOURCE_DIR}/src ${XQUIC_INCLUDE_DIR}
)
# Shared lib needs shared xquic (static .a lacks -fPIC)
target_link_libraries(mqvpn_shared xquic ${SSL_LIB} ${CRYPTO_LIB} pthread)
if(MQVPN_HYBRID_TCP_LANE_BUILD)
    target_link_libraries(mqvpn_shared ${LWIP_LIB})
    target_compile_definitions(mqvpn_shared PRIVATE MQVPN_HYBRID_TCP_LANE_ENABLED)
endif()

# ---------- mqvpn CLI binary ----------
# Links libmqvpn for the library API; keeps platform-specific files separate.
add_executable(mqvpn
    src/main.c
    src/platform/linux/platform_linux.c
    src/platform/linux/control_socket.c
    src/platform/linux/status.c
    src/platform/linux/routing.c
    src/platform/linux/killswitch.c
    src/platform/linux/tun.c
    src/platform/linux/dns.c
    src/path_mgr.c
    src/config.c
)

target_include_directories(mqvpn PRIVATE
    ${XQUIC_INCLUDE_DIR}
    ${EVENT_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/platform/linux
)

target_link_libraries(mqvpn
    mqvpn_lib
    ${XQUIC_LIB}
    ${EVENT_LIB}
    ${SSL_LIB}
    ${CRYPTO_LIB}
    pthread
    dl
    m
    stdc++
)

# ---------- Tests ----------
option(BUILD_TESTING "Build unit tests" ON)
if(BUILD_TESTING)
    enable_testing()

    # Each test links only the source files it needs (no xquic dependency)
    add_executable(test_config  tests/test_config.c  src/config.c  src/log.c)
    add_executable(test_auth    tests/test_auth.c    src/auth.c    src/log.c)
    add_executable(test_session tests/test_session.c src/addr_pool.c src/log.c)
    add_executable(test_dns     tests/test_dns.c     src/platform/linux/dns.c     src/log.c)
    add_executable(test_flow_sched tests/test_flow_sched.c src/flow_sched.c src/log.c)
    add_executable(test_status tests/test_status.c)
    add_executable(test_path_state_machine
        tests/test_path_state_machine.c
        src/path_state_machine.c
    )
    add_executable(test_control_response_bound tests/test_control_response_bound.c)
    add_executable(test_reorder_common tests/test_reorder_common.c)
    add_executable(test_reorder_tx tests/test_reorder_tx.c src/reorder_tx.c src/log.c)
    # test_reorder_rx #include's src/reorder_rx.c to reach the file-local ring;
    # do NOT also list reorder_rx.c here (it would compile the TU twice).
    # mqvpn_config.c is linked (separate TU) for the composed-builder bridge test.
    add_executable(test_reorder_rx tests/test_reorder_rx.c src/mqvpn_config.c src/log.c)
    add_executable(test_reorder_config tests/test_reorder_config.c src/mqvpn_config.c src/config.c src/log.c)
    add_executable(test_classifier tests/test_classifier.c src/hybrid/classifier.c)

    foreach(t test_config test_auth test_session test_dns test_flow_sched test_status test_path_state_machine test_control_response_bound test_reorder_common test_reorder_tx test_reorder_rx test_reorder_config test_classifier)
        target_include_directories(${t} PRIVATE
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/platform/linux
            ${CMAKE_SOURCE_DIR}/include
        )
        set_target_properties(${t} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
        add_test(NAME ${t} COMMAND ${t})
    endforeach()

    # libmqvpn public API test (links libmqvpn + xquic)
    add_executable(test_api tests/test_api.c)
    target_link_libraries(test_api mqvpn_lib ${XQUIC_LIB} ${SSL_LIB} ${CRYPTO_LIB} dl m stdc++)
    target_include_directories(test_api PRIVATE ${CMAKE_SOURCE_DIR}/src)
    set_target_properties(test_api PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
    add_test(NAME test_api COMMAND test_api)

    # Server API test (links libmqvpn + xquic)
    add_executable(test_server tests/test_server.c)
    target_link_libraries(test_server mqvpn_lib ${XQUIC_LIB} ${SSL_LIB} ${CRYPTO_LIB} dl m stdc++)
    target_include_directories(test_server PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_compile_definitions(test_server PRIVATE
        TEST_CERT_FILE="${CMAKE_SOURCE_DIR}/tests/certs/test.crt"
        TEST_KEY_FILE="${CMAKE_SOURCE_DIR}/tests/certs/test.key"
    )
    set_target_properties(test_server PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
    add_test(NAME test_server COMMAND test_server)

    # Scheduler dispatch test (xquic-dependent — needs XQUIC_INCLUDE_DIR)
    add_executable(test_scheduler tests/test_scheduler.c)
    target_link_libraries(test_scheduler mqvpn_lib ${XQUIC_LIB} ${SSL_LIB} ${CRYPTO_LIB} dl m stdc++)
    target_include_directories(test_scheduler PRIVATE ${CMAKE_SOURCE_DIR}/src ${XQUIC_INCLUDE_DIR})
    set_target_properties(test_scheduler PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
    add_test(NAME test_scheduler COMMAND test_scheduler)

    add_executable(test_conn_settings tests/test_conn_settings.c)
    target_link_libraries(test_conn_settings mqvpn_lib ${XQUIC_LIB} ${SSL_LIB} ${CRYPTO_LIB} dl m stdc++)
    target_include_directories(test_conn_settings PRIVATE ${CMAKE_SOURCE_DIR}/src ${XQUIC_INCLUDE_DIR})
    set_target_properties(test_conn_settings PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
    add_test(NAME test_conn_settings COMMAND test_conn_settings)

    # CLI argv overflow shell test (runs the built mqvpn binary)
    add_test(NAME test_cli_path_argv
        COMMAND bash ${CMAKE_SOURCE_DIR}/tests/test_cli_path_argv.sh $<TARGET_FILE:mqvpn>)
endif()

# ---------- Install ----------
install(TARGETS mqvpn DESTINATION bin)
install(TARGETS mqvpn_lib DESTINATION lib)
install(TARGETS mqvpn_shared DESTINATION lib)
# Bundle xquic shared library (no standalone deb exists)
if(XQUIC_BUILD_DIR)
    if(IS_ABSOLUTE "${XQUIC_BUILD_DIR}")
        set(_XQUIC_BUILD_ABS "${XQUIC_BUILD_DIR}")
    else()
        get_filename_component(_XQUIC_BUILD_ABS
            "${CMAKE_BINARY_DIR}/${XQUIC_BUILD_DIR}" REALPATH)
    endif()
    install(FILES ${_XQUIC_BUILD_ABS}/libxquic.so DESTINATION lib)
endif()
install(FILES include/libmqvpn.h DESTINATION include)
configure_file(systemd/mqvpn-server.service.in
    ${CMAKE_BINARY_DIR}/systemd/mqvpn-server.service @ONLY)
configure_file(systemd/mqvpn-client@.service.in
    ${CMAKE_BINARY_DIR}/systemd/mqvpn-client@.service @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/systemd/mqvpn-server.service
              ${CMAKE_BINARY_DIR}/systemd/mqvpn-client@.service
        DESTINATION lib/systemd/system)
install(FILES systemd/server.conf.example systemd/client.conf.example
          systemd/server.json.example systemd/client.json.example
    DESTINATION /etc/mqvpn)
install(PROGRAMS scripts/mqvpn-server-nat.sh
        DESTINATION lib/mqvpn)

# Bundle the project license and NOTICE in /usr/share/doc/mqvpn/ inside the
# generated deb (and any tarball that runs `cmake --install`). Required by
# Apache-2.0 §4(a) for binary redistributions.
install(FILES
    "${CMAKE_SOURCE_DIR}/LICENSE"
    "${CMAKE_SOURCE_DIR}/NOTICE"
    DESTINATION share/doc/mqvpn)

# Bundle third-party LICENSE files for components statically/dynamically
# linked into the shipped binaries (xquic, BoringSSL). libevent is a system
# dependency (apt install libevent-dev) on Linux, so its LICENSE is not
# bundled here. Wintun is Windows-only.
#
# OPTIONAL: CI jobs that exercise install rules without checking out the
# xquic submodule (e.g., ci.yml systemd-test) skip these silently. Release
# jobs check out submodules; release.yml's "Verify license files in deb"
# step confirms presence post-build.
install(FILES
    "${CMAKE_SOURCE_DIR}/third_party/xquic/LICENSE"
    DESTINATION share/doc/mqvpn/third-party RENAME xquic.txt
    OPTIONAL)
install(FILES
    "${CMAKE_SOURCE_DIR}/third_party/xquic/third_party/boringssl/LICENSE"
    DESTINATION share/doc/mqvpn/third-party RENAME boringssl.txt
    OPTIONAL)

# ---------- CPack deb packaging (only when dpkg is available) ----------
find_program(DPKG_CMD dpkg)
if(DPKG_CMD)
    execute_process(COMMAND ${DPKG_CMD} --print-architecture
        OUTPUT_VARIABLE DPKG_ARCH OUTPUT_STRIP_TRAILING_WHITESPACE)

    set(CPACK_GENERATOR "DEB")
    set(CPACK_DEBIAN_PACKAGE_NAME "mqvpn")
    set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
    set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "${DPKG_ARCH}")
    set(CPACK_DEBIAN_FILE_NAME "mqvpn_${PROJECT_VERSION}_${DPKG_ARCH}.deb")
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
    set(CPACK_DEBIAN_PACKAGE_DESCRIPTION "Multipath QUIC VPN using MASQUE CONNECT-IP (RFC 9484)")
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "mp0rta")
    set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
        "${CMAKE_SOURCE_DIR}/packaging/postinst;${CMAKE_SOURCE_DIR}/packaging/postrm")
    include(CPack)
endif()

endif() # WIN32 / Linux

endif() # NOT ANDROID_CROSS_COMPILE
