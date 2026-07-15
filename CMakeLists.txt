cmake_minimum_required(VERSION 3.10)
project(mqvpn VERSION 0.11.1 LANGUAGES C)

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
        # Shared xquic's file extension differs between Darwin (.dylib) and
        # Linux (.so); the static archive name below is the same on both.
        if(APPLE)
            set(XQUIC_SHARED_LIB_NAME "libxquic.dylib")
        else()
            set(XQUIC_SHARED_LIB_NAME "libxquic.so")
        endif()
        set_target_properties(xquic PROPERTIES
            IMPORTED_LOCATION "${XQUIC_BUILD_DIR}/${XQUIC_SHARED_LIB_NAME}"
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

# ---------- Hybrid mode TCP lane (lwIP) ----------
option(MQVPN_ENABLE_HYBRID_TCP_LANE
       "Build the hybrid-mode lwIP TCP lane" ON)
# Effective-value var (not the option directly): consumed by the EGRESS gate
# below and the gates STATUS marker; the single seam if a platform ever needs
# exclusion again.
set(MQVPN_HYBRID_TCP_LANE_BUILD OFF)
if(MQVPN_ENABLE_HYBRID_TCP_LANE)
    set(MQVPN_HYBRID_TCP_LANE_BUILD ON)
endif()

# ---------- Hybrid mode server-side TCP egress (Linux-only) ----------
# Server-side connect-tcp egress (src/hybrid/tcp_egress.c): POSIX sockets +
# the platform egress-fd registry (platform_linux.c only). Depends on the
# client lane (shares classifier/ACL types; serves no purpose without the
# lane protocol). Unavailability downgrades with a warning, NEVER a
# configure error — plain -DMQVPN_ENABLE_HYBRID_TCP_LANE=OFF must keep
# configuring for existing CI jobs and downstream consumers.
option(MQVPN_ENABLE_HYBRID_TCP_EGRESS
       "Build the hybrid-mode server-side TCP egress (Linux-only)" ON)
if(MQVPN_ENABLE_HYBRID_TCP_EGRESS AND MQVPN_HYBRID_TCP_LANE_BUILD
   AND NOT WIN32 AND NOT APPLE AND NOT ANDROID_CROSS_COMPILE)
    set(MQVPN_HYBRID_TCP_EGRESS_BUILD ON)
else()
    if(MQVPN_ENABLE_HYBRID_TCP_EGRESS)
        message(WARNING "MQVPN_ENABLE_HYBRID_TCP_EGRESS requested but "
                         "unavailable (requires the hybrid TCP lane, on "
                         "Linux) — forcing OFF.")
    endif()
    set(MQVPN_HYBRID_TCP_EGRESS_BUILD OFF)
endif()
# Grep target for CI (quasi-stable once asserted — treat like a log marker):
message(STATUS "mqvpn hybrid gates: LANE_BUILD=${MQVPN_HYBRID_TCP_LANE_BUILD} "
               "EGRESS_BUILD=${MQVPN_HYBRID_TCP_EGRESS_BUILD}")

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
elseif(EXISTS "${BORINGSSL_BUILD_DIR}/ssl/libssl.a")
    # Prefer the sibling BoringSSL build artifacts explicitly when they
    # exist: find_library searches CMAKE_PREFIX_PATH (e.g. Homebrew on the
    # darwin CI runner) BEFORE the HINTS below, which can silently resolve
    # ssl/crypto to OpenSSL — but libxquic-static.a needs BoringSSL-only
    # symbols (SSL_set_quic_method, EVP_AEAD_*, HKDF_*, ...) at final link,
    # which only surfaces as undefined symbols when linking the CLI.
    set(SSL_LIB "${BORINGSSL_BUILD_DIR}/ssl/libssl.a")
    set(CRYPTO_LIB "${BORINGSSL_BUILD_DIR}/crypto/libcrypto.a")
elseif(EXISTS "${BORINGSSL_BUILD_DIR}/libssl.a")
    # Newer BoringSSL layouts place the archives at the build root.
    set(SSL_LIB "${BORINGSSL_BUILD_DIR}/libssl.a")
    set(CRYPTO_LIB "${BORINGSSL_BUILD_DIR}/libcrypto.a")
else()
    find_library(SSL_LIB ssl
        HINTS ${BORINGSSL_BUILD_DIR} ${BORINGSSL_BUILD_DIR}/ssl /usr/local/lib /usr/local/babassl/lib)
    find_library(CRYPTO_LIB crypto
        HINTS ${BORINGSSL_BUILD_DIR} ${BORINGSSL_BUILD_DIR}/crypto /usr/local/lib /usr/local/babassl/lib)
endif()
message(STATUS "SSL_LIB=${SSL_LIB} CRYPTO_LIB=${CRYPTO_LIB}")

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

# ---------- lwIP (hybrid mode TCP lane — see MQVPN_HYBRID_TCP_LANE_BUILD) ----------
# Deliberately single-mode: no pre-built LWIP_BUILD_DIR variant (unlike
# xquic's two-mode pattern above) — lwIP is a handful of .c files, always
# built from source. YAGNI; add a pre-built mode only if a real need appears.
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
    # Chunk 4: dual-stack (LWIP_IPV6=1 in lwipopts.h). MLD/dhcp6/autoconf are
    # OFF (lwipopts.h), so mld6.c/dhcp6.c are NOT needed — set pinned by the
    # linker (undefined-symbol errors), not added speculatively.
    ${LWIP_ROOT}/src/core/ipv6/ip6.c
    ${LWIP_ROOT}/src/core/ipv6/ip6_addr.c
    ${LWIP_ROOT}/src/core/ipv6/ip6_frag.c
    ${LWIP_ROOT}/src/core/ipv6/icmp6.c
    ${LWIP_ROOT}/src/core/ipv6/nd6.c
)

add_library(lwip_core STATIC ${LWIP_CORE_SOURCES})
target_include_directories(lwip_core PUBLIC
    ${LWIP_ROOT}/src/include
    ${LWIP_PORT_DIR}
)
# debug.h gates on #ifndef LWIP_NOASSERT — the macro must be entirely absent
# in Debug (defining it =0 would still disable asserts), present in Release.
target_compile_definitions(lwip_core PRIVATE $<$<CONFIG:Release>:LWIP_NOASSERT>)
# Vendored third-party code — not held to -Werror (ENABLE_SANITIZERS adds it
# at directory scope; clang trips on lwIP's tautological-compare warnings).
# GCC-syntax flag; MSVC applies /WX only to mqvpn/mqvpn_lib, never lwip_core.
if(NOT MSVC)
    target_compile_options(lwip_core PRIVATE -Wno-error)
endif()
# mqvpn_shared (a SHARED target) links this static lib below — its objects
# must be position-independent, same reason xquic-static is unusable there.
set_target_properties(lwip_core PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Registered into the SAME shared list classifier.c (H1) already lives in.
# Must happen here, before MQVPN_LIB_SOURCES is consumed by add_library()
# below (mqvpn_lib) and further down (mqvpn_shared) — variable expansion in
# add_library() is immediate, not deferred.
list(APPEND MQVPN_LIB_SOURCES
    ${CMAKE_SOURCE_DIR}/src/hybrid/lwip_glue.c
    ${CMAKE_SOURCE_DIR}/src/hybrid/tcp_lane.c
    ${CMAKE_SOURCE_DIR}/src/hybrid/tcp_lane_uplink.c
)

# H2a micro-benchmark rig (Chunk 1 gate): TUN → classifier → lwIP → byte
# sink, NO QUIC. Standalone executable, deliberately NOT part of mqvpn_lib —
# links the hybrid sources directly. Driven by
# benchmarks/tcp_lane_microbench/run.sh (gate: >= 10 Gbit/s).
# harness.c is TUN/Linux-bound (<linux/if_tun.h>); the microbench is a
# Linux-only rig even where the lane itself builds.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(tcp_lane_microbench
        benchmarks/tcp_lane_microbench/harness.c
        src/hybrid/classifier.c
        src/hybrid/lwip_glue.c
        src/log.c
    )
    target_link_libraries(tcp_lane_microbench lwip_core)
    target_include_directories(tcp_lane_microbench PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
    )
    set_target_properties(tcp_lane_microbench PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
endif()

# libFuzzer target: classifier + lwIP packet-intake crash-safety (see
# fuzz/fuzz_tcp_lane.c for scope). Requires clang (-fsanitize=fuzzer is a
# clang-only flag); OFF by default so the normal build/CI is unaffected.
# Standalone executable, same "link the hybrid sources directly" shape as
# tcp_lane_microbench above — not part of mqvpn_lib.
option(MQVPN_ENABLE_FUZZING "Build libFuzzer targets (requires clang)" OFF)
if(MQVPN_ENABLE_FUZZING)
    # Fuzz-only instrumented lwIP: the production lwip_core links into the
    # non-sanitized mqvpn_lib/mqvpn_shared in this same tree, so ASan/SanCov
    # can't be added to it directly. Build a SEPARATE static lib from the
    # SAME lwIP sources with fuzzer-no-link,address (fuzzer-NO-link: only the
    # final exe carries the libFuzzer main; the lib just needs the coverage
    # instrumentation) so libFuzzer gets real coverage feedback from — and
    # ASan actually watches loads/stores inside — tcp_in.c/ip4.c/etc. Without
    # this the fuzzer explores lwIP BLIND (coverage plateaus, ASan is inert).
    # The -DCHECKSUM_CHECK_* overrides drop the ingress checksum wall
    # (lwipopts.h keeps 1 for production) so mutated packets reach the TCP
    # state machine instead of dying in ip4_input/tcp_input's checksum test.
    # -Wno-error: vendored code, same as lwip_core.
    add_library(lwip_core_fuzz STATIC ${LWIP_CORE_SOURCES})
    target_include_directories(lwip_core_fuzz PUBLIC
        ${LWIP_ROOT}/src/include
        ${LWIP_PORT_DIR}
    )
    target_compile_definitions(lwip_core_fuzz PRIVATE
        $<$<CONFIG:Release>:LWIP_NOASSERT>
        CHECKSUM_CHECK_IP=0
        CHECKSUM_CHECK_TCP=0)
    target_compile_options(lwip_core_fuzz PRIVATE
        -Wno-error -fsanitize=fuzzer-no-link,address)

    add_executable(fuzz_tcp_lane
        fuzz/fuzz_tcp_lane.c
        src/hybrid/classifier.c
        src/hybrid/lwip_glue.c
        src/log.c
    )
    target_compile_options(fuzz_tcp_lane PRIVATE -fsanitize=fuzzer,address)
    target_link_options(fuzz_tcp_lane PRIVATE -fsanitize=fuzzer,address)
    target_link_libraries(fuzz_tcp_lane PRIVATE lwip_core_fuzz)
    target_include_directories(fuzz_tcp_lane PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
    )
    set_target_properties(fuzz_tcp_lane PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
endif()
endif() # MQVPN_HYBRID_TCP_LANE_BUILD
# Same-list append as the lane sources above (still before add_library
# consumes it); EGRESS_BUILD implies LANE_BUILD, kept as a parallel
# top-level gate.
if(MQVPN_HYBRID_TCP_EGRESS_BUILD)
    list(APPEND MQVPN_LIB_SOURCES ${CMAKE_SOURCE_DIR}/src/hybrid/tcp_egress.c)
endif()

# fuzz_tcp_lane links classifier.c + lwip_glue.c directly (mirrors
# tcp_lane_microbench) against the instrumented lwip_core_fuzz built inside
# the block above — MQVPN_ENABLE_FUZZING with the hybrid TCP lane unavailable
# (Windows, or explicitly disabled) has nothing to build against.
if(MQVPN_ENABLE_FUZZING AND NOT MQVPN_HYBRID_TCP_LANE_BUILD)
    message(WARNING "MQVPN_ENABLE_FUZZING requires the hybrid TCP lane "
                     "(MQVPN_HYBRID_TCP_LANE_BUILD) — skipping fuzz_tcp_lane")
endif()

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
    target_link_libraries(mqvpn_lib lwip_core)
    target_compile_definitions(mqvpn_lib PRIVATE MQVPN_HYBRID_TCP_LANE_ENABLED)
endif()
if(MQVPN_HYBRID_TCP_EGRESS_BUILD)
    target_compile_definitions(mqvpn_lib PRIVATE MQVPN_HYBRID_TCP_EGRESS_ENABLED)
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
    src/platform/windows/net_mon.c
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

# MSVC warnings-as-errors, scoped to first-party targets only (xquic and
# BoringSSL build in their own trees and are unaffected). Much of the
# Windows platform code has no other automated gate than this compile,
# so a silent warning here is a bug that ships.
if(MSVC)
    # /utf-8: our sources are UTF-8. Without this, MSVC decodes them in the
    # system ANSI code page, so on non-UTF-8 locales (e.g. CP932 Japanese)
    # every non-ASCII byte raises C4819 — which /WX below turns fatal. CI
    # runs an English-locale image so it never trips; build it anyway to keep
    # first-party compiles locale-independent.
    target_compile_options(mqvpn PRIVATE /WX /utf-8)
    target_compile_options(mqvpn_lib PRIVATE /WX /utf-8)
    # C4996 nags on strncpy/strerror; every use is bounds-checked with
    # explicit NUL termination (the _s variants are not portable C11).
    target_compile_definitions(mqvpn PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(mqvpn_lib PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

elseif(APPLE)

# ---------- mqvpn CLI binary (Darwin) ----------
# Darwin platform layer: client mode is fully wired (drop+reactivate path
# lifecycle, routing, killswitch, DNS). Server mode + control_socket are
# intentionally not ported here (server mode is not built on macOS in v1).
# This branch exists so CMake picks up APPLE instead of falling into the
# Linux else() below (which would pull in netlink_mon.c and Linux
# tun.c/dns.c and fail to compile on Darwin).
add_executable(mqvpn
    src/main.c
    src/platform/darwin/platform_darwin.c
    src/platform/darwin/route_mon.c
    src/platform/darwin/tun_utun.c
    src/platform/darwin/routing.c
    src/platform/darwin/dns.c
    src/platform/darwin/killswitch.c
    src/platform/posix/status.c
    src/platform/posix/dns_common.c
    src/path_mgr.c
    src/config.c
)

target_include_directories(mqvpn PRIVATE
    ${XQUIC_INCLUDE_DIR}
    ${EVENT_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/platform/posix
    ${CMAKE_SOURCE_DIR}/src/platform/darwin
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
    c++ # C++ runtime for BoringSSL; macOS SDKs ship libc++, not libstdc++
)

# Compile gate for CI: builds the Darwin platform TUs as a standalone
# OBJECT target, independent of the full CLI link above. See
# .github/workflows/ci.yml darwin job.
add_library(mqvpn_darwin_platform OBJECT
    src/platform/darwin/platform_darwin.c
    src/platform/darwin/route_mon.c
    src/platform/darwin/tun_utun.c
    src/platform/darwin/routing.c
    src/platform/darwin/dns.c
    src/platform/darwin/killswitch.c
    src/platform/posix/status.c
    src/platform/posix/dns_common.c
)

target_include_directories(mqvpn_darwin_platform PRIVATE
    ${XQUIC_INCLUDE_DIR}
    ${EVENT_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/platform/posix
    ${CMAKE_SOURCE_DIR}/src/platform/darwin
)

# Shared library variant — mirrors the Linux mqvpn_shared block below (kept
# per-branch: everything past the platform split, tests/install/CPack
# included, is Linux-only; same SOVERSION rationale as the Linux block).
# Links c++ (not stdc++) for BoringSSL's C++ internals — macOS SDKs ship
# libc++ only, and a .dylib must fully resolve its symbols at link time.
add_library(mqvpn_shared SHARED ${MQVPN_LIB_SOURCES})
set_target_properties(mqvpn_shared PROPERTIES
    OUTPUT_NAME mqvpn
    SOVERSION 2
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
target_include_directories(mqvpn_shared
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    PRIVATE ${CMAKE_SOURCE_DIR}/src ${XQUIC_INCLUDE_DIR}
)
# Shared lib links shared xquic, same as Linux (static .a is unusable there
# for -fPIC reasons; kept symmetric here even though clang on Darwin emits
# PIC by default).
target_link_libraries(mqvpn_shared xquic ${SSL_LIB} ${CRYPTO_LIB} pthread c++)

# Keep in sync with the Linux twin (the mqvpn_shared lane block in the
# Linux branch below).
if(MQVPN_HYBRID_TCP_LANE_BUILD)
    target_link_libraries(mqvpn_shared lwip_core)
    target_compile_definitions(mqvpn_shared PRIVATE MQVPN_HYBRID_TCP_LANE_ENABLED)
endif()
if(MQVPN_HYBRID_TCP_EGRESS_BUILD)
    target_compile_definitions(mqvpn_shared PRIVATE MQVPN_HYBRID_TCP_EGRESS_ENABLED)
endif()

# ---------- Tests (Darwin) ----------
# Only the tests that exercise Darwin-specific parsing/formatting run here
# (plus the hybrid TCP-lane unit test below); the full unit suite stays
# Linux-only (see the Linux branch below).
option(BUILD_TESTING "Build unit tests" ON)
if(BUILD_TESTING)
    enable_testing()
    add_executable(test_route_parse_darwin
        tests/test_route_parse_darwin.c src/platform/darwin/routing.c
        src/platform/posix/dns_common.c src/log.c)
        # dns_common.c: routing.c calls mqvpn_sa_host_prefix/mqvpn_sa_ntop —
        # omitting it fails the darwin CI link with undefined symbols
    add_executable(test_dns_backup_darwin
        tests/test_dns_backup_darwin.c src/platform/darwin/dns.c
        src/platform/posix/dns_common.c src/log.c)

    # PATH-stub state machine tests (Task 10): inject fake networksetup/
    # route/pfctl scripts via PATH (tests/fake_cmd.h) and drive the real
    # apply/restore/setup/cleanup state machines end to end. Complement the
    # pure-function tests above (test_route_parse_darwin / test_dns_backup_
    # darwin), which never fork+exec anything.
    add_executable(test_dns_state_darwin
        tests/test_dns_state_darwin.c src/platform/darwin/dns.c
        src/platform/posix/dns_common.c src/log.c)
    add_executable(test_routing_seq_darwin
        tests/test_routing_seq_darwin.c src/platform/darwin/routing.c
        src/platform/posix/dns_common.c src/log.c)
    # killswitch.c's build_pf_rules() is static, so this TU #includes
    # killswitch.c directly (test_status.c's idiom) rather than linking it —
    # only log.c is needed alongside.
    add_executable(test_killswitch_rules_darwin
        tests/test_killswitch_rules_darwin.c src/log.c)

    foreach(t test_route_parse_darwin test_dns_backup_darwin
              test_dns_state_darwin test_routing_seq_darwin test_killswitch_rules_darwin)
        target_include_directories(${t} PRIVATE
            ${EVENT_INCLUDE_DIR}   # platform_internal.h includes <event2/event.h>;
                                   # brew's /opt/homebrew/include is not a default search path
            ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/platform/posix
            ${CMAKE_SOURCE_DIR}/src/platform/darwin)
        add_test(NAME ${t} COMMAND ${t})
    endforeach()

    # Hybrid TCP-lane unit test — keep in sync with the Linux twin (the
    # test_tcp_lane block in the Linux branch below). The test TU
    # #include's BOTH src/hybrid/tcp_lane.c AND src/hybrid/tcp_lane_uplink.c
    # (one logical module — see src/hybrid/tcp_lane_internal.h); do NOT
    # also list either .c here. lwIP + port include dirs arrive via
    # lwip_core's PUBLIC include directories.
    if(MQVPN_HYBRID_TCP_LANE_BUILD)
        add_executable(test_tcp_lane tests/test_tcp_lane.c src/hybrid/classifier.c
                       src/hybrid/lwip_glue.c src/log.c)
        target_link_libraries(test_tcp_lane lwip_core)
        target_include_directories(test_tcp_lane PRIVATE
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/include
        )
        add_test(NAME test_tcp_lane COMMAND test_tcp_lane)
    endif()
endif()

else() # NOT WIN32, NOT APPLE — Linux

# Shared library variant
add_library(mqvpn_shared SHARED ${MQVPN_LIB_SOURCES})
set_target_properties(mqvpn_shared PROPERTIES
    OUTPUT_NAME mqvpn
    # Bumped 1 -> 2: mqvpn_stats_t grew (hybrid lane/flow counters). Producers
    # write sizeof(mqvpn_stats_t) with no caller-size negotiation, so a binary
    # built against the old header must not resolve to the new .so.
    SOVERSION 2
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
    target_link_libraries(mqvpn_shared lwip_core)
    target_compile_definitions(mqvpn_shared PRIVATE MQVPN_HYBRID_TCP_LANE_ENABLED)
endif()
if(MQVPN_HYBRID_TCP_EGRESS_BUILD)
    target_compile_definitions(mqvpn_shared PRIVATE MQVPN_HYBRID_TCP_EGRESS_ENABLED)
endif()

# ---------- mqvpn CLI binary ----------
# Links libmqvpn for the library API; keeps platform-specific files separate.
add_executable(mqvpn
    src/main.c
    src/platform/linux/platform_linux.c
    src/platform/linux/netlink_mon.c
    src/platform/linux/route_check.c
    src/platform/linux/control_socket.c
    src/platform/posix/status.c
    src/platform/linux/routing.c
    src/platform/linux/killswitch.c
    src/platform/linux/tun.c
    src/platform/linux/dns.c
    src/platform/posix/dns_common.c
    src/path_mgr.c
    src/config.c
)

target_include_directories(mqvpn PRIVATE
    ${XQUIC_INCLUDE_DIR}
    ${EVENT_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/platform/posix
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
    add_executable(test_dns     tests/test_dns.c     src/platform/linux/dns.c     src/platform/posix/dns_common.c     src/log.c)
    add_executable(test_route_check tests/test_route_check.c src/platform/linux/route_check.c src/log.c)
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
    add_executable(test_icmp tests/test_icmp.c src/icmp.c)
    set(MQVPN_UNIT_TESTS test_config test_auth test_session test_dns test_route_check test_flow_sched test_status test_path_state_machine test_control_response_bound test_reorder_common test_reorder_tx test_reorder_rx test_reorder_config test_classifier test_icmp)

    # test_tcp_lane #include's BOTH src/hybrid/tcp_lane.c AND
    # src/hybrid/tcp_lane_uplink.c (Task 12 split the uplink relay out of
    # tcp_lane.c; the two are one logical module — see
    # src/hybrid/tcp_lane_internal.h) to reach the file-local flow table
    # (mirrors test_reorder_rx's idiom); do NOT also list either .c here (it
    # would compile the TU twice). Gated on MQVPN_HYBRID_TCP_LANE_BUILD since
    # Task 8: tcp_lane.c's accept callback calls real lwIP (tcp_arg/
    # tcp_recv/...), so the test links lwip_core (whose PUBLIC include dirs
    # also supply the lwIP/port headers). classifier.c is linked for the
    # accept-key correspondence test; lwip_glue.c + log.c satisfy lwip_core's
    # port symbols (mqvpn_lwip_platform_diag / sys_now — same trio the
    # microbench links). The test TU itself provides the cli_tcp_lane_open_
    # stream/cli_tcp_lane_h3_close stubs (the real ones live in
    # mqvpn_client.c, not linked here).
    if(MQVPN_HYBRID_TCP_LANE_BUILD)
        add_executable(test_tcp_lane tests/test_tcp_lane.c src/hybrid/classifier.c
                       src/hybrid/lwip_glue.c src/log.c)
        target_link_libraries(test_tcp_lane lwip_core)
        list(APPEND MQVPN_UNIT_TESTS test_tcp_lane)
    endif()

    foreach(t ${MQVPN_UNIT_TESTS})
        target_include_directories(${t} PRIVATE
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/platform/posix
            ${CMAKE_SOURCE_DIR}/src/platform/linux
            ${CMAKE_SOURCE_DIR}/include
        )
        set_target_properties(${t} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
        add_test(NAME ${t} COMMAND ${t})
    endforeach()

    # Darwin platform-twin PATH-stub state machine tests (Task 10), also
    # registered here on Linux: the twins (darwin/dns.c, darwin/routing.c,
    # darwin/killswitch.c) are portable POSIX C except for two Darwin-only
    # fcntl commands, given placeholder values below for this compile only
    # (inert on the real Darwin build, which already has both from
    # <fcntl.h>).
    #   - F_FULLFSYNC (dns.c's durability_flush): has an EINVAL fallback —
    #     any value fcntl() rejects makes durability_flush() fall back to
    #     fsync(), which is the correct and fully exercised behavior here,
    #     so this uses an arbitrary placeholder (1000).
    #   - F_SETNOSIGPIPE (killswitch.c's run_pfctl_stdin SIGPIPE guard): has
    #     NO fallback — a nonzero fcntl() return hard-fails the call before
    #     pfctl is ever forked. Its real Darwin value (73) is not a valid
    #     Linux fcntl command and returns EINVAL there, which would block
    #     every setup_killswitch() call at the first line and make 3 of the
    #     4 killswitch scenarios below unreachable. Defined instead as
    #     F_SETFD (2): a real POSIX fcntl command that always succeeds on a
    #     pipe fd (it just sets FD_CLOEXEC — harmless, since the pipe is
    #     closed before exec() either way), so the intended pfctl call
    #     sequence actually runs on Linux too.
    add_executable(test_dns_state_darwin
        tests/test_dns_state_darwin.c src/platform/darwin/dns.c
        src/platform/posix/dns_common.c src/log.c)
    target_compile_definitions(test_dns_state_darwin PRIVATE F_FULLFSYNC=1000)

    add_executable(test_routing_seq_darwin
        tests/test_routing_seq_darwin.c src/platform/darwin/routing.c
        src/platform/posix/dns_common.c src/log.c)

    add_executable(test_killswitch_rules_darwin
        tests/test_killswitch_rules_darwin.c src/log.c)
    target_compile_definitions(test_killswitch_rules_darwin PRIVATE F_SETNOSIGPIPE=2)

    foreach(t test_dns_state_darwin test_routing_seq_darwin test_killswitch_rules_darwin)
        target_include_directories(${t} PRIVATE
            ${EVENT_INCLUDE_DIR}   # platform_internal.h includes <event2/event.h>
            ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/platform/posix
            ${CMAKE_SOURCE_DIR}/src/platform/darwin)
        set_target_properties(${t} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
        add_test(NAME ${t} COMMAND ${t})
    endforeach()

    # Control-API command dispatch test. dispatch() is static, so the test
    # #include's control_socket.c directly (test_reorder_rx idiom) and mocks the
    # mqvpn_server_* API — no mqvpn_server.c / xquic linked. libevent is required
    # because the connection handlers in the same TU reference event2; gated on
    # libevent being available (Linux test builds only, never Android).
    if(Libevent_FOUND OR EVENT_LIB)
        add_executable(test_control_socket tests/test_control_socket.c src/log.c)
        target_include_directories(test_control_socket PRIVATE
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/platform/linux
            ${CMAKE_SOURCE_DIR}/include
        )
        if(Libevent_FOUND)
            target_link_libraries(test_control_socket libevent::core libevent::extra)
        else()
            target_include_directories(test_control_socket PRIVATE ${EVENT_INCLUDE_DIR})
            target_link_libraries(test_control_socket ${EVENT_LIB})
        endif()
        set_target_properties(test_control_socket PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
        add_test(NAME test_control_socket COMMAND test_control_socket)
    endif()

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

    # xquic ABI pin — compile-time only. The one TU allowed to reach into
    # xquic's private src/transport headers, so it can pin the numeric
    # values libmqvpn hardcodes against the real private enum (see
    # tests/test_xquic_abi_pin.c). No xquic link: the _Static_asserts need
    # only declarations. The extra include dirs are the xquic source root
    # (private "src/..."-style includes) and the public header dir.
    add_executable(test_xquic_abi_pin tests/test_xquic_abi_pin.c)
    target_include_directories(test_xquic_abi_pin PRIVATE
        ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/third_party/xquic ${XQUIC_INCLUDE_DIR})
    # Pulling in xquic's private transport headers drags internal macros that
    # are not warning-clean under mqvpn's strict/-Werror flags (e.g.
    # xqc_str.h -Wunused-value). This TU has no logic of its own — the
    # _Static_asserts are the whole test — so silence warnings for it only.
    target_compile_options(test_xquic_abi_pin PRIVATE -w)
    set_target_properties(test_xquic_abi_pin PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
    add_test(NAME test_xquic_abi_pin COMMAND test_xquic_abi_pin)

    add_executable(test_conn_settings tests/test_conn_settings.c)
    target_link_libraries(test_conn_settings mqvpn_lib ${XQUIC_LIB} ${SSL_LIB} ${CRYPTO_LIB} dl m stdc++)
    target_include_directories(test_conn_settings PRIVATE ${CMAKE_SOURCE_DIR}/src ${XQUIC_INCLUDE_DIR})
    set_target_properties(test_conn_settings PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
    add_test(NAME test_conn_settings COMMAND test_conn_settings)

    # Server-side mqvpn-tcp dispatch test (real xquic engine, gated on the
    # server-side egress being built — see SVR_STREAM_ROLE_CONNECT_TCP).
    if(MQVPN_HYBRID_TCP_EGRESS_BUILD)
        add_executable(test_tcp_egress tests/test_tcp_egress.c)
        target_link_libraries(test_tcp_egress mqvpn_lib ${XQUIC_LIB} ${SSL_LIB} ${CRYPTO_LIB} dl m stdc++)
        target_include_directories(test_tcp_egress PRIVATE ${CMAKE_SOURCE_DIR}/src ${XQUIC_INCLUDE_DIR})
        target_compile_definitions(test_tcp_egress PRIVATE
            TEST_CERT_FILE="${CMAKE_SOURCE_DIR}/tests/certs/test.crt"
            TEST_KEY_FILE="${CMAKE_SOURCE_DIR}/tests/certs/test.key"
        )
        set_target_properties(test_tcp_egress PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
        add_test(NAME test_tcp_egress COMMAND test_tcp_egress)
    endif()

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
# lwIP is statically linked only when the hybrid TCP lane is built in.
if(MQVPN_HYBRID_TCP_LANE_BUILD)
    install(FILES
        "${CMAKE_SOURCE_DIR}/third_party/lwip/LICENSE"
        DESTINATION share/doc/mqvpn/third-party RENAME lwip.txt
        OPTIONAL)
endif()

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

endif() # WIN32 / APPLE / Linux

endif() # NOT ANDROID_CROSS_COMPILE
