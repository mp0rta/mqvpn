cmake_minimum_required(VERSION 3.10)
project(mqvpn C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ---------- Options ----------
option(XQUIC_BUILD_DIR "Path to pre-built xquic build directory" "")

# ---------- xquic ----------
# xquic has its own complex build system (SSL dependency, etc).
# Two modes:
#   1. XQUIC_BUILD_DIR is set → use pre-built xquic from that directory
#   2. Otherwise → try add_subdirectory (requires SSL_PATH to be set)

set(XQUIC_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/third_party/xquic/include)

if(XQUIC_BUILD_DIR)
    message(STATUS "Using pre-built xquic from: ${XQUIC_BUILD_DIR}")
    add_library(xquic SHARED IMPORTED)
    set_target_properties(xquic PROPERTIES
        IMPORTED_LOCATION "${XQUIC_BUILD_DIR}/libxquic.so"
    )
    # Also provide static option
    if(EXISTS "${XQUIC_BUILD_DIR}/libxquic-static.a")
        add_library(xquic-static STATIC IMPORTED)
        set_target_properties(xquic-static PROPERTIES
            IMPORTED_LOCATION "${XQUIC_BUILD_DIR}/libxquic-static.a"
        )
    endif()
else()
    message(STATUS "Building xquic from source (requires SSL_PATH or SSL_DIR)")
    add_subdirectory(third_party/xquic)
endif()

# ---------- libevent ----------
find_path(EVENT_INCLUDE_DIR event2/event.h)
find_library(EVENT_LIB event)
if(NOT EVENT_LIB)
    message(FATAL_ERROR "libevent not found. Install: apt install libevent-dev")
endif()

# ---------- mqvpn ----------
add_executable(mqvpn
    src/main.c
    src/tun.c
    src/vpn_client.c
    src/vpn_server.c
    src/addr_pool.c
    src/path_mgr.c
    src/flow_sched.c
    src/config.c
    src/auth.c
    src/dns.c
    src/log.c
)

target_include_directories(mqvpn PRIVATE
    ${XQUIC_INCLUDE_DIR}
    ${EVENT_INCLUDE_DIR}
)

# Prefer static xquic to avoid runtime library path issues
if(TARGET xquic-static)
    set(XQUIC_LIB xquic-static)
else()
    set(XQUIC_LIB xquic)
endif()

# Find SSL libraries (same ones xquic links against)
# When using pre-built xquic, BoringSSL static libs live next to the xquic source
set(BORINGSSL_BUILD_DIR "${CMAKE_SOURCE_DIR}/third_party/xquic/third_party/boringssl/build")
find_library(SSL_LIB ssl
    HINTS ${BORINGSSL_BUILD_DIR} /usr/local/lib /usr/local/babassl/lib)
find_library(CRYPTO_LIB crypto
    HINTS ${BORINGSSL_BUILD_DIR} /usr/local/lib /usr/local/babassl/lib)

target_link_libraries(mqvpn
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
    add_executable(test_dns     tests/test_dns.c     src/dns.c     src/log.c)
    add_executable(test_flow_sched tests/test_flow_sched.c src/flow_sched.c src/log.c)

    foreach(t test_config test_auth test_session test_dns test_flow_sched)
        target_include_directories(${t} PRIVATE ${CMAKE_SOURCE_DIR}/src)
        set_target_properties(${t} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
        add_test(NAME ${t} COMMAND ${t})
    endforeach()
endif()

# ---------- Install ----------
install(TARGETS mqvpn DESTINATION bin)
