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

# Prefer static xquic to avoid runtime library path issues
if(TARGET xquic-static)
    set(XQUIC_LIB xquic-static)
else()
    set(XQUIC_LIB xquic)
endif()

# Find SSL libraries (same ones xquic links against)
set(BORINGSSL_BUILD_DIR "${CMAKE_SOURCE_DIR}/third_party/xquic/third_party/boringssl/build")
find_library(SSL_LIB ssl
    HINTS ${BORINGSSL_BUILD_DIR} /usr/local/lib /usr/local/babassl/lib)
find_library(CRYPTO_LIB crypto
    HINTS ${BORINGSSL_BUILD_DIR} /usr/local/lib /usr/local/babassl/lib)

# ---------- libmqvpn (static library — no libevent, no platform I/O) ----------
add_library(mqvpn_lib STATIC
    src/mqvpn_config.c
    src/mqvpn_client.c
    src/mqvpn_util.c
    src/flow_sched.c
    src/addr_pool.c
    src/auth.c
    src/log.c
)
set_target_properties(mqvpn_lib PROPERTIES OUTPUT_NAME mqvpn)
target_include_directories(mqvpn_lib
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    PRIVATE ${CMAKE_SOURCE_DIR}/src ${XQUIC_INCLUDE_DIR}
)
target_link_libraries(mqvpn_lib pthread)

# Shared library variant
add_library(mqvpn_shared SHARED
    src/mqvpn_config.c
    src/mqvpn_client.c
    src/mqvpn_util.c
    src/flow_sched.c
    src/addr_pool.c
    src/auth.c
    src/log.c
)
set_target_properties(mqvpn_shared PROPERTIES
    OUTPUT_NAME mqvpn
    SOVERSION 0
)
target_include_directories(mqvpn_shared
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    PRIVATE ${CMAKE_SOURCE_DIR}/src ${XQUIC_INCLUDE_DIR}
)
# Shared lib needs shared xquic (static .a lacks -fPIC)
target_link_libraries(mqvpn_shared xquic ${SSL_LIB} ${CRYPTO_LIB} pthread)

# ---------- mqvpn CLI binary ----------
# Links libmqvpn for the library API; keeps platform-specific files separate.
add_executable(mqvpn
    src/main.c
    src/platform/linux/platform_linux.c
    src/platform/linux/routing.c
    src/platform/linux/killswitch.c
    src/tun.c
    src/vpn_client.c
    src/vpn_server.c
    src/path_mgr.c
    src/config.c
    src/dns.c
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
    add_executable(test_dns     tests/test_dns.c     src/dns.c     src/log.c)
    add_executable(test_flow_sched tests/test_flow_sched.c src/flow_sched.c src/log.c)

    foreach(t test_config test_auth test_session test_dns test_flow_sched)
        target_include_directories(${t} PRIVATE ${CMAKE_SOURCE_DIR}/src)
        set_target_properties(${t} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
        add_test(NAME ${t} COMMAND ${t})
    endforeach()

    # libmqvpn public API test (links libmqvpn + xquic)
    add_executable(test_api tests/test_api.c)
    target_link_libraries(test_api mqvpn_lib ${XQUIC_LIB} ${SSL_LIB} ${CRYPTO_LIB} dl m stdc++)
    target_include_directories(test_api PRIVATE ${CMAKE_SOURCE_DIR}/src)
    set_target_properties(test_api PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
    add_test(NAME test_api COMMAND test_api)
endif()

# ---------- Install ----------
install(TARGETS mqvpn DESTINATION bin)
install(TARGETS mqvpn_lib DESTINATION lib)
install(TARGETS mqvpn_shared DESTINATION lib)
install(FILES include/libmqvpn.h DESTINATION include)
install(FILES systemd/mqvpn-server.service systemd/mqvpn-client@.service
        DESTINATION lib/systemd/system)
install(PROGRAMS scripts/mqvpn-server-nat.sh
        DESTINATION lib/mqvpn)
