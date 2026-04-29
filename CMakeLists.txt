cmake_minimum_required(VERSION 3.10)
project(mqvpn VERSION 0.3.2 LANGUAGES C)

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
    src/mqvpn_util.c
    src/flow_sched.c
    src/addr_pool.c
    src/auth.c
    src/log.c
    src/icmp.c
)

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

    foreach(t test_config test_auth test_session test_dns test_flow_sched test_status)
        target_include_directories(${t} PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/src/platform/linux)
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
