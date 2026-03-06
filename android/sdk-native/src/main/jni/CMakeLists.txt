cmake_minimum_required(VERSION 3.22)
project(mqvpn_jni C CXX)

# Prebuilt libmqvpn.a, xquic, BoringSSL per ABI
set(PREBUILT_DIR ${CMAKE_SOURCE_DIR}/../../../prebuilt/${ANDROID_ABI})

# libmqvpn (static)
add_library(mqvpn STATIC IMPORTED)
set_target_properties(mqvpn PROPERTIES
    IMPORTED_LOCATION ${PREBUILT_DIR}/libmqvpn.a)

# xquic (static)
add_library(xquic-static STATIC IMPORTED)
set_target_properties(xquic-static PROPERTIES
    IMPORTED_LOCATION ${PREBUILT_DIR}/libxquic.a)

# BoringSSL
add_library(ssl STATIC IMPORTED)
set_target_properties(ssl PROPERTIES
    IMPORTED_LOCATION ${PREBUILT_DIR}/libssl.a)
add_library(crypto STATIC IMPORTED)
set_target_properties(crypto PROPERTIES
    IMPORTED_LOCATION ${PREBUILT_DIR}/libcrypto.a)

# Include paths
# From src/main/jni/ → up 5 levels → mqvpn/
set(MQVPN_ROOT ${CMAKE_SOURCE_DIR}/../../../../../)
include_directories(
    ${MQVPN_ROOT}/include
    ${MQVPN_ROOT}/src
    ${MQVPN_ROOT}/third_party/xquic/include
)

# JNI shared library
# LINKER_LANGUAGE CXX: BoringSSL (libssl.a) is C++ and needs clang++ for linking
# to resolve C++ ABI symbols (__cxa_begin_catch, __gxx_personality_v0, etc.)
add_library(mqvpn_jni SHARED mqvpn_jni.c)
set_target_properties(mqvpn_jni PROPERTIES LINKER_LANGUAGE CXX)

target_link_libraries(mqvpn_jni
    mqvpn
    xquic-static
    ssl
    crypto
    log           # Android __android_log_print
    c++_static)   # BoringSSL is C++ — needs libc++ for vtable/RTTI/exceptions
