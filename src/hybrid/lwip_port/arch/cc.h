#ifndef MQVPN_LWIP_ARCH_CC_H
#define MQVPN_LWIP_ARCH_CC_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

/* lwIP integer typedefs — map directly onto stdint.h, no custom sizes. */
typedef uint8_t u8_t;
typedef int8_t s8_t;
typedef uint16_t u16_t;
typedef int16_t s16_t;
typedef uint32_t u32_t;
typedef int32_t s32_t;
typedef uintptr_t mem_ptr_t;

#define U16_F "hu"
#define S16_F "hd"
#define X16_F "hx"
#define U32_F PRIu32
#define S32_F PRId32
#define X32_F PRIx32

/* lwIP's arch.h already auto-detects byte order via __BYTE_ORDER__ on
 * GCC/Clang, and glibc's endian.h (pulled in via stdlib.h above) defines
 * BYTE_ORDER itself. This #ifndef-guarded define therefore only matters
 * for compilers lacking __BYTE_ORDER__ (e.g. MSVC, for the future Windows
 * port), where little-endian is correct on all supported targets. */
#ifndef BYTE_ORDER
#  define BYTE_ORDER LITTLE_ENDIAN
#endif

/* Struct packing. GCC/Clang: lwIP's own PACK_STRUCT_* defaults apply
 * __attribute__((packed)) (vendored arch.h gates on __GNUC__/__clang__).
 * MSVC: those defaults silently produce NO packing — define the pragma
 * bracket pair explicitly so wire-format structs stay byte-exact. */
#if defined(_MSC_VER) && !defined(__clang__)
#  define PACK_STRUCT_BEGIN __pragma(pack(push, 1))
#  define PACK_STRUCT_END   __pragma(pack(pop))
#  define PACK_STRUCT_STRUCT
/* ssize_t: vendored arch.h (lwip/arch.h) does `typedef int ssize_t` when
 * SSIZE_MAX is undefined — a 32-bit type that clashes (C2371) with xquic's
 * and tcp_lane.h's __int64 ssize_t in any TU that sees both. Define
 * SSIZE_MAX so arch.h skips that typedef, and LWIP_NO_UNISTD_H=1 so it does
 * not then #include <unistd.h> (absent on MSVC). lwip_core itself never uses
 * ssize_t; the lane TUs get their __int64 ssize_t from tcp_lane.h / xquic. */
#  include <limits.h>
#  ifndef SSIZE_MAX
#    define SSIZE_MAX _I64_MAX
#  endif
#  ifndef LWIP_NO_UNISTD_H
#    define LWIP_NO_UNISTD_H 1
#  endif
#endif

/* Route lwIP's internal LWIP_PLATFORM_DIAG through mqvpn's logger. Declared
 * here, defined in lwip_glue.c (must not pull src/log.h into every lwIP
 * translation unit — keeps the port layer decoupled from mqvpn's log macros). */
#if defined(__GNUC__)
__attribute__((format(printf, 1, 2)))
#endif
void
mqvpn_lwip_platform_diag(const char *fmt, ...);
#define LWIP_PLATFORM_DIAG(x) mqvpn_lwip_platform_diag x

#define LWIP_PLATFORM_ASSERT(x)                                                          \
    do {                                                                                 \
        mqvpn_lwip_platform_diag("lwIP assertion \"%s\" failed at %s:%d\n", x, __FILE__, \
                                 __LINE__);                                              \
        abort();                                                                         \
    } while (0)

#endif /* MQVPN_LWIP_ARCH_CC_H */
