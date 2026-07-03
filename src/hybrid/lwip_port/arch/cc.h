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

/* No packed-struct pragma needed; lwIP's own PACK_STRUCT_* macros default
 * to GCC/Clang __attribute__((packed)) when left undefined, which is what
 * we want (matches xquic's own build assumptions on this repo's targets). */

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
