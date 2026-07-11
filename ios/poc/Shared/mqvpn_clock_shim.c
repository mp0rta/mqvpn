#include "mqvpn_clock_shim.h"
#include <mach/mach_time.h>

uint64_t
mqvpn_ios_clock_us(void *ctx)
{
    (void)ctx;
    static mach_timebase_info_data_t tb; /* zero-init; idempotent fill —
                                            concurrent first calls write the
                                            same values, benign */
    if (tb.denom == 0) mach_timebase_info(&tb);
    uint64_t t = mach_continuous_time();
    return t * tb.numer / tb.denom / 1000; /* ns -> us */
}
