/* Host-side sanity test:
 *   cc -o /tmp/cst clock_shim_host_test.c mqvpn_clock_shim.c && /tmp/cst */
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include "mqvpn_clock_shim.h"

int
main(void)
{
    uint64_t a = mqvpn_ios_clock_us(NULL);
    usleep(20000); /* 20 ms */
    uint64_t b = mqvpn_ios_clock_us(NULL);
    assert(b > a);
    uint64_t d = b - a;
    /* A 20ms sleep must read as 15..200 ms in microsecond units — catches
     * tick-vs-us unit bugs: a raw mach-tick reading (24 MHz tick on Apple
     * Silicon gives ~480000+ ticks for a 20ms sleep) lands clearly outside
     * the upper bound. */
    assert(d > 15000 && d < 200000);
    printf("OK delta=%llu us\n", (unsigned long long)d);
    return 0;
}
