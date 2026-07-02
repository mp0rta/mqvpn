/* src/hybrid/lwip_port/arch/sys_arch.h (path per Step 1's grep result) */
#ifndef MQVPN_LWIP_SYS_ARCH_H
#define MQVPN_LWIP_SYS_ARCH_H
/* NO_SYS=1: lwIP's sys_arch.h contract shrinks to almost nothing — no
 * sys_sem_t/sys_mbox_t/sys_thread_t are required. Left intentionally empty;
 * sys_now() is declared by lwip/sys.h itself and defined in lwip_glue.c. */
#endif
