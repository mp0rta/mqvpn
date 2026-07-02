#ifndef MQVPN_LWIPOPTS_H
#define MQVPN_LWIPOPTS_H

#define NO_SYS               1
#define LWIP_TIMERS          0 /* mqvpn drives tcp_tmr()/ip_reass_tmr() manually from tick() */
#define SYS_LIGHTWEIGHT_PROT 0 /* single-threaded, all lwIP calls on the tick thread */

#define LWIP_NETCONN 0
#define LWIP_SOCKET  0
#define LWIP_DHCP    0
#define LWIP_DNS     0
#define LWIP_AUTOIP  0
#define LWIP_IGMP    0
#define PPP_SUPPORT  0
#define LWIP_UDP     0 /* v1: TCP lane only; UDP stays on the DATAGRAM lane */

#define LWIP_IPV4 1
#define LWIP_IPV6 0 /* v1 non-goal: IPv6 TCP termination — IPv6 TCP goes RAW */

/* MEM_LIBC_MALLOC (standard lwIP opt, NOT heiher's fork-specific
 * MEM_CUSTOM_ALLOCATOR — that macro plus its mem_malloc→hev_malloc weak-
 * symbol hookup lives in the port/ tree we deliberately do NOT vendor, see
 * Task 1's VENDOR.md license note): raw heap allocations (mem_malloc/
 * mem_free, used for pbuf payloads etc.) go straight to libc malloc/free,
 * no custom function needed. MEMP_MEM_MALLOC stays 0 — that is the
 * INDEPENDENT flag controlling the pool-based allocator (pcbs, tcp
 * segments); keeping THIS flag 0 keeps MEMP_NUM_* caps enforced
 * (memp_malloc returns NULL on pool exhaustion instead of falling through
 * to an unbounded heap). */
#define MEM_LIBC_MALLOC 1
#define MEMP_MEM_MALLOC 0

/* TCP_MSS is set at runtime from the actual TUN MTU (spec: TUN MTU - 40);
 * this compile-time value is the worst-case upper bound used to size
 * TCP_WND/TCP_SND_BUF below (9000 MTU ceiling per project's MTU config docs
 * — actual MSS is clamped lower via tcp_mss() at connection accept time if
 * the real TUN MTU is smaller; verify the pinned lwIP version exposes a
 * per-pcb MSS override — if not, this becomes a compile-time-only bound and the runtime
 * TUN MTU must not exceed it). */
#define TCP_MSS 8960 /* 9000 - 40 */

#define LWIP_WND_SCALE 1
#define TCP_RCV_SCALE  5 /* shift count for the wire encoding, range [0..14] */
/* Per opt.h: "when using TCP_RCV_SCALE, TCP_WND is the total size WITH
 * scaling applied" — i.e. TCP_WND is the effective receive window in bytes
 * (post-scaling total) and the 16-bit header field advertises
 * TCP_WND >> TCP_RCV_SCALE (tcp_out.c). The effective ~2 MB window must
 * therefore be encoded in TCP_WND itself; the scale factor only widens the
 * wire encoding. 65535 << 5 = 2,097,120 (~2 MB effective; header advertises
 * 65535, the 16-bit max). tcpwnd_size_t is u32_t when LWIP_WND_SCALE==1
 * (tcpbase.h), so this fits. */
#define TCP_WND     (65535 << TCP_RCV_SCALE)
#define TCP_SND_BUF (2 * 1024 * 1024)
/* TCP_SNDLOWAT: only consumed by the netconn/sockets layer (api_msg.c),
 * which is compiled out here (LWIP_NETCONN=0, LWIP_SOCKET=0) — but opt.h's
 * default formula (TCP_SND_BUF/2 = 1 MB) trips init.c's unconditional
 * sanity check "TCP_SNDLOWAT must at least be 4*MSS below u16_t overflow".
 * Pin it to one MSS: functionally inert in this config, satisfies the
 * check (8960 < 0xFFFF - 4*8960 = 29695, and < TCP_SND_BUF). */
#define TCP_SNDLOWAT     (TCP_MSS)
#define TCP_SND_QUEUELEN ((4 * (TCP_SND_BUF) + (TCP_MSS - 1)) / (TCP_MSS))
#define LWIP_TCP_SACK_OUT                                 \
    1 /* only if the vendored fork supports it — verify \
       * TCP_SACK-related symbols exist before enabling;  \
       * if absent, drop this line (compile error is      \
       * the correct signal, do not silently no-op). */

#define MEMP_NUM_TCP_PCB                               \
    512 /* mqvpn's tcp_max_flows default is 256; this  \
         * pool is the hard lwIP-side cap, sized above \
         * the config default with headroom — the    \
         * hybrid.tcp_max_flows check in tcp_lane.c is \
         * the real enforcement point (spec: on reject \
         * → tcp_abort, do NOT silently fall to RAW). */
#define MEMP_NUM_TCP_SEG 2048
/* PBUF_POOL_SIZE: must hold a full receive window of queued data —
 * init.c's sanity check enforces TCP_WND <= PBUF_POOL_SIZE *
 * (PBUF_POOL_BUFSIZE - protocol headers). With TCP_WND ~2 MB and ~8946
 * usable bytes per pool pbuf (9000 - 54 header bytes), 128 pbufs
 * (~1.1 MB) is too small; 256 gives ~2.29 MB >= 2,097,120. */
#define PBUF_POOL_SIZE    256
#define PBUF_POOL_BUFSIZE LWIP_MEM_ALIGN_SIZE(TCP_MSS + 40 + PBUF_LINK_ENCAPSULATION_HLEN)

/* Checksums: keep ON in v1 (fuzz safety per spec Notes) — this is a known
 * perf knob, do not flip without a documented follow-up. */
#define CHECKSUM_CHECK_IP     1
#define CHECKSUM_CHECK_TCP    1
#define CHECKSUM_GEN_IP       1
#define CHECKSUM_GEN_TCP      1
#define LWIP_CHECKSUM_ON_COPY 1

#define TCP_QUEUE_OOSEQ     1
#define LWIP_TCP_TIMESTAMPS 0

#define MEM_ALIGNMENT 8
#define LWIP_STATS    0
/* LWIP_DEBUG intentionally left undefined — lwIP gates on #ifdef, not
 * value (debug.h), so `#define LWIP_DEBUG 0` would still compile the debug
 * machinery in. Define it (any value) ad hoc for local debugging. */

#endif /* MQVPN_LWIPOPTS_H */
