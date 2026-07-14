#ifndef MQVPN_LWIPOPTS_H
#define MQVPN_LWIPOPTS_H

#define NO_SYS               1
#define LWIP_TIMERS          0 /* mqvpn drives tcp_tmr()/ip_reass_tmr() manually from tick() */
#define SYS_LIGHTWEIGHT_PROT 0 /* single-threaded, all lwIP calls on the tick thread */

/* Do NOT alias htons/ntohs/htonl/ntohl to lwip_htons & co. Darwin's
 * <sys/types.h> chain (sys/_endian.h) already defines them as macros, so
 * lwIP's aliases trip -Wmacro-redefined under -Werror in any TU that sees
 * both. Nothing we compile relies on the aliases: lwIP core uses
 * lwip_htons() internally, and first-party code (classifier.h,
 * tcp_egress.c) gets the standard names from its own system includes. */
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1

#define LWIP_NETCONN  0
#define LWIP_SOCKET   0
#define LWIP_DHCP     0
#define LWIP_DNS      0
#define LWIP_AUTOIP   0
#define LWIP_IGMP     0
#define PPP_SUPPORT   0
#define LWIP_ARP      0 /* TUN is raw-IP L3 — no Ethernet machinery */
#define LWIP_ETHERNET 0
#define LWIP_UDP      0 /* v1: TCP lane only; UDP stays on the DATAGRAM lane */

#define LWIP_IPV4 1
#define LWIP_IPV6                                                 \
    1 /* Chunk 4: dual-stack — v6 SYNs admitted to the lwIP TCP \
       * lane alongside v4 (classifier gates which v6 traffic     \
       * reaches here; lwIP itself is family-agnostic). */
/* The address-less pretend netif (lwip_glue.c) must stay silent on the wire
 * beyond what the classifier explicitly routes here: no Router Solicitation,
 * no SLAAC address assignment, no Multicast Listener Discovery joins. All
 * three default to LWIP_IPV6 (i.e. would turn ON with it) unless forced off
 * here individually. */
#define LWIP_IPV6_MLD                 0
#define LWIP_IPV6_AUTOCONFIG          0
#define LWIP_IPV6_SEND_ROUTER_SOLICIT 0

/* MEM_LIBC_MALLOC (standard lwIP opt, NOT heiher's fork-specific
 * MEM_CUSTOM_ALLOCATOR — that macro plus its mem_malloc→hev_malloc weak-
 * symbol hookup lives in the port/ tree we deliberately do NOT vendor, see
 * VENDOR.md's license note): raw heap allocations (mem_malloc/
 * mem_free, used for pbuf payloads etc.) go straight to libc malloc/free,
 * no custom function needed. MEMP_MEM_MALLOC stays 0 — that is the
 * INDEPENDENT flag controlling the pool-based allocator (pcbs, tcp
 * segments); keeping THIS flag 0 keeps MEMP_NUM_* caps enforced
 * (memp_malloc returns NULL on pool exhaustion instead of falling through
 * to an unbounded heap). */
#define MEM_LIBC_MALLOC 1
#define MEMP_MEM_MALLOC 0

/* TCP_MSS here is the compile-time worst-case UPPER BOUND (9000 MTU
 * ceiling per project's MTU config docs), used to size TCP_WND/TCP_SND_BUF
 * below. There is no per-pcb MSS setter in the vendored tree — tcp_mss(pcb)
 * (tcp.h) is a read-only accessor. Instead lwIP derives each pcb's MSS
 * automatically at connect/accept time via tcp_eff_send_mss_netif() from
 * the netif's MTU, and clamps the peer's advertised MSS option to TCP_MSS
 * (tcp_in.c). So the glue MUST set the lwIP netif->mtu from the real
 * TUN MTU; the effective per-pcb MSS then becomes
 * min(TCP_MSS, netif->mtu - 40, peer-advertised MSS). */
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
/* SACK-out: vendored lwIP 2.2.1 implements it (opt.h option, generation in
 * tcp_out.c, tracking in tcp_in.c) — verified. */
#define LWIP_TCP_SACK_OUT 1

/* mqvpn's tcp_max_flows default is 256; this pool is the hard lwIP-side
 * cap, sized above the config default with headroom — the
 * hybrid.tcp_max_flows check in tcp_lane.c is the real enforcement point
 * (spec: on reject → tcp_abort, do NOT silently fall to RAW). */
#define MEMP_NUM_TCP_PCB 512
/* MEMP_NUM_TCP_SEG is a GLOBAL pool shared by all flows: 2048 segments
 * covers only ~2 flows at full TCP_SND_BUF (2 MB / 8960-byte MSS ~ 234
 * segs each x safety factor). tcp_write() returns ERR_MEM on pool
 * exhaustion — the TCP-lane relay (tcp_lane.c) MUST handle that as
 * backpressure (retry on sent-callback), it is not optional. */
#define MEMP_NUM_TCP_SEG 2048
/* PBUF_POOL_SIZE: sized to satisfy init.c's compile-time sanity check
 * (TCP_WND <= PBUF_POOL_SIZE * (PBUF_POOL_BUFSIZE - protocol headers)),
 * which lwIP enforces unconditionally whenever MEMP_MEM_MALLOC == 0 and
 * PBUF_POOL_SIZE > 0 (init.c) — REGARDLESS of whether this project's own
 * code actually allocates PBUF_POOL pbufs (see the RESOLVED note below).
 * With TCP_WND ~2 MB and ~8946 usable bytes per pool pbuf (9000 - 54
 * header bytes), 128 pbufs (~1.1 MB) is too small; 256 gives ~2.29 MB
 * >= 2,097,120.
 *
 * RESOLVED (I1, cross-flow PBUF_POOL exhaustion DoS): mqvpn_lwip_input
 * (lwip_glue.c) allocates every ingress packet as PBUF_RAM (exact-size,
 * MEM_LIBC_MALLOC-backed heap), NOT PBUF_POOL. Previously each ingress
 * packet occupied one full-size pool pbuf regardless of its actual
 * length, so at the real ~1382-byte tunnel MTU the global 256-pbuf pool
 * held only ~350 KB of real payload — far below the 2 MB window
 * advertised PER FLOW — and a single xquic-backpressured flow's stash
 * could exhaust the shared pool and stall RX (SYNs/ACKs/FINs) for every
 * OTHER flow. PBUF_RAM's pbuf_take copy cost is unchanged; the real
 * per-flow bound is now TCP_WND (the pcb's own receive window), which the
 * TCP-lane relay (tcp_lane.c) already backpressures against via recved
 * withholding. PBUF_POOL_SIZE stays 256 purely to satisfy the compile-time
 * check above — it no longer bounds ingress throughput. */
#define PBUF_POOL_SIZE    256
#define PBUF_POOL_BUFSIZE LWIP_MEM_ALIGN_SIZE(TCP_MSS + 40 + PBUF_LINK_ENCAPSULATION_HLEN)

/* Checksums: keep ON in v1 (fuzz safety per spec Notes) — this is a known
 * perf knob, do not flip without a documented follow-up. The CHECK_* pair is
 * #ifndef-guarded ONLY so the dedicated libFuzzer build (lwip_core_fuzz —
 * see CMakeLists.txt, gated on MQVPN_ENABLE_FUZZING) can pass
 * -DCHECKSUM_CHECK_IP=0 / -DCHECKSUM_CHECK_TCP=0 to drop the ingress
 * checksum wall, so mutated packets actually reach the TCP state machine
 * instead of dying in ip4_input/tcp_input. Production defines neither, so it
 * still gets 1 — behavior is byte-for-byte identical to the plain #define.
 * The GEN_* side stays unconditional: it never gates ingress and flipping it
 * has no fuzzing value. */
#ifndef CHECKSUM_CHECK_IP
#  define CHECKSUM_CHECK_IP 1
#endif
#ifndef CHECKSUM_CHECK_TCP
#  define CHECKSUM_CHECK_TCP 1
#endif
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
