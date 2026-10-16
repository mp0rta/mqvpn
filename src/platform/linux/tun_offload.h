// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef MQVPN_TUN_OFFLOAD_H
#define MQVPN_TUN_OFFLOAD_H

/*
 * Userspace half of the Linux TUN offloads (IFF_VNET_HDR + TUNSETOFFLOAD).
 *
 * With TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 (and TUN_F_USO4 | TUN_F_USO6 on
 * kernels that accept them) the kernel hands the TUN reader TCP segmentation
 * super-packets of up to 64 KiB and leaves transport checksums unfinished
 * (partial checksum), each packet prefixed by a struct virtio_net_hdr. The
 * functions here finish the checksums and cut a super-packet into MTU-sized
 * IP packets, so everything behind the TUN read (MASQUE framing, the reorder
 * stamp, the datagram send) still sees one ordinary IP packet at a time and
 * the wire format does not change.
 *
 * Pure functions on memory, no I/O: unit-testable without root or a TUN.
 */

#include <stddef.h>
#include <stdint.h>
#include <linux/virtio_net.h>

#include "tun.h"

/* USO (UDP segmentation offload) needs Linux >= 6.2 headers to name it. */
#ifndef VIRTIO_NET_HDR_GSO_UDP_L4
#  define VIRTIO_NET_HDR_GSO_UDP_L4 5
#endif

/* Iterator over the segments of one GSO super-packet. The packet it points
 * at must stay unchanged until mqvpn_gso_next() returns 0. */
typedef struct {
    const uint8_t *pkt; /* super-packet, IP header first (no vnet header) */
    size_t len;         /* its length */
    size_t hdr_len;     /* IP + transport header bytes of every segment */
    size_t off;         /* payload bytes emitted so far */
    uint16_t ip_hlen;   /* IP header bytes (including IPv6 extension headers) */
    uint16_t gso_size;  /* payload bytes per segment (the last may be less) */
    uint16_t ip_id0;    /* IPv4: identification of the super-packet */
    uint32_t idx;       /* segments emitted so far */
    uint32_t seq0;      /* TCP: sequence number of the super-packet, host order */
    uint8_t proto;      /* IPPROTO_TCP or IPPROTO_UDP */
    uint8_t v6;         /* 1 = IPv6, 0 = IPv4 */
    uint8_t done;       /* all segments emitted */
} mqvpn_gso_iter_t;

/* Finish the checksum of a non-GSO packet whose header has
 * VIRTIO_NET_HDR_F_NEEDS_CSUM. Edits pkt in place. 0 on success, -1 when
 * csum_start / csum_offset do not fit in the packet. */
int mqvpn_vnet_finish_csum(uint8_t *pkt, size_t len, const struct virtio_net_hdr *vh);

/* Start splitting a GSO super-packet. 0 on success, -1 when the header or
 * the packet is not something the kernel would legitimately produce. */
int mqvpn_gso_begin(mqvpn_gso_iter_t *it, const uint8_t *pkt, size_t len,
                    const struct virtio_net_hdr *vh);

/* Write the next segment, with IP and transport checksums complete, into out.
 * Returns its length, 0 once every segment has been returned, -1 when out_cap
 * is too small. */
int mqvpn_gso_next(mqvpn_gso_iter_t *it, uint8_t *out, size_t out_cap);

/*
 * Receive side: TCP GRO. Packets headed for the TUN are held briefly and
 * consecutive data segments of one flow are merged into a single super-packet
 * that the kernel receives with a virtio_net_hdr (VIRTIO_NET_HDR_GSO_TCPV4/6,
 * partial checksum), the same shape a NIC GRO produces. Each push() may emit
 * packets through the callback; flush() must run before the caller returns to
 * its event loop. Order within a flow is preserved: a packet that cannot join
 * its flow's open super-packet flushes it first.
 *
 * Inner checksums are not verified here (QUIC already authenticates the
 * packet), so a coalesced packet is accepted even if its own TCP checksum was
 * wrong; packets that are not merged are written untouched and checked by the
 * kernel as before.
 */
typedef struct mqvpn_gro mqvpn_gro_t;

/* Deliver one packet to the TUN; vh is all-zero for a plain packet. */
typedef int (*mqvpn_gro_emit_fn)(void *ctx, const struct virtio_net_hdr *vh,
                                 const uint8_t *pkt, size_t len);

mqvpn_gro_t *mqvpn_gro_new(mqvpn_gro_emit_fn emit, void *ctx);
void mqvpn_gro_free(mqvpn_gro_t *g);
void mqvpn_gro_push(mqvpn_gro_t *g, const uint8_t *pkt, size_t len);
void mqvpn_gro_flush(mqvpn_gro_t *g);
int mqvpn_gro_pending(const mqvpn_gro_t *g);
/* Counters: packets pushed, super-packets emitted, packets merged into them. */
void mqvpn_gro_stats(const mqvpn_gro_t *g, uint64_t *pushed, uint64_t *supers,
                     uint64_t *merged);

/* Deliver the packets mqvpn_tun_write() held back for GRO. Call it before
 * returning to the event loop after anything that can produce TUN output. */
void mqvpn_tun_flush(mqvpn_tun_t *tun);

/* 1 when mqvpn_tun_flush() has packets to deliver. */
int mqvpn_tun_gro_pending(const mqvpn_tun_t *tun);

/* 1 when mqvpn_tun_read() still holds segments of an earlier super-packet.
 * The fd may not be readable then, so the caller must run its read handler
 * again by other means (see schedule_next_tick() in platform_linux.c). */
int mqvpn_tun_has_pending(const mqvpn_tun_t *tun);

#endif /* MQVPN_TUN_OFFLOAD_H */
