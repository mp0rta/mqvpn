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

/* 1 when mqvpn_tun_read() still holds segments of an earlier super-packet.
 * The fd may not be readable then, so the caller must run its read handler
 * again by other means (see schedule_next_tick() in platform_linux.c). */
int mqvpn_tun_has_pending(const mqvpn_tun_t *tun);

#endif /* MQVPN_TUN_OFFLOAD_H */
