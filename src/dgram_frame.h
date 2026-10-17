// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef MQVPN_DGRAM_FRAME_H
#define MQVPN_DGRAM_FRAME_H

/*
 * dgram_frame.h — per-packet buffers of the DATAGRAM lane.
 *
 * Every inner IP packet crosses the tunnel as one HTTP Datagram: the MASQUE
 * header (quarter stream ID, context ID 0), the 8-byte reorder header when
 * the packet is stamped, then the packet. mqvpn_dgram_frame() writes the
 * header first and copies the packet once behind it, so a sender needs no
 * staging copy for the reorder header or for the TTL decrement (the server
 * decrements it in the frame itself).
 *
 * The buffers are sized for the packets that can actually cross: a DATAGRAM
 * is never larger than the connection's datagram MSS, which the outer
 * packet size bounds (MQVPN_XQC_MAX_PKT_OUT_SIZE at most, whatever the
 * PathMTU), and xquic decrypts packets into a 1500-byte buffer. A larger
 * packet takes a heap buffer instead, so it is handled exactly as before.
 * Keep these buffers small: with -fstack-clash-protection (Ubuntu's gcc
 * default), a function with a 64 KiB stack array writes to each of its 16
 * pages on every call, which costs more than the copy itself.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>

#include "reorder.h" /* MQVPN_REORDER_HDR_LEN */

/* Stack room for one frame or one received inner packet; see above. */
#define MQVPN_DGRAM_STACK_BUF 2048

/* MASQUE header: quarter stream ID (varint, at most 8 bytes) + context ID. */
#define MQVPN_MASQUE_HDR_MAX 9

/* Bytes mqvpn_dgram_frame() may need for a len-byte packet. */
static inline size_t
mqvpn_dgram_frame_cap(size_t len, int stamp)
{
    return MQVPN_MASQUE_HDR_MAX + (stamp ? MQVPN_REORDER_HDR_LEN : 0) + len;
}

/* Frames [reorder_hdr (8 bytes, optional)] + pkt for the CONNECT-IP request
 * stream_id into out (cap bytes). On XQC_OK, *written is the frame length
 * and the copy of pkt is its last len bytes. */
static inline xqc_int_t
mqvpn_dgram_frame(uint8_t *out, size_t cap, uint64_t stream_id,
                  const uint8_t *reorder_hdr, const uint8_t *pkt, size_t len,
                  size_t *written)
{
    size_t hlen = 0;
    xqc_int_t ret = xqc_h3_ext_masque_frame_udp(out, cap, &hlen, stream_id, NULL, 0);
    if (ret != XQC_OK) return ret;
    size_t rlen = reorder_hdr ? MQVPN_REORDER_HDR_LEN : 0;
    if (cap - hlen < rlen + len) return -XQC_ENOBUF;
    if (rlen) memcpy(out + hlen, reorder_hdr, rlen);
    memcpy(out + hlen + rlen, pkt, len);
    *written = hlen + rlen + len;
    return XQC_OK;
}

#endif /* MQVPN_DGRAM_FRAME_H */
