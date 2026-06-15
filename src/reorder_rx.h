// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#ifndef MQVPN_REORDER_RX_H
#define MQVPN_REORDER_RX_H

/*
 * reorder_rx.h — receiver-side engine for the flow-aware reorder-only datagram
 * shim (design spec v2.5 §11, §12, §13).
 *
 * The RX side owns a 5-tuple-keyed reorder_flow table, a per-flow elastic ring
 * (§13), and the §11.1 invariant (gap timer active ⟺ buffer non-empty). It never
 * writes to TUN directly: in-order delivery is routed through an injected
 * `deliver` callback so the engine is unit-testable with a mock recorder and no
 * platform/tx linkage.
 *
 * TX and RX are zero-coupled: they share ONLY reorder.h (wire format, flow key,
 * config). This header must never include any tx header.
 *
 * Time is injected: every API that observes time takes `now_us`. There is no
 * wall-clock read inside reorder_rx.c (test determinism). Timeout/eviction is
 * driven by mqvpn_reorder_rx_tick().
 */

#include <stddef.h>
#include <stdint.h>

#include "reorder.h" /* wire codec, flow_key, config, 5-tuple parser */

/* Opaque receiver state. */
typedef struct mqvpn_reorder_rx mqvpn_reorder_rx_t;

/* Deliver callback: hands one in-order inner IP packet to the platform (TUN).
 * `pkt[0..len)` is the bare inner IP packet (no reorder header). */
typedef void (*mqvpn_reorder_deliver_fn)(const uint8_t *pkt, size_t len, void *ctx);

/*
 * Create/destroy. cfg is copied; hash_seed seeds the keyed flow hash (§6.2).
 * `deliver` is invoked for every in-order delivery with `deliver_ctx`.
 * Returns NULL on allocation failure or invalid config.
 */
mqvpn_reorder_rx_t *mqvpn_reorder_rx_new(const mqvpn_reorder_config_t *cfg,
                                         uint64_t hash_seed,
                                         mqvpn_reorder_deliver_fn deliver,
                                         void *deliver_ctx);
void mqvpn_reorder_rx_free(mqvpn_reorder_rx_t *rx);

/*
 * Receive one de-framed reorder datagram `payload[0..len)` =
 * [type][flags][seq48][inner IP]. Decodes the header, extracts the inner-IP
 * 5-tuple (§6), finds/creates the reorder_flow, and runs the §11.3 dispatch.
 * Malformed (len < 8 / non-REORDER type / unparseable inner) datagrams are
 * dropped. now_us is injected (no wall-clock inside).
 */
void mqvpn_reorder_rx_on_packet(mqvpn_reorder_rx_t *rx, const uint8_t *payload,
                                size_t len, uint64_t now_us);

/*
 * Periodic driver: fires gap timeouts and idle eviction. STUB in phase-1
 * part A (real timeout/eviction lands in part B). Maintains the §11.1 invariant.
 */
void mqvpn_reorder_rx_tick(mqvpn_reorder_rx_t *rx, uint64_t now_us);

#endif /* MQVPN_REORDER_RX_H */
