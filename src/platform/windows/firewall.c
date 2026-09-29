// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * firewall.c — WFP-based kill switch for Windows
 *
 * Uses the Windows Filtering Platform (WFP) to block all outbound traffic
 * except:
 *   - Loopback
 *   - Traffic to the VPN server (UDP on original interface)
 *   - Traffic on the TUN (Wintun) interface
 *
 * All objects are added through a DYNAMIC WFP session. BFE deletes everything
 * a dynamic session added once that session ends, including when the process
 * dies without running cleanup. That matters because WFP objects are static by
 * default and "live until they are deleted, BFE stops, or the system is
 * shutdown" (WFP Object Management) — a crash with static filters leaves the
 * block-all rules in place and cuts the host off until the next reboot.
 */

#ifdef _WIN32

#  include "platform_internal_win.h"
#  include "log.h"

#  include <stdio.h>
#  include <string.h>

/* ── Filter helpers ── */

/* Initialize common FWPM_FILTER0 fields */
static void
wfp_filter_base(FWPM_FILTER0 *f, const GUID *layer, const GUID *sublayer,
                const wchar_t *name, UINT8 weight, UINT32 action)
{
    memset(f, 0, sizeof(*f));
    f->layerKey = *layer;
    f->subLayerKey = *sublayer;
    f->displayData.name = (wchar_t *)name;
    f->weight.type = FWP_UINT8;
    f->weight.uint8 = weight;
    f->action.type = action;
}

/* Add a single WFP filter */
static int
add_filter(platform_win_ctx_t *p, const FWPM_FILTER0 *filter)
{
    DWORD err = FwpmFilterAdd0(p->wfp_engine, filter, NULL, NULL);
    if (err != ERROR_SUCCESS) {
        LOG_ERR("FwpmFilterAdd0: error %lu", err);
        return -1;
    }

    p->n_wfp_filters++;
    return 0;
}

/* PERMIT loopback (IPv4 + IPv6) */
static int
wfp_add_loopback_permit(platform_win_ctx_t *p)
{
    static const GUID *layers[] = {
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    };
    static const wchar_t *names[] = {
        L"mqvpn: permit loopback v4",
        L"mqvpn: permit loopback v6",
    };

    for (int i = 0; i < 2; i++) {
        FWPM_FILTER0 f;
        wfp_filter_base(&f, layers[i], &p->wfp_sublayer_key, names[i], 15,
                        FWP_ACTION_PERMIT);

        FWPM_FILTER_CONDITION0 cond;
        cond.fieldKey = FWPM_CONDITION_FLAGS;
        cond.matchType = FWP_MATCH_FLAGS_ALL_SET;
        cond.conditionValue.type = FWP_UINT32;
        cond.conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;

        f.filterCondition = &cond;
        f.numFilterConditions = 1;
        if (add_filter(p, &f) < 0) return -1;
    }
    return 0;
}

/* PERMIT traffic on TUN interface (IPv4 + IPv6) */
static int
wfp_add_iface_permit(platform_win_ctx_t *p)
{
    static const GUID *layers[] = {
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    };
    static const wchar_t *names[] = {
        L"mqvpn: permit TUN v4",
        L"mqvpn: permit TUN v6",
    };

    for (int i = 0; i < 2; i++) {
        FWPM_FILTER0 f;
        wfp_filter_base(&f, layers[i], &p->wfp_sublayer_key, names[i], 14,
                        FWP_ACTION_PERMIT);

        FWPM_FILTER_CONDITION0 cond;
        cond.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue.type = FWP_UINT64;
        cond.conditionValue.uint64 = &p->tun.luid.Value;

        f.filterCondition = &cond;
        f.numFilterConditions = 1;
        if (add_filter(p, &f) < 0) return -1;
    }
    return 0;
}

/* PERMIT UDP to VPN server (IPv4 or IPv6, based on server_addr family) */
static int
wfp_add_server_permit(platform_win_ctx_t *p)
{
    if (p->server_addr.ss_family == AF_INET) {
        FWPM_FILTER0 f;
        wfp_filter_base(&f, &FWPM_LAYER_ALE_AUTH_CONNECT_V4, &p->wfp_sublayer_key,
                        L"mqvpn: permit server UDP v4", 13, FWP_ACTION_PERMIT);

        FWPM_FILTER_CONDITION0 conds[2];

        conds[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        conds[0].matchType = FWP_MATCH_EQUAL;
        conds[0].conditionValue.type = FWP_UINT32;
        conds[0].conditionValue.uint32 =
            ntohl(((struct sockaddr_in *)&p->server_addr)->sin_addr.s_addr);

        conds[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        conds[1].matchType = FWP_MATCH_EQUAL;
        conds[1].conditionValue.type = FWP_UINT16;
        conds[1].conditionValue.uint16 = (UINT16)p->server_port;

        f.filterCondition = conds;
        f.numFilterConditions = 2;
        return add_filter(p, &f);
    }

    if (p->server_addr.ss_family == AF_INET6) {
        FWPM_FILTER0 f;
        wfp_filter_base(&f, &FWPM_LAYER_ALE_AUTH_CONNECT_V6, &p->wfp_sublayer_key,
                        L"mqvpn: permit server UDP v6", 13, FWP_ACTION_PERMIT);

        FWPM_FILTER_CONDITION0 conds[2];

        conds[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        conds[0].matchType = FWP_MATCH_EQUAL;
        conds[0].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
        conds[0].conditionValue.byteArray16 =
            (FWP_BYTE_ARRAY16 *)&((struct sockaddr_in6 *)&p->server_addr)->sin6_addr;

        conds[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        conds[1].matchType = FWP_MATCH_EQUAL;
        conds[1].conditionValue.type = FWP_UINT16;
        conds[1].conditionValue.uint16 = (UINT16)p->server_port;

        f.filterCondition = conds;
        f.numFilterConditions = 2;
        return add_filter(p, &f);
    }

    return 0; /* unknown family — skip */
}

/* BLOCK all other outbound (IPv4 + IPv6) */
static int
wfp_add_block_all(platform_win_ctx_t *p)
{
    static const GUID *layers[] = {
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    };
    static const wchar_t *names[] = {
        L"mqvpn: block all v4",
        L"mqvpn: block all v6",
    };

    for (int i = 0; i < 2; i++) {
        FWPM_FILTER0 f;
        wfp_filter_base(&f, layers[i], &p->wfp_sublayer_key, names[i], 1,
                        FWP_ACTION_BLOCK);
        f.numFilterConditions = 0;
        if (add_filter(p, &f) < 0) return -1;
    }
    return 0;
}

/* ── Public API ── */

int
win_setup_killswitch(platform_win_ctx_t *p)
{
    if (!p->killswitch_enabled) return 0;

    /* Checked before killswitch_active, which a failed close deliberately
     * leaves set: the early return below would otherwise report success for a
     * kill switch that is really the stale, unreachable session. */
    if (p->wfp_close_failed) {
        LOG_ERR("kill switch: the previous WFP session could not be closed; "
                "refusing to open a second one on top of it");
        return -1;
    }

    if (p->killswitch_active) return 0;

    DWORD err;

    /* Open WFP engine on a dynamic session — see the file header for why. */
    FWPM_SESSION0 session;
    memset(&session, 0, sizeof(session));
    session.displayData.name = L"mqvpn kill switch";
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    err = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &p->wfp_engine);
    if (err != ERROR_SUCCESS) {
        LOG_ERR("FwpmEngineOpen0: error %lu", err);
        return -1;
    }

    /* Begin transaction */
    err = FwpmTransactionBegin0(p->wfp_engine, 0);
    if (err != ERROR_SUCCESS) {
        LOG_ERR("FwpmTransactionBegin0: error %lu", err);
        FwpmEngineClose0(p->wfp_engine);
        p->wfp_engine = NULL;
        return -1;
    }

    /* Create sublayer */
    CoCreateGuid(&p->wfp_sublayer_key);

    FWPM_SUBLAYER0 sublayer;
    memset(&sublayer, 0, sizeof(sublayer));
    sublayer.subLayerKey = p->wfp_sublayer_key;
    sublayer.displayData.name = L"mqvpn kill switch";
    sublayer.weight = 0xFFFF; /* highest priority */

    err = FwpmSubLayerAdd0(p->wfp_engine, &sublayer, NULL);
    if (err != ERROR_SUCCESS) {
        LOG_ERR("FwpmSubLayerAdd0: error %lu", err);
        FwpmTransactionAbort0(p->wfp_engine);
        FwpmEngineClose0(p->wfp_engine);
        p->wfp_engine = NULL;
        return -1;
    }

    p->n_wfp_filters = 0;

    /* Add filters: permit loopback → permit TUN → permit server → block all */
    if (wfp_add_loopback_permit(p) < 0 || wfp_add_iface_permit(p) < 0 ||
        wfp_add_server_permit(p) < 0 || wfp_add_block_all(p) < 0) {
        FwpmTransactionAbort0(p->wfp_engine);
        FwpmEngineClose0(p->wfp_engine);
        p->wfp_engine = NULL;
        return -1;
    }

    /* Commit transaction */
    err = FwpmTransactionCommit0(p->wfp_engine);
    if (err != ERROR_SUCCESS) {
        LOG_ERR("FwpmTransactionCommit0: error %lu", err);
        FwpmTransactionAbort0(p->wfp_engine);
        FwpmEngineClose0(p->wfp_engine);
        p->wfp_engine = NULL;
        return -1;
    }

    p->killswitch_active = 1;
    LOG_INF("kill switch active (%d WFP filters)", p->n_wfp_filters);
    return 0;
}

void
win_cleanup_killswitch(platform_win_ctx_t *p)
{
    if (!p->killswitch_active || !p->wfp_engine) return;

    /* Never close a handle whose close already failed: a WFP engine handle is
     * an RPC context handle, and its state after a failed close is undefined. */
    if (p->wfp_close_failed) return;

    /* Closing the engine ends the dynamic session, which deletes the sublayer
     * and every filter in it.
     *
     * WFP has no cascade delete: "An object cannot be deleted until all
     * objects that reference it have first been deleted" (WFP Object
     * Management), and every filter references the sublayer it was added to.
     * Deleting the sublayer on its own therefore leaves the filters — and the
     * block-all rules among them — in place. */
    DWORD err = FwpmEngineClose0(p->wfp_engine);
    if (err != ERROR_SUCCESS) {
        /* The session may still be blocking everything, and nothing can reach
         * it any more: the handle is the only reference to it, and the next
         * setup overwrites wfp_sublayer_key with a fresh GUID. Keep
         * wfp_engine and killswitch_active set so no second session is stacked
         * on the stale one, and let the caller end the process — the one
         * remedy that always works, because BFE runs down a dynamic session
         * when its owner dies. That is why the session is dynamic at all. */
        p->wfp_close_failed = 1;
        LOG_ERR("FwpmEngineClose0: error %lu; kill switch filters are still "
                "live and can no longer be addressed — shutting down so BFE "
                "removes them",
                err);
        return;
    }

    p->wfp_engine = NULL;
    p->killswitch_active = 0;
    p->n_wfp_filters = 0;
    LOG_INF("kill switch deactivated");
}

#endif /* _WIN32 */
