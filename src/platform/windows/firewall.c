/*
 * firewall.c — WFP-based kill switch for Windows
 *
 * Uses the Windows Filtering Platform (WFP) to block all outbound traffic
 * except:
 *   - Loopback
 *   - Traffic to the VPN server (UDP on original interface)
 *   - Traffic on the TUN (Wintun) interface
 *
 * All filters are added under a single sublayer so cleanup is atomic.
 */

#ifdef _WIN32

#include "platform_internal_win.h"
#include "log.h"

#include <stdio.h>
#include <string.h>

/* {8D5E9B7A-3C1F-4E8B-9F2A-1D6E4A5B3C7F} */
static const GUID MQVPN_PROVIDER_KEY = {
    0x8d5e9b7a, 0x3c1f, 0x4e8b,
    {0x9f, 0x2a, 0x1d, 0x6e, 0x4a, 0x5b, 0x3c, 0x7f}
};

/* Helper: add a single WFP filter */
static int
add_filter(platform_win_ctx_t *p, const FWPM_FILTER0 *filter)
{
    if (p->n_wfp_filters >= 8) {
        LOG_WRN("killswitch: max filter count reached");
        return -1;
    }

    UINT64 fid = 0;
    DWORD err = FwpmFilterAdd0(p->wfp_engine, filter, NULL, &fid);
    if (err != ERROR_SUCCESS) {
        LOG_ERR("FwpmFilterAdd0: error %lu", err);
        return -1;
    }

    p->wfp_filter_ids[p->n_wfp_filters++] = fid;
    return 0;
}

int
win_setup_killswitch(platform_win_ctx_t *p)
{
    if (!p->killswitch_enabled || p->killswitch_active)
        return 0;

    DWORD err;

    /* Open WFP engine */
    err = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &p->wfp_engine);
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
    sublayer.weight = 0xFFFF;  /* highest priority */

    err = FwpmSubLayerAdd0(p->wfp_engine, &sublayer, NULL);
    if (err != ERROR_SUCCESS) {
        LOG_ERR("FwpmSubLayerAdd0: error %lu", err);
        FwpmTransactionAbort0(p->wfp_engine);
        FwpmEngineClose0(p->wfp_engine);
        p->wfp_engine = NULL;
        return -1;
    }

    p->n_wfp_filters = 0;

    /*
     * Filter 1: PERMIT loopback (IPv4)
     */
    {
        FWPM_FILTER0 f;
        memset(&f, 0, sizeof(f));
        f.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        f.subLayerKey = p->wfp_sublayer_key;
        f.displayData.name = L"mqvpn: permit loopback v4";
        f.weight.type = FWP_UINT8;
        f.weight.uint8 = 15;
        f.action.type = FWP_ACTION_PERMIT;

        FWPM_FILTER_CONDITION0 cond;
        cond.fieldKey = FWPM_CONDITION_FLAGS;
        cond.matchType = FWP_MATCH_FLAGS_ALL_SET;
        cond.conditionValue.type = FWP_UINT32;
        cond.conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;

        f.filterCondition = &cond;
        f.numFilterConditions = 1;
        add_filter(p, &f);
    }

    /*
     * Filter 2: PERMIT loopback (IPv6)
     */
    {
        FWPM_FILTER0 f;
        memset(&f, 0, sizeof(f));
        f.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
        f.subLayerKey = p->wfp_sublayer_key;
        f.displayData.name = L"mqvpn: permit loopback v6";
        f.weight.type = FWP_UINT8;
        f.weight.uint8 = 15;
        f.action.type = FWP_ACTION_PERMIT;

        FWPM_FILTER_CONDITION0 cond;
        cond.fieldKey = FWPM_CONDITION_FLAGS;
        cond.matchType = FWP_MATCH_FLAGS_ALL_SET;
        cond.conditionValue.type = FWP_UINT32;
        cond.conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;

        f.filterCondition = &cond;
        f.numFilterConditions = 1;
        add_filter(p, &f);
    }

    /*
     * Filter 3: PERMIT traffic on TUN interface (IPv4)
     */
    {
        FWPM_FILTER0 f;
        memset(&f, 0, sizeof(f));
        f.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        f.subLayerKey = p->wfp_sublayer_key;
        f.displayData.name = L"mqvpn: permit TUN v4";
        f.weight.type = FWP_UINT8;
        f.weight.uint8 = 14;
        f.action.type = FWP_ACTION_PERMIT;

        FWPM_FILTER_CONDITION0 cond;
        cond.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue.type = FWP_UINT64;
        cond.conditionValue.uint64 = &p->tun.luid.Value;

        f.filterCondition = &cond;
        f.numFilterConditions = 1;
        add_filter(p, &f);
    }

    /*
     * Filter 4: PERMIT traffic on TUN interface (IPv6)
     */
    {
        FWPM_FILTER0 f;
        memset(&f, 0, sizeof(f));
        f.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
        f.subLayerKey = p->wfp_sublayer_key;
        f.displayData.name = L"mqvpn: permit TUN v6";
        f.weight.type = FWP_UINT8;
        f.weight.uint8 = 14;
        f.action.type = FWP_ACTION_PERMIT;

        FWPM_FILTER_CONDITION0 cond;
        cond.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue.type = FWP_UINT64;
        cond.conditionValue.uint64 = &p->tun.luid.Value;

        f.filterCondition = &cond;
        f.numFilterConditions = 1;
        add_filter(p, &f);
    }

    /*
     * Filter 5: PERMIT UDP to VPN server (IPv4)
     */
    if (p->server_addr.ss_family == AF_INET) {
        FWPM_FILTER0 f;
        memset(&f, 0, sizeof(f));
        f.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        f.subLayerKey = p->wfp_sublayer_key;
        f.displayData.name = L"mqvpn: permit server UDP";
        f.weight.type = FWP_UINT8;
        f.weight.uint8 = 13;
        f.action.type = FWP_ACTION_PERMIT;

        FWPM_FILTER_CONDITION0 conds[2];

        /* Condition: remote address == server IP */
        conds[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        conds[0].matchType = FWP_MATCH_EQUAL;
        conds[0].conditionValue.type = FWP_UINT32;
        conds[0].conditionValue.uint32 = ntohl(
            ((struct sockaddr_in *)&p->server_addr)->sin_addr.s_addr);

        /* Condition: remote port == server port */
        conds[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        conds[1].matchType = FWP_MATCH_EQUAL;
        conds[1].conditionValue.type = FWP_UINT16;
        conds[1].conditionValue.uint16 = (UINT16)p->server_port;

        f.filterCondition = conds;
        f.numFilterConditions = 2;
        add_filter(p, &f);
    }

    /*
     * Filter 6: BLOCK all other outbound (IPv4)
     */
    {
        FWPM_FILTER0 f;
        memset(&f, 0, sizeof(f));
        f.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        f.subLayerKey = p->wfp_sublayer_key;
        f.displayData.name = L"mqvpn: block all v4";
        f.weight.type = FWP_UINT8;
        f.weight.uint8 = 1;
        f.action.type = FWP_ACTION_BLOCK;
        f.numFilterConditions = 0;
        add_filter(p, &f);
    }

    /*
     * Filter 7: BLOCK all other outbound (IPv6)
     */
    {
        FWPM_FILTER0 f;
        memset(&f, 0, sizeof(f));
        f.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
        f.subLayerKey = p->wfp_sublayer_key;
        f.displayData.name = L"mqvpn: block all v6";
        f.weight.type = FWP_UINT8;
        f.weight.uint8 = 1;
        f.action.type = FWP_ACTION_BLOCK;
        f.numFilterConditions = 0;
        add_filter(p, &f);
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
    if (!p->killswitch_active || !p->wfp_engine)
        return;

    /* Deleting the sublayer cascades and removes all filters in it */
    DWORD err = FwpmSubLayerDeleteByKey0(p->wfp_engine, &p->wfp_sublayer_key);
    if (err != ERROR_SUCCESS && err != FWP_E_SUBLAYER_NOT_FOUND)
        LOG_WRN("FwpmSubLayerDeleteByKey0: error %lu", err);

    FwpmEngineClose0(p->wfp_engine);
    p->wfp_engine = NULL;
    p->killswitch_active = 0;
    p->n_wfp_filters = 0;
    LOG_INF("kill switch deactivated");
}

#endif /* _WIN32 */
