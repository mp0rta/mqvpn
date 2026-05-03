/*
 * tun_wintun.c — Wintun TUN device implementation for Windows
 *
 * Dynamically loads wintun.dll and provides TUN create/read/write/destroy.
 * A dedicated reader thread reads packets from the Wintun ring buffer and
 * forwards them through a socketpair so libevent can pick them up.
 */

#ifdef _WIN32

#  include "tun_wintun.h"
#  include "log.h"
#  include "wintun.h"

#  include <stdio.h>
#  include <string.h>

/* ── Wintun function pointers (resolved at runtime) ── */

static WINTUN_CREATE_ADAPTER_FUNC *WintunCreateAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC *WintunCloseAdapter;
static WINTUN_GET_ADAPTER_LUID_FUNC *WintunGetAdapterLUID;
static WINTUN_START_SESSION_FUNC *WintunStartSession;
static WINTUN_END_SESSION_FUNC *WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC *WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC *WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC *WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC *WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC *WintunSendPacket;

static HMODULE g_wintun_dll = NULL;

int
mqvpn_wintun_load(void)
{
    if (g_wintun_dll) return 0;

    g_wintun_dll = LoadLibraryA("wintun.dll");
    if (!g_wintun_dll) {
        LOG_ERR("failed to load wintun.dll (error %lu)", GetLastError());
        return -1;
    }

#  define LOAD(name)                                               \
      do {                                                         \
          *(FARPROC *)&name = GetProcAddress(g_wintun_dll, #name); \
          if (!name) {                                             \
              LOG_ERR("wintun.dll missing: " #name);               \
              return -1;                                           \
          }                                                        \
      } while (0)

    LOAD(WintunCreateAdapter);
    LOAD(WintunCloseAdapter);
    LOAD(WintunGetAdapterLUID);
    LOAD(WintunStartSession);
    LOAD(WintunEndSession);
    LOAD(WintunGetReadWaitEvent);
    LOAD(WintunReceivePacket);
    LOAD(WintunReleaseReceivePacket);
    LOAD(WintunAllocateSendPacket);
    LOAD(WintunSendPacket);
#  undef LOAD

    return 0;
}

/* ── Adapter creation ── */

int
mqvpn_tun_win_create(mqvpn_tun_win_t *tun, const char *dev_name)
{
    memset(tun, 0, sizeof(*tun));
    tun->pipe_rd = EVUTIL_INVALID_SOCKET;
    tun->pipe_wr = EVUTIL_INVALID_SOCKET;
    tun->mtu = 1400;

    if (mqvpn_wintun_load() < 0) return -1;

    /* Convert adapter name to wide string */
    const char *name = dev_name ? dev_name : "mqvpn0";
    snprintf(tun->name, sizeof(tun->name), "%s", name);

    WCHAR wname[256];
    MultiByteToWideChar(CP_UTF8, 0, name, -1, wname, 256);

    /* Create adapter */
    GUID guid;
    CoCreateGuid(&guid);
    tun->adapter = WintunCreateAdapter(wname, L"mqvpn", &guid);
    if (!tun->adapter) {
        DWORD err = GetLastError();
        const char *hint = "";
        if (err == ERROR_ACCESS_DENIED) {
            hint = " — run as Administrator (right-click PowerShell -> Run as "
                   "Administrator)";
        }
        LOG_ERR("WintunCreateAdapter failed (error %lu)%s", err, hint);
        return -1;
    }

    /* Get LUID and interface index */
    WintunGetAdapterLUID(tun->adapter, &tun->luid);
    ConvertInterfaceLuidToIndex(&tun->luid, &tun->if_index);

    /* Start session (ring capacity = 8 MB) */
    tun->session = WintunStartSession(tun->adapter, 0x800000);
    if (!tun->session) {
        LOG_ERR("WintunStartSession failed (error %lu)", GetLastError());
        WintunCloseAdapter(tun->adapter);
        tun->adapter = NULL;
        return -1;
    }

    tun->read_event = WintunGetReadWaitEvent(tun->session);

    /* Create socketpair for reader thread → main thread bridge */
    evutil_socket_t pair[2];
    if (evutil_socketpair(AF_INET, SOCK_STREAM, 0, pair) < 0) {
        LOG_ERR("evutil_socketpair failed");
        WintunEndSession(tun->session);
        WintunCloseAdapter(tun->adapter);
        tun->session = NULL;
        tun->adapter = NULL;
        return -1;
    }
    tun->pipe_rd = pair[0];
    tun->pipe_wr = pair[1];

    /* Make both ends non-blocking */
    evutil_make_socket_nonblocking(tun->pipe_rd);
    evutil_make_socket_nonblocking(tun->pipe_wr);

    /* Increase socketpair buffer to reduce packet drops under load */
    {
        int pipebuf = 7 * 1024 * 1024; /* 7 MB (aligned with WireGuard) */
        setsockopt(tun->pipe_wr, SOL_SOCKET, SO_SNDBUF, (const char *)&pipebuf,
                   sizeof(pipebuf));
        setsockopt(tun->pipe_rd, SOL_SOCKET, SO_RCVBUF, (const char *)&pipebuf,
                   sizeof(pipebuf));

        int actual_snd = 0, actual_rcv = 0;
        int optlen = sizeof(actual_snd);
        getsockopt(tun->pipe_wr, SOL_SOCKET, SO_SNDBUF, (char *)&actual_snd, &optlen);
        getsockopt(tun->pipe_rd, SOL_SOCKET, SO_RCVBUF, (char *)&actual_rcv, &optlen);
        LOG_INF("TUN pipe buffers: SO_SNDBUF=%d SO_RCVBUF=%d", actual_snd, actual_rcv);
    }

    LOG_INF("TUN %s created (if_index=%lu)", tun->name, (unsigned long)tun->if_index);
    return 0;
}

/* ── IP address configuration ── */

int
mqvpn_tun_win_set_addr(mqvpn_tun_win_t *tun, const char *addr, const char *peer_addr,
                       int prefix_len)
{
    MIB_UNICASTIPADDRESS_ROW row;
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = tun->luid;
    row.Address.Ipv4.sin_family = AF_INET;
    inet_pton(AF_INET, addr, &row.Address.Ipv4.sin_addr);
    row.OnLinkPrefixLength = (UINT8)prefix_len;
    row.DadState = IpDadStatePreferred;

    DWORD err = CreateUnicastIpAddressEntry(&row);
    if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS) {
        LOG_ERR("CreateUnicastIpAddressEntry(%s): error %lu", addr, err);
        return -1;
    }

    inet_pton(AF_INET, addr, &tun->addr);
    inet_pton(AF_INET, peer_addr, &tun->peer_addr);

    LOG_INF("TUN %s addr: %s → %s /%d", tun->name, addr, peer_addr, prefix_len);
    return 0;
}

int
mqvpn_tun_win_set_addr6(mqvpn_tun_win_t *tun, const char *addr6, int prefix_len)
{
    MIB_UNICASTIPADDRESS_ROW row;
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = tun->luid;
    row.Address.Ipv6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, addr6, &row.Address.Ipv6.sin6_addr);
    row.OnLinkPrefixLength = (UINT8)prefix_len;
    row.DadState = IpDadStatePreferred;

    DWORD err = CreateUnicastIpAddressEntry(&row);
    if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS) {
        LOG_ERR("CreateUnicastIpAddressEntry(%s): error %lu", addr6, err);
        return -1;
    }

    inet_pton(AF_INET6, addr6, &tun->addr6);
    tun->has_v6 = 1;
    return 0;
}

/* Helper: set MTU for one address family via IPHLPAPI */
static int
set_iface_mtu(const NET_LUID *luid, ADDRESS_FAMILY family, ULONG mtu)
{
    MIB_IPINTERFACE_ROW row;
    InitializeIpInterfaceEntry(&row);
    row.InterfaceLuid = *luid;
    row.Family = family;

    DWORD err = GetIpInterfaceEntry(&row);
    if (err != NO_ERROR) {
        LOG_WRN("GetIpInterfaceEntry(%s): error %lu", family == AF_INET ? "v4" : "v6",
                err);
        return -1;
    }

    row.NlMtu = mtu;
    row.SitePrefixLength = 0; /* required: avoids ERROR_INVALID_PARAMETER */

    err = SetIpInterfaceEntry(&row);
    if (err != NO_ERROR) {
        LOG_WRN("SetIpInterfaceEntry(%s, mtu=%lu): error %lu",
                family == AF_INET ? "v4" : "v6", mtu, err);
        return -1;
    }
    return 0;
}

int
mqvpn_tun_win_set_mtu(mqvpn_tun_win_t *tun, int mtu)
{
    if (set_iface_mtu(&tun->luid, AF_INET, (ULONG)mtu) < 0)
        LOG_WRN("IPv4 MTU set failed, continuing with default");

    if (tun->has_v6) {
        if (set_iface_mtu(&tun->luid, AF_INET6, (ULONG)mtu) < 0)
            LOG_WRN("IPv6 MTU set failed, continuing with default");
    }

    tun->mtu = mtu;
    return 0;
}

/* ── Reader thread ── */

/*
 * Protocol on the socketpair:
 *   [2-byte big-endian length] [IP packet payload]
 *
 * This framing is needed because the socketpair uses SOCK_STREAM.
 */

static DWORD WINAPI
tun_reader_thread(LPVOID arg)
{
    mqvpn_tun_win_t *tun = (mqvpn_tun_win_t *)arg;
    uint64_t drop_count = 0;
    uint64_t drop_bytes = 0;
    DWORD last_drop_log = 0;

    while (!InterlockedCompareExchange(&tun->stop, 0, 0)) {
        /* Wait for Wintun to signal data available */
        DWORD wait = WaitForSingleObject(tun->read_event, 250);
        if (wait == WAIT_TIMEOUT) continue;
        if (wait != WAIT_OBJECT_0) break;

        /* Drain all available packets */
        for (;;) {
            if (InterlockedCompareExchange(&tun->stop, 0, 0)) goto done;

            DWORD pkt_size = 0;
            BYTE *pkt = WintunReceivePacket(tun->session, &pkt_size);
            if (!pkt) break;

            if (pkt_size > 0 && pkt_size <= 65535) {
                /* Frame: [2-byte length][payload] */
                uint8_t frame[2 + 65536];
                frame[0] = (uint8_t)(pkt_size >> 8);
                frame[1] = (uint8_t)(pkt_size & 0xFF);
                memcpy(frame + 2, pkt, pkt_size);

                int ret = send(tun->pipe_wr, (const char *)frame, (int)(2 + pkt_size), 0);
                if (ret < 0) {
                    drop_count++;
                    drop_bytes += pkt_size;
                    /* Log at most once per second */
                    DWORD now = GetTickCount();
                    if (now - last_drop_log >= 1000) {
                        LOG_WRN("TUN pipe full: dropped %llu pkts (%llu bytes total)",
                                (unsigned long long)drop_count,
                                (unsigned long long)drop_bytes);
                        last_drop_log = now;
                    }
                }
            }

            WintunReleaseReceivePacket(tun->session, pkt);
        }
    }

done:
    return 0;
}

int
mqvpn_tun_win_start_reader(mqvpn_tun_win_t *tun)
{
    InterlockedExchange(&tun->stop, 0);

    tun->reader_thread = CreateThread(NULL, 0, tun_reader_thread, tun, 0, NULL);
    if (!tun->reader_thread) {
        LOG_ERR("CreateThread for TUN reader failed (%lu)", GetLastError());
        return -1;
    }
    return 0;
}

/* ── Write (DL direction — main thread) ── */

int
mqvpn_tun_win_write(mqvpn_tun_win_t *tun, const uint8_t *buf, size_t len)
{
    if (!tun->session || len == 0 || len > 65535) return -1;

    BYTE *pkt = WintunAllocateSendPacket(tun->session, (DWORD)len);
    if (!pkt) return MQVPN_TUN_EAGAIN;

    memcpy(pkt, buf, len);
    WintunSendPacket(tun->session, pkt);
    return (int)len;
}

/* ── Cleanup ── */

void
mqvpn_tun_win_destroy(mqvpn_tun_win_t *tun)
{
    /* Signal reader thread to stop */
    InterlockedExchange(&tun->stop, 1);

    if (tun->reader_thread) {
        WaitForSingleObject(tun->reader_thread, 3000);
        CloseHandle(tun->reader_thread);
        tun->reader_thread = NULL;
    }

    if (tun->session) {
        WintunEndSession(tun->session);
        tun->session = NULL;
    }

    if (tun->adapter) {
        WintunCloseAdapter(tun->adapter);
        tun->adapter = NULL;
    }

    if (tun->pipe_rd != EVUTIL_INVALID_SOCKET) {
        evutil_closesocket(tun->pipe_rd);
        tun->pipe_rd = EVUTIL_INVALID_SOCKET;
    }
    if (tun->pipe_wr != EVUTIL_INVALID_SOCKET) {
        evutil_closesocket(tun->pipe_wr);
        tun->pipe_wr = EVUTIL_INVALID_SOCKET;
    }

    LOG_INF("TUN %s destroyed", tun->name);
}

#endif /* _WIN32 */
