/*
 * Offline apply/recover smoke test (Linux host with OpenSSL).
 * Build: gcc -I../implant/headers tests/test_profile_vm.c \
 *   implant/src/profile.c implant/src/encoders.c implant/src/parse.c \
 *   -lssl -lcrypto -o test_profile_vm
 *
 * Stubs setting_ptr for Host header only.
 */
#include "profile.h"
#include "parse.h"
#include "encoders.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* stubs */
char *setting_ptr(int field) { (void)field; return NULL; }
unsigned int bigger_rand(void) { return 0xA1B2C3D4u; }

static void be32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

static int fail(const char *m) { fprintf(stderr, "FAIL: %s\n", m); return 1; }

int main(void) {
    profile_t p;
    unsigned char prog[128];
    unsigned char meta[] = {0x01, 0x02, 0x03, 0x04, 0xde, 0xad};
    int n = 0;
    char buf[256];
    int r;

    /* GET program: BUILD meta(0), BASE64, HEADER "Cookie", end */
    be32(prog + n, 7); n += 4;
    be32(prog + n, 0); n += 4;
    be32(prog + n, 3); n += 4;
    be32(prog + n, 6); n += 4;
    be32(prog + n, 6); n += 4;
    memcpy(prog + n, "Cookie", 6); n += 6;
    be32(prog + n, 0); n += 4;

    profile_setup(&p, 64);
    snprintf(p.uri, 1024, "%s", "/jquery.js");
    apply((char *)prog, n, &p, (char *)meta, (int)sizeof(meta), NULL, 0);

    if (!strstr(p.headers, "Cookie: "))
        return fail("expected Cookie header");
    if (p.blen != 0)
        return fail("GET should not print body");
    printf("OK apply GET Cookie headers:\n%s\n", p.headers);
    profile_free(&p);

    /* POST: BUILD id(0) PARAMETER id; BUILD out(1) PRINT */
    n = 0;
    be32(prog + n, 7); n += 4;
    be32(prog + n, 0); n += 4;
    be32(prog + n, 5); n += 4;
    be32(prog + n, 2); n += 4;
    memcpy(prog + n, "id", 2); n += 2;
    be32(prog + n, 7); n += 4;
    be32(prog + n, 1); n += 4;
    be32(prog + n, 4); n += 4;
    be32(prog + n, 0); n += 4;

    {
        char id[] = "12345";
        char out[] = "hello-output";
        profile_setup(&p, 64);
        snprintf(p.uri, 1024, "%s", "/submit.php");
        apply((char *)prog, n, &p, id, (int)strlen(id), out, (int)strlen(out));
        if (!strstr(p.parameters, "?id=12345"))
            return fail("post parameter id");
        if (p.blen != (int)strlen(out) || memcmp(p.buffer, out, p.blen) != 0)
            return fail("post print body");
        printf("OK apply POST params=%s blen=%d\n", p.parameters, p.blen);
        profile_free(&p);
    }

    /* recover: PREPEND 3 + APPEND 2 around payload, then reverse */
    {
        unsigned char rprog[32];
        int rn = 0;
        /* recover order is reverse of transform: first strip append then prepend */
        /* server recover program for prepend "ABC" append "XY":
         * rsteps reverse: APPEND 2, PREPEND 3, end
         */
        be32(rprog + rn, 1); rn += 4; /* APPEND strip right */
        be32(rprog + rn, 2); rn += 4;
        be32(rprog + rn, 2); rn += 4; /* PREPEND strip left */
        be32(rprog + rn, 3); rn += 4;
        be32(rprog + rn, 0); rn += 4;

        memcpy(buf, "ABCpayloadXY", 12);
        r = recover((char *)rprog, rn, buf, 12, (int)sizeof(buf));
        if (r != 7 || memcmp(buf, "payload", 7) != 0)
            return fail("recover prepend/append");
        printf("OK recover strip -> '%.*s'\n", r, buf);
    }

    /* base64 round-trip via apply+recover */
    {
        unsigned char gprog[64];
        unsigned char rec[16];
        int gn = 0, rn = 0;
        char body[128];
        int blen;

        be32(gprog + gn, 7); gn += 4;
        be32(gprog + gn, 1); gn += 4; /* BUILD output */
        be32(gprog + gn, 3); gn += 4; /* BASE64 */
        be32(gprog + gn, 4); gn += 4; /* PRINT */
        be32(gprog + gn, 0); gn += 4;

        be32(rec + rn, 3); rn += 4; /* BASE64 decode */
        be32(rec + rn, 0); rn += 4;

        profile_setup(&p, 64);
        apply((char *)gprog, gn, &p, NULL, 0, (char *)"secret", 6);
        blen = p.blen;
        memcpy(body, p.buffer, (size_t)blen);
        body[blen] = 0;
        profile_free(&p);

        r = recover((char *)rec, rn, body, blen, (int)sizeof(body));
        if (r != 6 || memcmp(body, "secret", 6) != 0)
            return fail("base64 recover");
        printf("OK base64 apply/recover\n");
    }

    /* netbios + mask encode/decode helpers */
    {
        char src[] = "ab";
        char dst[16];
        char dec[16];
        int L = netbios_encode('a', src, 2, dst, 16);
        if (L != 4) return fail("netbios encode len");
        if (netbios_decode('a', dst, L, dec, 16) != 2 || memcmp(dec, src, 2))
            return fail("netbios decode");
        L = xor_encode(src, 2, dst, 16);
        if (L != 6) return fail("xor encode len");
        if (xor_decode(dst, L, dec, 16) != 2 || memcmp(dec, src, 2))
            return fail("xor decode");
        printf("OK netbios+mask\n");
    }

    printf("ALL PROFILE VM TESTS PASSED\n");
    return 0;
}
