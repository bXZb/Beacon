/*
 * udc2_tcp.c - 4.12 UDC2 test BOF: a TCP channel over the udc2-vs contract.
 *
 * LITERAL-FREE build: the client-side BOF packer (OBJExecutable) only
 * extracts the FIRST section of each name, and MSVC splits string literals
 * across multiple .rdata COMDATs - a literal in a dropped section faults at
 * first reference. Until the packer learns to merge same-named sections,
 * every string here is constructed in code on the stack.
 *
 * go(UDC2_INFO*) connects to the relay and fills udc2Proxy/udc2Close.
 * Each proxy round ships the complete [4B LE len][data] frame and reads the
 * response frame back verbatim (never strip the length - the #1 UDC2
 * failure mode per the template README).
 */
#include <winsock2.h>
#include <windows.h>

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

static void path_udc2_step(char * buf, int max) {
	/* C:\Users\Public\udc2_step.txt built without a string literal */
	char parts[30];
	int i;
	parts[0]='C'; parts[1]=':'; parts[2]='\\'; parts[3]='U'; parts[4]='s';
	parts[5]='e'; parts[6]='r'; parts[7]='s'; parts[8]='\\'; parts[9]='P';
	parts[10]='u'; parts[11]='b'; parts[12]='l'; parts[13]='i'; parts[14]='c';
	parts[15]='\\'; parts[16]='u'; parts[17]='d'; parts[18]='c'; parts[19]='2';
	parts[20]='_'; parts[21]='s'; parts[22]='t'; parts[23]='e'; parts[24]='p';
	parts[25]='.'; parts[26]='t'; parts[27]='x'; parts[28]='t'; parts[29]=0;
	for (i = 0; parts[i] && i < max - 1; i++)
		buf[i] = parts[i];
	buf[i] = 0;
}

static void mark(int v) {
	char path[40];
	HANDLE f;
	char b[16];
	int i = 0;
	char num[12];
	int n = 0;
	int x = v;
	DWORD w;

	path_udc2_step(path, 40);
	f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f == INVALID_HANDLE_VALUE)
		return;
	if (x == 0)
		num[n++] = '0';
	while (x > 0 && n < 11) {
		num[n++] = (char)('0' + (x % 10));
		x /= 10;
	}
	while (n && i < 14)
		b[i++] = num[--n];
	b[i] = 0;
	WriteFile(f, b, i, &w, NULL);
	CloseHandle(f);
}

int udc2Proxy(const char * sendBuf, int sendBufLen, char * recvBuf, int recvBufMaxLen) {
	int sent = 0;
	int n;
	unsigned int len;
	int total;

	if (g_sock == INVALID_SOCKET)
		return -1;

	while (sent < sendBufLen) {
		n = send(g_sock, sendBuf + sent, sendBufLen - sent, 0);
		if (n <= 0)
			return -1;
		sent += n;
	}

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

void go(UDC2INFO * info) {
	struct sockaddr_in sa;

	mark(1);

	if (info == NULL)
		return;

	if (WSAStartup(MAKEWORD(2, 2), &g_wsa) != 0)
		return;

	mark(3);

	g_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (g_sock == INVALID_SOCKET)
		return;

	sa.sin_family = AF_INET;
	sa.sin_port = htons(UDC2_PORT);
	/* loopback without the "127.0.0.1" literal */
	sa.sin_addr.S_un.S_un_b.s_b1 = 127;
	sa.sin_addr.S_un.S_un_b.s_b2 = 0;
	sa.sin_addr.S_un.S_un_b.s_b3 = 0;
	sa.sin_addr.S_un.S_un_b.s_b4 = 1;

	if (connect(g_sock, (struct sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR) {
		mark((int)WSAGetLastError());
		closesocket(g_sock);
		g_sock = INVALID_SOCKET;
		return;
	}

	mark(9);
	info->proxy = udc2Proxy;
	info->close = udc2Close;
	mark(10);
}
