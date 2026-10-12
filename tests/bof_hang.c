/* P3 watchdog live-path BOF: admitted to the masked window, then blocks
 * past the 120s default watchdog. Timeline (marker file then Sleep):
 *   t0 "t0"     -> 60s  -> "t60"   (masked period; external scan expects
 *                                  ciphertext against the disk plaintext)
 *                -> 55s  -> "t115"  (still masked; second ciphertext scan)
 *                -> 10s  -> "t125-done" (watchdog fired at 120s: image is
 *                                  PLAINTEXT again while this BOF still
 *                                  runs) -> return.
 * Real-path coverage: watchdog_stub claims the restore, bw_watchdog_rest
 * unmasks the remaining blocks from plain C; when this BOF finally
 * returns, exit_stub takes the loser path (state==CLOSED) and the window
 * teardown skips the decrypt (rest_done) - the session must survive and
 * still print "bofwin window served". */
#include <windows.h>

EXTERN_C __declspec(dllimport) void WINAPI kernel32$Sleep(DWORD);
EXTERN_C __declspec(dllimport) HANDLE WINAPI kernel32$CreateFileA(LPCSTR, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, void *);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$CloseHandle(HANDLE);

static char g_path[] = "C:\\Users\\Public\\bw_hang_probe.txt";
static char g_t0[] = "t0\n";
static char g_t60[] = "t60\n";
static char g_t115[] = "t115\n";
static char g_t125[] = "t125-done\n";

void go(char * args, int len)
{
	DWORD wr = 0;
	HANDLE h;

	(void)args;
	(void)len;
	h = kernel32$CreateFileA(g_path, GENERIC_WRITE, 0, NULL,
	                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return;
	kernel32$WriteFile(h, g_t0, 3, &wr, NULL);
	kernel32$Sleep(60000);
	kernel32$WriteFile(h, g_t60, 4, &wr, NULL);
	kernel32$Sleep(55000);
	kernel32$WriteFile(h, g_t115, 5, &wr, NULL);
	kernel32$Sleep(10000);
	kernel32$WriteFile(h, g_t125, 10, &wr, NULL);
	kernel32$CloseHandle(h);
}
