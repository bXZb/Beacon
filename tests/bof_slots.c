/* Dynamic-import slot capacity BOF (4.12 Dynamic Import parity test).
 *
 * References 130 distinct dll$Func dynamic imports. The client-side COFF
 * parser only recognizes dynamic imports that are CALL references (the
 * address-of form used in the first revision surfaced as "Unknown
 * symbol"), so every import appears as a call guarded by a runtime-false
 * gate: the call sites exist for the linker (REL32 relocs through the
 * symbol table) but never execute. Only the three marker-file functions
 * actually run.
 *
 * Against the pre-4.12-parity loader (fixed other[64]) this BOF dies at
 * import #65 with post_error_na(0x4e) and never runs. With the chunked
 * slot table it loads, writes the marker, and exits clean.
 *
 * Packer shape: /O0 /Zl, static data only, no CRT.
 * Marker: "SLOTSOK128" (128 unique imports).
 */
#include <windows.h>

/* marker writer (actually runs) */
EXTERN_C __declspec(dllimport) HANDLE WINAPI kernel32$CreateFileA(LPCSTR, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, void *);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$CloseHandle(HANDLE);

/* the 127 gated imports - one call each, never taken */
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetTickCount(void);
EXTERN_C __declspec(dllimport) void WINAPI kernel32$Sleep(DWORD);
EXTERN_C __declspec(dllimport) HANDLE WINAPI kernel32$GetCurrentProcess(void);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetCurrentThreadId(void);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetCurrentProcessId(void);
EXTERN_C __declspec(dllimport) LPSTR WINAPI kernel32$GetCommandLineA(void);
EXTERN_C __declspec(dllimport) LPWSTR WINAPI kernel32$GetCommandLineW(void);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetVersion(void);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$IsDebuggerPresent(void);
EXTERN_C __declspec(dllimport) VOID WINAPI kernel32$GetSystemTime(LPSYSTEMTIME);
EXTERN_C __declspec(dllimport) VOID WINAPI kernel32$GetLocalTime(LPSYSTEMTIME);
EXTERN_C __declspec(dllimport) ULONGLONG WINAPI kernel32$GetTickCount64(void);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetLastError(void);
EXTERN_C __declspec(dllimport) VOID WINAPI kernel32$SetLastError(DWORD);
EXTERN_C __declspec(dllimport) LPWSTR WINAPI kernel32$GetEnvironmentStringsW(void);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$FreeEnvironmentStringsW(LPWSTR);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetModuleFileNameA(HMODULE, LPSTR, DWORD);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetModuleFileNameW(HMODULE, LPWSTR, DWORD);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$GetModuleHandleExA(DWORD, LPCSTR, HMODULE *);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$GetProcessTimes(HANDLE, LPFILETIME, LPFILETIME, LPFILETIME, LPFILETIME);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$GetSystemTimes(LPFILETIME, LPFILETIME, LPFILETIME);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$GetDiskFreeSpaceExA(LPCSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$GetDiskFreeSpaceExW(LPCWSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetLogicalDrives(void);
EXTERN_C __declspec(dllimport) UINT WINAPI kernel32$GetDriveTypeA(LPCSTR);
EXTERN_C __declspec(dllimport) UINT WINAPI kernel32$GetDriveTypeW(LPCWSTR);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetFileAttributesA(LPCSTR);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetFileAttributesW(LPCWSTR);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetTempPathA(DWORD, LPSTR);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetTempPathW(DWORD, LPWSTR);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$ExpandEnvironmentStringsA(LPCSTR, LPSTR, DWORD);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$ExpandEnvironmentStringsW(LPCWSTR, LPWSTR, DWORD);
EXTERN_C __declspec(dllimport) HANDLE WINAPI kernel32$CreateEventA(void *, BOOL, BOOL, LPCSTR);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$SetEvent(HANDLE);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$ResetEvent(HANDLE);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$PulseEvent(HANDLE);
EXTERN_C __declspec(dllimport) HANDLE WINAPI kernel32$CreateMutexA(void *, BOOL, LPCSTR);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$ReleaseMutex(HANDLE);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$WaitForSingleObject(HANDLE, DWORD);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$WaitForMultipleObjects(DWORD, void *, BOOL, DWORD);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$InitializeCriticalSection(void *);
EXTERN_C __declspec(dllimport) VOID WINAPI kernel32$EnterCriticalSection(void *);
EXTERN_C __declspec(dllimport) VOID WINAPI kernel32$LeaveCriticalSection(void *);
EXTERN_C __declspec(dllimport) VOID WINAPI kernel32$DeleteCriticalSection(void *);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$TryEnterCriticalSection(void *);
EXTERN_C __declspec(dllimport) VOID WINAPI kernel32$SleepEx(DWORD, BOOL);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$QueueUserAPC(void *, HANDLE, ULONG_PTR);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$SwitchToThread(void);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$TlsAlloc(void);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$TlsFree(DWORD);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$HeapLock(HANDLE);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$HeapUnlock(HANDLE);
EXTERN_C __declspec(dllimport) SIZE_T WINAPI kernel32$HeapSize(HANDLE, DWORD, LPCVOID);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$HeapValidate(HANDLE, DWORD, LPCVOID);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$HeapSetInformation(HANDLE, HEAP_INFORMATION_CLASS, PVOID, SIZE_T);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$GlobalMemoryStatusEx(LPMEMORYSTATUSEX);
EXTERN_C __declspec(dllimport) VOID WINAPI kernel32$GetSystemInfo(LPSYSTEM_INFO);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$IsWow64Process(HANDLE, PBOOL);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetThreadId(HANDLE);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetProcessId(HANDLE);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$GetProcessIdOfThread(HANDLE, LPDWORD);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$GetThreadContext(HANDLE, void *);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$SetThreadContext(HANDLE, void *);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$GetThreadTimes(HANDLE, LPFILETIME, LPFILETIME, LPFILETIME, LPFILETIME);
EXTERN_C __declspec(dllimport) int WINAPI kernel32$MultiByteToWideChar(UINT, DWORD, LPCSTR, int, LPWSTR, int);
EXTERN_C __declspec(dllimport) int WINAPI kernel32$WideCharToMultiByte(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);
EXTERN_C __declspec(dllimport) int WINAPI kernel32$lstrlenA(LPCSTR);
EXTERN_C __declspec(dllimport) int WINAPI kernel32$lstrlenW(LPCWSTR);
EXTERN_C __declspec(dllimport) LPSTR WINAPI kernel32$lstrcpynA(LPSTR, LPCSTR, int);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$WriteProcessMemory(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$FlushInstructionCache(HANDLE, LPCVOID, SIZE_T);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$GetExitCodeProcess(HANDLE, LPDWORD);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$SetPriorityClass(HANDLE, DWORD);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetPriorityClass(HANDLE);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$SetThreadPriority(HANDLE, int);
EXTERN_C __declspec(dllimport) int WINAPI kernel32$GetThreadPriority(HANDLE);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$Beep(DWORD, DWORD);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$QueryPerformanceCounter(LARGE_INTEGER *);
EXTERN_C __declspec(dllimport) void * WINAPI advapi32$OpenSCManagerA(LPCSTR, LPCSTR, DWORD);
EXTERN_C __declspec(dllimport) BOOL WINAPI advapi32$GetUserNameA(LPSTR, LPDWORD);
EXTERN_C __declspec(dllimport) BOOL WINAPI advapi32$GetUserNameW(LPWSTR, LPDWORD);
EXTERN_C __declspec(dllimport) BOOL WINAPI advapi32$GetComputerNameA(LPSTR, LPDWORD);
EXTERN_C __declspec(dllimport) BOOL WINAPI advapi32$GetComputerNameW(LPWSTR, LPDWORD);
EXTERN_C __declspec(dllimport) BOOL WINAPI advapi32$CloseServiceHandle(void *);
EXTERN_C __declspec(dllimport) int WINAPI user32$MessageBoxA(void *, LPCSTR, LPCSTR, UINT);
EXTERN_C __declspec(dllimport) BOOL WINAPI user32$GetCursorPos(LPPOINT);
EXTERN_C __declspec(dllimport) BOOL WINAPI user32$SetCursorPos(int, int);
EXTERN_C __declspec(dllimport) int WINAPI user32$GetSystemMetrics(int);
EXTERN_C __declspec(dllimport) HANDLE WINAPI user32$GetForegroundWindow(void);
EXTERN_C __declspec(dllimport) BOOL WINAPI user32$SetForegroundWindow(HANDLE);
EXTERN_C __declspec(dllimport) BOOL WINAPI user32$IsWindow(HANDLE);
EXTERN_C __declspec(dllimport) BOOL WINAPI user32$IsWindowVisible(HANDLE);
EXTERN_C __declspec(dllimport) int WINAPI user32$GetWindowTextA(HANDLE, LPSTR, int);
EXTERN_C __declspec(dllimport) int WINAPI user32$GetWindowTextLengthA(HANDLE);
EXTERN_C __declspec(dllimport) BOOL WINAPI user32$GetWindowRect(HANDLE, void *);
EXTERN_C __declspec(dllimport) BOOL WINAPI user32$GetClientRect(HANDLE, void *);
EXTERN_C __declspec(dllimport) BOOL WINAPI user32$ScreenToClient(HANDLE, LPPOINT);
EXTERN_C __declspec(dllimport) BOOL WINAPI user32$ClientToScreen(HANDLE, LPPOINT);
EXTERN_C __declspec(dllimport) DWORD WINAPI user32$GetSysColor(int);
EXTERN_C __declspec(dllimport) HBRUSH WINAPI user32$GetSysColorBrush(int);
EXTERN_C __declspec(dllimport) BOOL WINAPI user32$MessageBeep(UINT);
EXTERN_C __declspec(dllimport) BOOL WINAPI user32$SwapMouseButton(BOOL);
EXTERN_C __declspec(dllimport) BOOL WINAPI user32$GetKeyboardState(BYTE *);
EXTERN_C __declspec(dllimport) SHORT WINAPI user32$GetAsyncKeyState(int);
EXTERN_C __declspec(dllimport) SHORT WINAPI user32$GetKeyState(int);
EXTERN_C __declspec(dllimport) int WINAPI user32$GetKeyboardType(int);
EXTERN_C __declspec(dllimport) BOOL WINAPI user32$BlockInput(BOOL);
EXTERN_C __declspec(dllimport) int WINAPI user32$GetDoubleClickTime(void);
EXTERN_C __declspec(dllimport) BOOL WINAPI user32$SetDoubleClickTime(UINT);
EXTERN_C __declspec(dllimport) LRESULT WINAPI user32$DefWindowProcA(void *, UINT, WPARAM, LPARAM);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, void *);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$CreateDirectoryA(LPCSTR, void *);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$DeleteFileA(LPCSTR);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$MoveFileA(LPCSTR, LPCSTR);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$CopyFileA(LPCSTR, LPCSTR, BOOL);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetFileSize(HANDLE, LPDWORD);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetFileType(HANDLE);
EXTERN_C __declspec(dllimport) HANDLE WINAPI kernel32$GetStdHandle(DWORD);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$SetStdHandle(DWORD, HANDLE);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$FlushFileBuffers(HANDLE);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$SetFilePointer(HANDLE, LONG, PLONG, DWORD);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$GetFileTime(HANDLE, LPFILETIME, LPFILETIME, LPFILETIME);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$SetFileTime(HANDLE, const FILETIME *, const FILETIME *, const FILETIME *);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetCurrentDirectoryA(DWORD, LPSTR);

static volatile unsigned int g_gate = 0;
static char g_path[]  = "C:\\Users\\Public\\bw_slots_probe.txt";
static char g_magic[] = "SLOTSOK128";

#define G (g_gate == 0x7E57A1B2u)

void go(char * args, int len)
{
	void * f;
	DWORD w = 0;

	(void)args;
	(void)len;

	/* gated calls: link-time references only, never taken at runtime */
	if (G) kernel32$GetTickCount();
	if (G) kernel32$Sleep(0);
	if (G) kernel32$GetCurrentProcess();
	if (G) kernel32$GetCurrentThreadId();
	if (G) kernel32$GetCurrentProcessId();
	if (G) kernel32$GetCommandLineA();
	if (G) kernel32$GetCommandLineW();
	if (G) kernel32$GetVersion();
	if (G) kernel32$IsDebuggerPresent();
	if (G) kernel32$GetSystemTime(0);
	if (G) kernel32$GetLocalTime(0);
	if (G) kernel32$GetTickCount64();
	if (G) kernel32$GetLastError();
	if (G) kernel32$SetLastError(0);
	if (G) kernel32$GetEnvironmentStringsW();
	if (G) kernel32$FreeEnvironmentStringsW(0);
	if (G) kernel32$GetModuleFileNameA(0, 0, 0);
	if (G) kernel32$GetModuleFileNameW(0, 0, 0);
	if (G) kernel32$GetModuleHandleExA(0, 0, 0);
	if (G) kernel32$GetProcessTimes(0, 0, 0, 0, 0);
	if (G) kernel32$GetSystemTimes(0, 0, 0);
	if (G) kernel32$GetDiskFreeSpaceExA(0, 0, 0, 0);
	if (G) kernel32$GetDiskFreeSpaceExW(0, 0, 0, 0);
	if (G) kernel32$GetLogicalDrives();
	if (G) kernel32$GetDriveTypeA(0);
	if (G) kernel32$GetDriveTypeW(0);
	if (G) kernel32$GetFileAttributesA(0);
	if (G) kernel32$GetFileAttributesW(0);
	if (G) kernel32$GetTempPathA(0, 0);
	if (G) kernel32$GetTempPathW(0, 0);
	if (G) kernel32$ExpandEnvironmentStringsA(0, 0, 0);
	if (G) kernel32$ExpandEnvironmentStringsW(0, 0, 0);
	if (G) kernel32$CreateEventA(0, 0, 0, 0);
	if (G) kernel32$SetEvent(0);
	if (G) kernel32$ResetEvent(0);
	if (G) kernel32$PulseEvent(0);
	if (G) kernel32$CreateMutexA(0, 0, 0);
	if (G) kernel32$ReleaseMutex(0);
	if (G) kernel32$WaitForSingleObject(0, 0);
	if (G) kernel32$WaitForMultipleObjects(0, 0, 0, 0);
	if (G) kernel32$InitializeCriticalSection(0);
	if (G) kernel32$EnterCriticalSection(0);
	if (G) kernel32$LeaveCriticalSection(0);
	if (G) kernel32$DeleteCriticalSection(0);
	if (G) kernel32$TryEnterCriticalSection(0);
	if (G) kernel32$SleepEx(0, 0);
	if (G) kernel32$QueueUserAPC(0, 0, 0);
	if (G) kernel32$SwitchToThread();
	if (G) kernel32$TlsAlloc();
	if (G) kernel32$TlsFree(0);
	if (G) kernel32$HeapLock(0);
	if (G) kernel32$HeapUnlock(0);
	if (G) kernel32$HeapSize(0, 0, 0);
	if (G) kernel32$HeapValidate(0, 0, 0);
	if (G) kernel32$HeapSetInformation(0, 0, 0, 0);
	if (G) kernel32$GlobalMemoryStatusEx(0);
	if (G) kernel32$GetSystemInfo(0);
	if (G) kernel32$IsWow64Process(0, 0);
	if (G) kernel32$GetThreadId(0);
	if (G) kernel32$GetProcessId(0);
	if (G) kernel32$GetProcessIdOfThread(0, 0);
	if (G) kernel32$GetThreadContext(0, 0);
	if (G) kernel32$SetThreadContext(0, 0);
	if (G) kernel32$GetThreadTimes(0, 0, 0, 0, 0);
	if (G) kernel32$MultiByteToWideChar(0, 0, 0, 0, 0, 0);
	if (G) kernel32$WideCharToMultiByte(0, 0, 0, 0, 0, 0, 0, 0);
	if (G) kernel32$lstrlenA(0);
	if (G) kernel32$lstrlenW(0);
	if (G) kernel32$lstrcpynA(0, 0, 0);
	if (G) kernel32$ReadProcessMemory(0, 0, 0, 0, 0);
	if (G) kernel32$WriteProcessMemory(0, 0, 0, 0, 0);
	if (G) kernel32$FlushInstructionCache(0, 0, 0);
	if (G) kernel32$GetExitCodeProcess(0, 0);
	if (G) kernel32$SetPriorityClass(0, 0);
	if (G) kernel32$GetPriorityClass(0);
	if (G) kernel32$SetThreadPriority(0, 0);
	if (G) kernel32$GetThreadPriority(0);
	if (G) kernel32$Beep(0, 0);
	if (G) kernel32$QueryPerformanceCounter(0);
	if (G) advapi32$OpenSCManagerA(0, 0, 0);
	if (G) advapi32$GetUserNameA(0, 0);
	if (G) advapi32$GetUserNameW(0, 0);
	if (G) advapi32$GetComputerNameA(0, 0);
	if (G) advapi32$GetComputerNameW(0, 0);
	if (G) advapi32$CloseServiceHandle(0);
	if (G) user32$MessageBoxA(0, 0, 0, 0);
	if (G) user32$GetCursorPos(0);
	if (G) user32$SetCursorPos(0, 0);
	if (G) user32$GetSystemMetrics(0);
	if (G) user32$GetForegroundWindow();
	if (G) user32$SetForegroundWindow(0);
	if (G) user32$IsWindow(0);
	if (G) user32$IsWindowVisible(0);
	if (G) user32$GetWindowTextA(0, 0, 0);
	if (G) user32$GetWindowTextLengthA(0);
	if (G) user32$GetWindowRect(0, 0);
	if (G) user32$GetClientRect(0, 0);
	if (G) user32$ScreenToClient(0, 0);
	if (G) user32$ClientToScreen(0, 0);
	if (G) user32$GetSysColor(0);
	if (G) user32$GetSysColorBrush(0);
	if (G) user32$MessageBeep(0);
	if (G) user32$SwapMouseButton(0);
	if (G) user32$GetKeyboardState(0);
	if (G) user32$GetAsyncKeyState(0);
	if (G) user32$GetKeyState(0);
	if (G) user32$GetKeyboardType(0);
	if (G) user32$BlockInput(0);
	if (G) user32$GetDoubleClickTime();
	if (G) user32$SetDoubleClickTime(0);
	if (G) user32$DefWindowProcA(0, 0, 0, 0);
	if (G) kernel32$ReadFile(0, 0, 0, 0, 0);
	if (G) kernel32$CreateDirectoryA(0, 0);
	if (G) kernel32$DeleteFileA(0);
	if (G) kernel32$MoveFileA(0, 0);
	if (G) kernel32$CopyFileA(0, 0, 0);
	if (G) kernel32$GetFileSize(0, 0);
	if (G) kernel32$GetFileType(0);
	if (G) kernel32$GetStdHandle(0);
	if (G) kernel32$SetStdHandle(0, 0);
	if (G) kernel32$FlushFileBuffers(0);
	if (G) kernel32$SetFilePointer(0, 0, 0, 0);
	if (G) kernel32$GetFileTime(0, 0, 0, 0);
	if (G) kernel32$SetFileTime(0, 0, 0, 0);
	if (G) kernel32$GetCurrentDirectoryA(0, 0);

	f = kernel32$CreateFileA(g_path, (DWORD)0x40000000, (DWORD)0, (void *)0,
	                         (DWORD)2, (DWORD)0x80, (void *)0);
	if (f != (void *)-1) {
		kernel32$WriteFile(f, g_magic, (DWORD)sizeof(g_magic) - 1, &w, (void *)0);
		kernel32$CloseHandle(f);
	}
}
