/* Dynamic-import slot capacity BOF (4.12 Dynamic Import parity test).
 *
 * References 130 distinct dll$Func dynamic imports by address only (no
 * calls - dummy args on 130 different signatures would be its own crash
 * surface). Address-of still emits the external symbol and its ADDR64
 * relocation, so the loader must resolve all 130 through function_slot.
 *
 * Against the pre-4.12-parity loader (fixed other[64]) this BOF dies at
 * import #65 with post_error_na(0x4e) and never runs. With the chunked
 * slot table it loads, writes the marker, and exits clean.
 *
 * Packer shape: /O0 /Zl, static arrays only, no CRT. Marker:
 *   "SLOTSOK130" when all imports resolved and the body executed.
 */
#include <windows.h>

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
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetTickCount64(void);
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
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$WaitForMultipleObjects(DWORD, void * , BOOL, DWORD);
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
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$SetThreadContext(HANDLE, void * );
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$GetThreadTimes(HANDLE, LPFILETIME, LPFILETIME, LPFILETIME, LPFILETIME);
EXTERN_C __declspec(dllimport) int WINAPI kernel32$MultiByteToWideChar(UINT, DWORD, LPCSTR, int, LPWSTR, int);
EXTERN_C __declspec(dllimport) int WINAPI kernel32$WideCharToMultiByte(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);
EXTERN_C __declspec(dllimport) int WINAPI kernel32$lstrlenA(LPCSTR);
EXTERN_C __declspec(dllimport) int WINAPI kernel32$lstrlenW(LPCWSTR);
EXTERN_C __declspec(dllimport) LPSTR WINAPI kernel32$lstrcpynA(LPSTR, LPCSTR, int);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$WriteProcessMemory(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$FlushInstructionCache(HANDLE, LPCVOID, SIZE_T);
EXTERN_C __declspec(dllimport) VOID WINAPI kernel32$ExitProcess(UINT);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$TerminateProcess(HANDLE, UINT);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$GetExitCodeProcess(HANDLE, LPDWORD);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$SetPriorityClass(HANDLE, DWORD);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetPriorityClass(HANDLE);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$SetThreadPriority(HANDLE, int);
EXTERN_C __declspec(dllimport) int WINAPI kernel32$GetThreadPriority(HANDLE);
EXTERN_C __declspec(dllimport) VOID WINAPI kernel32$DebugBreak(void);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$Beep(DWORD, DWORD);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$SetLastErrorEx(DWORD, DWORD);

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

EXTERN_C __declspec(dllimport) BOOL WINAPI advapi32$GetUserNameA(LPSTR, LPDWORD);
EXTERN_C __declspec(dllimport) BOOL WINAPI advapi32$GetUserNameW(LPWSTR, LPDWORD);
EXTERN_C __declspec(dllimport) BOOL WINAPI advapi32$GetComputerNameA(LPSTR, LPDWORD);
EXTERN_C __declspec(dllimport) BOOL WINAPI advapi32$GetComputerNameW(LPWSTR, LPDWORD);
EXTERN_C __declspec(dllimport) BOOL WINAPI advapi32$CloseServiceHandle(void *);
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$QueryPerformanceCounter(LARGE_INTEGER *);
EXTERN_C __declspec(dllimport) void * WINAPI advapi32$OpenSCManagerA(LPCSTR, LPCSTR, DWORD);

EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, void *);
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
EXTERN_C __declspec(dllimport) BOOL WINAPI kernel32$WriteConsoleA(HANDLE, const void *, DWORD, LPDWORD, void *);
EXTERN_C __declspec(dllimport) DWORD WINAPI kernel32$GetCurrentDirectoryA(DWORD, LPSTR);

/* address-of forces every external symbol into the object; volatile keeps
 * the optimizer from ever collapsing the array (compiled /O0 anyway) */
static volatile void * g_fns[130];

static char g_path[]  = "C:\\Users\\Public\\bw_slots_probe.txt";
static char g_magic[] = "SLOTSOK130";

void go(char * args, int len)
{
	void * f;
	DWORD w;

	(void)args;
	(void)len;

	g_fns[0] = (void *)kernel32$GetTickCount;
	g_fns[1] = (void *)kernel32$Sleep;
	g_fns[2] = (void *)kernel32$GetCurrentProcess;
	g_fns[3] = (void *)kernel32$GetCurrentThreadId;
	g_fns[4] = (void *)kernel32$GetCurrentProcessId;
	g_fns[5] = (void *)kernel32$GetCommandLineA;
	g_fns[6] = (void *)kernel32$GetCommandLineW;
	g_fns[7] = (void *)kernel32$GetVersion;
	g_fns[8] = (void *)kernel32$IsDebuggerPresent;
	g_fns[9] = (void *)kernel32$GetSystemTime;
	g_fns[10] = (void *)kernel32$GetLocalTime;
	g_fns[11] = (void *)kernel32$GetTickCount64;
	g_fns[12] = (void *)kernel32$GetLastError;
	g_fns[13] = (void *)kernel32$SetLastError;
	g_fns[14] = (void *)kernel32$GetEnvironmentStringsW;
	g_fns[15] = (void *)kernel32$FreeEnvironmentStringsW;
	g_fns[16] = (void *)kernel32$GetModuleFileNameA;
	g_fns[17] = (void *)kernel32$GetModuleFileNameW;
	g_fns[18] = (void *)kernel32$GetModuleHandleExA;
	g_fns[19] = (void *)kernel32$GetProcessTimes;
	g_fns[20] = (void *)kernel32$GetSystemTimes;
	g_fns[21] = (void *)kernel32$GetDiskFreeSpaceExA;
	g_fns[22] = (void *)kernel32$GetDiskFreeSpaceExW;
	g_fns[23] = (void *)kernel32$GetLogicalDrives;
	g_fns[24] = (void *)kernel32$GetDriveTypeA;
	g_fns[25] = (void *)kernel32$GetDriveTypeW;
	g_fns[26] = (void *)kernel32$GetFileAttributesA;
	g_fns[27] = (void *)kernel32$GetFileAttributesW;
	g_fns[28] = (void *)kernel32$GetTempPathA;
	g_fns[29] = (void *)kernel32$GetTempPathW;
	g_fns[30] = (void *)kernel32$ExpandEnvironmentStringsA;
	g_fns[31] = (void *)kernel32$ExpandEnvironmentStringsW;
	g_fns[32] = (void *)kernel32$CreateEventA;
	g_fns[33] = (void *)kernel32$SetEvent;
	g_fns[34] = (void *)kernel32$ResetEvent;
	g_fns[35] = (void *)kernel32$PulseEvent;
	g_fns[36] = (void *)kernel32$CreateMutexA;
	g_fns[37] = (void *)kernel32$ReleaseMutex;
	g_fns[38] = (void *)kernel32$WaitForSingleObject;
	g_fns[39] = (void *)kernel32$WaitForMultipleObjects;
	g_fns[40] = (void *)kernel32$InitializeCriticalSection;
	g_fns[41] = (void *)kernel32$EnterCriticalSection;
	g_fns[42] = (void *)kernel32$LeaveCriticalSection;
	g_fns[43] = (void *)kernel32$DeleteCriticalSection;
	g_fns[44] = (void *)kernel32$TryEnterCriticalSection;
	g_fns[45] = (void *)kernel32$SleepEx;
	g_fns[46] = (void *)kernel32$QueueUserAPC;
	g_fns[47] = (void *)kernel32$SwitchToThread;
	g_fns[48] = (void *)kernel32$TlsAlloc;
	g_fns[49] = (void *)kernel32$TlsFree;
	g_fns[50] = (void *)kernel32$HeapLock;
	g_fns[51] = (void *)kernel32$HeapUnlock;
	g_fns[52] = (void *)kernel32$HeapSize;
	g_fns[53] = (void *)kernel32$HeapValidate;
	g_fns[54] = (void *)kernel32$HeapSetInformation;
	g_fns[55] = (void *)kernel32$GlobalMemoryStatusEx;
	g_fns[56] = (void *)kernel32$GetSystemInfo;
	g_fns[57] = (void *)kernel32$IsWow64Process;
	g_fns[58] = (void *)kernel32$GetThreadId;
	g_fns[59] = (void *)kernel32$GetProcessId;
	g_fns[60] = (void *)kernel32$GetProcessIdOfThread;
	g_fns[61] = (void *)kernel32$GetThreadContext;
	g_fns[62] = (void *)kernel32$SetThreadContext;
	g_fns[63] = (void *)kernel32$GetThreadTimes;
	g_fns[64] = (void *)kernel32$MultiByteToWideChar;
	g_fns[65] = (void *)kernel32$WideCharToMultiByte;
	g_fns[66] = (void *)kernel32$lstrlenA;
	g_fns[67] = (void *)kernel32$lstrlenW;
	g_fns[68] = (void *)kernel32$lstrcpynA;
	g_fns[69] = (void *)kernel32$ReadProcessMemory;
	g_fns[70] = (void *)kernel32$WriteProcessMemory;
	g_fns[71] = (void *)kernel32$FlushInstructionCache;
	g_fns[72] = (void *)kernel32$ExitProcess;
	g_fns[73] = (void *)kernel32$TerminateProcess;
	g_fns[74] = (void *)kernel32$GetExitCodeProcess;
	g_fns[75] = (void *)kernel32$SetPriorityClass;
	g_fns[76] = (void *)kernel32$GetPriorityClass;
	g_fns[77] = (void *)kernel32$SetThreadPriority;
	g_fns[78] = (void *)kernel32$GetThreadPriority;
	g_fns[79] = (void *)kernel32$DebugBreak;
	g_fns[80] = (void *)kernel32$Beep;
	g_fns[81] = (void *)kernel32$SetLastErrorEx;
	g_fns[82] = (void *)user32$MessageBoxA;
	g_fns[83] = (void *)user32$GetCursorPos;
	g_fns[84] = (void *)user32$SetCursorPos;
	g_fns[85] = (void *)user32$GetSystemMetrics;
	g_fns[86] = (void *)user32$GetForegroundWindow;
	g_fns[87] = (void *)user32$SetForegroundWindow;
	g_fns[88] = (void *)user32$IsWindow;
	g_fns[89] = (void *)user32$IsWindowVisible;
	g_fns[90] = (void *)user32$GetWindowTextA;
	g_fns[91] = (void *)user32$GetWindowTextLengthA;
	g_fns[92] = (void *)user32$GetWindowRect;
	g_fns[93] = (void *)user32$GetClientRect;
	g_fns[94] = (void *)user32$ScreenToClient;
	g_fns[95] = (void *)user32$ClientToScreen;
	g_fns[96] = (void *)user32$GetSysColor;
	g_fns[97] = (void *)user32$GetSysColorBrush;
	g_fns[98] = (void *)user32$MessageBeep;
	g_fns[99] = (void *)user32$SwapMouseButton;
	g_fns[100] = (void *)user32$GetKeyboardState;
	g_fns[101] = (void *)user32$GetAsyncKeyState;
	g_fns[102] = (void *)user32$GetKeyState;
	g_fns[103] = (void *)user32$GetKeyboardType;
	g_fns[104] = (void *)user32$BlockInput;
	g_fns[105] = (void *)user32$GetDoubleClickTime;
	g_fns[106] = (void *)user32$SetDoubleClickTime;
	g_fns[107] = (void *)user32$DefWindowProcA;
	g_fns[108] = (void *)advapi32$GetUserNameA;
	g_fns[109] = (void *)advapi32$GetUserNameW;
	g_fns[110] = (void *)advapi32$GetComputerNameA;
	g_fns[111] = (void *)advapi32$GetComputerNameW;
	g_fns[112] = (void *)advapi32$CloseServiceHandle;
	g_fns[113] = (void *)kernel32$QueryPerformanceCounter;
	g_fns[114] = (void *)advapi32$OpenSCManagerA;
	g_fns[115] = (void *)kernel32$ReadFile;
	g_fns[116] = (void *)kernel32$CreateDirectoryA;
	g_fns[117] = (void *)kernel32$DeleteFileA;
	g_fns[118] = (void *)kernel32$MoveFileA;
	g_fns[119] = (void *)kernel32$CopyFileA;
	g_fns[120] = (void *)kernel32$GetFileSize;
	g_fns[121] = (void *)kernel32$GetFileType;
	g_fns[122] = (void *)kernel32$GetStdHandle;
	g_fns[123] = (void *)kernel32$SetStdHandle;
	g_fns[124] = (void *)kernel32$FlushFileBuffers;
	g_fns[125] = (void *)kernel32$SetFilePointer;
	g_fns[126] = (void *)kernel32$GetFileTime;
	g_fns[127] = (void *)kernel32$SetFileTime;
	g_fns[128] = (void *)kernel32$WriteConsoleA;
	g_fns[129] = (void *)kernel32$GetCurrentDirectoryA;



	/* the marker write itself uses dynamic imports, exactly like the
	 * admission-matrix BOFs (CreateFileA/WriteFile/CloseHandle) */
	f = (void *)0;
	w = 0;

	f = kernel32$CreateFileA(g_path, (DWORD)0x40000000, (DWORD)0, (void *)0,
	                         (DWORD)2, (DWORD)0x80, (void *)0);
	if (f != (void *)-1) {
		kernel32$WriteFile(f, g_magic, (DWORD)sizeof(g_magic) - 1, &w, (void *)0);
		kernel32$CloseHandle(f);
	}
}
