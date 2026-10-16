BOOL inject_via_remotethread_wow64(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter);
BOOL inject_via_remotethread(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter);
BOOL inject_via_createuserthread(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter);
BOOL inject_via_createthread(HANDLE hProcess, DWORD pid, LPVOID lpStartAddress, LPVOID lpParameter);
BOOL inject_with_hinted_func(DWORD method, HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter, char * module, char * func, DWORD offset);

BOOL is_x64_process(HANDLE process);

void inject_process_logic(PROCESS_INFORMATION * pi, HANDLE hProcess, DWORD pid, char * buffer, int length, int offset, void * parameter, int plen);

char * local_mirror_data(char * buffer, int length);

#define PI_EXEC_FAIL                  0x0
#define PI_EXEC_CREATETHREAD          0x1
#define PI_EXEC_SETTHREADCONTEXT      0x2
#define PI_EXEC_CREATEREMOTETHREAD    0x3
#define PI_EXEC_RTLCREATEUSERTHREAD   0x4
#define PI_EXEC_NTQUEUEAPCTHREAD      0x5
#define PI_EXEC_CREATETHREAD_F        0x6
#define PI_EXEC_CREATEREMOTETHREAD_F  0x7
#define PI_EXEC_NTQUEUEAPCTHREAD_S    0x8
/* tier-2 item7 (4.11/4.12): */
#define PI_EXEC_OBFSETTHREADCONTEXT  0x9  /* legit start addr + context RIP (x64->x64, running targets) */
#define PI_EXEC_DIRTYVANITY          0xA  /* fork&run via RtlCloneUserProcess (spawn sites) */

#define INJECT_ARCH_X86 0
#define INJECT_ARCH_X64 1

typedef struct {
	HANDLE hProcess;
	HANDLE hThread;
	DWORD  pid;
	BYTE   targetArch;
	BYTE   myArch;
	BOOL   sameArch;
	BOOL   samePid;
	BOOL   isSuspended;
} INJECTCONTEXT;

/* context aware functions */
void SetupSmartInject(INJECTCONTEXT * context, char * buffer, int length);
BOOL inject_via_apcthread(INJECTCONTEXT * context, LPVOID lpStartAddress, LPVOID lpParameter);
BOOL inject_via_apcthread_targeted(INJECTCONTEXT * context, LPVOID lpStartAddress, LPVOID lpParameter);
BOOL inject_via_resumethread(INJECTCONTEXT * context, LPVOID lpStartAddress, LPVOID lpParameter);
char * remote_mirror_data(INJECTCONTEXT * context, char * buffer, int length);
void populate_inject_context(INJECTCONTEXT * context, PROCESS_INFORMATION * pi, HANDLE hProcess, DWORD pid);
/* tier-2 item7 techniques (inject_tier2.cpp) */
BOOL inject_via_obfsetthreadcontext(INJECTCONTEXT * context, LPVOID lpStartAddress, LPVOID lpParameter);
BOOL procinj_execute_has(BYTE opcode);
BOOL inject_dirtyvanity_forkrun(char * dll, int dllen, char * parameter, int plen);
BOOL finalize_memory_permissions(char * ptr, SIZE_T length);