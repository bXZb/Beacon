typedef struct {
	HANDLE  harg;
	DWORD64 parg;
	UINT    oerr;
	BOOL(*pre)(void *thisp, int ppid, void * pattr, void * siptr);
	void(*post)(void *thisp);
} EX_ATTR_MOD;

EX_ATTR_MOD process_ppid();
EX_ATTR_MOD process_blockdlls();

typedef struct {
	char *					cbuffer;
	int						clen;
	STARTUPINFO *			si;
	PROCESS_INFORMATION *	pi;
	DWORD					flags;
	BOOL					ignoreToken;
} PROCESS_CONTEXT;

#define MAX_RUNAS_CMD 16384

BOOL execute_program(PROCESS_CONTEXT * ctx);
BOOL runas(char * domain, char * user, char * pass, char * cmdline, DWORD flags, PROCESS_INFORMATION * pi);

void spoof_ppid_teb_pre(DWORD *oldpid);
void spoof_ppid_teb_post(DWORD oldpid);
