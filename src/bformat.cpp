#include <windows.h>
#include <stdio.h>
#include "bformat.h"
#include <winsock2.h>

/* initialize this formatted text buffer */
void bformat_init(formatp * buffer, int maxsz) {
	char * data = (char *)malloc(maxsz);
	bformat_existing(buffer, data, maxsz);
}

/* create a formatted text buffer on top of an existing buffer */
void bformat_existing(formatp * buffer, char * data, int maxsz) {
	buffer->original = data;
	buffer->self = buffer->original;
	buffer->length = 0;
	buffer->size = maxsz;

	memset(buffer->original, 0, maxsz);
}

/* reset this back to our original parameters to make re-use possible */
void bformat_reset(formatp * buffer) {
	buffer->self = buffer->original;
	buffer->length = 0;
	/* 修复：原实现 memset 的长度是刚清零的 buffer->length（恒 0 字节），
	   旧数据从未被真正清除。按语义清零整个缓冲区。 */
	memset(buffer->original, 0, buffer->size);
}

/* add an integer to our bformat data */
void bformat_int(formatp * buffer, int value) {
	value = htonl(value);
	bformat_copy(buffer, (char *)&value, 4);
}

/* copy some value into our buffer */
void bformat_copy(formatp * buffer, char * src, int length) {
	/* 负长度来自上游 size-4 之类的差值：既穿透上界比较又会以 (size_t)负数
	   传入 memcpy，这里统一拒绝。 */
	if (length <= 0 || length >= (buffer->size - buffer->length))
		return;

	memcpy(buffer->self, src, length);

	buffer->self   += length;
	buffer->length += length;
}

/* format some text into our buffer and append it */
void bformat_printf(formatp * buffer, char * fmt, ...) {
	INT32   est;
	INT32   read;
	va_list va;

	/* how much data do we expect to stuff into this buffer? */
	va_start(va, fmt);
	est = _vscprintf(fmt, va);
	va_end(va);

	/* let's sanity check the data */
	if (est <= 0 || est >= (buffer->size - buffer->length)) {
		return;
	}

	/* populate the data structure */
	va_start(va, fmt);
	read = vsprintf_s(buffer->self, buffer->size - buffer->length, fmt, va);
	va_end(va);

	/* update our values */
	buffer->self   += read;
	buffer->length += read;
}

/* free this buffer and make it forensically clean */
void bformat_free(formatp * buffer) {
	memset(buffer->original, 0, buffer->size);
	free(buffer->original);
}

/* return a pointer to the string managed by this buffer */
char * bformat_string(formatp * buffer) {
	return buffer->original;
}

/* return the length of the string in this buffer */
DWORD bformat_length(formatp * buffer) {
	return buffer->length;
}

char * bformat_tostring(formatp * buffer, int * size) {
	DWORD len = bformat_length(buffer);
	if (size != NULL)
		*size = (int)len;

	/* 修复：原实现此处有 if (size == 0) return NULL; —— 判断的是指针本身而非
	   指针所指的值，恒为假的死分支。BeaconFormatToString（BOF API 表绑定，
	   见 boff.cpp）要求始终返回缓冲区指针。 */
	return bformat_string(buffer);
}
