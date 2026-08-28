#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include "commands.h"

#define MAXPATH 32768

void walk_parent(char * parent, WIN32_FIND_DATA * ffd, RCALLBACK callback);

void walk_parent_child(char * parent, char * folder, WIN32_FIND_DATA * ffd, RCALLBACK callback) {
	char * folderz = (char *)malloc(sizeof(char) * MAXPATH);
	_snprintf(folderz, MAXPATH, "%s\\%s", parent, folder);
	walk_parent(folderz, ffd, callback);
	free(folderz);
}

void walk_parent(char * parent, WIN32_FIND_DATA * ffd, RCALLBACK callback) {
	HANDLE hFind;
	char * folder = (char *)malloc(sizeof(char) * MAXPATH);
	_snprintf(folder, MAXPATH, "%s\\*", parent);
	hFind = FindFirstFile(folder, ffd);
	free(folder);

	if (INVALID_HANDLE_VALUE == hFind)
		return;

	do {
		if (ffd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (strcmp(ffd->cFileName, ".") != 0 && strcmp(ffd->cFileName, "..") != 0) {
				folder = (char *)malloc(sizeof(char) * MAXPATH);
				_snprintf(folder, MAXPATH, "%s", ffd->cFileName);
				walk_parent_child(parent, ffd->cFileName, ffd, callback);
				callback(parent, folder, TRUE);
				free(folder);
			}
		}
		else {
			callback(parent, ffd->cFileName, FALSE);
		}
	} while (FindNextFile(hFind, ffd) != 0);

	FindClose(hFind);
}

void recurse(char * start, RCALLBACK callback) {
	WIN32_FIND_DATA ffd;
	walk_parent(start, &ffd, callback);
}