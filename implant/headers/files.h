#ifndef LINUX_BEACON_FILES_H
#define LINUX_BEACON_FILES_H

#include <stddef.h>
#include <stdint.h>

/* Async download queue (official files.cpp model) */
void files_download_start(const char *path);
void files_download_stop(const uint8_t *data, size_t len);
/* Call each beacon loop while callbacks enabled; max bytes this poll */
void files_download_poll(int max_chunk);

#endif
