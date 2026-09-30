#include "parse.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

static int g_nonce = 1;

void build_reset_nonce(void) {
    g_nonce = 1;
}

void data_init(datap *temp, char *buffer, int length) {
    temp->original = buffer;
    temp->buffer   = buffer;
    temp->length   = length;
    temp->size     = length;
}

datap *data_alloc(int size) {
    datap *temp = (datap *)malloc(sizeof(datap));
    char *ptr;
    if (!temp) return NULL;
    ptr = (char *)calloc(1, (size_t)size);
    if (!ptr) {
        free(temp);
        return NULL;
    }
    data_init(temp, ptr, size);
    return temp;
}

void data_cleanup(datap *temp) {
    if (temp && temp->original && temp->size > 0)
        memset(temp->original, 0, (size_t)temp->size);
}

void data_free(datap *temp) {
    if (!temp) return;
    data_cleanup(temp);
    free(temp->original);
    free(temp);
}

unsigned int data_int(datap *d) {
    uint32_t temp;
    if (d->length < 4) return 0;
    memcpy(&temp, d->buffer, 4);
    temp = ntohl(temp);
    d->buffer += 4;
    d->length -= 4;
    return temp;
}

unsigned short data_short(datap *d) {
    uint16_t temp;
    if (d->length < 2) return 0;
    memcpy(&temp, d->buffer, 2);
    temp = ntohs(temp);
    d->buffer += 2;
    d->length -= 2;
    return temp;
}

unsigned int data_byte(datap *d) {
    unsigned char c;
    if (d->length < 1) return 0;
    c = (unsigned char)d->buffer[0];
    d->buffer += 1;
    d->length -= 1;
    return c;
}

char *data_ptr(datap *d, int length) {
    char *ptr = d->buffer;
    if (d->length < length) return NULL;
    d->buffer += length;
    d->length -= length;
    return ptr;
}

datap_buffer data_extract(datap *d) {
    datap_buffer b;
    b.length = (int)data_int(d);
    b.buffer = data_ptr(d, b.length);
    return b;
}

int data_string(datap *d, char *buffer, int max) {
    int len = (int)data_int(d);
    char *p;
    if (len <= 0 || len > max) return 0;
    p = data_ptr(d, len);
    if (!p) return 0;
    memcpy(buffer, p, (size_t)len);
    if (len < max) buffer[len] = '\0';
    return len;
}

int data_length(datap *d) { return d->length; }
char *data_buffer(datap *d) { return d->buffer; }

void build_init(builder *b, char *dest, int max) {
    uint32_t temp = htonl((uint32_t)g_nonce);
    uint32_t length = htonl(0);
    b->dest = dest;
    b->max  = max;
    memcpy(dest, &temp, 4);
    memcpy(dest + 4, &length, 4);
    b->len = 8;
    g_nonce++;
}

void build_add_data(builder *b, char *data, int len) {
    uint32_t changeme;
    if ((b->len + len) > b->max) return;
    memcpy(b->dest + b->len, data, (size_t)len);
    b->len += len;
    changeme = htonl((uint32_t)(b->len - 8));
    memcpy(b->dest + 4, &changeme, 4);
}

void build_add_int(builder *b, uint32_t number) {
    number = htonl(number);
    build_add_data(b, (char *)&number, 4);
}

void build_add_short(builder *b, uint16_t number) {
    number = htons(number);
    build_add_data(b, (char *)&number, 2);
}

void build_add_byte(builder *b, uint8_t number) {
    build_add_data(b, (char *)&number, 1);
}

/* Official build_length returns len+4 for encrypt path sizing quirks;
 * encrypt uses the buffer content length = b->len (header + body). */
int build_length(builder *b) {
    return b->len;
}

int build_length_rsa(builder *b) {
    uint32_t magic = htonl(0x0000BEEF);
    memcpy(b->dest, &magic, 4);
    return b->len;
}
