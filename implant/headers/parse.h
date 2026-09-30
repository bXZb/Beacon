#ifndef LINUX_BEACON_PARSE_H
#define LINUX_BEACON_PARSE_H

#include <stdint.h>

typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} datap;

typedef struct {
    char *buffer;
    int   length;
} datap_buffer;

typedef struct {
    char *dest;
    int   len;
    int   max;
} builder;

void data_init(datap *temp, char *buffer, int length);
unsigned int data_int(datap *d);
unsigned short data_short(datap *d);
unsigned int data_byte(datap *d);
char *data_ptr(datap *d, int length);
datap_buffer data_extract(datap *d);
int data_string(datap *d, char *buffer, int max);
datap *data_alloc(int size);
void data_free(datap *temp);
void data_cleanup(datap *temp);
int data_length(datap *d);
char *data_buffer(datap *d);

void build_init(builder *b, char *dest, int max);
void build_add_data(builder *b, char *data, int len);
void build_add_int(builder *b, uint32_t data);
void build_add_short(builder *b, uint16_t data);
void build_add_byte(builder *b, uint8_t number);
int  build_length(builder *b);
int  build_length_rsa(builder *b);
void build_reset_nonce(void);

#endif
