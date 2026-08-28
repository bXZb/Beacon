#include <stdlib.h>
/*
 * This module is a safe way to format and append arbitrary text.
 */
typedef struct {
	char * original; /* the original buffer [so we can free it] */
	char * self;     /* pointer to myself... to free later */
	int  length;   /* number of bytes in our string */
	int  size;     /* size of this buffer */
} formatp;

void bformat_init(formatp * buffer, int maxsz);
void bformat_existing(formatp * buffer, char * data, int maxsz);
void bformat_printf(formatp * buffer, char * fmt, ...);
void bformat_free(formatp * buffer);
DWORD bformat_length(formatp * buffer);
char * bformat_string(formatp * buffer);
void bformat_reset(formatp * buffer);
char * bformat_tostring(formatp * buffer, int * size);

/* some more data values */
void bformat_copy(formatp * buffer, char * src, int length);
void bformat_int(formatp * buffer, int value);