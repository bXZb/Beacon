#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <wininet.h>
#include "build.h"
#include <WinSock2.h>

/* nonce/counter associated with this beacon session */
int nonce = 1;

/* initialize our memory builder object */
void build_init(builder * b, char * buffer, int max) {
	unsigned int temp    = htonl(nonce);
	unsigned int length  = htonl(0);     /* unnecessary, but only because it's 0. Don't forget! */

	/* setup our buffers */
	b->dest = buffer;
	b->max  = max;

	/* setup our data header */
	memcpy(buffer, &temp, 4);
	memcpy(buffer + 4, &length, 4);

	/* our current length is 8 */
	b->len = 8;

	/* increment counter */
	nonce++; 
}

/* append an integer please */
void build_add_int(builder * b, DWORD number) {
	number = htonl(number);
	build_add_data(b, (char *)&number, sizeof(DWORD));
}

void build_add_short(builder * b, WORD number) {
	number = htons(number);
	build_add_data(b, (char *)&number, sizeof(WORD));
}

void build_add_byte(builder *b, BYTE number) {
	build_add_data(b, (char *)&number, sizeof(BYTE));
}

/* add some data to our buffer please */
void build_add_data(builder * b, char * data, int len) {
	int changeme = 0;

	/* if we're going to go over, bail! */
	if ((b->len + len) > b->max)
			return;

	/* copy our data over */
	memcpy(b->dest + b->len, data, len);

	/* increment our total length */
	b->len += len;

	/* update the length part of our buffer; subtract 8 bytes for the header */
	changeme = ntohl(b->len - 8);
	memcpy(b->dest + 4, &changeme, 4);
}

/* total length of our buffer */
int build_length(builder * b) {
	return b->len + 4;
}

/* this is a slightly different finishing function for RSA encrypted packages */
int build_length_rsa(builder * b) {
	/* put our magic number first */
	unsigned int magic  = htonl(0x0000BEEF);
	memcpy(b->dest, &magic, 4);

	/* return the len without the magic number added to the end */
	return b->len;
}
