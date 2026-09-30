#ifndef LINUX_BEACON_SECURITY_H
#define LINUX_BEACON_SECURITY_H

#include "beacon.h"

int  security_decrypt(char *buffer, int length);
int  security_encrypt(char *buffer, int length);
void security_init(char *k);
int  rsa_encrypt_once(char *kbuffer, int klen, char *indata, int inlen,
                      char *outdata, int *outlen);

#endif
