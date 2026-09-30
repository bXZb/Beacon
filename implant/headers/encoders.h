#ifndef LINUX_BEACON_ENCODERS_H
#define LINUX_BEACON_ENCODERS_H

/* Match CobaltStrikeBeaconCppSource-main/src/encoders.{h,cpp} */

int netbios_encode(char base, const char *src, int length, char *dst, int maxlength);
int netbios_decode(char base, const char *src, int length, char *dst, int maxlength);

/* 0 on success (CRYPT_OK-compatible), non-zero on failure */
int b64_encode_buf(const unsigned char *in, unsigned long len,
                   unsigned char *out, unsigned long *outlen);
int b64_decode_buf(const unsigned char *in, unsigned long len,
                   unsigned char *out, unsigned long *outlen);

int base64url_encode(const unsigned char *in, unsigned long len,
                     unsigned char *out, unsigned long *outlen);
int base64url_decode(unsigned char *in, unsigned long len, unsigned long max,
                     unsigned char *out, unsigned long *outlen);

int xor_encode(const char *src, int length, char *dst, int maxlength);
int xor_decode(const char *src, int length, char *dst, int maxlength);

#endif
