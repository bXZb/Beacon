#include "security.h"
#include "beacon.h"
#include "parse.h"
#include "debug.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>

static unsigned char g_key[KEY_SIZE];
static unsigned char g_hmac_key[KEY_SIZE];
static unsigned char g_iv[16];
static unsigned int  g_lastcounter;
static short         g_scheme;

#define TOLERANCE (60 * 60)

void security_init(char *k) {
    unsigned char key_bucket[HASH_SIZE];
    SHA256((const unsigned char *)k, KEY_SIZE, key_bucket);
    memcpy(g_key, key_bucket, KEY_SIZE);
    memcpy(g_hmac_key, key_bucket + KEY_SIZE, KEY_SIZE);
    memcpy(g_iv, "abcdefghijklmnop", 16);
    g_lastcounter = 0;
    g_scheme = (short)setting_short(SETTING_CRYPTO_SCHEME);
    DEBUG_PRINT("[security] init scheme=%d\n", g_scheme);
}

/* Official pad: grow length to multiple of 16 (zeros in pre-sized buffer). */
static int pad_length(int length) {
    int pad = length % 16;
    if (pad == 0) return length;
    return length + (16 - pad);
}

int security_encrypt(char *ciphertext, int length) {
    unsigned char hmac_out[EVP_MAX_MD_SIZE];
    unsigned int  mac_len = 0;
    int outlen = 0, tmplen = 0;
    int padded = pad_length(length);
    EVP_CIPHER_CTX *ctx;
    unsigned char iv_copy[16];

    if (g_scheme == CRYPTO_TRIAL_PRODUCT) {
        /* no AES */
    } else {
        /* Zero-pad remainder (caller buffer must have room) */
        if (padded > length)
            memset(ciphertext + length, 0, (size_t)(padded - length));
        length = padded;

        memcpy(iv_copy, g_iv, 16);
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return 0;
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, g_key, iv_copy) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        if (EVP_EncryptUpdate(ctx, (unsigned char *)ciphertext, &outlen,
                              (unsigned char *)ciphertext, length) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        if (EVP_EncryptFinal_ex(ctx, (unsigned char *)ciphertext + outlen, &tmplen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        length = outlen + tmplen;
        EVP_CIPHER_CTX_free(ctx);
    }

    HMAC(EVP_sha256(), g_hmac_key, KEY_SIZE,
         (unsigned char *)ciphertext, (size_t)length, hmac_out, &mac_len);
    memcpy(ciphertext + length, hmac_out, HMAC_SIZE);
    return length + HMAC_SIZE;
}

int security_decrypt(char *ciphertext, int length) {
    unsigned char hmac_bytes[HMAC_SIZE];
    unsigned char hmac_calc[EVP_MAX_MD_SIZE];
    unsigned int  mac_len = 0;
    char *plaintext;
    datap data;
    unsigned int counter, len;
    char *dptr;
    int outlen = 0, tmplen = 0;
    EVP_CIPHER_CTX *ctx;
    unsigned char iv_copy[16];

    if (length <= HMAC_SIZE) return 0;
    if ((length % 16) != 0) return 0;

    /* HMAC over ciphertext without trailer */
    HMAC(EVP_sha256(), g_hmac_key, KEY_SIZE,
         (unsigned char *)ciphertext, (size_t)(length - HMAC_SIZE),
         hmac_calc, &mac_len);
    memcpy(hmac_bytes, ciphertext + length - HMAC_SIZE, HMAC_SIZE);
    if (memcmp(hmac_bytes, hmac_calc, HMAC_SIZE) != 0) {
        DEBUG_PRINT("[security] HMAC mismatch\n");
        return 0;
    }

    length -= HMAC_SIZE;
    plaintext = (char *)malloc((size_t)length);
    if (!plaintext) return 0;

    if (g_scheme == CRYPTO_TRIAL_PRODUCT) {
        memcpy(plaintext, ciphertext, (size_t)length);
    } else {
        memcpy(iv_copy, g_iv, 16);
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            free(plaintext);
            return 0;
        }
        if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, g_key, iv_copy) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            free(plaintext);
            return 0;
        }
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        if (EVP_DecryptUpdate(ctx, (unsigned char *)plaintext, &outlen,
                              (unsigned char *)ciphertext, length) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            free(plaintext);
            return 0;
        }
        if (EVP_DecryptFinal_ex(ctx, (unsigned char *)plaintext + outlen, &tmplen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            free(plaintext);
            return 0;
        }
        EVP_CIPHER_CTX_free(ctx);
        /* outlen+tmplen == length with padding disabled */
    }

    data_init(&data, plaintext, length);
    counter = data_int(&data);
    if ((counter + TOLERANCE) <= g_lastcounter) {
        free(plaintext);
        return 0;
    }
    len = data_int(&data);
    if (len == 0 || len > (unsigned int)length) {
        free(plaintext);
        return 0;
    }
    dptr = data_ptr(&data, (int)len);
    if (!dptr) {
        free(plaintext);
        return 0;
    }
    memcpy(ciphertext, dptr, len);
    g_lastcounter = counter;
    free(plaintext);
    return (int)len;
}

int rsa_encrypt_once(char *kbuffer, int klen, char *indata, int inlen,
                     char *outdata, int *outlen) {
    const unsigned char *p = (const unsigned char *)kbuffer;
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *ctx;
    size_t outl;

    g_scheme = (short)setting_short(SETTING_CRYPTO_SCHEME);

    /* CS always stores PUBKEY as 256-byte fixed field (zero-padded DER).
     * d2i_* stops at end of structure; pass full buffer length. */
    if (klen <= 0) klen = 256;
    pkey = d2i_PUBKEY(NULL, &p, klen);
    if (!pkey) {
        /* try PKCS#1 RSAPublicKey */
        p = (const unsigned char *)kbuffer;
        pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &p, klen);
    }
    if (!pkey) {
        ERROR_PRINT("[security] rsa: failed to load public key (len=%d)\n", klen);
        return -1;
    }

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    outl = (size_t)(*outlen);
    if (EVP_PKEY_encrypt(ctx, (unsigned char *)outdata, &outl,
                         (unsigned char *)indata, (size_t)inlen) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    *outlen = (int)outl;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return 0;
}
