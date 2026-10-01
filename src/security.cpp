#include "security.h"
#include "tomcrypt.h"
#include "crypto.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <wininet.h>

#include "parse.h"
#include "beacon.h"

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

/* Watermark code validation */
// Function to calculate (x^y) % p
// See: https://www.geeksforgeeks.org/modular-exponentiation-power-in-modular-arithmetic/
//
int modpow(int ix, int iy, int ip)
{
	unsigned long long res = 1;     // Initialize result
	unsigned long long xBig = ix;
	unsigned long long yBig = iy;
	unsigned long long pBig = ip;
	unsigned long long temp = 0;

	//dlog("modpow calculation 1: (%i^%i) mod %i", ix, iy, ip);
	//dlog("modpow calculation 2: (%d^%d) mod %d", ix, iy, ip);
	//dlog("modpow calculation 3: (%llu^%llu) mod %llu", xBig, yBig, pBig);

	xBig = xBig % pBig; // Update x if it is more than or equal to p

	if (xBig == 0) return 0; // In case x is divisible by p;

	while (yBig > 0)
	{
		//dlog("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
		//dlog("modpow sub-calculation 1: xBig=%llu yBig=%llu pBig=%llu res=%llu ", xBig, yBig, pBig, res);
		// If y is odd, multiply x with result
		if ((yBig & 1) != 0)
			res = (res * xBig) % pBig;

		//dlog("modpow sub-calculation 2: xBig=%llu yBig=%llu pBig=%llu res=%llu ", xBig, yBig, pBig, res);

		// y must be even now
		yBig = yBig >> 1; // y = y/2
		temp = xBig * xBig;
		xBig = temp % pBig;
		//dlog("modpow sub-calculation 3: xBig=%llu yBig=%llu pBig=%llu res=%llu temp=%llu", xBig, yBig, pBig, res, temp);
	}
	//dlog("modpow result: %llu", res);
	return (int) res;
}

// We want a small representation of the watermark
int reduceWatermark(unsigned int watermark) {
	char wStr[16];
	char rStr[5];
	int wlen, rwm;

	_snprintf(wStr, sizeof(wStr), "%u", watermark);
	wlen = strlen(wStr);

	// Use the 1st, 3rd, 3rd from end, and last digits, caller made sure there is enough digits.
	_snprintf(rStr, sizeof(rStr), "%c%c%c%c", wStr[0], wStr[2], wStr[wlen - 3], wStr[wlen - 1]);
	rwm = atoi(rStr);

	//dlog("Reducing Watermark3 Digits: %c %c %c %c", wStr[0], wStr[2], wStr[wlen - 3], wStr[wlen - 1]);
	//dlog("Reduced Watermark3: %d (from %u)", rwm, watermark);

	return rwm;
}

int createWMKey(unsigned int watermark) {
	int g = 999999888;
	int p = 999999987;
	int rwm, powwed;

	if (watermark <= 9999) {
		return 0;
	}

	// Convert watermark to something '9999' or less...
	rwm = reduceWatermark(watermark);
	powwed = modpow(g, rwm, p);
	//dlog("createWMKey:   %d = %d pow %d mod %d", powwed, g, rwm, p);

	return powwed;
}

int decodeWatermark(unsigned char * encodedText, unsigned long encodedLen, int watermarkKey, unsigned int watermark) {

// ===========================================================
// THIS IS REPLICATED IN: .../external/sshagent/src/security.c
// ===========================================================

	unsigned char decodedText[16];
	unsigned char decryptedText[16];
	unsigned char wmBytes[16];
	unsigned char wmKeyBytes[16];
	unsigned char wmiv[16];
	unsigned char padding[16];

	int  i, length, check;
	int dtlen;
	int bad = 1;

	//dlog("Decoding Watermark Hash: %s Key: %i Mark: %u", encodedText, watermarkKey, watermark);

	memset(wmBytes, 0, sizeof(wmBytes));
	memset(wmKeyBytes, 0, sizeof(wmKeyBytes));
	memset(decodedText, 0, sizeof(decodedText));
	memset(decryptedText, 0, sizeof(decryptedText));
	memset(wmiv, 0, sizeof(wmiv));
	memcpy(padding, "123456789abcdefg", 16);

	_snprintf((char *)wmBytes, sizeof(wmBytes), "%u", watermark);
	_snprintf((char*)wmKeyBytes, sizeof(wmKeyBytes), "%d", watermarkKey);

	// Pad the watermark key, because AES key must be 16/24/32 bytes...
	length = strlen((char*)wmKeyBytes);
	for (i = length; i < sizeof(wmKeyBytes); i++) {
		// wmKeyBytes[i] = (unsigned char)i;
		wmKeyBytes[i] = padding[i];
	}

	// Pad the watermark, because the java side did the same.
	length = strlen((const char*)wmBytes);
	for (i = length; i < sizeof(wmBytes); i++) {
		// wmBytes[i] = (unsigned char)i;
		wmBytes[i] = padding[i];
	}

	//dlog("Padded Watermark: %.16s Watermark Key: %.16s", wmBytes, wmKeyBytes);

	/* b64 decode the encrypted buffer */
	dtlen = sizeof(decodedText);
	//dlog("Calling base64_decode with Encoded Text Len: %lu Decoded Text Len: %i", encodedLen, dtlen);
	check = base64_decode(encodedText, encodedLen, decodedText, (unsigned long*) & dtlen);
	sanity("base64_decode", check);
	//dlog("Decoded From Base64 Watermark Hash: %.16s Length: %i", decodedText, dtlen);

	// Decrypt the Watermark.
	//dlog("Preparing AES Cipher");
	register_cipher(&aes_desc);
	cipher = find_cipher("aes");

	//dlog("Starting Cipher");
	memcpy(wmiv, "abcdefghijklmnop", 16);
	check = cbc_start(cipher, wmiv, wmKeyBytes, KEY_SIZE, 0, &in_state);
	sanity("decrypt/cbc_start", check);

	//dlog("Decrypting With Cipher");
	check = cbc_decrypt(decodedText, decryptedText, sizeof(decryptedText), &in_state);
	sanity("decrypt/cbc_decrypt", check);

	//dlog("Finishing Cipher");
	check = cbc_done(&in_state);
	sanity("decrypt/cbc_done", check);

	// Are we OK?
	//dlog("Comparing Decoded/Decrypted Padded Watermark: %.16s Calculated Padded Watermark: %.16s Size: %i", decryptedText, wmBytes, sizeof(wmBytes));
	if (strncmp((const char*)wmBytes, (const char*)decryptedText, sizeof(wmBytes)) == 0) {
		//dlog("Whoo-Hoo!");
		bad = 0;
	} else {
		//dlog("Boo-Hoo!");
		bad = 1;
	}

	// Clean up some memory...
	memset(wmBytes, 0, sizeof(wmBytes));
	memset(wmKeyBytes, 0, sizeof(wmKeyBytes));
	memset(decodedText, 0, sizeof(decodedText));
	memset(decryptedText, 0, sizeof(decryptedText));
	check = 0;
	i = 0;
	length = 0;
	dtlen = 0;

	// Get Out!
	//dlog("Getting Out Of decodeWatermark with bad: %i", bad);
	return bad;
}
