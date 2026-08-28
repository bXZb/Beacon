/* 加密/编码薄抽象层的实现（P4.15）。本单元与 security.cpp 是仅有的两个
 * 允许包含 tomcrypt.h 的文件（见 crypto.h 边界约定）。 */
#include "crypto.h"
#include "tomcrypt.h"

#include <windows.h>
#include <wincrypt.h>

/* ------------------------------------------------------------------ */
/* base64 直通包装                                                     */
/* ------------------------------------------------------------------ */

int crypto_base64_encode(const unsigned char * in, unsigned long inlen,
                         unsigned char * out, unsigned long * outlen) {
	return base64_encode(in, inlen, out, outlen);
}

int crypto_base64_decode(const unsigned char * in, unsigned long inlen,
                         unsigned char * out, unsigned long * outlen) {
	return base64_decode(in, inlen, out, outlen);
}

/* ------------------------------------------------------------------ */
/* OS 随机数源：ProcessPrng（Win10 1809+）→ CryptGenRandom 回退          */
/* ------------------------------------------------------------------ */

typedef BOOL(WINAPI * ProcessPrngFn)(unsigned char * pbData, unsigned long cbData);

static ProcessPrngFn g_processPrng = NULL;
static int           g_processPrngResolved = 0;
static HCRYPTPROV    g_fallbackProv = 0;

static void resolve_rng_source(void) {
	HMODULE bcrypt;
	if (g_processPrngResolved)
		return;
	g_processPrngResolved = 1;

	bcrypt = GetModuleHandleA("bcrypt.dll");
	if (bcrypt != NULL)
		g_processPrng = (ProcessPrngFn)GetProcAddress(bcrypt, "ProcessPrng");

	if (g_processPrng == NULL) {
		/* Win7/8 回退：CryptGenRandom（advapi32） */
		if (!CryptAcquireContextA(&g_fallbackProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
			g_fallbackProv = 0;
	}
}

/* 以下回调签名对齐 LTC 1.17 的 ltc_prng_descriptor；我们的随机源无状态，
   prng_state 一律忽略。 */

static int os_rng_start(prng_state * prng) { (void)prng; return CRYPT_OK; }

static int os_rng_add_entropy(const unsigned char * in, unsigned long inlen, prng_state * prng) {
	(void)in; (void)inlen; (void)prng;
	return CRYPT_OK; /* OS 源自带熵，外部熵可选 */
}

static int os_rng_ready(prng_state * prng) { (void)prng; return CRYPT_OK; }

static unsigned long os_rng_read(unsigned char * out, unsigned long outlen, prng_state * prng) {
	(void)prng;
	resolve_rng_source();

	if (out == NULL || outlen == 0)
		return 0;

	if (g_processPrng != NULL) {
		if (g_processPrng(out, outlen))
			return outlen;
		return 0;
	}

	if (g_fallbackProv != 0 && CryptGenRandom(g_fallbackProv, (DWORD)outlen, out))
		return outlen;

	return 0;
}

static int os_rng_done(prng_state * prng) {
	(void)prng;
	/* 保留 fallback 句柄供进程后续使用，进程退出由 OS 回收 */
	return CRYPT_OK;
}

static int os_rng_pexport(unsigned char * out, unsigned long * outlen, prng_state * prng) {
	(void)prng;
	if (outlen != NULL)
		*outlen = 0; /* 无状态可导出 */
	(void)out;
	return CRYPT_OK;
}

static int os_rng_pimport(const unsigned char * in, unsigned long inlen, prng_state * prng) {
	(void)in; (void)inlen; (void)prng;
	return CRYPT_OK;
}

static int os_rng_test(void) { return CRYPT_NOP; }

static char g_os_rng_name[] = "processprng";

static const struct ltc_prng_descriptor g_os_rng_desc = {
	g_os_rng_name,
	0,              /* export_size：无状态 */
	os_rng_start,
	os_rng_add_entropy,
	os_rng_ready,
	os_rng_read,
	os_rng_done,
	os_rng_pexport,
	os_rng_pimport,
	os_rng_test
};

int crypto_init(void) {
	int idx;

	if (register_prng(&g_os_rng_desc) == -1)
		return -1;

	idx = find_prng("processprng");
	resolve_rng_source();
	return idx;
}
