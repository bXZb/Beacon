// crypto_stub.cpp (project file name: der_stub.cpp) -- no-op stubs for libtomcrypt
// symbols that are LINKED into the beacon but never EXECUTED, so /OPT:REF can't drop
// them and they drag in fat dependency chains. Same "override the symbol, win the
// link, the real .obj loses its sole reference and gets removed" trick as
// miniprintf.cpp / ecc_stub.cpp. Each stub returns a non-zero error so that IF it
// were ever reached it fails the operation gracefully instead of corrupting state.

// ---------------------------------------------------------------------------
// (1) rsa_make_key  --  ~5 KB prime-testing chain (Lucas/Miller-Rabin/Toom/invmod).
// ---------------------------------------------------------------------------
// The beacon never generates a key: it IMPORTS a hardcoded RSA-1024 public key and
// only ever encrypts via rsa_exptmod. Yet rsa_make_key.obj (and through it rand_prime
// -> bn_mp_prime_strong_lucas_selfridge / bn_mp_prime_is_prime /
// bn_mp_prime_miller_rabin / bn_mp_is_square / bn_mp_kronecker /
// bn_s_mp_prime_is_divisible) all get linked. The sole reference is a DEAD function
// pointer: ltm_desc.c:496 stores &rsa_make_key in the math descriptor (the same
// ltm_desc.obj that drives RSA bignum math), right next to &rsa_exptmod (which IS
// used). That pointer is stored but never invoked -- structurally identical to the
// 5 dead ECC pointers ecc_stub.cpp already neutralizes. Confirmed: rsa_make_key has
// zero callers anywhere in LTC or beacon src (only demos/tests). So stubbing it is
// safe and lets the whole ~5 KB keygen/prime-testing chain fall out.
// Signature matches int rsa_make_key(prng_state*, int wprng, int size, long e, rsa_key*).

extern "C" int rsa_make_key(void *prng, int wprng, int size, long e, void *key) {
	(void)prng; (void)wprng; (void)size; (void)e; (void)key;
	return -1; // never executed; beacon does no keygen.
}

// ---------------------------------------------------------------------------
// (1b) mp_prime_is_prime  --  the rest of the prime-testing chain (~4.5 KB).
// ---------------------------------------------------------------------------
// Stubbing rsa_make_key above dropped rsa_make_key.obj + rand_prime.obj, but the
// prime-testing chain (bn_mp_prime_strong_lucas_selfridge / miller_rabin /
// is_square / kronecker / is_divisible) STAYED. Root cause: ltm_desc.c:471 stores
// &isprime in the math descriptor; that static isprime() (ltm_desc.c:401) calls
// mp_prime_is_prime, which pulls the whole chain. The descriptor's isprime field is
// never invoked (the beacon never tests primality -- no keygen, no DSA/ECC), so the
// field is dead, exactly like the rsa_make_key / ECC pointers. With rsa_make_key +
// rand_prime gone, mp_prime_is_prime's ONLY remaining referencer is that dead field.
// Stub it here (overrides the tommath member) -> bn_mp_prime_is_prime.obj drops ->
// lucas / miller-rabin / is_square / kronecker / is_divisible drop with it.
// NOTE: s_mp_toom_mul / s_mp_toom_sqr are NOT in this chain -- they're pulled by
// mp_mul's large-number fast path and stay. Signature: int mp_prime_is_prime(mp_int*, int, int*).

extern "C" int mp_prime_is_prime(void *a, int t, int *result) {
	(void)a; (void)t;
	if (result) *result = 0; // report "not prime" if ever (never) invoked.
	return -1;               // MP_VAL; beacon does no primality testing.
}

// ---------------------------------------------------------------------------
// (2) der_decode_choice  --  DIAGNOSTIC: confirmed it does NOT cascade (see log).
// ---------------------------------------------------------------------------
// The beacon's RSA public key is a 162-byte SubjectPublicKeyInfo blob decoded by
// der_decode_subject_public_key_info via a fixed { SEQUENCE[OID, NULL],
// RAW_BIT_STRING } list -- NO LTC_ASN1_CHOICE element. So the `case CHOICE:` branch
// inside der_decode_sequence_ex (the only call site of der_decode_choice; flexi, the
// other caller, is absent from this 1.17 MAP) is dead at runtime. Stubbing choice
// removes choice.obj itself (~1 KB) but, as the rebuild confirmed, the cert-type
// decoders (utctime/generalizedtime/boolean/short_integer/*_string) STAY -- because
// der_decode_sequence_ex's OWN switch references them directly. So choice-stubbing
// is a dead end for bulk DER savings; the real DER lever would be replacing
// sequence_ex itself (not done -- risky, and insufficient to close the gap alone).
// Kept here as a measured data point + harmless dead symbol (choice is now also
// unreferenced, so this whole block is /OPT:REF'd out of the final binary).

extern "C" int der_decode_choice(const void *in, void *inlen, void *list, unsigned long outlen) {
	(void)in; (void)inlen; (void)list; (void)outlen;
	return -3; // CRYPT_INVALID_PACKET sentinel; unreachable for the beacon.
}

// ---------------------------------------------------------------------------
// (3) s_mp_toom_mul / s_mp_toom_sqr  --  Toom-Cook big-int fast path (~2.8 KB).
// ---------------------------------------------------------------------------
// tommath's mp_mul dispatches: min(a->used,b->used) >= TOOM_MUL_CUTOFF -> toom;
// >= KARATSUBA_MUL_CUTOFF -> karatsuba; else Comba (s_mp_mul_digs_fast). mp_sqr is
// analogous with TOOM_SQR_CUTOFF / KARATSUBA_SQR_CUTOFF.
//
// SAFETY (verified from THIS binary's .data, not from memory):
//   TOOM_MUL_CUTOFF = 350, TOOM_SQR_CUTOFF = 400, KARATSUBA = 80/120.
// The beacon only ever RSA-1024 encrypts: every bignum operand is a 1024-bit value,
// which is at most ceil(1024/8) = 128 mp_digits under the worst-case (MP_8BIT) digit
// width -- 128 < 350, so the toom branch is structurally unreachable for any tommath
// digit config. (Realistically digits are 28 or 64 bits -> 37 or 16 digits, not even
// reaching the 80-digit karatsuba cutoff, so Comba handles all of RSA-1024.) The toom
// objects (bn_s_mp_toom_mul.c.obj 1904B + bn_s_mp_toom_sqr.c.obj 912B) are pulled only
// because mp_mul/mp_sqr statically reference them in the dispatch -- dead at runtime,
// exactly like the ECC/rsa_make_key/prime pointers. extern "C" so the name links
// against the tommath member by symbol name (x64 ABI is uniform, arg count is cosmetic
// but we match: toom_mul takes 3, toom_sqr takes 2).

extern "C" int s_mp_toom_mul(void *a, void *b, void *c) {
	(void)a; (void)b; (void)c;
	return -3; // MP_VAL; unreachable for RSA-1024 (operands < TOOM cutoff 350).
}
extern "C" int s_mp_toom_sqr(void *a, void *b) {
	(void)a; (void)b;
	return -3; // MP_VAL; unreachable for RSA-1024 (operand < TOOM cutoff 400).
}
